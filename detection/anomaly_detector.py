"""Thread-safe statistical anomaly detection for SentinelAI-X."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Callable, Final
from uuid import uuid4


PacketMetadata = Mapping[str, Any] | object


class JsonLogFormatter(logging.Formatter):
    """Format log records as JSON objects."""

    _standard_attributes: Final[frozenset[str]] = frozenset(
        logging.makeLogRecord({}).__dict__
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._standard_attributes and key != "message":
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)


def build_logger(name: str = "sentinelai_x.anomaly_detector") -> logging.Logger:
    """Create a structured logger without modifying the root logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


class AnomalyType(str, Enum):
    """Supported statistical anomaly categories."""

    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    RARE_PORT = "RARE_PORT"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"


@dataclass(frozen=True, slots=True)
class AnomalyFinding:
    """Immutable anomaly emitted by the detector."""

    id: str
    timestamp: datetime
    anomaly_type: AnomalyType
    risk_score: float
    source_ip: str | None
    destination_ip: str | None
    description: str
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("AnomalyFinding id must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("AnomalyFinding timestamp must be timezone-aware")
        if not self.description.strip():
            raise ValueError("AnomalyFinding description must not be empty")
        if isinstance(self.risk_score, bool) or not isinstance(
            self.risk_score, (int, float)
        ):
            raise ValueError("AnomalyFinding risk_score must be numeric")
        if self.risk_score < 0.0 or self.risk_score > 100.0:
            raise ValueError("AnomalyFinding risk_score must be between 0 and 100")
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable anomaly representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "anomaly_type": self.anomaly_type.value,
            "risk_score": self.risk_score,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class BaselineSnapshot:
    """Point-in-time baseline statistics."""

    total_packets: int = 0
    packets_per_second: float = 0.0
    protocol_distribution: Mapping[str, float] = field(default_factory=dict)
    port_distribution: Mapping[int, float] = field(default_factory=dict)
    learning_complete: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "protocol_distribution",
            MappingProxyType(dict(self.protocol_distribution)),
        )
        object.__setattr__(
            self,
            "port_distribution",
            MappingProxyType(dict(self.port_distribution)),
        )


@dataclass(frozen=True, slots=True)
class AnomalyDetectorConfig:
    """Configuration for baseline learning and anomaly thresholds."""

    min_learning_packets: int = 100
    learning_window_seconds: float = 60.0
    observation_window_seconds: float = 10.0
    traffic_spike_multiplier: float = 3.0
    rare_port_frequency_threshold: float = 0.01
    protocol_rarity_threshold: float = 0.02
    max_tracked_ports: int = 10_000
    max_tracked_protocols: int = 256
    max_window_events: int = 50_000
    findings_limit_per_packet: int = 10
    risk_weight_traffic_spike: float = 40.0
    risk_weight_rare_port: float = 30.0
    risk_weight_protocol_anomaly: float = 35.0

    def __post_init__(self) -> None:
        positive_ints = {
            "min_learning_packets": self.min_learning_packets,
            "max_tracked_ports": self.max_tracked_ports,
            "max_tracked_protocols": self.max_tracked_protocols,
            "max_window_events": self.max_window_events,
            "findings_limit_per_packet": self.findings_limit_per_packet,
        }
        for name, int_value in positive_ints.items():
            if isinstance(int_value, bool) or int_value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        positive_floats: dict[str, int | float] = {
            "learning_window_seconds": self.learning_window_seconds,
            "observation_window_seconds": self.observation_window_seconds,
            "traffic_spike_multiplier": self.traffic_spike_multiplier,
            "rare_port_frequency_threshold": self.rare_port_frequency_threshold,
            "protocol_rarity_threshold": self.protocol_rarity_threshold,
            "risk_weight_traffic_spike": self.risk_weight_traffic_spike,
            "risk_weight_rare_port": self.risk_weight_rare_port,
            "risk_weight_protocol_anomaly": self.risk_weight_protocol_anomaly,
        }
        for name, float_value in positive_floats.items():
            if isinstance(float_value, bool) or not isinstance(
                float_value, (int, float)
            ):
                raise ValueError(f"{name} must be numeric")
            if float_value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        if self.rare_port_frequency_threshold > 1.0:
            raise ValueError(
                "rare_port_frequency_threshold must be between 0 and 1"
            )
        if self.protocol_rarity_threshold > 1.0:
            raise ValueError("protocol_rarity_threshold must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class AnomalyDetectorMetrics:
    """Point-in-time detector metrics."""

    packets_observed: int = 0
    findings_generated: int = 0
    learning_packets: int = 0
    detection_packets: int = 0
    observation_failures: int = 0
    processing_latency: float = 0.0

    @property
    def average_processing_latency(self) -> float:
        """Return average packet observation latency in seconds."""
        if self.packets_observed == 0:
            return 0.0
        return self.processing_latency / self.packets_observed


class AnomalyDetector:
    """Learn traffic baselines and detect statistical anomalies."""

    def __init__(
        self,
        config: AnomalyDetectorConfig | None = None,
        logger: logging.Logger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or AnomalyDetectorConfig()
        self._logger = logger or build_logger()
        self._clock = clock
        self._lock = RLock()
        self._learning_packets = 0
        self._baseline_total_packets = 0
        self._baseline_packets_per_second = 0.0
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._port_counts: dict[int, int] = defaultdict(int)
        self._learning_timestamps: deque[float] = deque(
            maxlen=self._config.max_window_events
        )
        self._source_observation_events: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=self._config.max_window_events)
        )
        self._metrics = AnomalyDetectorMetrics()
        self._active_spike_sources: set[str] = set()

    @property
    def config(self) -> AnomalyDetectorConfig:
        return self._config

    def is_baseline_ready(self) -> bool:
        """Return whether enough packets have been observed to detect anomalies."""
        with self._lock:
            return self._learning_packets >= self._config.min_learning_packets

    def observe(self, packet_metadata: PacketMetadata) -> list[AnomalyFinding]:
        """Observe one packet, update the baseline, and return anomalies."""
        started_at = self._clock()
        findings: list[AnomalyFinding] = []
        failures = 0
        baseline_ready_before = False

        try:
            event_time = _event_time(packet_metadata, self._clock)
            protocol = _normalized_protocol(packet_metadata)
            destination_port = _get_optional_int(
                packet_metadata, "destination_port"
            )
            source_ip = _get_optional_str(packet_metadata, "source_ip")

            with self._lock:
                baseline_ready_before = (
                    self._learning_packets >= self._config.min_learning_packets
                )
                if baseline_ready_before:
                    findings = self._detect_anomalies_locked(
                        packet_metadata=packet_metadata,
                        event_time=event_time,
                        protocol=protocol,
                        destination_port=destination_port,
                        source_ip=source_ip,
                    )
                self._record_learning_locked(event_time, protocol, destination_port)
        except Exception:
            failures = 1
            self._logger.exception("Anomaly observation failed")

        latency = max(0.0, self._clock() - started_at)
        with self._lock:
            current = self._metrics
            self._metrics = AnomalyDetectorMetrics(
                packets_observed=current.packets_observed + 1,
                findings_generated=current.findings_generated + len(findings),
                learning_packets=current.learning_packets
                + (0 if baseline_ready_before else 1),
                detection_packets=current.detection_packets
                + (1 if baseline_ready_before else 0),
                observation_failures=current.observation_failures + failures,
                processing_latency=current.processing_latency + latency,
            )

        if findings:
            self._logger.info(
                "Statistical anomalies detected",
                extra={
                    "finding_count": len(findings),
                    "anomaly_types": [
                        finding.anomaly_type.value for finding in findings
                    ],
                    "max_risk_score": max(
                        finding.risk_score for finding in findings
                    ),
                },
            )
        return findings

    process_packet = observe

    def get_baseline(self) -> BaselineSnapshot:
        """Return the current baseline snapshot."""
        with self._lock:
            total = max(self._baseline_total_packets, 1)
            protocol_distribution = {
                protocol: count / total
                for protocol, count in sorted(self._protocol_counts.items())
            }
            port_distribution = {
                port: count / total
                for port, count in sorted(self._port_counts.items())
            }
            return BaselineSnapshot(
                total_packets=self._baseline_total_packets,
                packets_per_second=self._baseline_packets_per_second,
                protocol_distribution=protocol_distribution,
                port_distribution=port_distribution,
                learning_complete=self.is_baseline_ready(),
            )

    def reset_baseline(self) -> None:
        """Clear learned baseline state and restart learning."""
        with self._lock:
            self._learning_packets = 0
            self._baseline_total_packets = 0
            self._baseline_packets_per_second = 0.0
            self._protocol_counts.clear()
            self._port_counts.clear()
            self._learning_timestamps.clear()
            self._source_observation_events.clear()
            self._active_spike_sources.clear()

    def get_metrics(self) -> AnomalyDetectorMetrics:
        with self._lock:
            return self._metrics

    def reset_metrics(self) -> None:
        with self._lock:
            self._metrics = AnomalyDetectorMetrics()

    def _record_learning_locked(
        self,
        event_time: float,
        protocol: str,
        destination_port: int | None,
    ) -> None:
        self._learning_packets += 1
        self._baseline_total_packets += 1
        self._learning_timestamps.append(event_time)
        cutoff = event_time - self._config.learning_window_seconds
        while self._learning_timestamps and self._learning_timestamps[0] < cutoff:
            self._learning_timestamps.popleft()

        self._protocol_counts[protocol] += 1
        if len(self._protocol_counts) > self._config.max_tracked_protocols:
            self._prune_least_frequent(self._protocol_counts)

        if destination_port is not None:
            if not _is_valid_port(destination_port):
                return
            self._port_counts[destination_port] += 1
            if len(self._port_counts) > self._config.max_tracked_ports:
                self._prune_least_frequent(self._port_counts)

        window_span = max(
            self._config.learning_window_seconds,
            event_time - self._learning_timestamps[0]
            if self._learning_timestamps
            else self._config.learning_window_seconds,
        )
        self._baseline_packets_per_second = (
            len(self._learning_timestamps) / window_span
        )

    def _detect_anomalies_locked(
        self,
        *,
        packet_metadata: PacketMetadata,
        event_time: float,
        protocol: str,
        destination_port: int | None,
        source_ip: str | None,
    ) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        current_rate = 0.0
        baseline_rate = self._baseline_packets_per_second
        if source_ip is not None:
            events = self._source_observation_events[source_ip]
            events.append(event_time)
            cutoff = event_time - self._config.observation_window_seconds
            while events and events[0] < cutoff:
                events.popleft()
            current_rate = len(events) / max(
                self._config.observation_window_seconds, 1e-9
            )

        spike_detected = (
            source_ip is not None
            and baseline_rate > 0.0
            and current_rate
            >= baseline_rate * self._config.traffic_spike_multiplier
        )
        if spike_detected and source_ip is not None:
            if source_ip not in self._active_spike_sources:
                self._active_spike_sources.add(source_ip)
                findings.append(
                    self._finding(
                        packet_metadata,
                        AnomalyType.TRAFFIC_SPIKE,
                        "Traffic spike detected relative to learned baseline",
                        {
                            "current_packets_per_second": current_rate,
                            "baseline_packets_per_second": baseline_rate,
                            "spike_multiplier": self._config.traffic_spike_multiplier,
                            "observation_window_seconds": (
                                self._config.observation_window_seconds
                            ),
                        },
                        self._config.risk_weight_traffic_spike,
                    )
                )
        elif source_ip is not None:
            self._active_spike_sources.discard(source_ip)

        if (
            destination_port is not None
            and _is_valid_port(destination_port)
            and len(findings) < self._config.findings_limit_per_packet
        ):
            port_frequency = self._port_frequency_locked(destination_port)
            if (
                destination_port not in self._port_counts
                or port_frequency < self._config.rare_port_frequency_threshold
            ):
                findings.append(
                    self._finding(
                        packet_metadata,
                        AnomalyType.RARE_PORT,
                        f"Rare destination port {destination_port} observed",
                        {
                            "destination_port": destination_port,
                            "port_frequency": port_frequency,
                            "threshold": self._config.rare_port_frequency_threshold,
                        },
                        self._config.risk_weight_rare_port,
                    )
                )

        if len(findings) < self._config.findings_limit_per_packet:
            protocol_frequency = self._protocol_frequency_locked(protocol)
            if (
                protocol not in self._protocol_counts
                or protocol_frequency < self._config.protocol_rarity_threshold
            ):
                findings.append(
                    self._finding(
                        packet_metadata,
                        AnomalyType.PROTOCOL_ANOMALY,
                        f"Protocol anomaly detected for {protocol}",
                        {
                            "protocol": protocol,
                            "protocol_frequency": protocol_frequency,
                            "threshold": self._config.protocol_rarity_threshold,
                        },
                        self._config.risk_weight_protocol_anomaly,
                    )
                )

        return findings[: self._config.findings_limit_per_packet]

    def _port_frequency_locked(self, port: int) -> float:
        total = max(self._baseline_total_packets, 1)
        return self._port_counts.get(port, 0) / total

    def _protocol_frequency_locked(self, protocol: str) -> float:
        total = max(self._baseline_total_packets, 1)
        return self._protocol_counts.get(protocol, 0) / total

    def _finding(
        self,
        packet_metadata: PacketMetadata,
        anomaly_type: AnomalyType,
        description: str,
        metadata: Mapping[str, Any],
        risk_weight: float,
    ) -> AnomalyFinding:
        return AnomalyFinding(
            id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            anomaly_type=anomaly_type,
            risk_score=min(100.0, max(0.0, float(risk_weight))),
            source_ip=_get_optional_str(packet_metadata, "source_ip"),
            destination_ip=_get_optional_str(packet_metadata, "destination_ip"),
            description=description,
            metadata=metadata,
        )

    @staticmethod
    def _prune_least_frequent(counts: dict[Any, int]) -> None:
        if not counts:
            return
        key_to_remove = min(counts, key=lambda key: counts[key])
        counts.pop(key_to_remove, None)


def compute_aggregate_risk_score(findings: Iterable[AnomalyFinding]) -> float:
    """Combine multiple findings into a single capped risk score."""
    total = 0.0
    for finding in findings:
        total += finding.risk_score
    return min(100.0, total)


def _get_value(packet_metadata: PacketMetadata, key: str) -> Any:
    if isinstance(packet_metadata, Mapping):
        return packet_metadata.get(key)
    return getattr(packet_metadata, key, None)


def _get_optional_str(packet_metadata: PacketMetadata, key: str) -> str | None:
    value = _get_value(packet_metadata, key)
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _get_optional_int(
    packet_metadata: PacketMetadata,
    key: str,
    *,
    fallback_key: str | None = None,
) -> int | None:
    value = _get_value(packet_metadata, key)
    if value is None and fallback_key is not None:
        value = _get_value(packet_metadata, fallback_key)
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _normalized_protocol(packet_metadata: PacketMetadata) -> str:
    protocol = _get_optional_str(packet_metadata, "protocol")
    if protocol is None:
        return "UNKNOWN"
    return protocol.upper()


def _is_valid_port(port: int) -> bool:
    return 1 <= port <= 65_535


def _event_time(
    packet_metadata: PacketMetadata,
    clock: Callable[[], float],
) -> float:
    timestamp = _get_value(packet_metadata, "timestamp")
    if timestamp is None:
        return float(clock())
    if isinstance(timestamp, datetime):
        return timestamp.timestamp()
    try:
        return float(timestamp)
    except (TypeError, ValueError, OverflowError):
        return float(clock())


__all__ = [
    "AnomalyDetector",
    "AnomalyDetectorConfig",
    "AnomalyDetectorMetrics",
    "AnomalyFinding",
    "AnomalyType",
    "BaselineSnapshot",
    "JsonLogFormatter",
    "build_logger",
    "compute_aggregate_risk_score",
]
