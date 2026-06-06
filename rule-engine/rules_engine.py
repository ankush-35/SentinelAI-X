"""Thread-safe, extensible packet detection rules for SentinelAI-X."""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
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


def build_logger(name: str = "sentinelai_x.rules_engine") -> logging.Logger:
    """Create a structured logger without modifying the root logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


class AlertSeverity(str, Enum):
    """Alert impact levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(str, Enum):
    """Supported security alert categories."""

    PORT_SCAN = "PORT_SCAN"
    ICMP_FLOOD = "ICMP_FLOOD"
    DNS_TUNNELING = "DNS_TUNNELING"
    SUSPICIOUS_PORT = "SUSPICIOUS_PORT"
    BLACKLISTED_IP = "BLACKLISTED_IP"
    MALFORMED_PACKET = "MALFORMED_PACKET"
    BRUTE_FORCE = "BRUTE_FORCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


@dataclass(frozen=True, slots=True)
class Alert:
    """Immutable security alert emitted by a detection rule."""

    id: str
    timestamp: datetime
    severity: AlertSeverity
    alert_type: AlertType
    source_ip: str | None
    destination_ip: str | None
    description: str
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Alert id must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("Alert timestamp must be timezone-aware")
        if not self.description.strip():
            raise ValueError("Alert description must not be empty")
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable alert representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "alert_type": self.alert_type.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RulesEngineConfig:
    """Configuration shared by the rules engine and built-in rules."""

    thresholds: Mapping[str, int | float] = field(default_factory=dict)
    blacklist: frozenset[str] = field(default_factory=frozenset)
    suspicious_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({21, 22, 23, 135, 139, 445, 3389})
    )
    alert_limit_per_packet: int = 100
    max_retained_alerts: int = 10_000
    alert_retention_seconds: float = 3600.0
    port_scan_window_seconds: float = 60.0
    horizontal_scan_threshold: int = 10
    vertical_scan_threshold: int = 20
    icmp_flood_window_seconds: float = 10.0
    icmp_flood_threshold: int = 100

    def __post_init__(self) -> None:
        positive_values = {
            "alert_limit_per_packet": self.alert_limit_per_packet,
            "max_retained_alerts": self.max_retained_alerts,
            "alert_retention_seconds": self.alert_retention_seconds,
            "port_scan_window_seconds": self.port_scan_window_seconds,
            "horizontal_scan_threshold": self.horizontal_scan_threshold,
            "vertical_scan_threshold": self.vertical_scan_threshold,
            "icmp_flood_window_seconds": self.icmp_flood_window_seconds,
            "icmp_flood_threshold": self.icmp_flood_threshold,
        }
        for name, value in positive_values.items():
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        normalized_ports = frozenset(int(port) for port in self.suspicious_ports)
        if any(port < 1 or port > 65_535 for port in normalized_ports):
            raise ValueError("suspicious_ports must contain valid TCP/UDP ports")

        normalized_blacklist: set[str] = set()
        for address in self.blacklist:
            normalized_blacklist.add(str(ip_address(address)))

        normalized_thresholds = dict(self.thresholds)
        for name, value in normalized_thresholds.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Threshold {name!r} must be numeric")
            if value <= 0:
                raise ValueError(f"Threshold {name!r} must be greater than zero")

        object.__setattr__(
            self,
            "thresholds",
            MappingProxyType(normalized_thresholds),
        )
        object.__setattr__(self, "suspicious_ports", normalized_ports)
        object.__setattr__(self, "blacklist", frozenset(normalized_blacklist))

    def threshold(self, name: str, default: int | float) -> int | float:
        """Return a named override or its supplied default."""
        return self.thresholds.get(name, default)


@dataclass(frozen=True, slots=True)
class RulesEngineMetrics:
    """Point-in-time engine metrics."""

    packets_processed: int = 0
    alerts_generated: int = 0
    rules_executed: int = 0
    rule_failures: int = 0
    processing_latency: float = 0.0

    @property
    def average_processing_latency(self) -> float:
        """Return average packet processing latency in seconds."""
        if self.packets_processed == 0:
            return 0.0
        return self.processing_latency / self.packets_processed


class DetectionRule(ABC):
    """Contract implemented by all packet detection rules."""

    @abstractmethod
    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        """Evaluate one packet and return an alert when it matches."""

    @abstractmethod
    def get_name(self) -> str:
        """Return the stable, unique rule name."""

    @abstractmethod
    def get_severity(self) -> AlertSeverity:
        """Return the rule's alert severity."""


class _BaseRule(DetectionRule):
    """Common alert creation support for built-in rules."""

    def __init__(self, severity: AlertSeverity) -> None:
        self._severity = severity
        self._lock = RLock()

    def get_name(self) -> str:
        return self.__class__.__name__

    def get_severity(self) -> AlertSeverity:
        return self._severity

    def _alert(
        self,
        packet_metadata: PacketMetadata,
        alert_type: AlertType,
        description: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> Alert:
        return Alert(
            id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            severity=self.get_severity(),
            alert_type=alert_type,
            source_ip=_get_optional_str(packet_metadata, "source_ip"),
            destination_ip=_get_optional_str(packet_metadata, "destination_ip"),
            description=description,
            metadata=metadata or {},
        )


class PortScanRule(_BaseRule):
    """Detect horizontal and vertical scans within a sliding window."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        horizontal_threshold: int = 10,
        vertical_threshold: int = 20,
        severity: AlertSeverity = AlertSeverity.HIGH,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(severity)
        _validate_positive("window_seconds", window_seconds)
        _validate_positive("horizontal_threshold", horizontal_threshold)
        _validate_positive("vertical_threshold", vertical_threshold)
        self._window_seconds = float(window_seconds)
        self._horizontal_threshold = int(horizontal_threshold)
        self._vertical_threshold = int(vertical_threshold)
        self._clock = clock
        self._events: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self._active_detections: set[tuple[str, str, str | None]] = set()

    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        source_ip = _get_optional_str(packet_metadata, "source_ip")
        destination_ip = _get_optional_str(packet_metadata, "destination_ip")
        destination_port = _get_optional_int(packet_metadata, "destination_port")
        if source_ip is None or destination_ip is None or destination_port is None:
            return None

        now = _event_time(packet_metadata, self._clock)
        with self._lock:
            events = self._events[source_ip]
            events.append((now, destination_ip, destination_port))
            cutoff = now - self._window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()

            destinations = {event[1] for event in events}
            horizontal_key = (source_ip, "horizontal", None)
            if len(destinations) >= self._horizontal_threshold:
                if horizontal_key not in self._active_detections:
                    self._active_detections.add(horizontal_key)
                    return self._alert(
                        packet_metadata,
                        AlertType.PORT_SCAN,
                        "Horizontal port scan detected",
                        {
                            "scan_type": "horizontal",
                            "unique_destinations": len(destinations),
                            "window_seconds": self._window_seconds,
                        },
                    )
            else:
                self._active_detections.discard(horizontal_key)

            ports = {
                event[2] for event in events if event[1] == destination_ip
            }
            vertical_key = (source_ip, "vertical", destination_ip)
            if len(ports) >= self._vertical_threshold:
                if vertical_key not in self._active_detections:
                    self._active_detections.add(vertical_key)
                    return self._alert(
                        packet_metadata,
                        AlertType.PORT_SCAN,
                        "Vertical port scan detected",
                        {
                            "scan_type": "vertical",
                            "unique_ports": len(ports),
                            "window_seconds": self._window_seconds,
                        },
                    )
            else:
                self._active_detections.discard(vertical_key)
        return None


class ICMPFloodRule(_BaseRule):
    """Detect excessive ICMP packet rates per source."""

    def __init__(
        self,
        window_seconds: float = 10.0,
        packet_threshold: int = 100,
        severity: AlertSeverity = AlertSeverity.HIGH,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(severity)
        _validate_positive("window_seconds", window_seconds)
        _validate_positive("packet_threshold", packet_threshold)
        self._window_seconds = float(window_seconds)
        self._packet_threshold = int(packet_threshold)
        self._clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._active_sources: set[str] = set()

    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        protocol = (_get_optional_str(packet_metadata, "protocol") or "").upper()
        source_ip = _get_optional_str(packet_metadata, "source_ip")
        if protocol not in {"ICMP", "ICMPV6"} or source_ip is None:
            return None

        now = _event_time(packet_metadata, self._clock)
        with self._lock:
            events = self._events[source_ip]
            events.append(now)
            cutoff = now - self._window_seconds
            while events and events[0] < cutoff:
                events.popleft()

            if len(events) >= self._packet_threshold:
                if source_ip not in self._active_sources:
                    self._active_sources.add(source_ip)
                    return self._alert(
                        packet_metadata,
                        AlertType.ICMP_FLOOD,
                        "ICMP flood detected",
                        {
                            "packet_count": len(events),
                            "window_seconds": self._window_seconds,
                            "packets_per_second": len(events)
                            / self._window_seconds,
                        },
                    )
            else:
                self._active_sources.discard(source_ip)
        return None


class SuspiciousPortRule(_BaseRule):
    """Detect traffic to configured high-risk destination ports."""

    def __init__(
        self,
        suspicious_ports: Iterable[int],
        severity: AlertSeverity = AlertSeverity.MEDIUM,
    ) -> None:
        super().__init__(severity)
        self._suspicious_ports = frozenset(int(port) for port in suspicious_ports)
        if any(port < 1 or port > 65_535 for port in self._suspicious_ports):
            raise ValueError("suspicious_ports must contain valid ports")

    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        destination_port = _get_optional_int(packet_metadata, "destination_port")
        if destination_port not in self._suspicious_ports:
            return None
        return self._alert(
            packet_metadata,
            AlertType.SUSPICIOUS_PORT,
            f"Access to suspicious destination port {destination_port}",
            {"destination_port": destination_port},
        )


class BlacklistedIPRule(_BaseRule):
    """Detect traffic involving a configured blocked IP address."""

    def __init__(
        self,
        blacklist: Iterable[str],
        severity: AlertSeverity = AlertSeverity.CRITICAL,
    ) -> None:
        super().__init__(severity)
        self._blacklist = frozenset(str(ip_address(item)) for item in blacklist)

    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        source_ip = _normalized_ip(packet_metadata, "source_ip")
        destination_ip = _normalized_ip(packet_metadata, "destination_ip")
        matches = sorted(
            address
            for address in (source_ip, destination_ip)
            if address in self._blacklist
        )
        if not matches:
            return None
        return self._alert(
            packet_metadata,
            AlertType.BLACKLISTED_IP,
            "Communication with a blacklisted IP address detected",
            {"matched_ips": matches},
        )


class MalformedPacketRule(_BaseRule):
    """Detect missing fields, parser errors, and explicit anomaly markers."""

    _anomaly_fields: Final[tuple[str, ...]] = (
        "parser_error",
        "parse_error",
        "malformed",
        "anomalies",
        "parser_anomalies",
    )

    def __init__(
        self,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
    ) -> None:
        super().__init__(severity)

    def evaluate(self, packet_metadata: PacketMetadata) -> Alert | None:
        anomalies: list[str] = []
        protocol = _get_optional_str(packet_metadata, "protocol")
        packet_size = _get_optional_int(
            packet_metadata,
            "packet_size",
            fallback_key="packet_length",
        )
        if protocol is None or protocol.upper() == "UNKNOWN":
            anomalies.append("unknown_protocol")
        if packet_size is None or packet_size < 0:
            anomalies.append("invalid_packet_size")

        for field_name in self._anomaly_fields:
            value = _get_value(packet_metadata, field_name)
            if value not in (None, False, "", (), [], {}):
                anomalies.append(field_name)

        if not anomalies:
            return None
        return self._alert(
            packet_metadata,
            AlertType.MALFORMED_PACKET,
            "Malformed packet metadata detected",
            {"anomalies": sorted(set(anomalies))},
        )


class RulesEngine:
    """Coordinate dynamic rules, alert retention, and runtime metrics."""

    def __init__(
        self,
        config: RulesEngineConfig | None = None,
        rules: Iterable[DetectionRule] | None = None,
        logger: logging.Logger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or RulesEngineConfig()
        self._logger = logger or build_logger()
        self._clock = clock
        self._lock = RLock()
        self._rules: dict[str, DetectionRule] = {}
        self._enabled_rules: set[str] = set()
        self._alerts: deque[Alert] = deque(
            maxlen=self._config.max_retained_alerts
        )
        self._metrics = RulesEngineMetrics()
        initial_rules = create_default_rules(self._config) if rules is None else rules
        for rule in initial_rules:
            self.register_rule(rule)

    @property
    def config(self) -> RulesEngineConfig:
        return self._config

    def register_rule(
        self,
        rule: DetectionRule,
        *,
        enabled: bool = True,
        replace: bool = False,
    ) -> None:
        """Register a rule using its stable name."""
        if not isinstance(rule, DetectionRule):
            raise TypeError("rule must implement DetectionRule")
        name = rule.get_name().strip()
        if not name:
            raise ValueError("Rule name must not be empty")
        with self._lock:
            if name in self._rules and not replace:
                raise ValueError(f"Rule {name!r} is already registered")
            self._rules[name] = rule
            if enabled:
                self._enabled_rules.add(name)
            else:
                self._enabled_rules.discard(name)

    def unregister_rule(self, name: str) -> DetectionRule:
        """Remove and return a registered rule."""
        with self._lock:
            try:
                rule = self._rules.pop(name)
            except KeyError as exc:
                raise KeyError(f"Rule {name!r} is not registered") from exc
            self._enabled_rules.discard(name)
            return rule

    def enable_rule(self, name: str) -> None:
        self._set_rule_enabled(name, True)

    def disable_rule(self, name: str) -> None:
        self._set_rule_enabled(name, False)

    def is_rule_enabled(self, name: str) -> bool:
        with self._lock:
            self._require_rule(name)
            return name in self._enabled_rules

    def list_rules(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._rules)

    def evaluate(self, packet_metadata: PacketMetadata) -> list[Alert]:
        """Evaluate one packet against a snapshot of enabled rules."""
        started_at = self._clock()
        with self._lock:
            rule_snapshot = tuple(
                (name, rule)
                for name, rule in self._rules.items()
                if name in self._enabled_rules
            )

        generated: list[Alert] = []
        executed = 0
        failures = 0
        for name, rule in rule_snapshot:
            executed += 1
            try:
                alert = rule.evaluate(packet_metadata)
            except Exception:
                failures += 1
                self._logger.exception(
                    "Detection rule evaluation failed",
                    extra={"rule_name": name},
                )
                continue
            if alert is not None:
                generated.append(alert)
                if len(generated) >= self._config.alert_limit_per_packet:
                    break

        latency = max(0.0, self._clock() - started_at)
        with self._lock:
            self._prune_alerts_locked()
            self._alerts.extend(generated)
            current = self._metrics
            self._metrics = RulesEngineMetrics(
                packets_processed=current.packets_processed + 1,
                alerts_generated=current.alerts_generated + len(generated),
                rules_executed=current.rules_executed + executed,
                rule_failures=current.rule_failures + failures,
                processing_latency=current.processing_latency + latency,
            )

        if generated:
            self._logger.info(
                "Packet generated security alerts",
                extra={
                    "alert_count": len(generated),
                    "alert_types": [
                        alert.alert_type.value for alert in generated
                    ],
                },
            )
        return generated

    process_packet = evaluate

    def get_alerts(self) -> tuple[Alert, ...]:
        """Return retained alerts after applying time-based retention."""
        with self._lock:
            self._prune_alerts_locked()
            return tuple(self._alerts)

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()

    def get_metrics(self) -> RulesEngineMetrics:
        with self._lock:
            return self._metrics

    def reset_metrics(self) -> None:
        with self._lock:
            self._metrics = RulesEngineMetrics()

    def _set_rule_enabled(self, name: str, enabled: bool) -> None:
        with self._lock:
            self._require_rule(name)
            if enabled:
                self._enabled_rules.add(name)
            else:
                self._enabled_rules.discard(name)

    def _require_rule(self, name: str) -> None:
        if name not in self._rules:
            raise KeyError(f"Rule {name!r} is not registered")

    def _prune_alerts_locked(self) -> None:
        cutoff = datetime.now(timezone.utc).timestamp() - (
            self._config.alert_retention_seconds
        )
        while self._alerts and self._alerts[0].timestamp.timestamp() < cutoff:
            self._alerts.popleft()


def create_default_rules(config: RulesEngineConfig) -> tuple[DetectionRule, ...]:
    """Build the standard rules using configuration overrides."""
    return (
        PortScanRule(
            window_seconds=float(
                config.threshold(
                    "port_scan_window_seconds",
                    config.port_scan_window_seconds,
                )
            ),
            horizontal_threshold=int(
                config.threshold(
                    "horizontal_scan_threshold",
                    config.horizontal_scan_threshold,
                )
            ),
            vertical_threshold=int(
                config.threshold(
                    "vertical_scan_threshold",
                    config.vertical_scan_threshold,
                )
            ),
        ),
        ICMPFloodRule(
            window_seconds=float(
                config.threshold(
                    "icmp_flood_window_seconds",
                    config.icmp_flood_window_seconds,
                )
            ),
            packet_threshold=int(
                config.threshold(
                    "icmp_flood_threshold",
                    config.icmp_flood_threshold,
                )
            ),
        ),
        SuspiciousPortRule(config.suspicious_ports),
        BlacklistedIPRule(config.blacklist),
        MalformedPacketRule(),
    )


def _get_value(packet_metadata: PacketMetadata, key: str) -> Any:
    if isinstance(packet_metadata, Mapping):
        return packet_metadata.get(key)
    return getattr(packet_metadata, key, None)


def _get_optional_str(
    packet_metadata: PacketMetadata,
    key: str,
) -> str | None:
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


def _normalized_ip(
    packet_metadata: PacketMetadata,
    key: str,
) -> str | None:
    value = _get_optional_str(packet_metadata, key)
    if value is None:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


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


def _validate_positive(name: str, value: int | float) -> None:
    if isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be greater than zero")


__all__ = [
    "Alert",
    "AlertSeverity",
    "AlertType",
    "BlacklistedIPRule",
    "DetectionRule",
    "ICMPFloodRule",
    "JsonLogFormatter",
    "MalformedPacketRule",
    "PortScanRule",
    "RulesEngine",
    "RulesEngineConfig",
    "RulesEngineMetrics",
    "SuspiciousPortRule",
    "build_logger",
    "create_default_rules",
]
