"""Thread-safe alert management with deduplication and aggregation for SentinelAI-X."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Final
from uuid import uuid4


AlertCallback = Callable[["Alert"], None]


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


def build_logger(name: str = "sentinelai_x.alert_manager") -> logging.Logger:
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
    """Alert impact and urgency levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    """Alert lifecycle status."""

    CREATED = "CREATED"
    DEDUPLICATED = "DEDUPLICATED"
    AGGREGATED = "AGGREGATED"
    EXPORTED = "EXPORTED"
    SUPPRESSED = "SUPPRESSED"


class AlertManagerStatus(str, Enum):
    """Alert Manager operational status."""

    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    STOPPED = "STOPPED"


@dataclass(frozen=True, slots=True)
class Alert:
    """Immutable security alert record."""

    id: str
    timestamp: datetime
    anomaly_type: str
    severity: AlertSeverity
    source_ip: str | None
    destination_ip: str | None
    description: str
    metadata: Mapping[str, Any]
    status: AlertStatus = AlertStatus.CREATED

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Alert id must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("Alert timestamp must be timezone-aware")
        if not self.anomaly_type.strip():
            raise ValueError("Alert anomaly_type must not be empty")
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
            "anomaly_type": self.anomaly_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "status": self.status.value,
            "metadata": dict(self.metadata),
        }

    def deduplication_key(self) -> tuple[str | None, str | None, str, str]:
        """Return the composite deduplication key for this alert."""
        return (
            self.source_ip,
            self.destination_ip,
            self.anomaly_type,
            self.severity.value,
        )


@dataclass(frozen=True, slots=True)
class AlertManagerConfig:
    """Configuration for alert management, deduplication, and aggregation."""

    max_retained_alerts: int = 10_000
    dedup_window_seconds: float = 300.0
    aggregation_window_seconds: float = 60.0
    max_callbacks: int = 100
    alert_retention_seconds: float = 3600.0

    def __post_init__(self) -> None:
        positive_ints = {
            "max_retained_alerts": self.max_retained_alerts,
            "max_callbacks": self.max_callbacks,
        }
        for name, value in positive_ints.items():
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        positive_floats = {
            "dedup_window_seconds": self.dedup_window_seconds,
            "aggregation_window_seconds": self.aggregation_window_seconds,
            "alert_retention_seconds": self.alert_retention_seconds,
        }
        for name, value in positive_floats.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(frozen=True, slots=True)
class AlertManagerMetrics:
    """Point-in-time alert manager metrics."""

    alerts_created: int = 0
    alerts_deduplicated: int = 0
    alerts_aggregated: int = 0
    alerts_exported: int = 0
    alerts_suppressed: int = 0
    callbacks_triggered: int = 0
    processing_failures: int = 0
    processing_latency: float = 0.0

    @property
    def average_processing_latency(self) -> float:
        """Return average alert processing latency in seconds."""
        total_alerts = (
            self.alerts_created
            + self.alerts_deduplicated
            + self.alerts_aggregated
        )
        if total_alerts == 0:
            return 0.0
        return self.processing_latency / total_alerts


class AlertManager:
    """Manage alerts with deduplication, aggregation, and export capabilities."""

    def __init__(
        self,
        config: AlertManagerConfig | None = None,
        logger: logging.Logger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or AlertManagerConfig()
        self._logger = logger or build_logger()
        self._clock = clock
        self._lock = RLock()
        self._status = AlertManagerStatus.INITIALIZING
        self._alerts: deque[Alert] = deque(
            maxlen=self._config.max_retained_alerts
        )
        self._dedup_window: dict[tuple[str | None, str | None, str, str], float] = {}
        self._aggregation_window: dict[
            tuple[str | None, str | None, str, str], list[Alert]
        ] = defaultdict(list)
        self._callbacks: dict[str, AlertCallback] = {}
        self._metrics = AlertManagerMetrics()
        self._status = AlertManagerStatus.RUNNING
        self._logger.info(
            "Alert Manager initialized",
            extra={
                "max_retained_alerts": self._config.max_retained_alerts,
                "dedup_window_seconds": self._config.dedup_window_seconds,
                "aggregation_window_seconds": self._config.aggregation_window_seconds,
            },
        )

    @property
    def config(self) -> AlertManagerConfig:
        return self._config

    @property
    def status(self) -> AlertManagerStatus:
        with self._lock:
            return self._status

    def ingest(self, alert: Alert) -> Alert | None:
        """Ingest an alert, apply deduplication, and return the processed alert."""
        if not isinstance(alert, Alert):
            raise TypeError("alert must be an Alert instance")

        started_at = self._clock()
        processed_alert = None
        failures = 0

        try:
            dedup_key = alert.deduplication_key()

            with self._lock:
                current_time = datetime.now(timezone.utc).timestamp()

                # Check deduplication window
                last_seen = self._dedup_window.get(dedup_key)
                if last_seen is not None:
                    elapsed = current_time - last_seen
                    if elapsed < self._config.dedup_window_seconds:
                        # Alert is a duplicate
                        current = self._metrics
                        self._metrics = AlertManagerMetrics(
                            alerts_created=current.alerts_created,
                            alerts_deduplicated=current.alerts_deduplicated + 1,
                            alerts_aggregated=current.alerts_aggregated,
                            alerts_exported=current.alerts_exported,
                            alerts_suppressed=current.alerts_suppressed,
                            callbacks_triggered=current.callbacks_triggered,
                            processing_failures=current.processing_failures,
                            processing_latency=current.processing_latency
                            + max(0.0, self._clock() - started_at),
                        )
                        self._logger.debug(
                            "Alert deduplicated",
                            extra={
                                "alert_id": alert.id,
                                "dedup_key": str(dedup_key),
                            },
                        )
                        return None

                # Update deduplication window
                self._dedup_window[dedup_key] = current_time

                # Add to retention queue
                processed_alert = alert
                self._alerts.append(alert)

                # Add to aggregation window
                self._aggregation_window[dedup_key].append(alert)

                # Update metrics
                current = self._metrics
                self._metrics = AlertManagerMetrics(
                    alerts_created=current.alerts_created + 1,
                    alerts_deduplicated=current.alerts_deduplicated,
                    alerts_aggregated=current.alerts_aggregated,
                    alerts_exported=current.alerts_exported,
                    alerts_suppressed=current.alerts_suppressed,
                    callbacks_triggered=current.callbacks_triggered,
                    processing_failures=current.processing_failures,
                    processing_latency=current.processing_latency
                    + max(0.0, self._clock() - started_at),
                )

            # Trigger callbacks outside the lock
            self._trigger_callbacks(alert)

            self._logger.info(
                "Alert ingested",
                extra={
                    "alert_id": alert.id,
                    "severity": alert.severity.value,
                    "anomaly_type": alert.anomaly_type,
                },
            )
            return processed_alert

        except Exception:
            failures = 1
            self._logger.exception("Alert ingestion failed")
            with self._lock:
                current = self._metrics
                self._metrics = AlertManagerMetrics(
                    alerts_created=current.alerts_created,
                    alerts_deduplicated=current.alerts_deduplicated,
                    alerts_aggregated=current.alerts_aggregated,
                    alerts_exported=current.alerts_exported,
                    alerts_suppressed=current.alerts_suppressed,
                    callbacks_triggered=current.callbacks_triggered,
                    processing_failures=current.processing_failures + failures,
                    processing_latency=current.processing_latency
                    + max(0.0, self._clock() - started_at),
                )
            return None

    def register_callback(
        self,
        callback_id: str,
        callback: AlertCallback,
        *,
        replace: bool = False,
    ) -> None:
        """Register a callback to be triggered when alerts are ingested."""
        if not callable(callback):
            raise TypeError("callback must be callable")
        if not callback_id.strip():
            raise ValueError("callback_id must not be empty")

        with self._lock:
            if callback_id in self._callbacks and not replace:
                raise ValueError(f"Callback {callback_id!r} is already registered")
            if len(self._callbacks) >= self._config.max_callbacks and callback_id not in self._callbacks:
                raise RuntimeError(
                    f"Maximum callbacks ({self._config.max_callbacks}) reached"
                )
            self._callbacks[callback_id] = callback
            self._logger.info(
                "Callback registered",
                extra={"callback_id": callback_id},
            )

    def unregister_callback(self, callback_id: str) -> AlertCallback:
        """Remove and return a registered callback."""
        with self._lock:
            try:
                callback = self._callbacks.pop(callback_id)
            except KeyError as exc:
                raise KeyError(f"Callback {callback_id!r} is not registered") from exc
            self._logger.info(
                "Callback unregistered",
                extra={"callback_id": callback_id},
            )
            return callback

    def list_callbacks(self) -> tuple[str, ...]:
        """Return registered callback IDs."""
        with self._lock:
            return tuple(self._callbacks)

    def get_alerts(self) -> tuple[Alert, ...]:
        """Return all retained alerts."""
        with self._lock:
            self._prune_alerts_locked()
            return tuple(self._alerts)

    def get_aggregation(
        self,
        dedup_key: tuple[str | None, str | None, str, str] | None = None,
    ) -> dict[tuple[str | None, str | None, str, str], list[Alert]]:
        """Return aggregated alerts, optionally filtered by dedup key."""
        with self._lock:
            if dedup_key is not None:
                return {dedup_key: self._aggregation_window.get(dedup_key, [])}
            return dict(self._aggregation_window)

    def clear_alerts(self) -> None:
        """Remove all retained alerts."""
        with self._lock:
            self._alerts.clear()
            self._aggregation_window.clear()
            self._dedup_window.clear()
            self._logger.info("Alerts cleared")

    def export_json(self) -> str:
        """Export all retained alerts as compact JSON."""
        with self._lock:
            self._prune_alerts_locked()
            alerts_list = [alert.to_dict() for alert in self._alerts]
            return json.dumps(alerts_list, default=str, ensure_ascii=True)

    def export_ndjson(self) -> str:
        """Export all retained alerts as newline-delimited JSON."""
        with self._lock:
            self._prune_alerts_locked()
            lines = [json.dumps(alert.to_dict(), default=str, ensure_ascii=True)
                     for alert in self._alerts]
            return "\n".join(lines)

    def get_metrics(self) -> AlertManagerMetrics:
        """Return current manager metrics."""
        with self._lock:
            return self._metrics

    def reset_metrics(self) -> None:
        """Reset all manager metrics."""
        with self._lock:
            self._metrics = AlertManagerMetrics()
            self._logger.info("Metrics reset")

    def pause(self) -> None:
        """Pause alert ingestion."""
        with self._lock:
            self._status = AlertManagerStatus.PAUSED
            self._logger.info("Alert Manager paused")

    def resume(self) -> None:
        """Resume alert ingestion."""
        with self._lock:
            self._status = AlertManagerStatus.RUNNING
            self._logger.info("Alert Manager resumed")

    def shutdown(self) -> None:
        """Gracefully shut down the alert manager."""
        with self._lock:
            self._status = AlertManagerStatus.SHUTTING_DOWN
            self._logger.info("Alert Manager shutting down")
            self._status = AlertManagerStatus.STOPPED

    def _trigger_callbacks(self, alert: Alert) -> None:
        """Execute all registered callbacks for an alert."""
        with self._lock:
            callback_snapshot = dict(self._callbacks)

        callback_count = 0
        for callback_id, callback in callback_snapshot.items():
            try:
                callback(alert)
                callback_count += 1
            except Exception:
                self._logger.exception(
                    "Callback execution failed",
                    extra={"callback_id": callback_id, "alert_id": alert.id},
                )

        with self._lock:
            current = self._metrics
            self._metrics = AlertManagerMetrics(
                alerts_created=current.alerts_created,
                alerts_deduplicated=current.alerts_deduplicated,
                alerts_aggregated=current.alerts_aggregated,
                alerts_exported=current.alerts_exported,
                alerts_suppressed=current.alerts_suppressed,
                callbacks_triggered=current.callbacks_triggered + callback_count,
                processing_failures=current.processing_failures,
                processing_latency=current.processing_latency,
            )

    def _prune_alerts_locked(self) -> None:
        """Remove expired alerts from retention."""
        cutoff = datetime.now(timezone.utc).timestamp() - (
            self._config.alert_retention_seconds
        )
        while self._alerts and self._alerts[0].timestamp.timestamp() < cutoff:
            self._alerts.popleft()


__all__ = [
    "Alert",
    "AlertManager",
    "AlertManagerConfig",
    "AlertManagerMetrics",
    "AlertManagerStatus",
    "AlertSeverity",
    "AlertStatus",
    "JsonLogFormatter",
    "build_logger",
]
