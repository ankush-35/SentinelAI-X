<<<<<<< HEAD
"""Thread-safe alert management with deduplication and aggregation for SentinelAI-X."""
=======
"""Thread-safe alert management for SentinelAI-X SOC dashboards."""
>>>>>>> feature/dashboard-backend

from __future__ import annotations

import json
import logging
import time
<<<<<<< HEAD
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
=======
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
>>>>>>> feature/dashboard-backend
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from types import MappingProxyType
<<<<<<< HEAD
from typing import Any, Final
from uuid import uuid4

=======
from typing import Any, Callable, Final, overload
from uuid import uuid4

try:
    from detection.anomaly_detector import AnomalyFinding
except ImportError:  # pragma: no cover - supports package-relative imports.
    from .anomaly_detector import AnomalyFinding

>>>>>>> feature/dashboard-backend

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
<<<<<<< HEAD
    """Alert impact and urgency levels."""
=======
    """SOC alert severity levels."""
>>>>>>> feature/dashboard-backend

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
<<<<<<< HEAD
    """Alert lifecycle status."""
=======
    """Lifecycle status for an alert."""
>>>>>>> feature/dashboard-backend

    CREATED = "CREATED"
    DEDUPLICATED = "DEDUPLICATED"
    AGGREGATED = "AGGREGATED"
<<<<<<< HEAD
    EXPORTED = "EXPORTED"
=======
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
>>>>>>> feature/dashboard-backend
    SUPPRESSED = "SUPPRESSED"


class AlertManagerStatus(str, Enum):
<<<<<<< HEAD
    """Alert Manager operational status."""
=======
    """Runtime status for the alert manager."""
>>>>>>> feature/dashboard-backend

    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    STOPPED = "STOPPED"


@dataclass(frozen=True, slots=True)
class Alert:
<<<<<<< HEAD
    """Immutable security alert record."""

    id: str
    timestamp: datetime
=======
    """Immutable enterprise alert emitted by the alert manager."""

    alert_id: str
    timestamp: datetime
    first_seen: datetime
    last_seen: datetime
>>>>>>> feature/dashboard-backend
    anomaly_type: str
    severity: AlertSeverity
    source_ip: str | None
    destination_ip: str | None
    description: str
    metadata: Mapping[str, Any]
    status: AlertStatus = AlertStatus.CREATED
<<<<<<< HEAD

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Alert id must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("Alert timestamp must be timezone-aware")
        if not self.anomaly_type.strip():
            raise ValueError("Alert anomaly_type must not be empty")
        if not self.description.strip():
            raise ValueError("Alert description must not be empty")
=======
    occurrence_count: int = 1

    def __post_init__(self) -> None:
        if not self.alert_id.strip():
            raise ValueError("Alert alert_id must not be empty")
        _validate_aware_datetime(self.timestamp, "timestamp")
        _validate_aware_datetime(self.first_seen, "first_seen")
        _validate_aware_datetime(self.last_seen, "last_seen")
        if self.first_seen > self.last_seen:
            raise ValueError(
                "Alert first_seen must not be later than last_seen"
            )
        if not self.anomaly_type.strip():
            raise ValueError("Alert anomaly_type must not be empty")
        if not isinstance(self.severity, AlertSeverity):
            object.__setattr__(
                self,
                "severity",
                AlertSeverity(str(self.severity)),
            )
        if not self.description.strip():
            raise ValueError("Alert description must not be empty")
        if not isinstance(self.status, AlertStatus):
            object.__setattr__(self, "status", AlertStatus(str(self.status)))
        if (
            isinstance(self.occurrence_count, bool)
            or self.occurrence_count <= 0
        ):
            raise ValueError(
                "Alert occurrence_count must be greater than zero"
            )
        object.__setattr__(
            self,
            "source_ip",
            _normalized_optional(self.source_ip),
        )
        object.__setattr__(
            self,
            "destination_ip",
            _normalized_optional(self.destination_ip),
        )
>>>>>>> feature/dashboard-backend
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable alert representation."""
        return {
<<<<<<< HEAD
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
=======
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "severity": self.severity.value,
            "status": self.status.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "anomaly_type": self.anomaly_type,
            "description": self.description,
            "occurrence_count": self.occurrence_count,
            "metadata": dict(self.metadata),
        }

    def deduplication_key(self) -> tuple[
        str | None,
        str | None,
        str,
        AlertSeverity,
        str,
    ]:
        """Return the exact-match key used for duplicate suppression."""
>>>>>>> feature/dashboard-backend
        return (
            self.source_ip,
            self.destination_ip,
            self.anomaly_type,
<<<<<<< HEAD
            self.severity.value,
=======
            self.severity,
            self.description,
>>>>>>> feature/dashboard-backend
        )


@dataclass(frozen=True, slots=True)
class AlertManagerConfig:
<<<<<<< HEAD
    """Configuration for alert management, deduplication, and aggregation."""

    max_retained_alerts: int = 10_000
    dedup_window_seconds: float = 300.0
    aggregation_window_seconds: float = 60.0
    max_callbacks: int = 100
    alert_retention_seconds: float = 3600.0
=======
    """Configuration for alert retention and correlation windows."""

    max_retained_alerts: int = 10_000
    dedup_window_seconds: float = 60.0
    aggregation_window_seconds: float = 300.0
    max_callbacks: int = 32
    alert_retention_seconds: float = 86_400.0
>>>>>>> feature/dashboard-backend

    def __post_init__(self) -> None:
        positive_ints = {
            "max_retained_alerts": self.max_retained_alerts,
            "max_callbacks": self.max_callbacks,
        }
<<<<<<< HEAD
        for name, value in positive_ints.items():
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        positive_floats = {
=======
        for name, int_value in positive_ints.items():
            if isinstance(int_value, bool) or not isinstance(int_value, int):
                raise ValueError(f"{name} must be an integer")
            if int_value <= 0:
                raise ValueError(f"{name} must be greater than zero")

        positive_floats: dict[str, int | float] = {
>>>>>>> feature/dashboard-backend
            "dedup_window_seconds": self.dedup_window_seconds,
            "aggregation_window_seconds": self.aggregation_window_seconds,
            "alert_retention_seconds": self.alert_retention_seconds,
        }
<<<<<<< HEAD
        for name, value in positive_floats.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if value <= 0:
=======
        for name, float_value in positive_floats.items():
            if isinstance(float_value, bool) or not isinstance(
                float_value, (int, float)
            ):
                raise ValueError(f"{name} must be numeric")
            if float_value <= 0:
>>>>>>> feature/dashboard-backend
                raise ValueError(f"{name} must be greater than zero")


@dataclass(frozen=True, slots=True)
class AlertManagerMetrics:
<<<<<<< HEAD
    """Point-in-time alert manager metrics."""

    alerts_created: int = 0
    alerts_deduplicated: int = 0
    alerts_aggregated: int = 0
    alerts_exported: int = 0
    alerts_suppressed: int = 0
=======
    """Point-in-time alert manager metrics for dashboard observability."""

    total_alerts_created: int = 0
    total_alerts_deduplicated: int = 0
    total_alerts_aggregated: int = 0
    total_alerts_exported: int = 0
    total_alerts_suppressed: int = 0
>>>>>>> feature/dashboard-backend
    callbacks_triggered: int = 0
    processing_failures: int = 0
    processing_latency: float = 0.0

    @property
    def average_processing_latency(self) -> float:
        """Return average alert processing latency in seconds."""
<<<<<<< HEAD
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
=======
        total_processed = (
            self.total_alerts_created
            + self.total_alerts_deduplicated
            + self.total_alerts_aggregated
            + self.total_alerts_suppressed
            + self.processing_failures
        )
        if total_processed == 0:
            return 0.0
        return self.processing_latency / total_processed


class AlertManager:
    """Convert anomaly findings into correlated SOC-ready alerts."""
>>>>>>> feature/dashboard-backend

    def __init__(
        self,
        config: AlertManagerConfig | None = None,
        logger: logging.Logger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or AlertManagerConfig()
        self._logger = logger or build_logger()
        self._clock = clock
<<<<<<< HEAD
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
=======
        self._alerts: deque[Alert] = deque(
            maxlen=self._config.max_retained_alerts
        )
        self._dedup_window = float(self._config.dedup_window_seconds)
        self._aggregation_window = float(
            self._config.aggregation_window_seconds
        )
        self._callbacks: dict[str, AlertCallback] = {}
        self._metrics = AlertManagerMetrics()
        self._lock = RLock()
        self._status = AlertManagerStatus.RUNNING
>>>>>>> feature/dashboard-backend

    @property
    def config(self) -> AlertManagerConfig:
        return self._config

    @property
    def status(self) -> AlertManagerStatus:
        with self._lock:
            return self._status

<<<<<<< HEAD
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
=======
    def create_alert(
        self,
        *,
        anomaly_type: str,
        severity: AlertSeverity | str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        metadata: Mapping[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> Alert:
        """Create, deduplicate, aggregate, retain, and publish an alert."""
        started_at = self._clock()
        callbacks: tuple[AlertCallback, ...] = ()
        alert = self._build_alert(
            anomaly_type=anomaly_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            metadata=metadata or {},
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        failure = 0

        try:
            with self._lock:
                self._ensure_accepting_alerts_locked()
                self._prune_expired_alerts_locked(alert.timestamp)
                alert = self._correlate_alert_locked(alert)
                callbacks = tuple(self._callbacks.values())
        except Exception:
            failure = 1
            self._logger.exception("Alert creation failed")
            raise
        finally:
            latency = max(0.0, self._clock() - started_at)
            if failure:
                with self._lock:
                    self._record_processing_failure_locked(latency)
        if not failure:
            with self._lock:
                self._metrics = _replace_metrics(
                    self._metrics,
                    processing_latency=(
                        self._metrics.processing_latency + latency
                    ),
                )

        triggered = self._trigger_callbacks(alert, callbacks)
        if triggered:
            with self._lock:
                self._metrics = _replace_metrics(
                    self._metrics,
                    callbacks_triggered=(
                        self._metrics.callbacks_triggered + triggered
                    ),
                )

        self._logger.info(
            "Alert processed",
            extra={
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "occurrence_count": alert.occurrence_count,
            },
        )
        return alert

    def ingest(self, finding: AnomalyFinding) -> Alert:
        """Convert an AnomalyFinding into an enterprise alert."""
        anomaly_type = getattr(
            finding.anomaly_type,
            "value",
            finding.anomaly_type,
        )
        return self.create_alert(
            anomaly_type=str(anomaly_type),
            severity=_severity_from_risk_score(finding.risk_score),
            source_ip=finding.source_ip,
            destination_ip=finding.destination_ip,
            description=finding.description,
            metadata={
                "anomaly_finding_id": finding.id,
                "risk_score": finding.risk_score,
                **dict(finding.metadata),
            },
            timestamp=finding.timestamp,
        )

    def acknowledge_alert(self, alert_id: str) -> Alert:
        """Mark an alert as acknowledged."""
        return self._update_alert_status(alert_id, AlertStatus.ACKNOWLEDGED)

    def resolve_alert(self, alert_id: str) -> Alert:
        """Mark an alert as resolved."""
        return self._update_alert_status(alert_id, AlertStatus.RESOLVED)

    def suppress_alert(self, alert_id: str) -> Alert:
        """Mark an alert as suppressed and update suppression metrics."""
        with self._lock:
            alert = self._replace_alert_locked(
                alert_id,
                AlertStatus.SUPPRESSED,
            )
            self._metrics = _replace_metrics(
                self._metrics,
                total_alerts_suppressed=(
                    self._metrics.total_alerts_suppressed + 1
                ),
            )
            return alert

    def register_callback(
        self,
        callback: AlertCallback,
        callback_id: str | None = None,
    ) -> str:
        """Register a callback and return its stable callback identifier."""
        if not callable(callback):
            raise ValueError("callback must be callable")
        normalized_id = callback_id or str(uuid4())
        if not normalized_id.strip():
            raise ValueError("callback_id must not be empty")
        with self._lock:
            if (
                normalized_id not in self._callbacks
                and len(self._callbacks) >= self._config.max_callbacks
            ):
                raise ValueError("maximum registered callbacks exceeded")
            self._callbacks[normalized_id] = callback
        return normalized_id

    def unregister_callback(self, callback_id: str) -> bool:
        """Unregister a callback by identifier."""
        with self._lock:
            return self._callbacks.pop(callback_id, None) is not None

    def list_callbacks(self) -> tuple[str, ...]:
        """Return registered callback identifiers."""
        with self._lock:
            return tuple(sorted(self._callbacks))

    def get_alert(self, alert_id: str) -> Alert | None:
        """Return an alert by identifier."""
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    return alert
            return None
>>>>>>> feature/dashboard-backend

    def get_alerts(self) -> tuple[Alert, ...]:
        """Return all retained alerts."""
        with self._lock:
<<<<<<< HEAD
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
=======
            return tuple(self._alerts)

    def get_recent_alerts(self, limit: int = 25) -> tuple[Alert, ...]:
        """Return the most recent retained alerts."""
        if isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._lock:
            return tuple(list(self._alerts)[-limit:])

    @overload
    def get_alerts_by_severity(self) -> dict[str, int]:
        ...

    @overload
    def get_alerts_by_severity(
        self,
        severity: AlertSeverity | str,
    ) -> tuple[Alert, ...]:
        ...

    def get_alerts_by_severity(
        self,
        severity: AlertSeverity | str | None = None,
    ) -> dict[str, int] | tuple[Alert, ...]:
        """Return dashboard severity counts or alerts matching a severity.

        Calling without a severity returns a JSON-serializable dashboard
        dictionary. Passing a severity preserves the previous public API.
        """
        with self._lock:
            if severity is None:
                counts = {item.value: 0 for item in AlertSeverity}
                for alert in self._alerts:
                    counts[alert.severity.value] += 1
                return counts

            normalized = _coerce_severity(severity)
            return tuple(
                alert for alert in self._alerts if alert.severity == normalized
            )

    @overload
    def get_alerts_by_status(self) -> dict[str, int]:
        ...

    @overload
    def get_alerts_by_status(
        self,
        status: AlertStatus | str,
    ) -> tuple[Alert, ...]:
        ...

    def get_alerts_by_status(
        self,
        status: AlertStatus | str | None = None,
    ) -> dict[str, int] | tuple[Alert, ...]:
        """Return dashboard status counts or alerts matching a status.

        Calling without a status returns a JSON-serializable dashboard
        dictionary. Passing a status preserves the previous public API.
        """
        with self._lock:
            if status is None:
                counts = {item.value: 0 for item in AlertStatus}
                for alert in self._alerts:
                    counts[alert.status.value] += 1
                return counts

            normalized = _coerce_status(status)
            return tuple(
                alert for alert in self._alerts if alert.status == normalized
            )

    def get_alerts_by_source(self, source_ip: str | None) -> tuple[Alert, ...]:
        """Return alerts for a source IP address."""
        normalized = _normalized_optional(source_ip)
        with self._lock:
            return tuple(
                alert
                for alert in self._alerts
                if alert.source_ip == normalized
            )

    def get_top_source_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top source IPs by retained alert occurrence volume."""
        return self._top_counts("source_ip", limit)

    def get_top_destination_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top destination IPs by retained alert occurrence volume."""
        return self._top_counts("destination_ip", limit)

    def get_top_anomaly_types(self, limit: int = 10) -> dict[str, int]:
        """Return top anomaly types by retained alert occurrence volume."""
        return self._top_counts("anomaly_type", limit)

    def get_dashboard_summary(self) -> dict[str, int | float]:
        """Return a JSON-serializable SOC/dashboard alert summary."""
        with self._lock:
            severity_counts = Counter(alert.severity for alert in self._alerts)
            status_counts = Counter(alert.status for alert in self._alerts)
            active_alerts = sum(
                1
                for alert in self._alerts
                if alert.status
                not in {AlertStatus.RESOLVED, AlertStatus.SUPPRESSED}
            )

            return {
                "total_alerts": len(self._alerts),
                "critical_alerts": severity_counts[AlertSeverity.CRITICAL],
                "high_alerts": severity_counts[AlertSeverity.HIGH],
                "medium_alerts": severity_counts[AlertSeverity.MEDIUM],
                "low_alerts": severity_counts[AlertSeverity.LOW],
                "suppressed_alerts": status_counts[AlertStatus.SUPPRESSED],
                "resolved_alerts": status_counts[AlertStatus.RESOLVED],
                "active_alerts": active_alerts,
                "processing_failures": self._metrics.processing_failures,
                "average_processing_latency": (
                    self._metrics.average_processing_latency
                ),
            }

    def get_metrics(self) -> AlertManagerMetrics:
        """Return current alert manager metrics."""
>>>>>>> feature/dashboard-backend
        with self._lock:
            return self._metrics

    def reset_metrics(self) -> None:
<<<<<<< HEAD
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
=======
        """Reset alert manager metrics."""
        with self._lock:
            self._metrics = AlertManagerMetrics()

    def clear_alerts(self) -> None:
        """Clear retained alerts without changing callbacks or metrics."""
        with self._lock:
            self._alerts.clear()

    def export_json(self) -> str:
        """Export retained alerts as a JSON array."""
        with self._lock:
            payload = [alert.to_dict() for alert in self._alerts]
            self._record_export_locked(len(payload))
        return json.dumps(payload, default=str, ensure_ascii=True)

    def export_dict(self) -> list[dict[str, Any]]:
        """Export retained alerts as JSON-serializable dictionaries."""
        with self._lock:
            payload = [alert.to_dict() for alert in self._alerts]
            self._record_export_locked(len(payload))
            return payload

    def export_ndjson(self) -> str:
        """Export retained alerts as newline-delimited JSON."""
        with self._lock:
            lines = [
                json.dumps(alert.to_dict(), default=str, ensure_ascii=True)
                for alert in self._alerts
            ]
            self._record_export_locked(len(lines))
        return "\n".join(lines)

    def pause(self) -> None:
        """Pause new alert ingestion."""
        with self._lock:
            if self._status == AlertManagerStatus.STOPPED:
                raise RuntimeError("cannot pause a stopped alert manager")
            self._status = AlertManagerStatus.PAUSED

    def resume(self) -> None:
        """Resume new alert ingestion."""
        with self._lock:
            if self._status == AlertManagerStatus.STOPPED:
                raise RuntimeError("cannot resume a stopped alert manager")
            self._status = AlertManagerStatus.RUNNING

    def shutdown(self) -> None:
        """Stop the alert manager and release callback registrations."""
        with self._lock:
            self._callbacks.clear()
            self._status = AlertManagerStatus.STOPPED

    def _build_alert(
        self,
        *,
        anomaly_type: str,
        severity: AlertSeverity | str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        metadata: Mapping[str, Any],
        timestamp: datetime,
    ) -> Alert:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return Alert(
            alert_id=str(uuid4()),
            timestamp=timestamp,
            first_seen=timestamp,
            last_seen=timestamp,
            anomaly_type=anomaly_type,
            severity=_coerce_severity(severity),
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            metadata=metadata,
            status=AlertStatus.CREATED,
            occurrence_count=1,
        )

    def _ensure_accepting_alerts_locked(self) -> None:
        if self._status == AlertManagerStatus.PAUSED:
            raise RuntimeError("alert manager is paused")
        if self._status in {
            AlertManagerStatus.SHUTTING_DOWN,
            AlertManagerStatus.STOPPED,
        }:
            raise RuntimeError("alert manager is stopped")

    def _correlate_alert_locked(self, candidate: Alert) -> Alert:
        deduplicated = self._deduplicate_alert_locked(candidate)
        if deduplicated is not None:
            self._record_processing_success_locked(
                started=False,
                deduplicated=True,
                aggregated=False,
                latency=0.0,
            )
            return deduplicated

        aggregated = self._aggregate_alert_locked(candidate)
        if aggregated is not None:
            self._record_processing_success_locked(
                started=False,
                deduplicated=False,
                aggregated=True,
                latency=0.0,
            )
            return aggregated

        self._alerts.append(candidate)
        self._record_processing_success_locked(
            started=True,
            deduplicated=False,
            aggregated=False,
            latency=0.0,
        )
        return candidate

    def _deduplicate_alert_locked(self, candidate: Alert) -> Alert | None:
        cutoff = candidate.timestamp.timestamp() - self._dedup_window
        for existing in reversed(self._alerts):
            if (
                existing.last_seen.timestamp() >= cutoff
                and existing.deduplication_key() == candidate.deduplication_key()
            ):
                updated = _evolve_alert(
                    existing,
                    last_seen=candidate.timestamp,
                    status=AlertStatus.DEDUPLICATED,
                    occurrence_count=existing.occurrence_count + 1,
                    metadata=_merged_metadata(
                        existing.metadata,
                        candidate.metadata,
                    ),
                )
                self._replace_existing_alert_locked(existing.alert_id, updated)
                return updated
        return None

    def _aggregate_alert_locked(self, candidate: Alert) -> Alert | None:
        cutoff = candidate.timestamp.timestamp() - self._aggregation_window
        for existing in reversed(self._alerts):
            if (
                existing.last_seen.timestamp() >= cutoff
                and _aggregation_key(existing) == _aggregation_key(candidate)
            ):
                updated = _evolve_alert(
                    existing,
                    last_seen=candidate.timestamp,
                    status=AlertStatus.AGGREGATED,
                    occurrence_count=existing.occurrence_count + 1,
                    description=existing.description,
                    metadata=_merged_metadata(
                        existing.metadata,
                        candidate.metadata,
                    ),
                )
                self._replace_existing_alert_locked(existing.alert_id, updated)
                return updated
        return None

    def _replace_alert_locked(
        self,
        alert_id: str,
        status: AlertStatus,
    ) -> Alert:
        for index, alert in enumerate(self._alerts):
            if alert.alert_id == alert_id:
                updated = _evolve_alert(alert, status=status)
                self._alerts[index] = updated
                return updated
        raise KeyError(f"alert_id not found: {alert_id}")

    def _replace_existing_alert_locked(
        self,
        alert_id: str,
        alert: Alert,
    ) -> None:
        for index, existing in enumerate(self._alerts):
            if existing.alert_id == alert_id:
                self._alerts[index] = alert
                return
        raise KeyError(f"alert_id not found: {alert_id}")

    def _update_alert_status(
        self,
        alert_id: str,
        status: AlertStatus,
    ) -> Alert:
        with self._lock:
            return self._replace_alert_locked(alert_id, status)

    def _top_counts(
        self,
        attribute: str,
        limit: int,
    ) -> dict[str, int]:
        if isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be greater than zero")
        with self._lock:
            counts: Counter[str] = Counter()
            for alert in self._alerts:
                value = getattr(alert, attribute)
                if value is not None:
                    counts[str(value)] += alert.occurrence_count
            return dict(counts.most_common(limit))

    def _prune_expired_alerts_locked(self, now: datetime) -> None:
        cutoff = now.timestamp() - self._config.alert_retention_seconds
        self._alerts = deque(
            (
                alert
                for alert in self._alerts
                if alert.last_seen.timestamp() >= cutoff
            ),
            maxlen=self._config.max_retained_alerts,
        )

    def _record_processing_success_locked(
        self,
        *,
        started: bool,
        deduplicated: bool,
        aggregated: bool,
        latency: float,
    ) -> None:
        current = self._metrics
        self._metrics = AlertManagerMetrics(
            total_alerts_created=(
                current.total_alerts_created + (1 if started else 0)
            ),
            total_alerts_deduplicated=(
                current.total_alerts_deduplicated + (1 if deduplicated else 0)
            ),
            total_alerts_aggregated=(
                current.total_alerts_aggregated + (1 if aggregated else 0)
            ),
            total_alerts_exported=current.total_alerts_exported,
            total_alerts_suppressed=current.total_alerts_suppressed,
            callbacks_triggered=current.callbacks_triggered,
            processing_failures=current.processing_failures,
            processing_latency=current.processing_latency + latency,
        )

    def _record_processing_failure_locked(self, latency: float) -> None:
        current = self._metrics
        self._metrics = AlertManagerMetrics(
            total_alerts_created=current.total_alerts_created,
            total_alerts_deduplicated=current.total_alerts_deduplicated,
            total_alerts_aggregated=current.total_alerts_aggregated,
            total_alerts_exported=current.total_alerts_exported,
            total_alerts_suppressed=current.total_alerts_suppressed,
            callbacks_triggered=current.callbacks_triggered,
            processing_failures=current.processing_failures + 1,
            processing_latency=current.processing_latency + latency,
        )

    def _record_export_locked(self, exported_count: int) -> None:
        self._metrics = _replace_metrics(
            self._metrics,
            total_alerts_exported=(
                self._metrics.total_alerts_exported + exported_count
            ),
        )

    def _trigger_callbacks(
        self,
        alert: Alert,
        callbacks: Iterable[AlertCallback],
    ) -> int:
        triggered = 0
        failures = 0
        for callback in callbacks:
            try:
                callback(alert)
                triggered += 1
            except Exception:
                failures += 1
                self._logger.exception(
                    "Alert callback failed",
                    extra={"alert_id": alert.alert_id},
                )
        if failures:
            with self._lock:
                current = self._metrics
                self._metrics = _replace_metrics(
                    current,
                    processing_failures=current.processing_failures + failures,
                )
        return triggered


def _replace_metrics(
    metrics: AlertManagerMetrics,
    **changes: Any,
) -> AlertManagerMetrics:
    return replace(metrics, **changes)


def _evolve_alert(alert: Alert, **changes: Any) -> Alert:
    return replace(alert, **changes)


def _coerce_severity(severity: AlertSeverity | str) -> AlertSeverity:
    if isinstance(severity, AlertSeverity):
        return severity
    normalized = str(severity).strip().upper()
    return AlertSeverity(normalized)


def _coerce_status(status: AlertStatus | str) -> AlertStatus:
    if isinstance(status, AlertStatus):
        return status
    normalized = str(status).strip().upper()
    return AlertStatus(normalized)


def _severity_from_risk_score(risk_score: float) -> AlertSeverity:
    if risk_score >= 90.0:
        return AlertSeverity.CRITICAL
    if risk_score >= 70.0:
        return AlertSeverity.HIGH
    if risk_score >= 40.0:
        return AlertSeverity.MEDIUM
    if risk_score > 0.0:
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def _aggregation_key(
    alert: Alert,
) -> tuple[str | None, str | None, str, AlertSeverity]:
    return (
        alert.source_ip,
        alert.destination_ip,
        alert.anomaly_type,
        alert.severity,
    )


def _merged_metadata(
    existing: Mapping[str, Any],
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(existing)
    merged.update(dict(incoming))
    return merged


def _normalized_optional(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _validate_aware_datetime(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"Alert {field_name} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"Alert {field_name} must be timezone-aware")
>>>>>>> feature/dashboard-backend


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
