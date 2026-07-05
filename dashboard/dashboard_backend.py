"""Dashboard-facing read model for SentinelAI-X alert data."""

from __future__ import annotations

from typing import Any

from detection.alert_manager import AlertManager


class DashboardBackend:
    """Expose JSON-serializable alert dashboard data.

    The backend delegates alert storage, aggregation, and analytics to
    ``AlertManager`` so dashboard code can consume stable read-only views
    without duplicating alert-management behavior.
    """

    def __init__(self, alert_manager: AlertManager | None = None) -> None:
        """Initialize the dashboard backend.

        Args:
            alert_manager: Existing alert manager instance to read from. When
                omitted, a new ``AlertManager`` instance is created.
        """
        if alert_manager is not None and not isinstance(
            alert_manager,
            AlertManager,
        ):
            raise TypeError("alert_manager must be an AlertManager instance")
        self._alert_manager = alert_manager or AlertManager()

    def get_dashboard_summary(self) -> dict[str, int | float]:
        """Return high-level alert metrics for dashboard summary cards.

        Returns:
            JSON-serializable counts and latency metrics produced by the alert
            manager.
        """
        return self._alert_manager.get_dashboard_summary()

    def get_recent_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        """Return the most recent alerts as JSON-serializable dictionaries.

        Args:
            limit: Maximum number of recent alerts to return.

        Returns:
            Alert records converted to dictionaries suitable for JSON encoding.
        """
        return [
            alert.to_dict()
            for alert in self._alert_manager.get_recent_alerts(limit)
        ]

    def get_alerts_by_severity(self) -> dict[str, int]:
        """Return retained alert counts grouped by severity.

        Returns:
            Mapping of severity name to retained alert count.
        """
        return self._alert_manager.get_alerts_by_severity()

    def get_alerts_by_status(self) -> dict[str, int]:
        """Return retained alert counts grouped by lifecycle status.

        Returns:
            Mapping of status name to retained alert count.
        """
        return self._alert_manager.get_alerts_by_status()

    def get_top_source_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top source IP addresses by alert occurrence volume.

        Args:
            limit: Maximum number of source IP addresses to return.

        Returns:
            Mapping of source IP address to occurrence count.
        """
        return self._alert_manager.get_top_source_ips(limit)

    def get_top_destination_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top destination IP addresses by alert occurrence volume.

        Args:
            limit: Maximum number of destination IP addresses to return.

        Returns:
            Mapping of destination IP address to occurrence count.
        """
        return self._alert_manager.get_top_destination_ips(limit)

    def get_top_anomaly_types(self, limit: int = 10) -> dict[str, int]:
        """Return top anomaly types by alert occurrence volume.

        Args:
            limit: Maximum number of anomaly types to return.

        Returns:
            Mapping of anomaly type to occurrence count.
        """
        return self._alert_manager.get_top_anomaly_types(limit)


__all__ = ["DashboardBackend"]
