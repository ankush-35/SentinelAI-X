"""Public dashboard API facade for SentinelAI-X."""

from __future__ import annotations

from typing import Any

from dashboard.dashboard_backend import DashboardBackend


class DashboardAPI:
    """Expose dashboard-ready alert data through a stable API facade.

    ``DashboardAPI`` keeps presentation/API callers decoupled from backend
    construction while delegating all dashboard data retrieval to
    ``DashboardBackend``.
    """

    def __init__(self, backend: DashboardBackend | None = None) -> None:
        """Initialize the dashboard API.

        Args:
            backend: Dashboard backend instance to delegate to. When omitted, a
                new ``DashboardBackend`` instance is created.

        Raises:
            TypeError: If ``backend`` is not a ``DashboardBackend`` instance.
        """
        if backend is not None and not isinstance(backend, DashboardBackend):
            raise TypeError("backend must be a DashboardBackend instance")
        self._backend = backend or DashboardBackend()

    def get_summary(self) -> dict[str, int | float]:
        """Return dashboard summary metrics.

        Returns:
            JSON-serializable summary metrics from the dashboard backend.
        """
        return self._backend.get_dashboard_summary()

    def get_recent_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        """Return recent alerts.

        Args:
            limit: Maximum number of recent alerts to return.

        Returns:
            JSON-serializable alert dictionaries from the dashboard backend.
        """
        return self._backend.get_recent_alerts(limit)

    def get_alerts_by_severity(self) -> dict[str, int]:
        """Return alert counts grouped by severity.

        Returns:
            Mapping of severity name to alert count.
        """
        return self._backend.get_alerts_by_severity()

    def get_alerts_by_status(self) -> dict[str, int]:
        """Return alert counts grouped by lifecycle status.

        Returns:
            Mapping of status name to alert count.
        """
        return self._backend.get_alerts_by_status()

    def get_top_source_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top source IP addresses by alert occurrence volume.

        Args:
            limit: Maximum number of source IP addresses to return.

        Returns:
            Mapping of source IP address to occurrence count.
        """
        return self._backend.get_top_source_ips(limit)

    def get_top_destination_ips(self, limit: int = 10) -> dict[str, int]:
        """Return top destination IP addresses by alert occurrence volume.

        Args:
            limit: Maximum number of destination IP addresses to return.

        Returns:
            Mapping of destination IP address to occurrence count.
        """
        return self._backend.get_top_destination_ips(limit)

    def get_top_anomaly_types(self, limit: int = 10) -> dict[str, int]:
        """Return top anomaly types by alert occurrence volume.

        Args:
            limit: Maximum number of anomaly types to return.

        Returns:
            Mapping of anomaly type to occurrence count.
        """
        return self._backend.get_top_anomaly_types(limit)


__all__ = ["DashboardAPI"]
