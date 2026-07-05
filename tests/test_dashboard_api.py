"""Unit tests for the SentinelAI-X dashboard API facade."""

from __future__ import annotations

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, create_autospec

from dashboard.dashboard_api import DashboardAPI
from dashboard.dashboard_backend import DashboardBackend


class TestDashboardAPI(unittest.TestCase):
    """Validate DashboardAPI delegation to DashboardBackend."""

    def setUp(self) -> None:
        self.backend = cast(
            DashboardBackend,
            create_autospec(DashboardBackend, instance=True),
        )
        self.api = DashboardAPI(self.backend)

    def test_get_summary_delegates_to_backend(self) -> None:
        expected = {
            "total_alerts": 3,
            "critical_alerts": 1,
            "average_processing_latency": 0.05,
        }
        backend_method = cast(
            MagicMock,
            self.backend.get_dashboard_summary,
        )
        backend_method.return_value = expected

        result = self.api.get_summary()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with()

    def test_get_recent_alerts_delegates_to_backend_with_default_limit(
        self,
    ) -> None:
        expected: list[dict[str, Any]] = [
            {"alert_id": "alert-1", "severity": "HIGH"},
        ]
        backend_method = cast(MagicMock, self.backend.get_recent_alerts)
        backend_method.return_value = expected

        result = self.api.get_recent_alerts()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(25)

    def test_get_recent_alerts_delegates_to_backend_with_custom_limit(
        self,
    ) -> None:
        expected: list[dict[str, Any]] = [
            {"alert_id": "alert-1", "severity": "HIGH"},
            {"alert_id": "alert-2", "severity": "LOW"},
        ]
        backend_method = cast(MagicMock, self.backend.get_recent_alerts)
        backend_method.return_value = expected

        result = self.api.get_recent_alerts(limit=2)

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(2)

    def test_get_alerts_by_severity_delegates_to_backend(self) -> None:
        expected = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        backend_method = cast(MagicMock, self.backend.get_alerts_by_severity)
        backend_method.return_value = expected

        result = self.api.get_alerts_by_severity()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with()

    def test_get_alerts_by_status_delegates_to_backend(self) -> None:
        expected = {"CREATED": 2, "DEDUPLICATED": 1, "RESOLVED": 0}
        backend_method = cast(MagicMock, self.backend.get_alerts_by_status)
        backend_method.return_value = expected

        result = self.api.get_alerts_by_status()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with()

    def test_get_top_source_ips_delegates_to_backend_with_default_limit(
        self,
    ) -> None:
        expected = {"10.0.0.1": 5, "10.0.0.2": 3}
        backend_method = cast(MagicMock, self.backend.get_top_source_ips)
        backend_method.return_value = expected

        result = self.api.get_top_source_ips()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(10)

    def test_get_top_source_ips_delegates_to_backend_with_custom_limit(
        self,
    ) -> None:
        expected = {"10.0.0.1": 5}
        backend_method = cast(MagicMock, self.backend.get_top_source_ips)
        backend_method.return_value = expected

        result = self.api.get_top_source_ips(limit=1)

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(1)

    def test_get_top_destination_ips_delegates_to_backend_with_default_limit(
        self,
    ) -> None:
        expected = {"10.0.1.1": 4, "10.0.1.2": 2}
        backend_method = cast(MagicMock, self.backend.get_top_destination_ips)
        backend_method.return_value = expected

        result = self.api.get_top_destination_ips()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(10)

    def test_get_top_destination_ips_delegates_to_backend_with_custom_limit(
        self,
    ) -> None:
        expected = {"10.0.1.1": 4}
        backend_method = cast(MagicMock, self.backend.get_top_destination_ips)
        backend_method.return_value = expected

        result = self.api.get_top_destination_ips(limit=1)

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(1)

    def test_get_top_anomaly_types_delegates_to_backend_with_default_limit(
        self,
    ) -> None:
        expected = {"TRAFFIC_SPIKE": 6, "RARE_PORT": 2}
        backend_method = cast(MagicMock, self.backend.get_top_anomaly_types)
        backend_method.return_value = expected

        result = self.api.get_top_anomaly_types()

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(10)

    def test_get_top_anomaly_types_delegates_to_backend_with_custom_limit(
        self,
    ) -> None:
        expected = {"TRAFFIC_SPIKE": 6}
        backend_method = cast(MagicMock, self.backend.get_top_anomaly_types)
        backend_method.return_value = expected

        result = self.api.get_top_anomaly_types(limit=1)

        self.assertEqual(result, expected)
        backend_method.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
