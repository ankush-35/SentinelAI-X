import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from detection.alert_manager import (
    AlertManager,
    AlertManagerConfig,
    AlertManagerStatus,
    AlertSeverity,
    AlertStatus,
)
from detection.anomaly_detector import AnomalyFinding, AnomalyType


class DeterministicClock:
    def __init__(self) -> None:
        self._value = 1000.0
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            self._value += 0.01
            return self._value


class TestAlertManager(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = DeterministicClock()
        self.base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.manager = AlertManager(clock=self.clock)

    def test_create_alert_retains_alert_with_expected_fields(self) -> None:
        alert = self.manager.create_alert(
            anomaly_type="TRAFFIC_SPIKE",
            severity=AlertSeverity.HIGH,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="Traffic spike detected",
            metadata={"risk_score": 80.0},
            timestamp=self.base_time,
        )

        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.status, AlertStatus.CREATED)
        self.assertEqual(alert.occurrence_count, 1)
        self.assertEqual(alert.first_seen, self.base_time)
        self.assertEqual(alert.last_seen, self.base_time)
        self.assertEqual(self.manager.get_alert(alert.alert_id), alert)
        self.assertEqual(self.manager.get_metrics().total_alerts_created, 1)

    def test_ingest_converts_anomaly_finding_to_alert(self) -> None:
        finding = AnomalyFinding(
            id="finding-1",
            timestamp=self.base_time,
            anomaly_type=AnomalyType.TRAFFIC_SPIKE,
            risk_score=95.0,
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            description="High risk anomaly",
            metadata={"packet_count": 500},
        )

        alert = self.manager.ingest(finding)

        self.assertEqual(alert.anomaly_type, AnomalyType.TRAFFIC_SPIKE.value)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.source_ip, "192.168.1.10")
        self.assertEqual(alert.destination_ip, "192.168.1.20")
        self.assertEqual(alert.metadata["anomaly_finding_id"], "finding-1")
        self.assertEqual(alert.metadata["risk_score"], 95.0)
        self.assertEqual(alert.metadata["packet_count"], 500)

    def test_deduplication_updates_existing_alert(self) -> None:
        first = self.manager.create_alert(
            anomaly_type="RARE_PORT",
            severity=AlertSeverity.MEDIUM,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.9",
            description="Rare port observed",
            metadata={"first": True},
            timestamp=self.base_time,
        )
        duplicate_time = self.base_time + timedelta(seconds=10)

        duplicate = self.manager.create_alert(
            anomaly_type="RARE_PORT",
            severity=AlertSeverity.MEDIUM,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.9",
            description="Rare port observed",
            metadata={"second": True},
            timestamp=duplicate_time,
        )

        self.assertEqual(first.alert_id, duplicate.alert_id)
        self.assertEqual(duplicate.status, AlertStatus.DEDUPLICATED)
        self.assertEqual(duplicate.occurrence_count, 2)
        self.assertEqual(duplicate.first_seen, self.base_time)
        self.assertEqual(duplicate.last_seen, duplicate_time)
        self.assertEqual(duplicate.metadata["first"], True)
        self.assertEqual(duplicate.metadata["second"], True)
        self.assertEqual(len(self.manager.get_alerts()), 1)
        self.assertEqual(self.manager.get_metrics().total_alerts_created, 1)
        self.assertEqual(self.manager.get_metrics().total_alerts_deduplicated, 1)

    def test_aggregation_updates_existing_alert(self) -> None:
        first = self.manager.create_alert(
            anomaly_type="PROTOCOL_ANOMALY",
            severity=AlertSeverity.HIGH,
            source_ip="172.16.0.1",
            destination_ip="172.16.0.2",
            description="First protocol anomaly",
            metadata={"first": "value"},
            timestamp=self.base_time,
        )
        aggregate_time = self.base_time + timedelta(seconds=30)

        aggregate = self.manager.create_alert(
            anomaly_type="PROTOCOL_ANOMALY",
            severity=AlertSeverity.HIGH,
            source_ip="172.16.0.1",
            destination_ip="172.16.0.2",
            description="Second protocol anomaly",
            metadata={"second": "value"},
            timestamp=aggregate_time,
        )

        self.assertEqual(first.alert_id, aggregate.alert_id)
        self.assertEqual(aggregate.status, AlertStatus.AGGREGATED)
        self.assertEqual(aggregate.occurrence_count, 2)
        self.assertEqual(aggregate.first_seen, self.base_time)
        self.assertEqual(aggregate.last_seen, aggregate_time)
        self.assertEqual(aggregate.description, "First protocol anomaly")
        self.assertEqual(aggregate.metadata["first"], "value")
        self.assertEqual(aggregate.metadata["second"], "value")
        self.assertEqual(self.manager.get_metrics().total_alerts_aggregated, 1)

    def test_acknowledge_resolve_and_suppress_alert(self) -> None:
        alert = self.manager.create_alert(
            anomaly_type="TRAFFIC_SPIKE",
            severity=AlertSeverity.LOW,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            description="Lifecycle alert",
            metadata={},
            timestamp=self.base_time,
        )

        acknowledged = self.manager.acknowledge_alert(alert.alert_id)
        resolved = self.manager.resolve_alert(alert.alert_id)
        suppressed = self.manager.suppress_alert(alert.alert_id)

        self.assertEqual(acknowledged.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(resolved.status, AlertStatus.RESOLVED)
        self.assertEqual(suppressed.status, AlertStatus.SUPPRESSED)
        self.assertEqual(self.manager.get_metrics().total_alerts_suppressed, 1)

    def test_callbacks_execute_outside_lock_and_are_counted(self) -> None:
        callback_alert_ids: list[str] = []

        def callback(alert) -> None:
            callback_alert_ids.append(alert.alert_id)
            self.assertIsNotNone(self.manager.get_alert(alert.alert_id))

        callback_id = self.manager.register_callback(callback, "soc-callback")

        alert = self.manager.create_alert(
            anomaly_type="TRAFFIC_SPIKE",
            severity=AlertSeverity.HIGH,
            source_ip="10.1.1.1",
            destination_ip="10.1.1.2",
            description="Callback alert",
            metadata={},
            timestamp=self.base_time,
        )

        self.assertEqual(callback_id, "soc-callback")
        self.assertEqual(callback_alert_ids, [alert.alert_id])
        self.assertEqual(self.manager.list_callbacks(), ("soc-callback",))
        self.assertEqual(self.manager.get_metrics().callbacks_triggered, 1)
        self.assertTrue(self.manager.unregister_callback("soc-callback"))
        self.assertEqual(self.manager.list_callbacks(), ())

    def test_callback_failures_do_not_stop_other_callbacks(self) -> None:
        successful_callbacks: list[str] = []

        def failing_callback(_alert) -> None:
            raise RuntimeError("callback failed")

        def successful_callback(alert) -> None:
            successful_callbacks.append(alert.alert_id)

        self.manager.register_callback(failing_callback, "bad")
        self.manager.register_callback(successful_callback, "good")

        alert = self.manager.create_alert(
            anomaly_type="RARE_PORT",
            severity=AlertSeverity.MEDIUM,
            source_ip="10.2.1.1",
            destination_ip="10.2.1.2",
            description="Callback failure alert",
            metadata={},
            timestamp=self.base_time,
        )

        metrics = self.manager.get_metrics()
        self.assertEqual(successful_callbacks, [alert.alert_id])
        self.assertEqual(metrics.callbacks_triggered, 1)
        self.assertEqual(metrics.processing_failures, 1)

    def test_export_json_and_ndjson_keep_schema_and_metrics(self) -> None:
        self.manager.create_alert(
            anomaly_type="TRAFFIC_SPIKE",
            severity=AlertSeverity.CRITICAL,
            source_ip="10.3.1.1",
            destination_ip="10.3.1.2",
            description="Export alert one",
            metadata={"a": 1},
            timestamp=self.base_time,
        )
        self.manager.create_alert(
            anomaly_type="RARE_PORT",
            severity=AlertSeverity.LOW,
            source_ip="10.3.1.3",
            destination_ip="10.3.1.4",
            description="Export alert two",
            metadata={"b": 2},
            timestamp=self.base_time + timedelta(seconds=1),
        )

        json_payload = json.loads(self.manager.export_json())
        ndjson_lines = self.manager.export_ndjson().splitlines()

        expected_keys = {
            "alert_id",
            "timestamp",
            "first_seen",
            "last_seen",
            "severity",
            "status",
            "source_ip",
            "destination_ip",
            "anomaly_type",
            "description",
            "occurrence_count",
            "metadata",
        }
        self.assertEqual(len(json_payload), 2)
        self.assertEqual(set(json_payload[0]), expected_keys)
        self.assertEqual(len(ndjson_lines), 2)
        self.assertEqual(set(json.loads(ndjson_lines[0])), expected_keys)
        self.assertEqual(self.manager.get_metrics().total_alerts_exported, 4)

    def test_metrics_consistency_and_average_processing_latency(self) -> None:
        self.manager.create_alert(
            anomaly_type="A",
            severity=AlertSeverity.HIGH,
            source_ip="1",
            destination_ip="2",
            description="same",
            metadata={},
            timestamp=self.base_time,
        )
        self.manager.create_alert(
            anomaly_type="A",
            severity=AlertSeverity.HIGH,
            source_ip="1",
            destination_ip="2",
            description="same",
            metadata={},
            timestamp=self.base_time + timedelta(seconds=1),
        )
        self.manager.create_alert(
            anomaly_type="A",
            severity=AlertSeverity.HIGH,
            source_ip="1",
            destination_ip="2",
            description="different",
            metadata={},
            timestamp=self.base_time + timedelta(seconds=2),
        )

        metrics = self.manager.get_metrics()
        processed = (
            metrics.total_alerts_created
            + metrics.total_alerts_deduplicated
            + metrics.total_alerts_aggregated
            + metrics.total_alerts_suppressed
            + metrics.processing_failures
        )

        self.assertEqual(metrics.total_alerts_created, 1)
        self.assertEqual(metrics.total_alerts_deduplicated, 1)
        self.assertEqual(metrics.total_alerts_aggregated, 1)
        self.assertGreater(metrics.processing_latency, 0.0)
        self.assertAlmostEqual(
            metrics.average_processing_latency,
            metrics.processing_latency / processed,
        )

    def test_retention_pruning_removes_expired_alerts_anywhere_in_deque(self) -> None:
        manager = AlertManager(
            config=AlertManagerConfig(alert_retention_seconds=50.0),
            clock=self.clock,
        )

        fresh = manager.create_alert(
            anomaly_type="FRESH",
            severity=AlertSeverity.HIGH,
            source_ip="fresh",
            destination_ip="target",
            description="fresh alert",
            metadata={},
            timestamp=self.base_time,
        )
        manager.create_alert(
            anomaly_type="OLD",
            severity=AlertSeverity.LOW,
            source_ip="old",
            destination_ip="target",
            description="old alert",
            metadata={},
            timestamp=self.base_time - timedelta(seconds=100),
        )
        trigger = manager.create_alert(
            anomaly_type="TRIGGER",
            severity=AlertSeverity.INFO,
            source_ip="trigger",
            destination_ip="target",
            description="trigger prune",
            metadata={},
            timestamp=self.base_time + timedelta(seconds=1),
        )

        remaining_ids = {alert.alert_id for alert in manager.get_alerts()}
        remaining_types = {alert.anomaly_type for alert in manager.get_alerts()}

        self.assertEqual(remaining_ids, {fresh.alert_id, trigger.alert_id})
        self.assertEqual(remaining_types, {"FRESH", "TRIGGER"})

    def test_status_transitions_pause_resume_shutdown(self) -> None:
        self.assertEqual(self.manager.status, AlertManagerStatus.RUNNING)

        self.manager.pause()
        self.assertEqual(self.manager.status, AlertManagerStatus.PAUSED)
        with self.assertRaises(RuntimeError):
            self.manager.create_alert(
                anomaly_type="PAUSED",
                severity=AlertSeverity.INFO,
                source_ip=None,
                destination_ip=None,
                description="Paused alert",
                metadata={},
                timestamp=self.base_time,
            )

        self.manager.resume()
        self.assertEqual(self.manager.status, AlertManagerStatus.RUNNING)
        self.manager.shutdown()
        self.assertEqual(self.manager.status, AlertManagerStatus.STOPPED)

        with self.assertRaises(RuntimeError):
            self.manager.resume()

    def test_thread_safety_with_callback_reentrant_read(self) -> None:
        observed: list[int] = []

        def callback(_alert) -> None:
            observed.append(len(self.manager.get_alerts()))

        self.manager.register_callback(callback, "reader")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(
                    self.manager.create_alert,
                    anomaly_type=f"THREAD-{index}",
                    severity=AlertSeverity.MEDIUM,
                    source_ip=f"10.10.0.{index}",
                    destination_ip="10.10.1.1",
                    description=f"Thread alert {index}",
                    metadata={"index": index},
                    timestamp=self.base_time + timedelta(seconds=index),
                )
                for index in range(40)
            ]

        alerts = [future.result() for future in futures]

        self.assertEqual(len(alerts), 40)
        self.assertEqual(len(self.manager.get_alerts()), 40)
        self.assertEqual(len(observed), 40)
        self.assertEqual(self.manager.get_metrics().callbacks_triggered, 40)

    def test_concurrent_alert_creation_is_consistent(self) -> None:
        manager = AlertManager(clock=self.clock)

        def create_unique_alert(index: int) -> str:
            alert = manager.create_alert(
                anomaly_type="CONCURRENT",
                severity=AlertSeverity.HIGH,
                source_ip=f"192.168.100.{index}",
                destination_ip="192.168.200.1",
                description=f"Concurrent alert {index}",
                metadata={"index": index},
                timestamp=self.base_time + timedelta(seconds=index),
            )
            return alert.alert_id

        with ThreadPoolExecutor(max_workers=10) as executor:
            alert_ids = list(executor.map(create_unique_alert, range(100)))

        self.assertEqual(len(alert_ids), 100)
        self.assertEqual(len(set(alert_ids)), 100)
        self.assertEqual(len(manager.get_alerts()), 100)
        self.assertEqual(manager.get_metrics().total_alerts_created, 100)
        self.assertEqual(manager.get_metrics().total_alerts_deduplicated, 0)
        self.assertEqual(manager.get_metrics().total_alerts_aggregated, 0)

    def test_first_seen_last_seen_occurrence_and_metadata_across_repeated_updates(
        self,
    ) -> None:
        first_time = self.base_time
        second_time = self.base_time + timedelta(seconds=5)
        third_time = self.base_time + timedelta(seconds=10)

        first = self.manager.create_alert(
            anomaly_type="REPEATED",
            severity=AlertSeverity.CRITICAL,
            source_ip="10.20.30.40",
            destination_ip="10.20.30.50",
            description="Repeated alert",
            metadata={"first": 1},
            timestamp=first_time,
        )
        second = self.manager.create_alert(
            anomaly_type="REPEATED",
            severity=AlertSeverity.CRITICAL,
            source_ip="10.20.30.40",
            destination_ip="10.20.30.50",
            description="Repeated alert",
            metadata={"second": 2},
            timestamp=second_time,
        )
        third = self.manager.create_alert(
            anomaly_type="REPEATED",
            severity=AlertSeverity.CRITICAL,
            source_ip="10.20.30.40",
            destination_ip="10.20.30.50",
            description="Repeated alert",
            metadata={"third": 3},
            timestamp=third_time,
        )

        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(second.alert_id, third.alert_id)
        self.assertEqual(third.first_seen, first_time)
        self.assertEqual(third.last_seen, third_time)
        self.assertEqual(third.occurrence_count, 3)
        self.assertEqual(third.metadata["first"], 1)
        self.assertEqual(third.metadata["second"], 2)
        self.assertEqual(third.metadata["third"], 3)
        with self.assertRaises(TypeError):
            third.metadata["fourth"] = 4


if __name__ == "__main__":
    unittest.main()
