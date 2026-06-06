"""Unit tests for the SentinelAI-X anomaly detector."""

from __future__ import annotations

import importlib.util
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "detection" / "anomaly_detector.py"
)
SPEC = importlib.util.spec_from_file_location("anomaly_detector", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
anomaly_detector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = anomaly_detector
SPEC.loader.exec_module(anomaly_detector)

AnomalyDetector = anomaly_detector.AnomalyDetector
AnomalyDetectorConfig = anomaly_detector.AnomalyDetectorConfig
AnomalyFinding = anomaly_detector.AnomalyFinding
AnomalyType = anomaly_detector.AnomalyType
compute_aggregate_risk_score = anomaly_detector.compute_aggregate_risk_score


@dataclass(frozen=True)
class Metadata:
    timestamp: float = 1.0
    source_ip: str | None = "10.0.0.1"
    destination_ip: str | None = "10.0.0.2"
    source_port: int | None = 50_000
    destination_port: int | None = 443
    protocol: str = "TCP"
    packet_size: int = 60


def _fast_config(**overrides: object) -> AnomalyDetectorConfig:
    defaults = {
        "min_learning_packets": 5,
        "learning_window_seconds": 60.0,
        "observation_window_seconds": 10.0,
        "traffic_spike_multiplier": 3.0,
        "rare_port_frequency_threshold": 0.05,
        "protocol_rarity_threshold": 0.05,
    }
    defaults.update(overrides)
    return AnomalyDetectorConfig(**defaults)


def _learn_baseline(
    detector: AnomalyDetector,
    *,
    count: int = 5,
    port: int = 443,
    protocol: str = "TCP",
) -> None:
    for index in range(count):
        detector.observe(
            Metadata(
                timestamp=float(index),
                destination_port=port,
                protocol=protocol,
            )
        )


def test_config_rejects_non_positive_values() -> None:
    with pytest.raises(ValueError, match="min_learning_packets"):
        AnomalyDetectorConfig(min_learning_packets=0)
    with pytest.raises(ValueError, match="traffic_spike_multiplier"):
        AnomalyDetectorConfig(traffic_spike_multiplier=-1)


def test_config_rejects_invalid_frequency_thresholds() -> None:
    with pytest.raises(ValueError, match="rare_port_frequency_threshold"):
        AnomalyDetectorConfig(rare_port_frequency_threshold=1.5)


def test_anomaly_finding_rejects_invalid_risk_score() -> None:
    with pytest.raises(ValueError, match="risk_score"):
        AnomalyFinding(
            id="finding-1",
            timestamp=anomaly_detector.datetime.now(anomaly_detector.timezone.utc),
            anomaly_type=AnomalyType.RARE_PORT,
            risk_score=150.0,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="invalid score",
            metadata={},
        )


def test_baseline_not_ready_during_learning_phase() -> None:
    detector = AnomalyDetector(config=_fast_config())
    detector.observe(Metadata(timestamp=0))
    assert detector.is_baseline_ready() is False
    assert detector.get_baseline().learning_complete is False
    assert detector.observe(Metadata(timestamp=1)) == []


def test_baseline_becomes_ready_after_minimum_packets() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=3))
    _learn_baseline(detector, count=2)
    assert detector.is_baseline_ready() is False
    _learn_baseline(detector, count=1)
    assert detector.is_baseline_ready() is True
    baseline = detector.get_baseline()
    assert baseline.total_packets == 3
    assert baseline.learning_complete is True
    assert baseline.protocol_distribution["TCP"] == pytest.approx(1.0)


def test_reset_baseline_restarts_learning() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=2))
    _learn_baseline(detector, count=2)
    assert detector.is_baseline_ready() is True
    detector.reset_baseline()
    assert detector.is_baseline_ready() is False
    assert detector.get_baseline().total_packets == 0


def test_traffic_spike_detected_after_baseline_learning() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=5))
    _learn_baseline(detector, count=5)
    spike_findings: list[AnomalyFinding] = []
    for index in range(8):
        findings = detector.observe(
            Metadata(timestamp=10.0 + (index * 0.1), source_ip="10.0.0.9")
        )
        spike_findings.extend(
            finding
            for finding in findings
            if finding.anomaly_type is AnomalyType.TRAFFIC_SPIKE
        )
    assert spike_findings
    assert spike_findings[0].risk_score == pytest.approx(40.0)
    assert spike_findings[0].metadata["current_packets_per_second"] > (
        spike_findings[0].metadata["baseline_packets_per_second"]
    )


def test_traffic_spike_not_detected_for_normal_rate() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=3))
    _learn_baseline(detector, count=3)
    findings = detector.observe(Metadata(timestamp=100.0))
    assert all(
        finding.anomaly_type is not AnomalyType.TRAFFIC_SPIKE
        for finding in findings
    )


def test_rare_port_detected_for_unseen_destination_port() -> None:
    detector = AnomalyDetector(
        config=_fast_config(min_learning_packets=5, rare_port_frequency_threshold=0.1)
    )
    _learn_baseline(detector, count=10, port=443)
    findings = detector.observe(Metadata(timestamp=20.0, destination_port=31337))
    rare_findings = [
        finding
        for finding in findings
        if finding.anomaly_type is AnomalyType.RARE_PORT
    ]
    assert rare_findings
    assert rare_findings[0].metadata["destination_port"] == 31337
    assert rare_findings[0].risk_score == pytest.approx(30.0)


def test_common_port_is_not_flagged_as_rare() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=3))
    _learn_baseline(detector, count=5, port=443)
    findings = detector.observe(Metadata(timestamp=10.0, destination_port=443))
    assert all(
        finding.anomaly_type is not AnomalyType.RARE_PORT
        for finding in findings
    )


def test_protocol_anomaly_detected_for_unseen_protocol() -> None:
    detector = AnomalyDetector(
        config=_fast_config(min_learning_packets=5, protocol_rarity_threshold=0.1)
    )
    _learn_baseline(detector, count=10, protocol="TCP")
    findings = detector.observe(Metadata(timestamp=15.0, protocol="ICMP"))
    protocol_findings = [
        finding
        for finding in findings
        if finding.anomaly_type is AnomalyType.PROTOCOL_ANOMALY
    ]
    assert protocol_findings
    assert protocol_findings[0].metadata["protocol"] == "ICMP"
    assert protocol_findings[0].risk_score == pytest.approx(35.0)


def test_common_protocol_is_not_flagged_as_anomalous() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=3))
    _learn_baseline(detector, count=5, protocol="TCP")
    findings = detector.observe(Metadata(timestamp=8.0, protocol="TCP"))
    assert all(
        finding.anomaly_type is not AnomalyType.PROTOCOL_ANOMALY
        for finding in findings
    )


def test_aggregate_risk_score_caps_at_one_hundred() -> None:
    findings = [
        AnomalyFinding(
            id="one",
            timestamp=anomaly_detector.datetime.now(anomaly_detector.timezone.utc),
            anomaly_type=AnomalyType.TRAFFIC_SPIKE,
            risk_score=40.0,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="spike",
            metadata={},
        ),
        AnomalyFinding(
            id="two",
            timestamp=anomaly_detector.datetime.now(anomaly_detector.timezone.utc),
            anomaly_type=AnomalyType.RARE_PORT,
            risk_score=30.0,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="rare port",
            metadata={},
        ),
        AnomalyFinding(
            id="three",
            timestamp=anomaly_detector.datetime.now(anomaly_detector.timezone.utc),
            anomaly_type=AnomalyType.PROTOCOL_ANOMALY,
            risk_score=35.0,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="protocol",
            metadata={},
        ),
    ]
    assert compute_aggregate_risk_score(findings) == pytest.approx(100.0)


def test_metrics_track_learning_and_detection_phases() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=2))
    detector.observe(Metadata(timestamp=0))
    detector.observe(Metadata(timestamp=1))
    metrics = detector.get_metrics()
    assert metrics.packets_observed == 2
    assert metrics.learning_packets == 2
    assert metrics.detection_packets == 0
    detector.observe(Metadata(timestamp=2))
    metrics = detector.get_metrics()
    assert metrics.detection_packets == 1
    assert metrics.average_processing_latency >= 0.0


def test_metrics_can_be_reset() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=1))
    detector.observe(Metadata())
    detector.reset_metrics()
    assert detector.get_metrics().packets_observed == 0


def test_invalid_destination_port_is_ignored_for_rare_port_detection() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=2))
    _learn_baseline(detector, count=2)
    findings = detector.observe(
        {"timestamp": 5.0, "destination_port": 99_999, "protocol": "TCP"}
    )
    assert all(
        finding.anomaly_type is not AnomalyType.RARE_PORT
        for finding in findings
    )


def test_detector_tolerates_missing_optional_fields() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=1))
    findings = detector.observe({"protocol": "TCP", "packet_size": 64})
    assert isinstance(findings, list)


def test_findings_limit_per_packet_is_enforced() -> None:
    detector = AnomalyDetector(
        config=_fast_config(min_learning_packets=2, findings_limit_per_packet=1)
    )
    _learn_baseline(detector, count=2, port=443, protocol="TCP")
    findings = detector.observe(
        Metadata(timestamp=5.0, destination_port=1234, protocol="ICMP")
    )
    assert len(findings) == 1


def test_thread_safe_concurrent_observations() -> None:
    detector = AnomalyDetector(config=_fast_config(min_learning_packets=20))
    errors: list[BaseException] = []

    def worker(source_suffix: int) -> None:
        try:
            for index in range(25):
                detector.observe(
                    Metadata(
                        timestamp=float(index),
                        source_ip=f"10.0.0.{source_suffix}",
                        destination_port=443 + (index % 3),
                        protocol="TCP",
                    )
                )
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(suffix,)) for suffix in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    metrics = detector.get_metrics()
    assert metrics.packets_observed == 100
    assert detector.is_baseline_ready() is True
