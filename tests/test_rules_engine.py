"""Unit tests for the SentinelAI-X rules engine."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "rule-engine" / "rules_engine.py"
)
SPEC = importlib.util.spec_from_file_location("rules_engine", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
rules_engine = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rules_engine
SPEC.loader.exec_module(rules_engine)

Alert = rules_engine.Alert
AlertSeverity = rules_engine.AlertSeverity
AlertType = rules_engine.AlertType
BlacklistedIPRule = rules_engine.BlacklistedIPRule
DetectionRule = rules_engine.DetectionRule
ICMPFloodRule = rules_engine.ICMPFloodRule
MalformedPacketRule = rules_engine.MalformedPacketRule
PortScanRule = rules_engine.PortScanRule
RulesEngine = rules_engine.RulesEngine
RulesEngineConfig = rules_engine.RulesEngineConfig
SuspiciousPortRule = rules_engine.SuspiciousPortRule
create_default_rules = rules_engine.create_default_rules


@dataclass(frozen=True)
class Metadata:
    timestamp: float = 1.0
    source_ip: str | None = "10.0.0.1"
    destination_ip: str | None = "10.0.0.2"
    source_port: int | None = 50_000
    destination_port: int | None = 443
    protocol: str = "TCP"
    packet_size: int = 60


class AlwaysAlertRule(DetectionRule):
    def evaluate(self, packet_metadata: object) -> Alert:
        return rules_engine.Alert(
            id="test-alert",
            timestamp=rules_engine.datetime.now(rules_engine.timezone.utc),
            severity=AlertSeverity.LOW,
            alert_type=AlertType.SUSPICIOUS_PORT,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description="Test alert",
            metadata={},
        )

    def get_name(self) -> str:
        return "always"

    def get_severity(self) -> AlertSeverity:
        return AlertSeverity.LOW


class FailingRule(DetectionRule):
    def evaluate(self, packet_metadata: object) -> None:
        raise RuntimeError("rule failure")

    def get_name(self) -> str:
        return "failing"

    def get_severity(self) -> AlertSeverity:
        return AlertSeverity.HIGH


def test_alert_enums_have_required_values() -> None:
    assert [item.value for item in AlertSeverity] == [
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]
    assert AlertType.DATA_EXFILTRATION.value == "DATA_EXFILTRATION"


def test_config_rejects_non_positive_thresholds() -> None:
    with pytest.raises(ValueError, match="horizontal_scan_threshold"):
        RulesEngineConfig(horizontal_scan_threshold=0)
    with pytest.raises(ValueError, match="greater than zero"):
        RulesEngineConfig(thresholds={"custom": -1})


def test_config_rejects_invalid_ports_and_ips() -> None:
    with pytest.raises(ValueError, match="valid TCP/UDP ports"):
        RulesEngineConfig(suspicious_ports=frozenset({70_000}))
    with pytest.raises(ValueError):
        RulesEngineConfig(blacklist=frozenset({"not-an-ip"}))


def test_suspicious_port_rule_generates_alert() -> None:
    alert = SuspiciousPortRule({22}).evaluate(Metadata(destination_port=22))
    assert alert is not None
    assert alert.alert_type is AlertType.SUSPICIOUS_PORT
    assert alert.metadata["destination_port"] == 22


def test_suspicious_port_rule_ignores_safe_port() -> None:
    assert SuspiciousPortRule({22}).evaluate(Metadata()) is None


def test_blacklisted_ip_detects_source_or_destination() -> None:
    rule = BlacklistedIPRule({"10.0.0.1", "192.0.2.4"})
    source_alert = rule.evaluate(Metadata())
    destination_alert = rule.evaluate(Metadata(destination_ip="192.0.2.4"))
    assert source_alert is not None
    assert destination_alert is not None
    assert destination_alert.severity is AlertSeverity.CRITICAL


def test_blacklisted_ip_ignores_invalid_packet_ip() -> None:
    rule = BlacklistedIPRule({"192.0.2.4"})
    assert rule.evaluate(Metadata(source_ip="invalid")) is None


def test_malformed_packet_detects_unknown_protocol() -> None:
    alert = MalformedPacketRule().evaluate(
        {"protocol": "UNKNOWN", "packet_size": 10}
    )
    assert alert is not None
    assert "unknown_protocol" in alert.metadata["anomalies"]


def test_malformed_packet_detects_parser_anomaly() -> None:
    alert = MalformedPacketRule().evaluate(
        {
            "protocol": "TCP",
            "packet_length": 40,
            "parser_error": "bad checksum",
        }
    )
    assert alert is not None
    assert "parser_error" in alert.metadata["anomalies"]


def test_well_formed_packet_is_not_malformed() -> None:
    assert MalformedPacketRule().evaluate(Metadata()) is None


def test_horizontal_port_scan_reaches_unique_host_threshold() -> None:
    rule = PortScanRule(
        window_seconds=10,
        horizontal_threshold=3,
        vertical_threshold=10,
    )
    assert rule.evaluate(Metadata(timestamp=1, destination_ip="10.0.0.2")) is None
    assert rule.evaluate(Metadata(timestamp=2, destination_ip="10.0.0.3")) is None
    alert = rule.evaluate(Metadata(timestamp=3, destination_ip="10.0.0.4"))
    assert alert is not None
    assert alert.metadata["scan_type"] == "horizontal"


def test_vertical_port_scan_reaches_unique_port_threshold() -> None:
    rule = PortScanRule(
        window_seconds=10,
        horizontal_threshold=10,
        vertical_threshold=3,
    )
    assert rule.evaluate(Metadata(timestamp=1, destination_port=20)) is None
    assert rule.evaluate(Metadata(timestamp=2, destination_port=21)) is None
    alert = rule.evaluate(Metadata(timestamp=3, destination_port=22))
    assert alert is not None
    assert alert.metadata["scan_type"] == "vertical"


def test_port_scan_sliding_window_expires_old_events() -> None:
    rule = PortScanRule(
        window_seconds=2,
        horizontal_threshold=3,
        vertical_threshold=10,
    )
    rule.evaluate(Metadata(timestamp=1, destination_ip="10.0.0.2"))
    rule.evaluate(Metadata(timestamp=2, destination_ip="10.0.0.3"))
    result = rule.evaluate(Metadata(timestamp=4, destination_ip="10.0.0.4"))
    assert result is None


def test_port_scan_ignores_missing_required_fields() -> None:
    rule = PortScanRule(horizontal_threshold=1, vertical_threshold=1)
    assert rule.evaluate(Metadata(source_ip=None)) is None
    assert rule.evaluate(Metadata(destination_port=None)) is None


def test_icmp_flood_reaches_packet_threshold() -> None:
    rule = ICMPFloodRule(window_seconds=5, packet_threshold=3)
    packet = Metadata(protocol="ICMP")
    assert rule.evaluate(packet) is None
    assert rule.evaluate(Metadata(timestamp=2, protocol="ICMP")) is None
    alert = rule.evaluate(Metadata(timestamp=3, protocol="ICMP"))
    assert alert is not None
    assert alert.alert_type is AlertType.ICMP_FLOOD


def test_icmp_flood_ignores_non_icmp_traffic() -> None:
    rule = ICMPFloodRule(window_seconds=5, packet_threshold=1)
    assert rule.evaluate(Metadata(protocol="TCP")) is None


def test_rule_registration_enable_disable_and_unregister() -> None:
    engine = RulesEngine(rules=[AlwaysAlertRule()])
    assert engine.list_rules() == ("always",)
    engine.disable_rule("always")
    assert engine.evaluate(Metadata()) == []
    engine.enable_rule("always")
    assert len(engine.evaluate(Metadata())) == 1
    assert engine.unregister_rule("always").get_name() == "always"


def test_duplicate_registration_is_rejected() -> None:
    engine = RulesEngine(rules=[AlwaysAlertRule()])
    with pytest.raises(ValueError, match="already registered"):
        engine.register_rule(AlwaysAlertRule())


def test_engine_isolates_rule_failures_and_updates_metrics() -> None:
    engine = RulesEngine(rules=[FailingRule(), AlwaysAlertRule()])
    alerts = engine.evaluate(Metadata())
    metrics = engine.get_metrics()
    assert len(alerts) == 1
    assert metrics.packets_processed == 1
    assert metrics.alerts_generated == 1
    assert metrics.rules_executed == 2
    assert metrics.rule_failures == 1
    assert metrics.processing_latency >= 0


def test_engine_enforces_per_packet_alert_limit() -> None:
    class NamedRule(AlwaysAlertRule):
        def __init__(self, name: str) -> None:
            self.name = name

        def get_name(self) -> str:
            return self.name

    engine = RulesEngine(
        config=RulesEngineConfig(alert_limit_per_packet=1),
        rules=[NamedRule("one"), NamedRule("two")],
    )
    assert len(engine.evaluate(Metadata())) == 1
    assert engine.get_metrics().rules_executed == 1


def test_engine_retains_only_configured_number_of_alerts() -> None:
    engine = RulesEngine(
        config=RulesEngineConfig(max_retained_alerts=2),
        rules=[AlwaysAlertRule()],
    )
    for _ in range(3):
        engine.evaluate(Metadata())
    assert len(engine.get_alerts()) == 2


def test_metrics_can_be_reset() -> None:
    engine = RulesEngine(rules=[AlwaysAlertRule()])
    engine.evaluate(Metadata())
    engine.reset_metrics()
    assert engine.get_metrics().packets_processed == 0


def test_default_rules_use_configuration_overrides() -> None:
    config = RulesEngineConfig(
        blacklist=frozenset({"192.0.2.1"}),
        suspicious_ports=frozenset({9999}),
        thresholds={"icmp_flood_threshold": 2},
    )
    rules = create_default_rules(config)
    assert len(rules) == 5
    flood = next(rule for rule in rules if rule.get_name() == "ICMPFloodRule")
    assert flood.evaluate(Metadata(protocol="ICMP")) is None
    assert flood.evaluate(Metadata(timestamp=2, protocol="ICMP")) is not None


def test_engine_registers_default_rules_when_rules_are_not_supplied() -> None:
    engine = RulesEngine()
    assert engine.list_rules() == (
        "PortScanRule",
        "ICMPFloodRule",
        "SuspiciousPortRule",
        "BlacklistedIPRule",
        "MalformedPacketRule",
    )


def test_engine_accepts_an_explicitly_empty_rule_collection() -> None:
    engine = RulesEngine(rules=[])
    assert engine.list_rules() == ()
