"""Unit and integration tests for interface discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from sensor.interface_discovery.classifier import InterfaceClassifier
from sensor.interface_discovery.config import InterfaceDiscoverySettings
from sensor.interface_discovery.discovery import InterfaceDiscovery
from sensor.interface_discovery.exceptions import (
    InterfaceNotFoundError,
    InterfaceProviderError,
    InterfaceValidationError,
)
from sensor.interface_discovery.health import InterfaceDiscoveryHealthCheck
from sensor.interface_discovery.models import InterfaceType, OperationalStatus
from sensor.interface_discovery.normalizer import InterfaceNormalizer
from sensor.interface_discovery.sanitization import validate_interface_name
from sensor.interface_discovery.selector import PrimaryInterfaceSelector


@dataclass
class FakeRawInterface:
    """Test double mimicking Scapy interface shape."""

    name: str
    description: str = ""
    index: int | None = None
    mac: str | None = None
    ip: str | None = None
    ips: list[str] | None = None
    mtu: int | None = None
    is_up: bool | None = None


class FakeProvider:
    """In-memory provider for deterministic tests."""

    provider_name = "fake"

    def __init__(self, interfaces: list[FakeRawInterface]) -> None:
        self._interfaces = interfaces

    def enumerate_raw_interfaces(self) -> list[FakeRawInterface]:
        return list(self._interfaces)


class FailingProvider:
    """Provider that always fails."""

    provider_name = "failing"

    def enumerate_raw_interfaces(self) -> list[Any]:
        raise InterfaceProviderError("simulated failure")


class TestInterfaceClassifier:
    def test_classifies_loopback(self) -> None:
        classifier = InterfaceClassifier()
        assert (
            classifier.classify("lo", "Loopback Pseudo-Interface")
            == InterfaceType.LOOPBACK
        )

    def test_classifies_wifi(self) -> None:
        classifier = InterfaceClassifier()
        assert classifier.classify("wlan0", "Wireless") == InterfaceType.WIFI

    def test_classifies_vpn(self) -> None:
        classifier = InterfaceClassifier()
        assert classifier.classify("tun0", "OpenVPN") == InterfaceType.VPN

    def test_classifies_virtual_docker(self) -> None:
        classifier = InterfaceClassifier()
        assert classifier.classify("docker0", "Docker bridge") == InterfaceType.VIRTUAL


class TestInterfaceNormalizer:
    def test_extracts_ipv4_and_ipv6(self) -> None:
        normalizer = InterfaceNormalizer()
        raw = FakeRawInterface(
            name="eth0",
            description="Intel Ethernet",
            mac="aa-bb-cc-dd-ee-ff",
            ips=["192.168.1.10", "fe80::1"],
            is_up=True,
            mtu=1500,
        )
        iface = normalizer.normalize(raw)
        assert iface.ipv4_address == "192.168.1.10"
        assert iface.ipv6_address is None  # link-local skipped
        assert iface.mac_address == "aa:bb:cc:dd:ee:ff"
        assert iface.mtu == 1500
        assert iface.is_active is True

    def test_loopback_not_active(self) -> None:
        normalizer = InterfaceNormalizer()
        raw = FakeRawInterface(
            name="lo",
            description="Loopback",
            ip="127.0.0.1",
            is_up=True,
        )
        iface = normalizer.normalize(raw)
        assert iface.interface_type == InterfaceType.LOOPBACK
        assert iface.is_active is False


class TestPrimaryInterfaceSelector:
    def test_prefers_ethernet_over_wifi(self) -> None:
        normalizer = InterfaceNormalizer()
        eth = normalizer.normalize(
            FakeRawInterface(
                name="eth0",
                description="Ethernet",
                ip="10.0.0.5",
                is_up=True,
            ),
        )
        wifi = normalizer.normalize(
            FakeRawInterface(
                name="wlan0",
                description="Wi-Fi",
                ip="10.0.0.8",
                is_up=True,
            ),
        )
        selector = PrimaryInterfaceSelector()
        primary = selector.select_primary([wifi, eth])
        assert primary is not None
        assert primary.name == "eth0"

    def test_excludes_virtual_when_configured(self) -> None:
        normalizer = InterfaceNormalizer()
        docker = normalizer.normalize(
            FakeRawInterface(
                name="docker0",
                description="Docker",
                ip="172.17.0.1",
                is_up=True,
            ),
        )
        settings = InterfaceDiscoverySettings(exclude_virtual_from_primary=True)
        selector = PrimaryInterfaceSelector(settings=settings)
        assert selector.select_primary([docker]) is None


class TestInterfaceDiscoveryService:
    def test_discover_snapshot_with_fake_provider(self) -> None:
        provider = FakeProvider(
            [
                FakeRawInterface(
                    name="eth0",
                    description="Ethernet",
                    ip="192.168.0.2",
                    mac="00:11:22:33:44:55",
                    is_up=True,
                ),
                FakeRawInterface(name="lo", description="Loopback", ip="127.0.0.1"),
            ],
        )
        discovery = InterfaceDiscovery(
            provider=provider,
            settings=InterfaceDiscoverySettings(cache_discovery=False),
        )
        snapshot = discovery.discover_snapshot()
        assert len(snapshot.interfaces) == 2
        assert snapshot.primary_interface is not None
        assert snapshot.primary_interface.name == "eth0"

    def test_get_interface_by_name_raises_when_missing(self) -> None:
        discovery = InterfaceDiscovery(provider=FakeProvider([]))
        with pytest.raises(InterfaceNotFoundError):
            discovery.get_interface_by_name("missing0")

    def test_find_interface_by_name_returns_none(self) -> None:
        discovery = InterfaceDiscovery(provider=FakeProvider([]))
        assert discovery.find_interface_by_name("missing0") is None

    def test_provider_failure_increments_metrics(self) -> None:
        discovery = InterfaceDiscovery(
            provider=FailingProvider(),
            settings=InterfaceDiscoverySettings(cache_discovery=False),
        )
        with pytest.raises(InterfaceProviderError):
            discovery.discover_snapshot()
        assert discovery.metrics.discovery_failures == 1


class TestValidationAndSanitization:
    def test_rejects_empty_name(self) -> None:
        settings = InterfaceDiscoverySettings()
        with pytest.raises(InterfaceValidationError):
            validate_interface_name("  ", settings)

    def test_rejects_control_characters(self) -> None:
        settings = InterfaceDiscoverySettings()
        with pytest.raises(InterfaceValidationError):
            validate_interface_name("eth\x000", settings)


class TestHealthCheck:
    def test_healthy_when_primary_present(self) -> None:
        provider = FakeProvider(
            [
                FakeRawInterface(
                    name="eth0",
                    description="Ethernet",
                    ip="10.1.1.5",
                    is_up=True,
                ),
            ],
        )
        discovery = InterfaceDiscovery(
            provider=provider,
            settings=InterfaceDiscoverySettings(cache_discovery=False),
        )
        result = InterfaceDiscoveryHealthCheck(discovery).check()
        assert result.status.value == "healthy"

    def test_degraded_when_no_interfaces(self) -> None:
        discovery = InterfaceDiscovery(
            provider=FakeProvider([]),
            settings=InterfaceDiscoverySettings(cache_discovery=False),
        )
        result = InterfaceDiscoveryHealthCheck(discovery).check()
        assert result.status.value == "degraded"


@pytest.mark.integration
class TestScapyIntegration:
    def test_scapy_discovery_runs(self) -> None:
        pytest.importorskip("scapy")
        from sensor.interface_discovery.providers.scapy_provider import (
            ScapyInterfaceProvider,
        )

        discovery = InterfaceDiscovery(
            provider=ScapyInterfaceProvider(),
            settings=InterfaceDiscoverySettings(cache_discovery=False),
        )
        snapshot = discovery.discover_snapshot()
        assert isinstance(snapshot.interfaces, tuple)
