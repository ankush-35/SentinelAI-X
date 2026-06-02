"""Unit tests for live packet capture metadata handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

scapy = pytest.importorskip("scapy.all")

from sensor.interface_discovery import NetworkInterface
from sensor.packet_capture import (
    PacketCapture,
    PacketCaptureError,
    PacketMetadata,
)


@dataclass
class FakeDiscovery:
    """Deterministic interface discovery service for packet capture tests."""

    interfaces: list[NetworkInterface]

    def discover(self) -> list[NetworkInterface]:
        return list(self.interfaces)

    def get_interface_by_name(self, name: str) -> NetworkInterface | None:
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None


def make_interface(
    name: str,
    ip_address: str | None = "192.168.1.10",
) -> NetworkInterface:
    """Create a normalized interface test object."""
    return NetworkInterface(
        name=name,
        description="Ethernet adapter",
        index=1,
        mac_address="00:11:22:33:44:55",
        ip_address=ip_address,
    )


def test_extract_metadata_from_ipv4_tcp_packet() -> None:
    packet = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP()
    packet.time = 1710000000.5

    metadata = PacketCapture.extract_metadata(packet)

    assert metadata == PacketMetadata(
        timestamp=1710000000.5,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        packet_length=len(packet),
    )


def test_capture_stores_metadata_in_memory() -> None:
    interface = make_interface("eth0")
    packet = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.UDP()

    def fake_sniff(**kwargs: Any) -> None:
        assert kwargs["iface"] == "eth0"
        assert kwargs["count"] == 1
        assert kwargs["timeout"] == 5.0
        kwargs["prn"](packet)

    capture = PacketCapture(
        discovery=FakeDiscovery([interface]),
        sniff_function=fake_sniff,
    )

    captured = capture.capture(count=1, timeout=5.0, interface_name="eth0")

    assert len(captured) == 1
    assert captured[0].protocol == "UDP"
    assert capture.export_metadata()[0]["source_ip"] == "10.0.0.1"


def test_capture_selects_default_non_loopback_interface() -> None:
    loopback = NetworkInterface(
        name="lo",
        description="Loopback",
        index=0,
        mac_address=None,
        ip_address="127.0.0.1",
    )
    ethernet = make_interface("eth0", ip_address="10.0.0.5")

    def fake_sniff(**kwargs: Any) -> None:
        assert kwargs["iface"] == "eth0"

    capture = PacketCapture(
        discovery=FakeDiscovery([loopback, ethernet]),
        sniff_function=fake_sniff,
    )

    assert capture.capture(count=0, timeout=1.0) == []


def test_capture_raises_when_requested_interface_is_missing() -> None:
    capture = PacketCapture(
        discovery=FakeDiscovery([make_interface("eth0")]),
        sniff_function=lambda **_: None,
    )

    with pytest.raises(PacketCaptureError, match="was not found"):
        capture.capture(interface_name="missing0")


def test_capture_wraps_sniff_errors() -> None:
    def failing_sniff(**_: Any) -> None:
        raise OSError("permission denied")

    capture = PacketCapture(
        discovery=FakeDiscovery([make_interface("eth0")]),
        sniff_function=failing_sniff,
    )

    with pytest.raises(PacketCaptureError, match="Unable to capture packets"):
        capture.capture(interface_name="eth0")
