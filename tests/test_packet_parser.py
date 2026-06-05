"""Unit tests for packet parser metadata extraction."""

from __future__ import annotations

import json

import pytest

scapy = pytest.importorskip("scapy.all")

from sensor.packet_parser import PacketMetadata, PacketParser, PacketParserError


class BrokenPacket:
    """Packet-like object that fails during layer inspection."""

    def haslayer(self, _: object) -> bool:
        raise ValueError("bad packet")


def test_parse_ipv4_tcp_packet() -> None:
    packet = (
        scapy.IP(src="10.0.0.1", dst="10.0.0.2")
        / scapy.TCP(sport=12345, dport=443)
    )
    packet.time = 1710000000.5

    metadata = PacketParser().parse(packet)

    assert metadata == PacketMetadata(
        timestamp=1710000000.5,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=12345,
        destination_port=443,
        protocol="TCP",
        packet_size=len(packet),
        flow_id="10.0.0.1:12345->10.0.0.2:443/TCP",
        ip_version=4,
    )


def test_parse_ipv4_udp_packet() -> None:
    packet = (
        scapy.IP(src="192.168.1.10", dst="8.8.8.8")
        / scapy.UDP(sport=53000, dport=53)
    )

    metadata = PacketParser().parse(packet)

    assert metadata.source_ip == "192.168.1.10"
    assert metadata.destination_ip == "8.8.8.8"
    assert metadata.source_port == 53000
    assert metadata.destination_port == 53
    assert metadata.protocol == "UDP"
    assert metadata.ip_version == 4


def test_parse_ipv4_icmp_packet_without_ports() -> None:
    packet = scapy.IP(src="10.1.1.1", dst="10.1.1.2") / scapy.ICMP()

    metadata = PacketParser().parse(packet)

    assert metadata.source_ip == "10.1.1.1"
    assert metadata.destination_ip == "10.1.1.2"
    assert metadata.source_port is None
    assert metadata.destination_port is None
    assert metadata.protocol == "ICMP"
    assert metadata.flow_id == "10.1.1.1:0->10.1.1.2:0/ICMP"


def test_parse_ipv6_tcp_packet() -> None:
    packet = (
        scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
        / scapy.TCP(sport=2222, dport=22)
    )

    metadata = PacketParser().parse(packet)

    assert metadata.source_ip == "2001:db8::1"
    assert metadata.destination_ip == "2001:db8::2"
    assert metadata.source_port == 2222
    assert metadata.destination_port == 22
    assert metadata.protocol == "TCP"
    assert metadata.ip_version == 6
    assert metadata.flow_id == "2001:db8::1:2222->2001:db8::2:22/TCP"


def test_parse_unknown_packet() -> None:
    packet = scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

    metadata = PacketParser().parse(packet)

    assert metadata.source_ip is None
    assert metadata.destination_ip is None
    assert metadata.source_port is None
    assert metadata.destination_port is None
    assert metadata.protocol == "UNKNOWN"
    assert metadata.ip_version is None
    assert metadata.flow_id == "unknown:0->unknown:0/UNKNOWN"


def test_generate_flow_id_handles_missing_fields() -> None:
    flow_id = PacketParser.generate_flow_id(
        source_ip=None,
        destination_ip="10.0.0.2",
        source_port=None,
        destination_port=443,
        protocol="tcp",
    )

    assert flow_id == "unknown:0->10.0.0.2:443/TCP"


def test_metadata_to_json_is_serializable() -> None:
    metadata = PacketParser().parse(
        scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.UDP(sport=1, dport=2)
    )

    payload = json.loads(metadata.to_json())

    assert payload["source_ip"] == "10.0.0.1"
    assert payload["destination_port"] == 2


def test_parse_wraps_packet_errors() -> None:
    with pytest.raises(PacketParserError, match="Unable to parse packet metadata"):
        PacketParser().parse(BrokenPacket())
