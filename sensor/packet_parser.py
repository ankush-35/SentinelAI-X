"""Single-file packet parser for SentinelAI-X sensors.

The parser converts Scapy packets into a stable metadata record that downstream
sensor stages can consume without depending on Scapy internals.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

from scapy.all import ICMP, IP, TCP, UDP, IPv6


class JsonLogFormatter(logging.Formatter):
    """Format parser logs as single-line JSON records."""

    def format(self, record: logging.LogRecord) -> str:
        """Return a JSON-formatted log entry."""
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


def build_logger(name: str = "sentinelai_x.packet_parser") -> logging.Logger:
    """Build a structured logger for packet parsing."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Normalized metadata extracted from a Scapy packet."""

    timestamp: float
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_size: int
    flow_id: str
    ip_version: int | None

    def to_dict(self) -> dict[str, Any]:
        """Return metadata as a JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Return metadata as compact JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class PacketParserError(RuntimeError):
    """Raised when a packet cannot be parsed into metadata."""


class PacketParser:
    """Parse IPv4, IPv6, TCP, UDP, and ICMP Scapy packets."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize the parser.

        Args:
            logger: Optional logger. If omitted, a structured module logger is used.
        """
        self._logger = logger or build_logger()

    def parse(self, packet: Any) -> PacketMetadata:
        """Parse one Scapy packet into normalized metadata.

        Args:
            packet: A Scapy packet or packet-like object.

        Returns:
            Parsed packet metadata.

        Raises:
            PacketParserError: If required packet attributes cannot be read.
        """
        try:
            source_ip, destination_ip, ip_version = self._extract_ip_fields(packet)
            source_port, destination_port = self._extract_ports(packet)
            protocol = self._detect_protocol(packet)
            timestamp = float(getattr(packet, "time", 0.0))
            packet_size = len(packet)
            flow_id = self.generate_flow_id(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
            )
        except Exception as exc:
            self._logger.exception("Packet parsing failed")
            raise PacketParserError("Unable to parse packet metadata") from exc

        metadata = PacketMetadata(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=packet_size,
            flow_id=flow_id,
            ip_version=ip_version,
        )

        self._logger.info(
            "Parsed packet metadata",
            extra={
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "flow_id": flow_id,
            },
        )
        return metadata

    @staticmethod
    def generate_flow_id(
        source_ip: str | None,
        destination_ip: str | None,
        source_port: int | None,
        destination_port: int | None,
        protocol: str,
    ) -> str:
        """Generate a deterministic flow identifier.

        The flow ID is directional because packet capture and alerting often
        need to preserve who initiated the observed packet.
        """
        src_ip = source_ip or "unknown"
        dst_ip = destination_ip or "unknown"
        src_port = str(source_port) if source_port is not None else "0"
        dst_port = str(destination_port) if destination_port is not None else "0"
        proto = protocol.upper() or "UNKNOWN"

        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"

    @staticmethod
    def _extract_ip_fields(packet: Any) -> tuple[str | None, str | None, int | None]:
        """Extract source IP, destination IP, and IP version."""
        if packet.haslayer(IP):
            layer = packet[IP]
            return str(layer.src), str(layer.dst), 4

        if packet.haslayer(IPv6):
            layer = packet[IPv6]
            return str(layer.src), str(layer.dst), 6

        return None, None, None

    @staticmethod
    def _extract_ports(packet: Any) -> tuple[int | None, int | None]:
        """Extract TCP or UDP ports when present."""
        if packet.haslayer(TCP):
            layer = packet[TCP]
            return int(layer.sport), int(layer.dport)

        if packet.haslayer(UDP):
            layer = packet[UDP]
            return int(layer.sport), int(layer.dport)

        return None, None

    @staticmethod
    def _detect_protocol(packet: Any) -> str:
        """Detect the primary network or transport protocol."""
        if packet.haslayer(TCP):
            return "TCP"

        if packet.haslayer(UDP):
            return "UDP"

        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(IP):
            return "IPv4"

        if packet.haslayer(IPv6):
            return "IPv6"

        return "UNKNOWN"
