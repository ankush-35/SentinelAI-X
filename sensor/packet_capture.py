"""Live packet capture module for SentinelAI-X.

This module captures live network packets from a selected local interface and
normalizes lightweight metadata for future parser and traffic logging stages.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Protocol

try:
    from scapy.all import ICMP, IP, TCP, UDP, IPv6, Packet, sniff
except ImportError as exc:
    raise RuntimeError(
        "Scapy is required for packet capture. Install it with: pip install scapy"
    ) from exc

from sensor.interface_discovery import (
    InterfaceDiscovery,
    InterfaceDiscoveryError,
    NetworkInterface,
    configure_logging,
)


SniffFunction = Callable[..., Any]


class PacketCaptureError(RuntimeError):
    """Raised when packet capture cannot be completed."""


class InterfaceDiscoveryService(Protocol):
    """Protocol for interface discovery services used by packet capture."""

    def discover(self) -> list[NetworkInterface]:
        """Return discovered network interfaces."""

    def get_interface_by_name(self, name: str) -> NetworkInterface | None:
        """Return a discovered interface by name, if present."""


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Normalized packet metadata captured from the wire.

    Attributes:
        timestamp: Packet capture timestamp as seconds since the Unix epoch.
        source_ip: Source IP address, if the packet has an IP layer.
        destination_ip: Destination IP address, if the packet has an IP layer.
        protocol: Transport or network protocol name.
        packet_length: Captured packet length in bytes.
    """

    timestamp: float
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    packet_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable metadata for downstream modules."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PacketCaptureConfig:
    """Runtime configuration for packet capture."""

    interface_name: str | None = None
    count: int = 100
    timeout: float | None = 30.0


@dataclass(slots=True)
class PacketCapture:
    """Capture live packets and retain normalized metadata in memory.

    The class intentionally stores metadata rather than raw packets so future
    modules such as `packet_parser.py` and `traffic_logger.py` can consume a
    stable, JSON-friendly representation without depending on Scapy internals.
    """

    config: PacketCaptureConfig = field(default_factory=PacketCaptureConfig)
    discovery: InterfaceDiscoveryService = field(
        default_factory=InterfaceDiscovery,
    )
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger("sentinelai_x.packet_capture"),
    )
    sniff_function: SniffFunction = sniff
    packet_metadata: list[PacketMetadata] = field(default_factory=list)

    def capture(
        self,
        count: int | None = None,
        timeout: float | None = None,
        interface_name: str | None = None,
    ) -> list[PacketMetadata]:
        """Capture packets from the selected interface.

        Args:
            count: Optional capture count override. A value of zero lets Scapy
                capture until timeout or interruption.
            timeout: Optional capture timeout override in seconds.
            interface_name: Optional interface name override.

        Returns:
            A snapshot list of packet metadata collected during this run.

        Raises:
            PacketCaptureError: If interface resolution or packet capture fails.
        """
        effective_count = self.config.count if count is None else count
        effective_timeout = self.config.timeout if timeout is None else timeout
        selected_interface = self._resolve_interface(
            interface_name or self.config.interface_name,
        )
        self._validate_capture_options(effective_count, effective_timeout)

        start_index = len(self.packet_metadata)
        self.logger.info(
            "Starting packet capture on interface %s",
            selected_interface.name,
        )

        try:
            self.sniff_function(
                iface=selected_interface.name,
                count=effective_count,
                timeout=effective_timeout,
                prn=self._store_packet_metadata,
                store=False,
            )
        except Exception as exc:
            self.logger.exception(
                "Packet capture failed on interface %s",
                selected_interface.name,
            )
            raise PacketCaptureError(
                f"Unable to capture packets on interface "
                f"{selected_interface.name!r}"
            ) from exc

        captured = self.packet_metadata[start_index:]
        self.logger.info(
            "Completed packet capture on interface %s: %d packet(s) captured",
            selected_interface.name,
            len(captured),
        )
        return list(captured)

    def clear(self) -> None:
        """Remove all packet metadata currently stored in memory."""
        self.packet_metadata.clear()
        self.logger.info("Cleared packet metadata buffer")

    def export_metadata(self) -> list[dict[str, Any]]:
        """Return buffered metadata for parser or logger integration."""
        return [metadata.to_dict() for metadata in self.packet_metadata]

    def _resolve_interface(
        self,
        requested_interface: str | None,
    ) -> NetworkInterface:
        """Resolve the requested interface or select a likely active one."""
        try:
            if requested_interface:
                interface = self.discovery.get_interface_by_name(
                    requested_interface,
                )
                if interface is None:
                    raise PacketCaptureError(
                        f"Interface {requested_interface!r} was not found"
                    )
                return interface

            interfaces = self.discovery.discover()
        except InterfaceDiscoveryError as exc:
            raise PacketCaptureError("Unable to discover capture interfaces") from exc

        if not interfaces:
            raise PacketCaptureError("No network interfaces are available")

        selected = self._select_default_interface(interfaces)
        self.logger.info(
            "Selected default capture interface %s",
            selected.name,
        )
        return selected

    @staticmethod
    def _select_default_interface(
        interfaces: list[NetworkInterface],
    ) -> NetworkInterface:
        """Select a likely active, non-loopback interface."""
        for interface in interfaces:
            name = interface.name.casefold()
            description = interface.description.casefold()

            if interface.ip_address and "loopback" not in description:
                if name not in {"lo", "localhost"}:
                    return interface

        return interfaces[0]

    def _store_packet_metadata(self, packet: Packet) -> None:
        """Extract and store metadata from a Scapy packet callback."""
        metadata = self.extract_metadata(packet)
        self.packet_metadata.append(metadata)
        self.logger.debug(
            "Captured packet metadata: %s",
            metadata.to_dict(),
        )

    @staticmethod
    def extract_metadata(packet: Packet) -> PacketMetadata:
        """Extract normalized metadata from a Scapy packet."""
        source_ip: str | None = None
        destination_ip: str | None = None
        protocol = "UNKNOWN"

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            source_ip = str(ip_layer.src)
            destination_ip = str(ip_layer.dst)
            protocol = str(ip_layer.sprintf("%IP.proto%")).upper()
        elif packet.haslayer(IPv6):
            ipv6_layer = packet.getlayer(IPv6)
            source_ip = str(ipv6_layer.src)
            destination_ip = str(ipv6_layer.dst)
            protocol = "IPv6"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return PacketMetadata(
            timestamp=float(getattr(packet, "time", 0.0)),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            packet_length=len(packet),
        )

    @staticmethod
    def _validate_capture_options(
        count: int,
        timeout: float | None,
    ) -> None:
        """Validate capture options before invoking Scapy."""
        if count < 0:
            raise PacketCaptureError("Capture count must be greater than or equal to 0")

        if timeout is not None and timeout <= 0:
            raise PacketCaptureError("Capture timeout must be greater than 0 seconds")


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse packet capture command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="packet_capture",
        description="Capture live packet metadata for SentinelAI-X.",
    )
    parser.add_argument(
        "--interface",
        dest="interface_name",
        help=(
            "Interface name to capture from. Defaults to a discovered active "
            "interface."
        ),
    )
    parser.add_argument(
        "--count",
        default=100,
        type=int,
        help="Number of packets to capture. Use 0 to capture until timeout.",
    )
    parser.add_argument(
        "--timeout",
        default=30.0,
        type=float,
        help="Capture timeout in seconds.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Set structured logging verbosity.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run live packet capture from the command line."""
    args = parse_args(argv or sys.argv[1:])
    configure_logging(args.log_level)

    logger = logging.getLogger("sentinelai_x.packet_capture")
    capture = PacketCapture(
        config=PacketCaptureConfig(
            interface_name=args.interface_name,
            count=args.count,
            timeout=args.timeout,
        ),
        logger=logger,
    )

    try:
        metadata = capture.capture()
    except PacketCaptureError as exc:
        logger.error("Packet capture failed: %s", exc)
        return 1

    logger.info("Packet capture produced %d metadata record(s)", len(metadata))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
