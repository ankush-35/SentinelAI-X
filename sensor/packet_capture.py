"""Live packet capture support for SentinelAI-X sensors."""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import asdict, dataclass
from typing import Any, Callable, Protocol

from scapy.all import ICMP, IP, TCP, UDP, IPv6, sniff

from sensor.interface_discovery import (
    InterfaceDiscovery,
    InterfaceDiscoveryError,
    NetworkInterface,
    configure_logging,
)


class InterfaceDiscoveryProtocol(Protocol):
    """Interface discovery behavior required by packet capture."""

    def discover(self) -> list[NetworkInterface]:
        """Return discovered network interfaces."""

    def get_interface_by_name(self, name: str) -> NetworkInterface | None:
        """Return a network interface by name, or None when not found."""


SniffFunction = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Small, stable metadata record extracted from a captured packet."""

    timestamp: float
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    packet_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return the metadata as a JSON-serializable dictionary."""
        return asdict(self)


class PacketCaptureError(RuntimeError):
    """Raised when packet capture cannot be completed."""


@dataclass(frozen=True, slots=True)
class PacketCaptureConfig:
    """Runtime configuration for packet capture."""

    interface_name: str | None = None
    count: int = 100
    timeout: float | None = 30.0


class PacketCapture:
    """Capture packets from a selected interface and store packet metadata."""

    def __init__(
        self,
        config: PacketCaptureConfig | None = None,
        discovery: InterfaceDiscoveryProtocol | None = None,
        sniff_function: SniffFunction | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialize the packet capture service.

        Args:
            config: Optional capture defaults.
            discovery: Interface discovery service. Defaults to InterfaceDiscovery.
            sniff_function: Packet sniffing callable. Defaults to scapy.sniff.
            logger: Optional logger instance.
        """
        self.config = config or PacketCaptureConfig()
        self._discovery = discovery or InterfaceDiscovery()
        self.discovery = self._discovery
        self._sniff = sniff_function or sniff
        self.sniff_function = self._sniff
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        self.logger = self._logger
        self._captured_metadata: list[PacketMetadata] = []
        self.packet_metadata = self._captured_metadata

    def capture(
        self,
        count: int | None = None,
        timeout: float | None = None,
        interface_name: str | None = None,
    ) -> list[PacketMetadata]:
        """Capture packets and return metadata extracted during this capture.

        Args:
            count: Maximum number of packets to capture. Zero delegates to Scapy.
            timeout: Optional capture timeout in seconds.
            interface_name: Optional explicit interface name.

        Returns:
            Metadata records captured during this call.

        Raises:
            PacketCaptureError: If interface selection or packet capture fails.
        """
        effective_count = self.config.count if count is None else count
        effective_timeout = self.config.timeout if timeout is None else timeout
        effective_interface = interface_name or self.config.interface_name

        self._validate_capture_options(effective_count, effective_timeout)
        interface = self._select_interface(effective_interface)
        captured_this_call: list[PacketMetadata] = []

        def handle_packet(packet: Any) -> None:
            metadata = self.extract_metadata(packet)
            self._captured_metadata.append(metadata)
            captured_this_call.append(metadata)

        try:
            self._logger.info("Starting packet capture on interface %s", interface.name)
            self._sniff(
                iface=interface.name,
                count=effective_count,
                timeout=effective_timeout,
                prn=handle_packet,
                store=False,
            )
        except PacketCaptureError:
            raise
        except Exception as exc:
            self._logger.exception("Packet capture failed")
            raise PacketCaptureError("Unable to capture packets") from exc

        self._logger.info(
            "Completed packet capture: %d packet(s) captured",
            len(captured_this_call),
        )
        return captured_this_call

    def clear(self) -> None:
        """Remove all packet metadata currently stored in memory."""
        self._captured_metadata.clear()

    def export_metadata(self) -> list[dict[str, Any]]:
        """Return all captured metadata as dictionaries."""
        return [metadata.to_dict() for metadata in self._captured_metadata]

    def _select_interface(self, interface_name: str | None) -> NetworkInterface:
        """Return the requested interface or a sensible default."""
        if interface_name:
            interface = self._discovery.get_interface_by_name(interface_name)
            if interface is None:
                raise PacketCaptureError(
                    f"Network interface {interface_name!r} was not found"
                )
            return interface

        try:
            interfaces = self._discovery.discover()
        except InterfaceDiscoveryError as exc:
            raise PacketCaptureError("Unable to discover capture interfaces") from exc

        for interface in interfaces:
            if self._is_capture_candidate(interface):
                return interface

        if interfaces:
            return interfaces[0]

        raise PacketCaptureError("No network interfaces are available")

    @staticmethod
    def _is_capture_candidate(interface: NetworkInterface) -> bool:
        """Return True when the interface is a practical default capture target."""
        name = interface.name.casefold()
        ip_address = interface.ip_address or ""

        if name in {"lo", "loopback"} or "loopback" in interface.description.casefold():
            return False
        if ip_address.startswith("127."):
            return False

        return True

    @staticmethod
    def extract_metadata(packet: Any) -> PacketMetadata:
        """Extract basic metadata from a Scapy packet."""
        source_ip: str | None = None
        destination_ip: str | None = None

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            source_ip = str(ip_layer.src)
            destination_ip = str(ip_layer.dst)
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            source_ip = str(ip_layer.src)
            destination_ip = str(ip_layer.dst)

        return PacketMetadata(
            timestamp=float(getattr(packet, "time", 0.0)),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=PacketCapture._detect_protocol(packet),
            packet_length=len(packet),
        )

    @staticmethod
    def _detect_protocol(packet: Any) -> str:
        """Return a simple protocol name for the packet."""
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(IP):
            return "IP"
        if packet.haslayer(IPv6):
            return "IPv6"
        return "UNKNOWN"

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
        help="Interface name to capture from.",
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
