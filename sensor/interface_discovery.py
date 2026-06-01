"""Network interface discovery module for SentinelAI-X.

This module discovers local network interfaces before packet capture begins.
It is designed to be reused by future SentinelAI-X sensor components such as
packet capture, packet parsing, traffic logging, and feature extraction.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any

try:
    from scapy.all import IFACES
except ImportError as exc:
    raise RuntimeError(
        "Scapy is required for interface discovery. "
        "Install it with: pip install scapy"
    ) from exc


class JsonLogFormatter(logging.Formatter):
    """Format log records as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Return a JSON-formatted log entry.

        Args:
            record: The logging record to format.

        Returns:
            A JSON string containing structured log fields.
        """
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structured application logging.

    Args:
        log_level: Logging level name such as DEBUG, INFO, WARNING, or ERROR.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level.upper())


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    """Normalized network interface information.

    Attributes:
        name: Interface name used by Scapy and the operating system.
        description: Human-readable interface description.
        index: Operating system interface index, if available.
        mac_address: MAC address, if available.
        ip_address: Primary IP address, if available.
    """

    name: str
    description: str
    index: int | None
    mac_address: str | None
    ip_address: str | None


class InterfaceDiscoveryError(RuntimeError):
    """Raised when network interface discovery fails."""


class InterfaceDiscovery:
    """Discover and normalize local network interfaces.

    This class provides a stable interface discovery layer for SentinelAI-X.
    Future packet capture modules should consume `NetworkInterface` objects
    from this class instead of directly depending on Scapy internals.
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize the interface discovery service.

        Args:
            logger: Optional logger instance. If omitted, a module logger is used.
        """
        self._logger = logger or logging.getLogger(self.__class__.__name__)

    def discover(self) -> list[NetworkInterface]:
        """Discover available local network interfaces.

        Returns:
            A list of normalized network interface objects.

        Raises:
            InterfaceDiscoveryError: If interface discovery fails.
        """
        self._logger.info("Starting network interface discovery")

        try:
            interfaces = [
                self._normalize_interface(raw_iface)
                for raw_iface in IFACES.values()
            ]
        except Exception as exc:
            self._logger.exception("Network interface discovery failed")
            raise InterfaceDiscoveryError(
                "Unable to discover network interfaces"
            ) from exc

        self._logger.info(
            "Completed network interface discovery: %d interface(s) found",
            len(interfaces),
        )

        return interfaces

    def get_interface_by_name(self, name: str) -> NetworkInterface | None:
        """Return a discovered interface by name.

        Args:
            name: Interface name to search for.

        Returns:
            The matching `NetworkInterface`, or `None` if no match is found.
        """
        normalized_name = name.casefold()

        for interface in self.discover():
            if interface.name.casefold() == normalized_name:
                return interface

        return None

    def render_table(self, interfaces: list[NetworkInterface]) -> str:
        """Render discovered interfaces as a readable table.

        Args:
            interfaces: Interfaces to render.

        Returns:
            A formatted table string.
        """
        if not interfaces:
            return "No network interfaces found."

        headers = ("Name", "Description", "Index", "MAC Address", "IP Address")
        rows = [
            (
                interface.name,
                interface.description,
                str(interface.index) if interface.index is not None else "N/A",
                interface.mac_address or "N/A",
                interface.ip_address or "N/A",
            )
            for interface in interfaces
        ]

        widths = [
            max(len(headers[column]), *(len(row[column]) for row in rows))
            for column in range(len(headers))
        ]

        header_line = " | ".join(
            header.ljust(widths[index])
            for index, header in enumerate(headers)
        )
        separator = "-+-".join("-" * width for width in widths)

        row_lines = [
            " | ".join(
                value.ljust(widths[index])
                for index, value in enumerate(row)
            )
            for row in rows
        ]

        return "\n".join((header_line, separator, *row_lines))

    def _normalize_interface(self, raw_iface: Any) -> NetworkInterface:
        """Convert a Scapy interface object into a stable internal model.

        Args:
            raw_iface: Raw interface object provided by Scapy.

        Returns:
            A normalized `NetworkInterface`.
        """
        name = self._safe_string(
            raw_iface,
            "name",
            fallback=str(raw_iface),
        )
        description = self._safe_string(
            raw_iface,
            "description",
            fallback="N/A",
        )
        index = self._safe_int(raw_iface, "index")
        mac_address = self._safe_optional_string(raw_iface, "mac")
        ip_address = self._extract_ip_address(raw_iface)

        self._logger.debug(
            "Discovered interface",
            extra={
                "interface_name": name,
                "interface_index": index,
                "mac_address": mac_address,
                "ip_address": ip_address,
            },
        )

        return NetworkInterface(
            name=name,
            description=description,
            index=index,
            mac_address=mac_address,
            ip_address=ip_address,
        )

    @staticmethod
    def _safe_string(
        source: Any,
        attribute: str,
        fallback: str,
    ) -> str:
        """Safely read a string attribute from an object."""
        value = getattr(source, attribute, None)

        if value is None:
            return fallback

        value_as_text = str(value).strip()
        return value_as_text or fallback

    @staticmethod
    def _safe_optional_string(source: Any, attribute: str) -> str | None:
        """Safely read an optional string attribute from an object."""
        value = getattr(source, attribute, None)

        if value is None:
            return None

        value_as_text = str(value).strip()
        return value_as_text or None

    @staticmethod
    def _safe_int(source: Any, attribute: str) -> int | None:
        """Safely read an optional integer attribute from an object."""
        value = getattr(source, attribute, None)

        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_ip_address(raw_iface: Any) -> str | None:
        """Extract a primary IP address from a Scapy interface object.

        Scapy may expose IP information differently across platforms.
        This method checks common attributes while keeping the rest of the
        module independent from Scapy-specific data shapes.
        """
        ip_value = getattr(raw_iface, "ip", None)

        if ip_value:
            return str(ip_value).strip() or None

        ips_value = getattr(raw_iface, "ips", None)

        if isinstance(ips_value, (list, tuple, set)):
            for candidate in ips_value:
                candidate_text = str(candidate).strip()
                if candidate_text:
                    return candidate_text

        return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Command-line arguments excluding the executable name.

    Returns:
        Parsed command-line namespace.
    """
    parser = argparse.ArgumentParser(
        prog="interface_discovery",
        description="Discover local network interfaces for SentinelAI-X.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Set structured logging verbosity.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run network interface discovery from the command line.

    Args:
        argv: Optional command-line arguments excluding the executable name.

    Returns:
        Process exit code. Zero indicates success.
    """
    args = parse_args(argv or sys.argv[1:])
    configure_logging(args.log_level)

    logger = logging.getLogger("sentinelai_x.interface_discovery")
    discovery = InterfaceDiscovery(logger=logger)

    try:
        interfaces = discovery.discover()
    except InterfaceDiscoveryError as exc:
        logger.error("Interface discovery failed: %s", exc)
        return 1

    print("\nSentinelAI-X Network Interface Discovery\n")
    print(discovery.render_table(interfaces))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())