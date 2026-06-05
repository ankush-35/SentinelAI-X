"""Tests for the single-file interface discovery module."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import pytest

from sensor import interface_discovery
from sensor.interface_discovery import (
    InterfaceDiscovery,
    InterfaceDiscoveryError,
    JsonLogFormatter,
    NetworkInterface,
    configure_logging,
    main,
    parse_args,
)


@dataclass
class FakeRawInterface:
    """Test double mimicking the Scapy interface attributes used by the module."""

    name: str | None = None
    description: str | None = None
    index: int | str | None = None
    mac: str | None = None
    ip: str | None = None
    ips: list[str] | tuple[str, ...] | set[str] | None = None

    def __str__(self) -> str:
        return "fallback-interface"


class FailingInterfaces:
    """Scapy IFACES test double that raises while enumerating interfaces."""

    def values(self) -> list[Any]:
        raise OSError("simulated scapy failure")


def test_network_interface_is_immutable() -> None:
    interface = NetworkInterface(
        name="eth0",
        description="Ethernet adapter",
        index=1,
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.10",
    )

    with pytest.raises(Exception):
        interface.name = "wlan0"  # type: ignore[misc]


def test_discover_normalizes_scapy_interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ifaces = {
        "eth0": FakeRawInterface(
            name="eth0",
            description=" Intel Ethernet ",
            index="7",
            mac=" 00:11:22:33:44:55 ",
            ip=" 192.168.1.10 ",
        ),
        "wlan0": FakeRawInterface(
            name="wlan0",
            description="Wi-Fi",
            index=None,
            mac=None,
            ips=["", "10.0.0.8"],
        ),
    }
    monkeypatch.setattr(interface_discovery, "IFACES", fake_ifaces)

    interfaces = InterfaceDiscovery().discover()

    assert interfaces == [
        NetworkInterface(
            name="eth0",
            description="Intel Ethernet",
            index=7,
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.10",
        ),
        NetworkInterface(
            name="wlan0",
            description="Wi-Fi",
            index=None,
            mac_address=None,
            ip_address="10.0.0.8",
        ),
    ]


def test_discover_uses_fallback_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        interface_discovery,
        "IFACES",
        {"fallback": FakeRawInterface(description="", index="not-an-int")},
    )

    interfaces = InterfaceDiscovery().discover()

    assert interfaces == [
        NetworkInterface(
            name="fallback-interface",
            description="N/A",
            index=None,
            mac_address=None,
            ip_address=None,
        ),
    ]


def test_discover_wraps_scapy_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(interface_discovery, "IFACES", FailingInterfaces())

    with pytest.raises(InterfaceDiscoveryError, match="Unable to discover"):
        InterfaceDiscovery().discover()


def test_get_interface_by_name_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        interface_discovery,
        "IFACES",
        {
            "eth0": FakeRawInterface(name="eth0", description="Ethernet"),
            "wlan0": FakeRawInterface(name="wlan0", description="Wi-Fi"),
        },
    )

    discovery = InterfaceDiscovery()

    assert discovery.get_interface_by_name("WLAN0") == NetworkInterface(
        name="wlan0",
        description="Wi-Fi",
        index=None,
        mac_address=None,
        ip_address=None,
    )
    assert discovery.get_interface_by_name("missing0") is None


def test_render_table_formats_interfaces() -> None:
    rendered = InterfaceDiscovery().render_table(
        [
            NetworkInterface(
                name="eth0",
                description="Ethernet",
                index=2,
                mac_address="00:11:22:33:44:55",
                ip_address="192.168.1.10",
            ),
        ],
    )

    assert "Name | Description | Index | MAC Address" in rendered
    assert "eth0 | Ethernet" in rendered
    assert "192.168.1.10" in rendered


def test_render_table_handles_empty_list() -> None:
    assert InterfaceDiscovery().render_table([]) == "No network interfaces found."


def test_json_log_formatter_outputs_structured_json() -> None:
    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="sentinelai_x.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="hello %s",
        args=("world",),
        exc_info=None,
        func="test_func",
    )

    payload = json.loads(formatter.format(record))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "sentinelai_x.test"
    assert payload["message"] == "hello world"
    assert payload["function"] == "test_func"


def test_configure_logging_installs_json_formatter() -> None:
    configure_logging("DEBUG")
    root_logger = logging.getLogger()

    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0].formatter, JsonLogFormatter)


def test_parse_args_defaults_to_info() -> None:
    args = parse_args([])

    assert args.log_level == "INFO"


def test_parse_args_accepts_supported_log_level() -> None:
    args = parse_args(["--log-level", "DEBUG"])

    assert args.log_level == "DEBUG"


def test_main_prints_discovered_interfaces(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        interface_discovery,
        "IFACES",
        {
            "eth0": FakeRawInterface(
                name="eth0",
                description="Ethernet",
                ip="10.0.0.5",
            ),
        },
    )

    exit_code = main(["--log-level", "INFO"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "SentinelAI-X Network Interface Discovery" in captured.out
    assert "eth0" in captured.out
    assert "10.0.0.5" in captured.out


def test_main_returns_error_code_when_discovery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(interface_discovery, "IFACES", FailingInterfaces())

    assert main(["--log-level", "INFO"]) == 1
