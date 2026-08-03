"""Unit tests for the IoT Security Scanner.

The scanner opens real TCP connections; these tests stub the connect and
banner-grab primitives with a fixed set of "open" ports, so they run offline
and deterministically. The suite locks in that device type, encryption
status, findings and score are derived from the observed open ports — the
previous version invented all of them (a device existed with probability
random.random() < 0.3, everything else was random.choice/randint).
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "iot_security_scanner"

sys.path.insert(0, str(APP_DIR))


def _load(name, path, extra_modules=None):
    """Load a tool module under a unique name (see test_ct_log_scanner)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    injected = list((extra_modules or {}).items())
    for key, value in injected:
        sys.modules[key] = value
    try:
        spec.loader.exec_module(module)
    finally:
        for key, _ in injected:
            sys.modules.pop(key, None)
    return module


_std = _load("iot_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load("iot_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std})
iot = _load("iot_main", TOOL_DIR / "main.py", {"schemas": _schemas})


@pytest.fixture
def open_ports(monkeypatch):
    """Make _is_open report a fixed set of ports as open, and stub banners."""

    def _install(ports, banner=None):
        port_set = set(ports)

        async def fake_is_open(ip, port, timeout):
            return port in port_set

        async def fake_banner(ip, port, timeout):
            return banner

        monkeypatch.setattr(iot.IoTSecurityScanner, "_is_open", staticmethod(fake_is_open))
        monkeypatch.setattr(iot.IoTSecurityScanner, "_grab_banner", staticmethod(fake_banner))

    return _install


def scan(**overrides):
    params = dict(target_ip="192.0.2.10", port_scan_range="1-65535", timeout=10)
    params.update(overrides)
    return asyncio.run(iot.execute_tool(_schemas.IoTSecurityScannerInput(**params)))


class TestDiscovery:
    def test_a_host_with_no_open_ports_yields_no_device(self, open_ports):
        open_ports([])
        out = scan()
        assert out.total_devices == 0
        assert out.success is True                     # a clean host is a success, not a failure

    def test_a_host_with_open_ports_is_reported(self, open_ports):
        open_ports([22, 80])
        out = scan()
        assert out.total_devices == 1
        assert out.devices_found[0].open_ports == [22, 80]

    def test_missing_target_is_rejected(self):
        out = asyncio.run(
            iot.execute_tool(_schemas.IoTSecurityScannerInput(port_scan_range="1-100"))
        )
        assert out.success is False
        assert "target_ip or ip_range" in out.summary


class TestClassificationFromRealPorts:
    def test_printer_ports_classify_as_printer(self, open_ports):
        open_ports([515, 631, 9100])
        assert scan().devices_found[0].device_type == "printer"

    def test_industrial_ports_classify_as_industrial(self, open_ports):
        open_ports([502, 20000])
        assert scan().devices_found[0].device_type == "industrial"

    def test_manufacturer_comes_from_the_real_server_banner(self, open_ports):
        open_ports([80], banner="HTTP/1.1 200 OK\r\nServer: Boa/0.94.13\r\n\r\n")
        assert scan().devices_found[0].manufacturer == "Boa/0.94.13"

    def test_mac_and_firmware_are_never_invented(self, open_ports):
        open_ports([80, 443])
        device = scan().devices_found[0]
        assert device.mac_address is None
        assert device.firmware_version is None
        assert device.default_credentials is False     # not tested, never claimed


class TestEncryptionAndScore:
    def test_only_tls_ports_are_strong(self, open_ports):
        open_ports([443, 8883])
        assert scan().devices_found[0].encryption_status == "Strong"

    def test_only_plaintext_ports_are_none(self, open_ports):
        open_ports([23, 80])
        assert scan().devices_found[0].encryption_status == "None"

    def test_mixed_ports_are_weak(self, open_ports):
        open_ports([22, 80])                            # SSH encrypted, HTTP not
        assert scan().devices_found[0].encryption_status == "Weak"

    def test_more_exposure_lowers_the_score(self, open_ports):
        open_ports([443])
        high = scan().devices_found[0].security_score
        open_ports([23, 80, 502, 20000])
        low = scan().devices_found[0].security_score
        assert low < high


class TestFindings:
    def test_telnet_is_a_high_cleartext_finding(self, open_ports):
        open_ports([23])
        titles = [(v.severity, v.title) for v in scan().vulnerabilities]
        assert ("High", "Telnet exposed on port 23") in titles

    def test_exposed_modbus_is_critical(self, open_ports):
        open_ports([502])
        out = scan()
        assert out.critical_vulnerabilities >= 1
        assert any("Modbus" in v.title and v.severity == "Critical" for v in out.vulnerabilities)

    def test_plaintext_mqtt_flags_missing_tls(self, open_ports):
        open_ports([1883])
        out = scan()
        assert any("MQTT without TLS" in v.title for v in out.vulnerabilities)

    def test_all_tls_host_has_no_cleartext_findings(self, open_ports):
        open_ports([443, 8883])
        out = scan()
        assert not any(v.category == "Cleartext Protocol" for v in out.vulnerabilities)

    def test_protocol_analysis_reports_real_facts(self, open_ports):
        open_ports([502])
        analysis = {p.protocol: p for p in scan().network_protocols}
        assert "Modbus" in analysis
        assert analysis["Modbus"].encryption is False
        assert "Protocol has no built-in authentication" in analysis["Modbus"].vulnerabilities
