"""
IoT Security Scanner

Discovers IoT devices by really connecting to the ports their device classes
listen on, grabs service banners, and reports the security issues that follow
from what is actually open — plaintext management protocols, missing
transport encryption, exposed unauthenticated industrial protocols.

Every field is observed. The previous version invented everything: a device
was "found" with random.random() < 0.3, and its type, open ports,
credentials, encryption, manufacturer, model and firmware were all
random.choice/randint, with CVE-2023-<random> ids attached to a fabricated
"outdated firmware" finding.

What this tool deliberately does NOT do: it does not attempt logins, so it
never claims default credentials are in use without evidence. An exposed
management interface is reported as an exposure; credential testing is left
to a tool run with explicit authorisation.
"""

import asyncio
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

from schemas import (
    IoTDevice,
    IoTSecurityScannerInput,
    IoTSecurityScannerOutput,
    IoTVulnerability,
    NetworkProtocolAnalysis,
)

logger = logging.getLogger(__name__)

# Port -> (service name, encrypted?). "encrypted" means the protocol provides
# transport security by default.
PORT_SERVICES: Dict[int, Tuple[str, bool]] = {
    21: ("FTP", False),
    22: ("SSH", True),
    23: ("Telnet", False),
    53: ("DNS", False),
    80: ("HTTP", False),
    81: ("HTTP-Alt", False),
    139: ("NetBIOS", False),
    443: ("HTTPS", True),
    445: ("SMB", False),
    502: ("Modbus", False),
    515: ("LPD", False),
    554: ("RTSP", False),
    631: ("IPP", False),
    993: ("IMAPS", True),
    995: ("POP3S", True),
    1883: ("MQTT", False),
    1911: ("Fox/Niagara", False),
    2404: ("IEC-104", False),
    4840: ("OPC-UA", False),
    5683: ("CoAP", False),
    8080: ("HTTP-Alt", False),
    8081: ("HTTP-Alt", False),
    8443: ("HTTPS-Alt", True),
    8883: ("MQTT-TLS", True),
    9100: ("JetDirect", False),
    9999: ("HTTP-Alt", False),
    20000: ("DNP3", False),
}

# Industrial/OT protocols with no authentication or encryption by design —
# exposing them on a reachable network is itself the finding.
UNAUTH_INDUSTRIAL = {502: "Modbus", 2404: "IEC-104", 4840: "OPC-UA", 20000: "DNP3", 1911: "Fox"}


class IoTSecurityScanner:
    """IoT Security Scanner — real discovery and configuration analysis."""

    name = "IoT Security Scanner"
    description = (
        "Discovers IoT devices by connecting to the ports their device classes "
        "listen on, grabs banners, and reports issues observable from the open "
        "services (plaintext management, missing encryption, exposed OT protocols)."
    )
    category = "iot_security"

    # Which open ports suggest which device class. Used to classify a device
    # from its real open-port set, not to invent one.
    DEVICE_FINGERPRINTS = {
        "camera": [554, 80, 81, 8080, 8081, 9999],
        "router": [22, 23, 53, 80, 443, 8080],
        "smart_home": [80, 443, 1883, 5683, 8883],
        "industrial": [102, 502, 1911, 2404, 4840, 20000],
        "printer": [515, 631, 9100],
        "nas": [21, 22, 80, 139, 443, 445, 993, 995],
    }

    def _candidate_ports(self, port_range: str) -> List[int]:
        """The known IoT service ports that fall inside the requested range."""
        known = sorted(PORT_SERVICES)
        try:
            low, _, high = port_range.partition("-")
            lo, hi = int(low), int(high or low)
        except ValueError:
            return known
        return [p for p in known if lo <= p <= hi]

    @staticmethod
    async def _is_open(ip: str, port: int, timeout: float) -> bool:
        """Real TCP connect: open only if the handshake completes."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    @staticmethod
    async def _grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
        """Read a service banner; for HTTP-ish ports send a minimal request."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        try:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                if data:
                    return data.decode("utf-8", "ignore").strip()
            except asyncio.TimeoutError:
                pass
            if port in (80, 81, 8080, 8081, 8000, 8888, 9999):
                writer.write(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=2)
                if resp:
                    return resp.decode("utf-8", "ignore").strip()
            return None
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _server_from_banner(banner: Optional[str]) -> Optional[str]:
        """Pull the HTTP Server header value from a banner, if present."""
        if not banner:
            return None
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip() or None
        return None

    def _classify_device(self, open_ports: List[int]) -> str:
        """Pick the device class whose fingerprint best matches the open ports."""
        best, best_overlap = "unknown", 0
        port_set = set(open_ports)
        for device_type, ports in self.DEVICE_FINGERPRINTS.items():
            overlap = len(port_set & set(ports))
            if overlap > best_overlap:
                best, best_overlap = device_type, overlap
        return best

    @staticmethod
    def _encryption_status(open_ports: List[int]) -> str:
        """Derive encryption posture from the real open ports."""
        services = [PORT_SERVICES.get(p) for p in open_ports]
        services = [s for s in services if s]
        if not services:
            return "Unknown"
        encrypted = sum(1 for _, enc in services if enc)
        plaintext = sum(1 for _, enc in services if not enc)
        if encrypted and not plaintext:
            return "Strong"
        if encrypted and plaintext:
            return "Weak"
        return "None"

    def _calculate_security_score(self, open_ports: List[int], encryption: str) -> float:
        """Deterministic posture score from observed facts (0-10)."""
        score = 10.0
        score -= min(len(open_ports) * 0.5, 4.0)          # attack surface
        for port in open_ports:
            svc = PORT_SERVICES.get(port)
            if svc and not svc[1] and port in (21, 23, 80, 554):
                score -= 1.0                                # plaintext management
            if port in UNAUTH_INDUSTRIAL:
                score -= 1.5                                # exposed OT protocol
        score -= {"None": 2.0, "Weak": 1.0}.get(encryption, 0.0)
        return round(max(score, 0.0), 1)

    async def _scan_device(
        self, ip: str, ports: List[int], timeout: float
    ) -> Optional[IoTDevice]:
        """Scan one host; return a device only if at least one port is open."""
        results = await asyncio.gather(*(self._is_open(ip, p, timeout) for p in ports))
        open_ports = [p for p, is_open in zip(ports, results) if is_open]
        if not open_ports:
            return None

        services = {p: PORT_SERVICES.get(p, (f"port-{p}", False))[0] for p in open_ports}

        # Banner-grab the first web-ish/plaintext port for a real Server hint.
        manufacturer = None
        for port in open_ports:
            if port in (80, 81, 8080, 8081, 443, 554, 23, 9999):
                server = self._server_from_banner(
                    await self._grab_banner(ip, port, timeout)
                )
                if server:
                    manufacturer = server
                    break

        encryption = self._encryption_status(open_ports)
        return IoTDevice(
            ip_address=ip,
            hostname=None,
            mac_address=None,          # not resolvable across an L3 hop
            device_type=self._classify_device(open_ports),
            manufacturer=manufacturer,
            model=None,
            firmware_version=None,     # not obtainable without device-specific probes
            open_ports=open_ports,
            services=services,
            web_interface=(
                f"http://{ip}/" if 80 in open_ports else
                (f"https://{ip}/" if 443 in open_ports else None)
            ),
            default_credentials=False,  # not tested — never claimed without evidence
            encryption_status=encryption,
            security_score=self._calculate_security_score(open_ports, encryption),
        )

    def _check_vulnerabilities(self, device: IoTDevice) -> List[IoTVulnerability]:
        """Findings that follow directly from the observed open services."""
        findings: List[IoTVulnerability] = []
        ip = device.ip_address

        plaintext_mgmt = {23: "Telnet", 21: "FTP", 80: "HTTP", 554: "RTSP"}
        for port, svc in plaintext_mgmt.items():
            if port in device.open_ports:
                findings.append(IoTVulnerability(
                    device_ip=ip,
                    severity="High" if port in (23, 21) else "Medium",
                    category="Cleartext Protocol",
                    title=f"{svc} exposed on port {port}",
                    description=(
                        f"{svc} transmits credentials and data without encryption; "
                        "anyone on the path can read or tamper with the session."
                    ),
                    port=port,
                    service=svc,
                    remediation=f"Disable {svc}; use an encrypted equivalent (SSH/HTTPS/SRTP).",
                ))

        for port, proto in UNAUTH_INDUSTRIAL.items():
            if port in device.open_ports:
                findings.append(IoTVulnerability(
                    device_ip=ip,
                    severity="Critical",
                    category="Exposed OT Protocol",
                    title=f"{proto} reachable on port {port}",
                    description=(
                        f"{proto} has no built-in authentication or encryption. "
                        "Exposing it on a reachable network allows unauthenticated "
                        "read/write to the device."
                    ),
                    port=port,
                    service=proto,
                    remediation=(
                        "Segment OT onto an isolated network; gateway access "
                        "through an authenticated proxy."
                    ),
                ))

        if 1883 in device.open_ports:
            has_tls = 8883 in device.open_ports
            findings.append(IoTVulnerability(
                device_ip=ip,
                severity="High",
                category="Cleartext Protocol",
                title="MQTT without TLS on port 1883",
                description=(
                    "Plaintext MQTT is reachable alongside the TLS port."
                    if has_tls else
                    "Plaintext MQTT exposes topic data and any credentials in "
                    "CONNECT packets; port 8883 (MQTT over TLS) was not observed."
                ),
                port=1883,
                service="MQTT",
                remediation="Require MQTT over TLS (8883) and disable 1883.",
            ))

        if device.encryption_status == "None" and device.open_ports:
            findings.append(IoTVulnerability(
                device_ip=ip,
                severity="High",
                category="Encryption",
                title="No encrypted service observed",
                description=(
                    "Every open service on this device uses a plaintext protocol; "
                    "no TLS-protected port was found."
                ),
                remediation="Expose management and data services over TLS only.",
            ))

        if device.web_interface:
            is_http = device.web_interface.startswith("http://")
            findings.append(IoTVulnerability(
                device_ip=ip,
                severity="Low",
                category="Exposure",
                title="Management web interface reachable",
                description=(
                    f"A web interface is exposed at {device.web_interface}. "
                    "Default credentials were NOT tested by this scan — verify "
                    "they have been changed."
                ),
                port=80 if is_http else 443,
                service="HTTP" if is_http else "HTTPS",
                remediation="Restrict access; confirm default credentials are changed.",
            ))

        return findings

    def _analyze_protocols(self, devices: List[IoTDevice]) -> List[NetworkProtocolAnalysis]:
        """Per-observed-port protocol facts (real protocol-level truths)."""
        seen: Dict[Tuple[str, int], NetworkProtocolAnalysis] = {}
        for device in devices:
            for port in device.open_ports:
                name, encrypted = PORT_SERVICES.get(port, (f"port-{port}", False))
                key = (name, port)
                if key in seen:
                    continue
                authed = port in (22, 443, 993, 995, 8443, 8883)
                vulns: List[str] = []
                recs: List[str] = []
                if not encrypted:
                    vulns.append("No transport encryption")
                    recs.append("Move to a TLS-protected equivalent")
                if port in UNAUTH_INDUSTRIAL:
                    vulns.append("Protocol has no built-in authentication")
                    recs.append("Gateway behind an authenticated proxy; isolate the segment")
                if port == 23:
                    vulns.append("Telnet is deprecated and cleartext")
                    recs.append("Replace with SSH")
                seen[key] = NetworkProtocolAnalysis(
                    protocol=name, port=port, encryption=encrypted,
                    authentication=authed, vulnerabilities=vulns, recommendations=recs,
                )
        return list(seen.values())

    def _expand_targets(self, input_data: IoTSecurityScannerInput) -> List[str]:
        """Resolve the target(s) to a concrete, bounded list of IPs."""
        if input_data.target_ip:
            return [input_data.target_ip.strip()]
        if input_data.ip_range:
            network = ipaddress.ip_network(input_data.ip_range.strip(), strict=False)
            # Bound the sweep so a huge range cannot be requested by accident.
            return [str(h) for h in network.hosts()][:256]
        return []

    async def execute(self, input_data: IoTSecurityScannerInput) -> IoTSecurityScannerOutput:
        empty = dict(
            devices_found=[], vulnerabilities=[], network_protocols=[],
            scan_summary={}, total_devices=0, critical_vulnerabilities=0,
            recommendations=[],
        )

        try:
            targets = self._expand_targets(input_data)
        except ValueError as exc:
            return IoTSecurityScannerOutput(**empty, success=False, summary=f"Invalid target: {exc}")
        if not targets:
            return IoTSecurityScannerOutput(
                **empty, success=False, summary="Provide either target_ip or ip_range."
            )

        ports = self._candidate_ports(input_data.port_scan_range)
        per_conn = max(0.5, min(3.0, input_data.timeout / max(len(targets), 1)))
        semaphore = asyncio.Semaphore(32)

        async def scan(ip):
            async with semaphore:
                return await self._scan_device(ip, ports, per_conn)

        devices = [d for d in await asyncio.gather(*(scan(ip) for ip in targets)) if d]

        vulnerabilities: List[IoTVulnerability] = []
        for device in devices:
            vulnerabilities.extend(self._check_vulnerabilities(device))

        protocols = self._analyze_protocols(devices)
        critical = sum(1 for v in vulnerabilities if v.severity == "Critical")

        summary = {
            "hosts_scanned": len(targets),
            "devices_found": len(devices),
            "ports_probed_per_host": len(ports),
            "device_types": sorted({d.device_type for d in devices}),
            "severity_breakdown": {
                sev: sum(1 for v in vulnerabilities if v.severity == sev)
                for sev in ("Critical", "High", "Medium", "Low")
            },
            "note": (
                "MAC address, firmware version and default-credential status are "
                "not reported: they are not obtainable by an unauthenticated "
                "network scan and are left unset rather than guessed."
            ),
        }

        recommendations: List[str] = []
        if any(23 in d.open_ports or 21 in d.open_ports for d in devices):
            recommendations.append("Disable Telnet/FTP on all devices; use SSH and SFTP.")
        if any(d.encryption_status == "None" for d in devices):
            recommendations.append("Put every management and data service behind TLS.")
        if any(p in UNAUTH_INDUSTRIAL for d in devices for p in d.open_ports):
            recommendations.append("Isolate OT protocols on a segmented, gatewayed network.")
        if not recommendations and devices:
            recommendations.append("No cleartext or exposed-OT issues observed on the open ports.")
        if not devices:
            recommendations.append("No devices with open IoT ports were found in range.")

        return IoTSecurityScannerOutput(
            devices_found=devices,
            vulnerabilities=vulnerabilities,
            network_protocols=protocols,
            scan_summary=summary,
            total_devices=len(devices),
            critical_vulnerabilities=critical,
            recommendations=recommendations,
            success=True,
            summary=(
                f"Scanned {len(targets)} host(s): {len(devices)} device(s) with "
                f"open IoT ports, {len(vulnerabilities)} finding(s)."
            ),
        )


async def execute_tool(params: IoTSecurityScannerInput) -> IoTSecurityScannerOutput:
    """Main entry point for the IoT Security Scanner tool."""
    return await IoTSecurityScanner().execute(params)


TOOL_INFO = {
    "name": "IoT Security Scanner",
    "description": (
        "Discovers IoT/OT devices by really connecting to the ports their "
        "device classes use, grabs banners, and reports issues observable from "
        "the open services: cleartext management (Telnet/FTP/HTTP/RTSP), missing "
        "TLS, and exposed unauthenticated OT protocols (Modbus/DNP3/OPC-UA). "
        "Does not attempt logins, so it never claims default credentials without "
        "evidence."
    ),
    "category": "iot_security",
    "version": "2.0.0",
    "author": "Wildbox Security",
    "input_schema": IoTSecurityScannerInput,
    "output_schema": IoTSecurityScannerOutput,
    "tool_class": IoTSecurityScanner,
}
