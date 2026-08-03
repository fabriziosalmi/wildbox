"""
Container Security Scanner

A wrapper around Trivy (https://trivy.dev): it runs the real scanner against a
container image or a Dockerfile and maps Trivy's JSON output onto this tool's
schema. Vulnerabilities, exposed secrets and misconfigurations are whatever
Trivy actually found.

The previous version invented everything: it picked N =
random.randint(5, 15) vulnerabilities with random.choice from a hardcoded
SAMPLE_VULNERABILITIES list, made up package versions with random.randint,
and had a 40% (random.random() < 0.4) chance of "finding secrets" in paths
that do not exist. It never looked at the image.

If Trivy is not installed, or the image cannot be pulled/scanned, the tool
returns success=False with the real error — it never falls back to
fabricated results.
"""

import asyncio
import json
import os
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from schemas import (
    ComplianceCheck,
    ConfigurationIssue,
    ContainerSecurityScannerInput,
    ContainerSecurityScannerOutput,
    SecretExposure,
    Vulnerability,
)

# Trivy is the scan engine. grype could be a drop-in alternative, but only
# trivy is wired up here.
TRIVY_BIN = os.getenv("TRIVY_BIN", "trivy")
SCAN_TIMEOUT = 600  # trivy may need to pull the image and update its DB


class TrivyNotAvailable(RuntimeError):
    """Raised when the trivy binary is not on PATH."""


class TrivyScanError(RuntimeError):
    """Raised when trivy runs but fails (bad image, pull failure, ...)."""


class ContainerSecurityScanner:
    """Container security scanner backed by Trivy."""

    name = "Container Security Scanner"
    description = (
        "Scans a container image or Dockerfile for vulnerabilities, exposed "
        "secrets and misconfigurations using Trivy. Reports exactly what Trivy "
        "finds; requires the trivy binary to be installed."
    )
    category = "container_security"

    # ---- running trivy -------------------------------------------------

    @staticmethod
    def _trivy_path() -> str:
        path = shutil.which(TRIVY_BIN)
        if not path:
            raise TrivyNotAvailable(
                "The 'trivy' binary is not installed or not on PATH. Install it "
                "from https://trivy.dev to scan container images."
            )
        return path

    async def _run_trivy(self, args: List[str]) -> Dict[str, Any]:
        """Run trivy with JSON output and return the parsed document."""
        trivy = self._trivy_path()
        cmd = [trivy, "--quiet", "--format", "json", *args]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            raise TrivyScanError(f"trivy timed out after {SCAN_TIMEOUT}s")

        if proc.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip().splitlines()
            last = detail[-1] if detail else "unknown error"
            raise TrivyScanError(f"trivy exited {proc.returncode}: {last}")

        try:
            return json.loads(stdout or b"{}")
        except ValueError as exc:
            raise TrivyScanError(f"could not parse trivy output: {exc}")

    # ---- mapping trivy JSON onto the tool schema -----------------------

    @staticmethod
    def _cvss(vuln: Dict[str, Any]) -> Tuple[float, Optional[str]]:
        """Best available CVSS base score and vector from trivy's CVSS map.

        Prefers NVD, then any other source. Missing -> (0.0, None) rather than
        a fabricated score.
        """
        cvss = vuln.get("CVSS") or {}
        for source in ("nvd", *[s for s in cvss if s != "nvd"]):
            data = cvss.get(source)
            if not data:
                continue
            score = data.get("V3Score") or data.get("V2Score")
            vector = data.get("V3Vector") or data.get("V2Vector")
            if score is not None:
                return float(score), vector
        return 0.0, None

    def _map_vulnerabilities(self, results: List[Dict[str, Any]]) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for result in results:
            for v in result.get("Vulnerabilities") or []:
                score, vector = self._cvss(v)
                out.append(Vulnerability(
                    cve_id=v.get("VulnerabilityID", "UNKNOWN"),
                    severity=(v.get("Severity") or "UNKNOWN").capitalize(),
                    package=v.get("PkgName", "unknown"),
                    version=v.get("InstalledVersion", "unknown"),
                    fixed_version=v.get("FixedVersion") or None,
                    description=(v.get("Title") or v.get("Description") or "").strip(),
                    score=score,
                    vector=vector,
                ))
        return out

    @staticmethod
    def _map_secrets(results: List[Dict[str, Any]]) -> List[SecretExposure]:
        out: List[SecretExposure] = []
        for result in results:
            target = result.get("Target", "")
            for s in result.get("Secrets") or []:
                start = s.get("StartLine")
                location = f"{target}:{start}" if start else target
                out.append(SecretExposure(
                    type=s.get("Category") or s.get("RuleID") or "secret",
                    location=location,
                    pattern_matched=s.get("Title") or s.get("RuleID") or "",
                    # Trivy secret matches are rule-based, not probabilistic; a
                    # match is a match. Report full confidence rather than a
                    # random float.
                    confidence=1.0,
                    recommendation=(
                        "Remove the secret from the image and rotate it; inject "
                        "secrets at runtime instead of baking them into layers."
                    ),
                ))
        return out

    @staticmethod
    def _map_misconfigurations(
        results: List[Dict[str, Any]],
    ) -> Tuple[List[ConfigurationIssue], List[ComplianceCheck]]:
        config_issues: List[ConfigurationIssue] = []
        compliance: List[ComplianceCheck] = []
        for result in results:
            target = result.get("Target", "")
            for m in result.get("Misconfigurations") or []:
                status = m.get("Status", "")
                severity = (m.get("Severity") or "UNKNOWN").capitalize()
                passed = status == "PASS"
                config_issues.append(ConfigurationIssue(
                    issue_type=m.get("Type") or m.get("ID") or "misconfiguration",
                    severity=severity,
                    description=(m.get("Title") or m.get("Description") or "").strip(),
                    file_location=target or None,
                    recommendation=(m.get("Resolution") or "").strip() or "See the referenced policy.",
                    compliant=passed,
                ))
                compliance.append(ComplianceCheck(
                    standard=m.get("Type") or "Trivy policy",
                    rule_id=m.get("ID") or m.get("AVDID") or "unknown",
                    rule_description=(m.get("Title") or "").strip(),
                    status="Pass" if passed else ("Warning" if status == "WARN" else "Fail"),
                    severity=severity,
                    recommendation=(m.get("Resolution") or "").strip() or "See the referenced policy.",
                ))
        return config_issues, compliance

    # ---- scoring / summary --------------------------------------------

    @staticmethod
    def _count_by_severity(vulns: List[Vulnerability]) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    @staticmethod
    def _security_score(
        vulns: List[Vulnerability],
        secrets: List[SecretExposure],
        config_issues: List[ConfigurationIssue],
    ) -> float:
        """Deterministic 0-10 score weighted by real finding severity."""
        penalty = 0.0
        weights = {"Critical": 3.0, "High": 1.5, "Medium": 0.5, "Low": 0.1}
        for v in vulns:
            penalty += weights.get(v.severity, 0.1)
        penalty += 3.0 * len(secrets)                      # a baked-in secret is severe
        penalty += sum(
            weights.get(c.severity, 0.1) for c in config_issues if not c.compliant
        )
        return round(max(10.0 - penalty, 0.0), 1)

    def _recommendations(
        self,
        counts: Dict[str, int],
        secrets: List[SecretExposure],
        config_issues: List[ConfigurationIssue],
    ) -> List[str]:
        recs: List[str] = []
        if counts.get("Critical") or counts.get("High"):
            recs.append(
                f"Patch {counts.get('Critical', 0)} critical and "
                f"{counts.get('High', 0)} high-severity package vulnerabilities; "
                "rebuild on an updated base image."
            )
        if secrets:
            recs.append(f"Remove and rotate {len(secrets)} secret(s) baked into the image.")
        failed = [c for c in config_issues if not c.compliant]
        if failed:
            recs.append(f"Resolve {len(failed)} failing security misconfiguration(s).")
        if not recs:
            recs.append("No vulnerabilities, secrets or misconfigurations were reported by Trivy.")
        return recs

    # ---- entry point ---------------------------------------------------

    def _failure(self, image: str, message: str) -> ContainerSecurityScannerOutput:
        return ContainerSecurityScannerOutput(
            image_analyzed=image,
            scan_timestamp=datetime.now(),
            total_vulnerabilities=0,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            medium_vulnerabilities=0,
            low_vulnerabilities=0,
            vulnerabilities=[],
            secrets_found=[],
            configuration_issues=[],
            layer_analysis=[],
            compliance_results=[],
            security_score=0.0,
            recommendations=[message],
            scan_summary={"error": message},
            success=False,
            summary=message,
        )

    async def execute(
        self, input_data: ContainerSecurityScannerInput
    ) -> ContainerSecurityScannerOutput:
        # Build the trivy invocation from the input. A Dockerfile is scanned
        # with `trivy config` (misconfig only, no image pull needed); an image
        # (or a running container's image) with `trivy image`.
        scanners: List[str] = []
        if input_data.check_vulnerabilities:
            scanners.append("vuln")
        if input_data.check_secrets:
            scanners.append("secret")
        if input_data.check_configuration or input_data.check_compliance:
            scanners.append("misconfig")
        scanners = scanners or ["vuln"]

        dockerfile_path = None
        try:
            if input_data.dockerfile_content:
                import tempfile

                tmpdir = tempfile.mkdtemp(prefix="wildbox-trivy-")
                dockerfile_path = os.path.join(tmpdir, "Dockerfile")
                with open(dockerfile_path, "w") as fh:
                    fh.write(input_data.dockerfile_content)
                target_label = "Dockerfile"
                args = ["config", tmpdir]
            elif input_data.image_name:
                target_label = input_data.image_name
                args = ["image", "--scanners", ",".join(scanners), input_data.image_name]
            else:
                return self._failure(
                    "unknown",
                    "Provide an image_name or dockerfile_content to scan.",
                )

            try:
                document = await self._run_trivy(args)
            except TrivyNotAvailable as exc:
                return self._failure(target_label, str(exc))
            except TrivyScanError as exc:
                return self._failure(target_label, f"Trivy scan failed: {exc}")
        finally:
            if dockerfile_path:
                try:
                    os.remove(dockerfile_path)
                    os.rmdir(os.path.dirname(dockerfile_path))
                except OSError:
                    pass

        results = document.get("Results") or []
        vulnerabilities = self._map_vulnerabilities(results)
        secrets = self._map_secrets(results)
        config_issues, compliance = self._map_misconfigurations(results)
        counts = self._count_by_severity(vulnerabilities)

        summary = {
            "scanner": "trivy",
            "artifact": document.get("ArtifactName", target_label),
            "artifact_type": document.get("ArtifactType"),
            "results_analyzed": len(results),
            "severity_breakdown": counts,
            "secrets_found": len(secrets),
            "misconfigurations": len(config_issues),
            "note": (
                "Layer-by-layer analysis is not reported: trivy's default image "
                "scan does not attribute findings to individual layers here."
            ),
        }

        return ContainerSecurityScannerOutput(
            image_analyzed=document.get("ArtifactName", target_label),
            scan_timestamp=datetime.now(),
            total_vulnerabilities=len(vulnerabilities),
            critical_vulnerabilities=counts.get("Critical", 0),
            high_vulnerabilities=counts.get("High", 0),
            medium_vulnerabilities=counts.get("Medium", 0),
            low_vulnerabilities=counts.get("Low", 0),
            vulnerabilities=vulnerabilities,
            secrets_found=secrets,
            configuration_issues=config_issues,
            layer_analysis=[],   # not attributed per-layer by this scan
            compliance_results=compliance,
            security_score=self._security_score(vulnerabilities, secrets, config_issues),
            recommendations=self._recommendations(counts, secrets, config_issues),
            scan_summary=summary,
            success=True,
            summary=(
                f"Trivy scanned {document.get('ArtifactName', target_label)}: "
                f"{len(vulnerabilities)} vulnerabilities, {len(secrets)} secrets, "
                f"{len(config_issues)} misconfigurations."
            ),
        )


async def execute_tool(
    params: ContainerSecurityScannerInput,
) -> ContainerSecurityScannerOutput:
    """Main entry point for the Container Security Scanner tool."""
    return await ContainerSecurityScanner().execute(params)


TOOL_INFO = {
    "name": "Container Security Scanner",
    "description": (
        "Scans a container image or Dockerfile for vulnerabilities, exposed "
        "secrets and misconfigurations using Trivy, and reports exactly what "
        "Trivy finds. Requires the trivy binary; returns an honest error when "
        "it is not installed or the image cannot be pulled."
    ),
    "category": "container_security",
    "version": "2.0.0",
    "author": "Wildbox Security",
    "input_schema": ContainerSecurityScannerInput,
    "output_schema": ContainerSecurityScannerOutput,
    "tool_class": ContainerSecurityScanner,
}
