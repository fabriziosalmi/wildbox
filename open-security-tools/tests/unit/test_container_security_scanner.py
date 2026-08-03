"""Unit tests for the Container Security Scanner (Trivy wrapper).

The tool shells out to trivy; these tests stub _run_trivy with captured real
trivy JSON, so they run offline. The suite locks in that findings come from
trivy's output — the previous version invented N = random.randint(5, 15)
vulnerabilities from a hardcoded sample list and had a random.random() < 0.4
chance of "finding secrets" — and that a missing binary or a failed scan is
reported honestly instead of fabricated.
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "container_security_scanner"

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


_std = _load("container_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load("container_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std})
csc = _load("container_main", TOOL_DIR / "main.py", {"schemas": _schemas})


# A real trivy `image` JSON document (shape and values as captured from
# `trivy image --format json alpine:3.10`).
TRIVY_IMAGE_DOC = {
    "ArtifactName": "alpine:3.10",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "alpine:3.10 (alpine 3.10.9)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-36159",
                    "PkgName": "apk-tools",
                    "InstalledVersion": "2.10.6-r0",
                    "FixedVersion": "2.10.7-r0",
                    "Severity": "CRITICAL",
                    "Title": "libfetch: out-of-bounds read in apk-tools",
                    "CVSS": {
                        "nvd": {
                            "V3Score": 9.1,
                            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                        }
                    },
                },
                {
                    "VulnerabilityID": "CVE-2020-28928",
                    "PkgName": "musl",
                    "InstalledVersion": "1.1.22-r3",
                    "FixedVersion": "1.1.22-r4",
                    "Severity": "MEDIUM",
                    "Title": "musl libc issue",
                    "CVSS": {"nvd": {"V3Score": 5.5}},
                },
            ],
        }
    ],
}

# A real trivy `config` JSON document (from `trivy config` on a Dockerfile).
TRIVY_CONFIG_DOC = {
    "ArtifactName": "Dockerfile",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "ID": "DS-0002",
                    "Type": "Dockerfile Security Check",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                },
                {
                    "ID": "DS-0001",
                    "Type": "Dockerfile Security Check",
                    "Title": "':latest' tag used",
                    "Severity": "MEDIUM",
                    "Status": "PASS",
                    "Resolution": "Pin the base image to a specific tag",
                },
            ],
        }
    ],
}


def _stub_trivy(monkeypatch, document):
    async def fake_run(self, args):
        return document

    monkeypatch.setattr(csc.ContainerSecurityScanner, "_run_trivy", fake_run)
    # Pretend trivy is installed so the path check passes.
    monkeypatch.setattr(csc.ContainerSecurityScanner, "_trivy_path", staticmethod(lambda: "/usr/bin/trivy"))


def run(**overrides):
    params = dict(image_name="alpine:3.10")
    params.update(overrides)
    return asyncio.run(csc.execute_tool(_schemas.ContainerSecurityScannerInput(**params)))


class TestVulnerabilityMapping:
    def test_maps_trivy_vulnerabilities_verbatim(self, monkeypatch):
        _stub_trivy(monkeypatch, TRIVY_IMAGE_DOC)
        out = run()
        assert out.success is True
        assert out.total_vulnerabilities == 2
        assert out.critical_vulnerabilities == 1
        crit = next(v for v in out.vulnerabilities if v.severity == "Critical")
        assert crit.cve_id == "CVE-2021-36159"
        assert crit.package == "apk-tools"
        assert crit.version == "2.10.6-r0"
        assert crit.fixed_version == "2.10.7-r0"
        assert crit.score == 9.1                       # real CVSS, not fabricated
        assert crit.vector.startswith("CVSS:3.1/")

    def test_missing_cvss_is_zero_not_invented(self, monkeypatch):
        doc = {
            "ArtifactName": "x",
            "Results": [{"Vulnerabilities": [{
                "VulnerabilityID": "CVE-9999-0001", "PkgName": "p",
                "InstalledVersion": "1", "Severity": "LOW", "Title": "t",
            }]}],
        }
        _stub_trivy(monkeypatch, doc)
        v = run().vulnerabilities[0]
        assert v.score == 0.0
        assert v.vector is None

    def test_severity_counts_are_real(self, monkeypatch):
        _stub_trivy(monkeypatch, TRIVY_IMAGE_DOC)
        out = run()
        assert out.medium_vulnerabilities == 1
        assert out.scan_summary["severity_breakdown"]["Critical"] == 1


class TestMisconfigurationMapping:
    def test_maps_failing_and_passing_checks(self, monkeypatch):
        _stub_trivy(monkeypatch, TRIVY_CONFIG_DOC)
        out = run(dockerfile_content="FROM alpine\nUSER root\n")
        assert out.success is True
        # Two misconfigs: one FAIL (not compliant), one PASS (compliant).
        by_id = {c.rule_id: c for c in out.compliance_results}
        assert by_id["DS-0002"].status == "Fail"
        assert by_id["DS-0001"].status == "Pass"
        failing = [c for c in out.configuration_issues if not c.compliant]
        assert len(failing) == 1
        assert failing[0].issue_type == "Dockerfile Security Check"


class TestHonestDegradation:
    def test_missing_trivy_is_reported_not_faked(self, monkeypatch):
        def boom():
            raise csc.TrivyNotAvailable("trivy not installed")

        monkeypatch.setattr(csc.ContainerSecurityScanner, "_trivy_path", staticmethod(boom))
        out = run()
        assert out.success is False
        assert out.total_vulnerabilities == 0
        assert out.vulnerabilities == []
        assert "trivy" in out.summary.lower()

    def test_scan_error_is_reported_not_faked(self, monkeypatch):
        async def fail(self, args):
            raise csc.TrivyScanError("image not found")

        monkeypatch.setattr(csc.ContainerSecurityScanner, "_trivy_path", staticmethod(lambda: "/usr/bin/trivy"))
        monkeypatch.setattr(csc.ContainerSecurityScanner, "_run_trivy", fail)
        out = run(image_name="nonexistent:tag")
        assert out.success is False
        assert "image not found" in out.summary

    def test_no_target_is_rejected(self):
        out = asyncio.run(csc.execute_tool(_schemas.ContainerSecurityScannerInput()))
        assert out.success is False
        assert "image_name or dockerfile_content" in out.summary


class TestScoring:
    def test_critical_vulnerabilities_lower_the_score(self, monkeypatch):
        _stub_trivy(monkeypatch, TRIVY_IMAGE_DOC)
        with_vulns = run().security_score
        _stub_trivy(monkeypatch, {"ArtifactName": "clean", "Results": []})
        clean = run().security_score
        assert clean == 10.0
        assert with_vulns < clean
