"""Tests for check_sbom_licences.py, the gate that keeps copyleft out of an MIT platform.

The case that brought these into being: on 2026-09-10 `Test Suite` was red on main
because the gate reported

    ERROR: no licence data in the SBOM(s). A filesystem scan records component
    names without licences; scan the built image instead.

on an SBOM that had 82 components and a licence for 81 of them, produced by an image
scan exactly as the message asked for. The gateway is OpenResty on Alpine, so it has
no language packages at all, and the gate asserted the one cause that was not true.

A gate that inspects nothing must say so. It must also say WHICH nothing.
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_sbom_licences.py"

APK = {"name": "aom-libs", "version": "3.9.0", "type": "library",
       "licenses": [{"license": {"id": "BSD-2-Clause"}}],
       "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "alpine"}]}


def pkg(name, licence, pkgtype="python-pkg"):
    c = {"name": name, "version": "1.0", "type": "library"}
    if licence:
        c["licenses"] = [{"license": {"id": licence}}]
    if pkgtype:
        c["properties"] = [{"name": "aquasecurity:trivy:PkgType", "value": pkgtype}]
    return c


def run(tmp_path, components, *args):
    p = tmp_path / "sbom.cdx.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))
    r = subprocess.run([sys.executable, str(SCRIPT), str(p), *args],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def test_os_only_image_passes_and_says_why(tmp_path):
    """OpenResty on Alpine: 81 apk packages, nothing of ours linked in."""
    rc, out = run(tmp_path, [APK] * 81)
    assert rc == 0
    assert "No language packages" in out
    assert "81 with a licence" in out
    assert "filesystem scan" not in out          # the wrong cause, previously asserted here


def test_a_filesystem_scan_is_still_rejected(tmp_path):
    """Components without licences is the symptom the old message described, and
    it must keep failing: that SBOM cannot support a licence decision."""
    rc, out = run(tmp_path, [pkg("requests", None), pkg("flask", None)])
    assert rc == 2
    assert "a licence for none of them" in out
    assert "scan the built image instead" in out


def test_an_empty_sbom_is_rejected_with_its_own_reason(tmp_path):
    rc, out = run(tmp_path, [])
    assert rc == 2
    assert "no components at all" in out


def test_copyleft_in_a_language_package_still_fails(tmp_path):
    """The point of the whole gate. An OS-only pass must not have blunted it."""
    rc, out = run(tmp_path, [APK, pkg("some-lib", "GPL-3.0-only")])
    assert rc == 1
    assert "Copyleft licences found" in out
    assert "some-lib" in out


def test_copyleft_in_the_base_image_is_ignored_by_default(tmp_path):
    """Alpine is GPL by nature and is not linked into our code."""
    gpl_apk = dict(APK, name="alpine-baselayout",
                   licenses=[{"license": {"id": "GPL-2.0-only"}}])
    rc, out = run(tmp_path, [gpl_apk])
    assert rc == 0
    assert "No language packages" in out


def test_include_os_gates_the_base_image_too(tmp_path):
    gpl_apk = dict(APK, name="alpine-baselayout",
                   licenses=[{"license": {"id": "GPL-2.0-only"}}])
    rc, out = run(tmp_path, [gpl_apk], "--include-os")
    assert rc == 1
    assert "alpine-baselayout" in out


def test_permissive_language_package_passes(tmp_path):
    rc, out = run(tmp_path, [pkg("requests", "Apache-2.0")])
    assert rc == 0
    assert "No copyleft licences found" in out
