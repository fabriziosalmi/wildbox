#!/usr/bin/env python3
"""Fail when a copyleft dependency reaches an MIT-licensed service.

The CI step that was supposed to do this printed a sentence and exited 0:

    python -m pip install --quiet pip-licenses
    echo "Licence inventory recorded in the SBOM artefact above."

pip-licenses inspects *installed* packages, and nothing was installed at that
point in the job, so there was nothing it could have reported even if it had
been invoked. This reads the CycloneDX SBOM the previous step already produces,
which carries the licence of every component.

Scope it to application dependencies. A CycloneDX SBOM of a container image
also lists the base OS packages -- busybox, coreutils, the Alpine toolchain --
which are GPL and always will be. They are separate programs the image ships,
not code linked into ours, so counting them makes the check fire on every image
and it gets switched off. Only language packages (pip, npm, go) are gated.

Usage:
    python scripts/check_sbom_licences.py sbom-tools.cdx.json [...]
    python scripts/check_sbom_licences.py --list sbom-tools.cdx.json
    python scripts/check_sbom_licences.py --include-os sbom-tools.cdx.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict

# Licences that impose source-disclosure obligations incompatible with shipping
# this platform under MIT. AGPL is the one that matters most for a networked
# service: it reaches across the network boundary.
DENY = (
    "AGPL",
    "GPL-2.0",
    "GPL-3.0",
    "GPLv2",
    "GPLv3",
    "SSPL",
    "OSL",
    "EUPL",
    "CC-BY-NC",
    "Commons-Clause",
)
# LGPL is dynamically linked here and does not trigger disclosure of our source;
# "GNU General Public License" substrings inside an LGPL name must not match.
ALLOW_SUBSTRINGS = ("LGPL", "GPL-2.0-with", "GPL-3.0-with", "Classpath")


# Trivy records the ecosystem in this property. Language ecosystems are the ones
# whose code is imported into ours; everything else is an OS package.
_PKGTYPE_PROPERTY = "aquasecurity:trivy:PkgType"
_LANGUAGE_PKGTYPES = {
    "python-pkg",
    "pip",
    "poetry",
    "uv",
    "node-pkg",
    "npm",
    "yarn",
    "pnpm",
    "gobinary",
    "gomod",
    "cargo",
    "gem",
    "composer",
    "jar",
    "pom",
    "gradle",
}


def is_language_package(component: dict) -> bool:
    for prop in component.get("properties", []) or []:
        if prop.get("name") == _PKGTYPE_PROPERTY:
            return prop.get("value") in _LANGUAGE_PKGTYPES
    # No PkgType at all: a filesystem SBOM, where every component is ours.
    return True


def licences_of(component: dict) -> list[str]:
    out = []
    for entry in component.get("licenses", []) or []:
        lic = entry.get("license") or {}
        name = lic.get("id") or lic.get("name") or entry.get("expression")
        if name:
            out.append(str(name))
    return out


def is_denied(name: str) -> bool:
    if any(a.lower() in name.lower() for a in ALLOW_SUBSTRINGS):
        return False
    return any(re.search(re.escape(d), name, re.IGNORECASE) for d in DENY)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sboms", nargs="+")
    ap.add_argument(
        "--list", action="store_true", help="print the inventory and exit 0"
    )
    ap.add_argument(
        "--include-os",
        action="store_true",
        help="also gate base-image OS packages (they are GPL by nature; off by default)",
    )
    args = ap.parse_args()

    violations = []
    inventory: dict[str, set] = defaultdict(set)

    for path in args.sboms:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        skipped_os = 0
        for comp in doc.get("components", []) or []:
            if not args.include_os and not is_language_package(comp):
                skipped_os += 1
                continue
            name = comp.get("name", "?")
            version = comp.get("version", "?")
            for lic in licences_of(comp):
                inventory[lic].add(f"{name}=={version}")
                if is_denied(lic):
                    violations.append((path, name, version, lic))

    if args.list:
        for lic in sorted(inventory):
            print(f"{lic}: {len(inventory[lic])} component(s)")
        return 0

    if violations:
        print("Copyleft licences found in the dependency tree:", file=sys.stderr)
        for path, name, version, lic in violations:
            print(f"  {path}: {name}=={version} is {lic}", file=sys.stderr)
        print(
            "\nThis platform ships under MIT. Replace the dependency, or record "
            "an explicit exception in scripts/check_sbom_licences.py.",
            file=sys.stderr,
        )
        return 1

    total = sum(len(v) for v in inventory.values())
    if total == 0:
        # A gate that inspects nothing passes for the wrong reason. Say so.
        print(
            "ERROR: no licence data in the SBOM(s). A filesystem scan records "
            "component names without licences; scan the built image instead.",
            file=sys.stderr,
        )
        return 2
    print(f"No copyleft licences found ({total} component licences checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
