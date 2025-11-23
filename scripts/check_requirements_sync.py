#!/usr/bin/env python3
"""
Check if requirements.txt is in sync with requirements.in
Used by pre-commit hook to prevent outdated lockfiles
"""
import sys
import subprocess
from pathlib import Path

def check_requirements_sync():
    """Check all services have synced requirements"""
    services = [
        "open-security-identity",
        "open-security-tools",
        "open-security-data",
        "open-security-guardian",
        "open-security-responder",
        "open-security-cspm",
        "open-security-agents",
    ]
    
    errors = []
    
    for service in services:
        service_path = Path(service)
        req_in = service_path / "requirements.in"
        req_txt = service_path / "requirements.txt"
        
        if not req_in.exists():
            continue  # Skip if not using pip-tools yet
        
        if not req_txt.exists():
            errors.append(f"{service}: requirements.txt missing (run: pip-compile --generate-hashes)")
            continue
        
        # Check if .in is newer than .txt
        if req_in.stat().st_mtime > req_txt.stat().st_mtime:
            errors.append(
                f"{service}: requirements.in is newer than requirements.txt\n"
                f"  Run: cd {service} && pip-compile --generate-hashes requirements.in"
            )
    
    if errors:
        print("❌ Requirements files out of sync:\n")
        for error in errors:
            print(f"  {error}")
        print("\nFix by running pip-compile in the affected services.")
        return 1
    
    print("✅ All requirements files in sync")
    return 0

if __name__ == "__main__":
    sys.exit(check_requirements_sync())
