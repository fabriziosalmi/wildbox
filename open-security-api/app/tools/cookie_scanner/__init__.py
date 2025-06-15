"""
Cookie Security Scanner Tool

Analyzes HTTP cookies for security misconfigurations and vulnerabilities.
"""

from .main import execute_tool
from .schemas import CookieScannerInput, CookieScannerOutput

__all__ = ["execute_tool", "CookieScannerInput", "CookieScannerOutput"]
