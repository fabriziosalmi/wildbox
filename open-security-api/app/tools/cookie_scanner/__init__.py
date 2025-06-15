"""
Cookie Security Scanner Tool

Analyzes HTTP cookies for security misconfigurations and vulnerabilities.
"""

from .main import execute_tool, TOOL_INFO
from .schemas import CookieScannerInput, CookieScannerOutput

__all__ = ["execute_tool", "TOOL_INFO", "CookieScannerInput", "CookieScannerOutput"]
