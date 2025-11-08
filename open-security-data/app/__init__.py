"""
Open Security Data - Main Application Package

A comprehensive security data lake platform for collecting, processing,
and serving threat intelligence from public sources.
"""

__version__ = "0.1.5"
__author__ = "Wildbox Security"
__email__ = "security@wildbox.dev"
__description__ = "Security Data Lake Platform"

# Application metadata
APP_NAME = "open-security-data"
APP_VERSION = __version__
APP_DESCRIPTION = __description__

# Supported data types
SUPPORTED_INDICATORS = [
    "ip_address",
    "domain",
    "url", 
    "file_hash",
    "email",
    "certificate",
    "asn",
    "vulnerability"
]

# Data categories
DATA_CATEGORIES = [
    "malware",
    "phishing", 
    "spam",
    "botnet",
    "exploit",
    "vulnerability",
    "certificate",
    "dns",
    "network_scan"
]
