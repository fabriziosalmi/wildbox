"""DNS Security Checker Tool"""

from .main import execute_tool
from .schemas import DNSSecurityInput, DNSSecurityOutput

__all__ = ['execute_tool', 'DNSSecurityInput', 'DNSSecurityOutput']
