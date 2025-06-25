"""
System connector for Open Security Responder

Provides basic system operations like logging, validation, and utility functions.
"""

import time
import re
import json
import logging
from typing import Dict, Any
from datetime import datetime
from urllib.parse import urlparse
import ipaddress

from .base import BaseConnector, ConnectorError


class SystemConnector(BaseConnector):
    """Connector for system operations and utilities"""
    
    def __init__(self):
        super().__init__("system")
        self.logger.info("Initialized System connector")
    
    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the System connector"""
        return {
            "log": "Log a message",
            "sleep": "Wait for a specified number of seconds",
            "validate": "Validate input data (IP, URL, etc.)",
            "extract": "Extract data from input (domain from URL, etc.)",
            "evaluate": "Evaluate conditions and expressions",
            "create_report": "Generate a structured report",
            "notification": "Send notifications (placeholder)",
            "timestamp": "Get current timestamp",
            "uuid": "Generate a UUID"
        }
    
    def log(self, message: str, level: str = "info") -> Dict[str, Any]:
        """
        Log a message
        
        Args:
            message: Message to log
            level: Log level (debug, info, warning, error)
            
        Returns:
            Log operation result
        """
        level = level.lower()
        log_levels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR
        }
        
        if level not in log_levels:
            level = "info"
        
        self.logger.log(log_levels[level], message)
        
        return {
            "status": "logged",
            "message": message,
            "level": level,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def sleep(self, seconds: int) -> Dict[str, Any]:
        """
        Wait for a specified number of seconds
        
        Args:
            seconds: Number of seconds to wait
            
        Returns:
            Sleep operation result
        """
        start_time = datetime.utcnow()
        time.sleep(seconds)
        end_time = datetime.utcnow()
        
        return {
            "status": "completed",
            "slept_seconds": seconds,
            "actual_duration": (end_time - start_time).total_seconds(),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
    
    def validate(self, type: str, value: str) -> Dict[str, Any]:
        """
        Validate input data
        
        Args:
            type: Type of validation (ip_address, url, email, etc.)
            value: Value to validate
            
        Returns:
            Validation result
        """
        validators = {
            "ip_address": self._validate_ip,
            "url": self._validate_url,
            "email": self._validate_email,
            "domain": self._validate_domain,
            "hash": self._validate_hash
        }
        
        if type not in validators:
            return {
                "valid": False,
                "error": f"Unknown validation type: {type}",
                "supported_types": list(validators.keys())
            }
        
        try:
            result = validators[type](value)
            return {
                "valid": result["valid"],
                "value": value,
                "type": type,
                "details": result.get("details", {}),
                "error": result.get("error")
            }
        except Exception as e:
            return {
                "valid": False,
                "value": value,
                "type": type,
                "error": str(e)
            }
    
    def extract(self, type: str, from_url: str = None, **kwargs) -> Dict[str, Any]:
        """
        Extract data from input
        
        Args:
            type: Type of extraction (domain, path, etc.)
            from_url: URL to extract from
            **kwargs: Additional parameters
            
        Returns:
            Extraction result
        """
        extractors = {
            "domain": self._extract_domain,
            "path": self._extract_path,
            "scheme": self._extract_scheme,
            "port": self._extract_port
        }
        
        if type not in extractors:
            return {
                "success": False,
                "error": f"Unknown extraction type: {type}",
                "supported_types": list(extractors.keys())
            }
        
        try:
            result = extractors[type](from_url or kwargs.get("value", ""))
            return {
                "success": True,
                "type": type,
                **result
            }
        except Exception as e:
            return {
                "success": False,
                "type": type,
                "error": str(e)
            }
    
    def evaluate(self, **conditions) -> Dict[str, Any]:
        """
        Evaluate conditions and expressions
        
        Args:
            **conditions: Named conditions to evaluate
            
        Returns:
            Evaluation results
        """
        results = {}
        overall_result = True
        
        for name, condition in conditions.items():
            try:
                if isinstance(condition, bool):
                    result = condition
                elif isinstance(condition, str):
                    # Simple string evaluation (could be enhanced)
                    result = condition.lower() in ["true", "yes", "1"]
                else:
                    result = bool(condition)
                
                results[name] = result
                if not result:
                    overall_result = False
                    
            except Exception as e:
                results[name] = False
                results[f"{name}_error"] = str(e)
                overall_result = False
        
        return {
            "overall_result": overall_result,
            "conditions": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def create_report(self, template: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a structured report
        
        Args:
            template: Template name
            data: Data for the report
            
        Returns:
            Generated report
        """
        return {
            "report_id": f"report_{int(time.time())}",
            "template": template,
            "generated_at": datetime.utcnow().isoformat(),
            "data": data,
            "summary": f"Report generated using template '{template}' with {len(data)} data fields"
        }
    
    def notification(self, channel: str, message: str, priority: str = "medium") -> Dict[str, Any]:
        """
        Send notifications (placeholder implementation)
        
        Args:
            channel: Notification channel
            message: Message to send
            priority: Priority level
            
        Returns:
            Notification result
        """
        self.logger.info(f"NOTIFICATION [{priority.upper()}] {channel}: {message}")
        
        return {
            "status": "sent",
            "channel": channel,
            "message": message,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def timestamp(self, format: str = "iso") -> Dict[str, Any]:
        """
        Get current timestamp
        
        Args:
            format: Timestamp format (iso, unix, etc.)
            
        Returns:
            Timestamp information
        """
        now = datetime.utcnow()
        
        formats = {
            "iso": now.isoformat(),
            "unix": int(now.timestamp()),
            "human": now.strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
        return {
            "timestamp": formats.get(format, formats["iso"]),
            "format": format,
            "all_formats": formats
        }
    
    def uuid(self) -> Dict[str, Any]:
        """
        Generate a UUID
        
        Returns:
            UUID information
        """
        import uuid
        generated_uuid = str(uuid.uuid4())
        
        return {
            "uuid": generated_uuid,
            "version": 4,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    # Private validation methods
    def _validate_ip(self, value: str) -> Dict[str, Any]:
        """Validate IP address"""
        try:
            ip = ipaddress.ip_address(value)
            return {
                "valid": True,
                "details": {
                    "version": ip.version,
                    "is_private": ip.is_private,
                    "is_multicast": ip.is_multicast,
                    "is_reserved": ip.is_reserved
                }
            }
        except ValueError as e:
            return {"valid": False, "error": str(e)}
    
    def _validate_url(self, value: str) -> Dict[str, Any]:
        """Validate URL"""
        try:
            parsed = urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                return {"valid": False, "error": "Invalid URL format"}
            
            return {
                "valid": True,
                "details": {
                    "scheme": parsed.scheme,
                    "domain": parsed.netloc,
                    "path": parsed.path,
                    "has_query": bool(parsed.query)
                }
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def _validate_email(self, value: str) -> Dict[str, Any]:
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, value):
            return {
                "valid": True,
                "details": {"domain": value.split("@")[1]}
            }
        return {"valid": False, "error": "Invalid email format"}
    
    def _validate_domain(self, value: str) -> Dict[str, Any]:
        """Validate domain name"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(pattern, value):
            return {"valid": True, "details": {"tld": value.split(".")[-1]}}
        return {"valid": False, "error": "Invalid domain format"}
    
    def _validate_hash(self, value: str) -> Dict[str, Any]:
        """Validate hash (MD5, SHA1, SHA256, etc.)"""
        hash_lengths = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        length = len(value)
        
        if length in hash_lengths and re.match(r'^[a-fA-F0-9]+$', value):
            return {
                "valid": True,
                "details": {"type": hash_lengths[length], "length": length}
            }
        return {"valid": False, "error": "Invalid hash format"}
    
    # Private extraction methods
    def _extract_domain(self, url: str) -> Dict[str, Any]:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return {"domain": parsed.netloc}
    
    def _extract_path(self, url: str) -> Dict[str, Any]:
        """Extract path from URL"""
        parsed = urlparse(url)
        return {"path": parsed.path}
    
    def _extract_scheme(self, url: str) -> Dict[str, Any]:
        """Extract scheme from URL"""
        parsed = urlparse(url)
        return {"scheme": parsed.scheme}
    
    def _extract_port(self, url: str) -> Dict[str, Any]:
        """Extract port from URL"""
        parsed = urlparse(url)
        return {"port": parsed.port}
