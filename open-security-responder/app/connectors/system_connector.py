"""
System connector for Open Security Responder

Provides basic system operations like logging, validation, and utility functions.
"""

import time
import re
import json
import logging
from typing import Any, Dict, Optional
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
            "evaluate": "Combine named boolean conditions (all, or at least min_true)",
            "create_report": "Generate a structured report",
            "notification": "Record a notification in the run log; nothing is delivered",
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
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            return {
                "success": False,
                "type": type,
                "error": str(e)
            }
    
    def evaluate(
        self,
        conditions: Optional[Dict[str, Any]] = None,
        min_true: Optional[int] = None,
        **named: Any,
    ) -> Dict[str, Any]:
        """
        Combine named boolean conditions into one result

        The conditions are given as a mapping under ``conditions`` (or, as
        before, as top-level names). Each value is normally a template such as
        ``"{{ steps.scan.output.open_ports | length > 5 }}"``, so it reaches
        this action as the string "True" or "False"; a real boolean is
        accepted too.

        Anything else is an error, not a guess. This action used to take
        ``bool()`` of whatever it was given, so a nested mapping was always
        true and a string such as "malicious" was always false: a step guarded
        on the result ran, or never ran, whatever the data said (#605).

        Args:
            conditions: Named conditions to evaluate
            min_true: How many conditions must hold for ``overall_result``
                to be true. Omitted, all of them must hold.
            **named: Further named conditions, merged with ``conditions``

        Returns:
            ``overall_result`` (bool), ``conditions`` (name -> bool),
            ``matched`` (the names that hold, in order), ``matched_count``,
            ``total``, ``min_true`` (the threshold applied) and ``timestamp``

        Raises:
            ValueError: If a condition is not a boolean, if there are no
                conditions, or if min_true is out of range
        """
        if conditions is not None and not isinstance(conditions, dict):
            raise ValueError(
                "conditions must be a mapping of names to booleans, "
                f"not {type(conditions).__name__}"
            )
        merged = {**(conditions or {}), **named}
        duplicated = set(conditions or {}) & set(named)
        if duplicated:
            raise ValueError(
                f"conditions named both inside and outside 'conditions': {sorted(duplicated)}"
            )
        if not merged:
            raise ValueError("evaluate needs at least one condition")

        results = {name: self._as_bool(name, value) for name, value in merged.items()}
        matched = [name for name, result in results.items() if result]

        threshold = len(results) if min_true is None else min_true
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise ValueError(f"min_true must be an integer, not {min_true!r}")
        if not 1 <= threshold <= len(results):
            raise ValueError(
                f"min_true must be between 1 and {len(results)}, not {threshold}"
            )

        return {
            "overall_result": len(matched) >= threshold,
            "conditions": results,
            "matched": matched,
            "matched_count": len(matched),
            "total": len(results),
            "min_true": threshold,
            "timestamp": datetime.utcnow().isoformat()
        }

    @staticmethod
    def _as_bool(name: str, value: Any) -> bool:
        """A rendered condition as a boolean; anything ambiguous is an error."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        raise ValueError(
            f"condition '{name}' is not a boolean (got {type(value).__name__}); "
            "write it as a comparison, for example \"{{ x > 5 }}\""
        )
    
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
        Record a notification; deliver nothing (#639).

        No e-mail, webhook or chat message leaves the responder. The message
        goes to the service log, and the step's input and output -- this
        result -- go to the run's log and record, where whoever reads the run
        sees it. The result says so: its status is "logged" and "delivered"
        is false. It used to answer "sent", reporting a notification that
        never happened.

        Args:
            channel: A label for the intended audience, recorded as given;
                no channel is looked up or contacted
            message: The message to record
            priority: Priority level, recorded as given

        Returns:
            What was recorded, with status "logged"
        """
        self.logger.info(f"NOTIFICATION (logged, not delivered) [{priority.upper()}] {channel}: {message}")

        return {
            "status": "logged",
            "delivered": False,
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
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
