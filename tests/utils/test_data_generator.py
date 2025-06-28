"""
Test data generator for Wildbox services
Creates sample data, test scenarios, and mock inputs
"""

import random
import string
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta


class TestDataGenerator:
    """Generates test data for comprehensive testing"""
    
    def __init__(self):
        self.sample_domains = [
            "test.example.com",
            "malicious.badactor.net", 
            "suspicious.domain.org",
            "clean.legitimate.com",
            "analysis.target.co"
        ]
        
        self.sample_ips = [
            "192.168.1.100",
            "10.0.0.50", 
            "172.16.0.25",
            "203.0.113.195",
            "198.51.100.42"
        ]
        
        self.sample_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "5d41402abc4b2a76b9719d911017c592",
            "098f6bcd4621d373cade4e832627b4f6",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"
        ]
        
        self.sample_urls = [
            "https://test.example.com/page",
            "http://suspicious.domain.org/malware.exe",
            "https://clean.legitimate.com/download.zip",
            "http://analysis.target.co/sample.pdf",
            "https://secure.website.net/login.php"
        ]
        
    async def setup(self):
        """Setup test data environment"""
        print("📊 Setting up test data...")
        
    def generate_random_string(self, length: int = 10) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        
    def get_sample_domain(self) -> str:
        """Get random sample domain"""
        return random.choice(self.sample_domains)
        
    def get_sample_ip(self) -> str:
        """Get random sample IP"""
        return random.choice(self.sample_ips)
        
    def get_sample_hash(self) -> str:
        """Get random sample hash"""
        return random.choice(self.sample_hashes)
        
    def get_sample_url(self) -> str:
        """Get random sample URL"""
        return random.choice(self.sample_urls)
        
    def generate_ioc_data(self) -> Dict[str, Any]:
        """Generate IOC lookup test data"""
        return {
            "indicator": self.get_sample_domain(),
            "type": "domain",
            "context": "test_lookup"
        }
        
    def generate_asset_data(self) -> Dict[str, Any]:
        """Generate asset test data for Guardian"""
        return {
            "name": f"Test Asset {self.generate_random_string(5)}",
            "type": "server",
            "ip_address": self.get_sample_ip(),
            "hostname": self.get_sample_domain(),
            "environment": "test",
            "criticality": random.choice(["low", "medium", "high", "critical"]),
            "tags": ["test", "automated", "pulse-check"]
        }
        
    def generate_vulnerability_data(self) -> Dict[str, Any]:
        """Generate vulnerability test data"""
        return {
            "title": f"Test Vulnerability {self.generate_random_string(5)}",
            "description": "Test vulnerability for pulse check",
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "cve_id": f"CVE-2024-{random.randint(1000, 9999)}",
            "cvss_score": round(random.uniform(1.0, 10.0), 1),
            "status": "open"
        }
        
    def generate_playbook_test_data(self) -> Dict[str, Any]:
        """Generate playbook execution test data"""
        return {
            "playbook_name": "ip_reputation_check",
            "inputs": {
                "ip_address": self.get_sample_ip(),
                "context": "automated_test"
            }
        }
        
    def generate_ai_analysis_data(self) -> Dict[str, Any]:
        """Generate AI analysis test data"""
        return {
            "text": f"Analyze this sample log entry: User login from {self.get_sample_ip()} to {self.get_sample_domain()}",
            "analysis_type": "security_event",
            "context": "pulse_check_test"
        }
        
    def generate_cloud_scan_data(self) -> Dict[str, Any]:
        """Generate cloud scanning test data"""
        return {
            "provider": "aws",
            "account_id": f"123456789{random.randint(100, 999)}",
            "regions": ["us-east-1", "us-west-2"],
            "scan_type": "security_assessment"
        }
        
    def generate_automation_workflow_data(self) -> Dict[str, Any]:
        """Generate automation workflow test data"""
        return {
            "workflow_name": "test_security_workflow",
            "trigger_data": {
                "event_type": "security_alert",
                "source": "pulse_check",
                "data": {
                    "alert_id": self.generate_random_string(10),
                    "severity": "medium",
                    "description": "Test security event for automation"
                }
            }
        }
        
    def generate_telemetry_data(self) -> Dict[str, Any]:
        """Generate sensor telemetry data"""
        return {
            "hostname": self.get_sample_domain(),
            "timestamp": datetime.now().isoformat(),
            "events": [
                {
                    "name": "process_start",
                    "pid": random.randint(1000, 9999),
                    "cmdline": f"test_process_{self.generate_random_string(5)}",
                    "timestamp": datetime.now().isoformat()
                }
            ]
        }
        
    def generate_tool_execution_data(self) -> List[Dict[str, Any]]:
        """Generate tool execution test cases"""
        return [
            {
                "tool": "base64_encoder",
                "input": {"text": "Hello Wildbox Test"},
                "expected_type": "encoded_data"
            },
            {
                "tool": "hash_generator", 
                "input": {"text": "test_string", "algorithm": "sha256"},
                "expected_type": "hash_value"
            },
            {
                "tool": "domain_analyzer",
                "input": {"domain": self.get_sample_domain()},
                "expected_type": "domain_info"
            },
            {
                "tool": "ip_geolocator",
                "input": {"ip": self.get_sample_ip()},
                "expected_type": "location_info"
            }
        ]
        
    def generate_dashboard_test_scenarios(self) -> List[Dict[str, Any]]:
        """Generate dashboard testing scenarios"""
        return [
            {
                "page": "dashboard",
                "expected_elements": ["nav", "sidebar", "main-content", "widgets"],
                "test_interactions": ["navigate", "refresh", "filter"]
            },
            {
                "page": "tools",
                "expected_elements": ["tool-list", "search", "categories"],
                "test_interactions": ["search", "select-tool", "execute"]
            },
            {
                "page": "reports",
                "expected_elements": ["report-list", "filters", "export"],
                "test_interactions": ["filter", "view-report", "export"]
            }
        ]
        
    def get_test_datasets(self) -> Dict[str, Any]:
        """Get comprehensive test datasets"""
        return {
            "iocs": [self.generate_ioc_data() for _ in range(5)],
            "assets": [self.generate_asset_data() for _ in range(3)],
            "vulnerabilities": [self.generate_vulnerability_data() for _ in range(3)],
            "playbooks": [self.generate_playbook_test_data() for _ in range(2)],
            "ai_analysis": [self.generate_ai_analysis_data() for _ in range(2)],
            "cloud_scans": [self.generate_cloud_scan_data() for _ in range(2)],
            "automations": [self.generate_automation_workflow_data() for _ in range(2)],
            "telemetry": [self.generate_telemetry_data() for _ in range(3)],
            "tool_executions": self.generate_tool_execution_data(),
            "dashboard_scenarios": self.generate_dashboard_test_scenarios()
        }