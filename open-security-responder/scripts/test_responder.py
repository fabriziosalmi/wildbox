#!/usr/bin/env python3
"""
End-to-end test script for Open Security Responder

Tests playbook execution by making API calls and monitoring results.
"""

import sys
import time
import json
import requests
from typing import Dict, Any, Optional


class ResponderTester:
    """Test client for the Open Security Responder API"""
    
    def __init__(self, base_url: str = "http://localhost:8003"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def check_health(self) -> Dict[str, Any]:
        """Check if the service is healthy"""
        try:
            response = self.session.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Health check failed: {e}")
            sys.exit(1)
    
    def list_playbooks(self) -> Dict[str, Any]:
        """List available playbooks"""
        try:
            response = self.session.get(f"{self.base_url}/v1/playbooks")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Failed to list playbooks: {e}")
            return {"playbooks": [], "total": 0}
    
    def execute_playbook(self, playbook_id: str, trigger_data: Dict[str, Any]) -> Optional[str]:
        """Execute a playbook and return the run ID"""
        try:
            payload = {"trigger_data": trigger_data}
            response = self.session.post(
                f"{self.base_url}/v1/playbooks/{playbook_id}/execute",
                json=payload
            )
            response.raise_for_status()
            result = response.json()
            return result.get("run_id")
        except Exception as e:
            print(f"❌ Failed to execute playbook {playbook_id}: {e}")
            return None
    
    def get_execution_status(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status and results"""
        try:
            response = self.session.get(f"{self.base_url}/v1/runs/{run_id}")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Failed to get execution status for {run_id}: {e}")
            return None
    
    def wait_for_completion(self, run_id: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
        """Wait for execution to complete and return final result"""
        print(f"⏳ Waiting for execution {run_id} to complete...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_execution_status(run_id)
            if not status:
                return None
            
            current_status = status.get("status", "unknown")
            print(f"   Status: {current_status}")
            
            if current_status in ["completed", "failed", "cancelled"]:
                return status
            
            time.sleep(2)
        
        print(f"❌ Timeout waiting for execution {run_id} to complete")
        return None
    
    def print_execution_summary(self, result: Dict[str, Any]):
        """Print a formatted summary of the execution result"""
        print("\n" + "="*60)
        print("📊 EXECUTION SUMMARY")
        print("="*60)
        
        print(f"Run ID: {result.get('run_id', 'N/A')}")
        print(f"Playbook: {result.get('playbook_name', 'N/A')} ({result.get('playbook_id', 'N/A')})")
        print(f"Status: {result.get('status', 'N/A')}")
        print(f"Duration: {result.get('duration_seconds', 0):.2f} seconds")
        
        if result.get('error'):
            print(f"❌ Error: {result['error']}")
        
        print(f"\n📝 TRIGGER DATA:")
        print(json.dumps(result.get('trigger_data', {}), indent=2))
        
        print(f"\n🔄 STEP RESULTS:")
        for step in result.get('step_results', []):
            status_icon = "✅" if step['status'] == 'completed' else "❌"
            print(f"  {status_icon} {step['step_name']} - {step['status']} ({step.get('duration_seconds', 0):.2f}s)")
            if step.get('error'):
                print(f"    Error: {step['error']}")
            elif step.get('output'):
                print(f"    Output: {json.dumps(step['output'], indent=6)}")
        
        print(f"\n📜 EXECUTION LOGS:")
        for log in result.get('logs', []):
            print(f"  {log}")
        
        print("="*60)


def main():
    """Main test function"""
    print("🚀 Open Security Responder - End-to-End Test")
    print("=" * 50)
    
    # Initialize tester
    tester = ResponderTester()
    
    # Check health
    print("🔍 Checking service health...")
    health = tester.check_health()
    print(f"   ✅ Service is {health.get('status', 'unknown')}")
    print(f"   📊 Playbooks loaded: {health.get('playbooks_loaded', 0)}")
    print(f"   🔗 Redis connected: {health.get('redis_connected', False)}")
    
    # List playbooks
    print("\n📚 Listing available playbooks...")
    playbooks_resp = tester.list_playbooks()
    playbooks = playbooks_resp.get('playbooks', [])
    
    if not playbooks:
        print("❌ No playbooks found!")
        sys.exit(1)
    
    print(f"   Found {len(playbooks)} playbooks:")
    for pb in playbooks:
        print(f"   - {pb['playbook_id']}: {pb['name']}")
    
    # Test scenarios
    test_scenarios = [
        {
            "name": "Simple Notification Test",
            "playbook_id": "simple_notification",
            "trigger_data": {
                "message": "Hello from test script!",
                "timestamp": time.time()
            }
        },
        {
            "name": "IP Triage Test",
            "playbook_id": "triage_ip",
            "trigger_data": {
                "ip": "8.8.8.8",
                "source": "manual_test"
            }
        },
        {
            "name": "URL Triage Test",
            "playbook_id": "triage_url",
            "trigger_data": {
                "url": "https://example.com/suspicious-page",
                "reporter": "test_system"
            }
        }
    ]
    
    # Run tests
    for scenario in test_scenarios:
        print(f"\n🧪 Testing: {scenario['name']}")
        print("-" * 40)
        
        # Check if playbook exists
        playbook_exists = any(pb['playbook_id'] == scenario['playbook_id'] for pb in playbooks)
        if not playbook_exists:
            print(f"   ⚠️  Skipping - playbook '{scenario['playbook_id']}' not found")
            continue
        
        # Execute playbook
        run_id = tester.execute_playbook(scenario['playbook_id'], scenario['trigger_data'])
        if not run_id:
            print(f"   ❌ Failed to start execution")
            continue
        
        print(f"   ✅ Execution started with ID: {run_id}")
        
        # Wait for completion
        result = tester.wait_for_completion(run_id)
        if not result:
            print(f"   ❌ Failed to get completion status")
            continue
        
        # Print summary
        tester.print_execution_summary(result)
        
        # Brief pause between tests
        time.sleep(1)
    
    print("\n✅ End-to-end testing completed!")


if __name__ == "__main__":
    main()
