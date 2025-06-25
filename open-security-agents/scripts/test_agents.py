#!/usr/bin/env python3
"""
End-to-end test for Open Security Agents

Tests the complete AI-powered threat analysis pipeline.
"""

import asyncio
import json
import time
import sys
import os
from datetime import datetime

import httpx

# Test configuration
API_BASE_URL = "http://localhost:8004"
TEST_TIMEOUT = 300  # 5 minutes max per test


class AgentsAPITester:
    """Test client for Open Security Agents API"""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.session = httpx.AsyncClient(timeout=30.0)
    
    async def health_check(self) -> dict:
        """Check API health"""
        response = await self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    async def get_stats(self) -> dict:
        """Get service statistics"""
        response = await self.session.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()
    
    async def submit_analysis(self, ioc_type: str, ioc_value: str, priority: str = "normal") -> dict:
        """Submit IOC for analysis"""
        payload = {
            "ioc": {
                "type": ioc_type,
                "value": ioc_value
            },
            "priority": priority
        }
        
        response = await self.session.post(
            f"{self.base_url}/v1/analyze",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def get_analysis_result(self, task_id: str) -> dict:
        """Get analysis result by task ID"""
        response = await self.session.get(f"{self.base_url}/v1/analyze/{task_id}")
        response.raise_for_status()
        return response.json()
    
    async def wait_for_completion(self, task_id: str, timeout: int = TEST_TIMEOUT) -> dict:
        """Wait for analysis to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = await self.get_analysis_result(task_id)
            
            status = result.get("status")
            if status == "completed":
                return result
            elif status == "failed":
                raise Exception(f"Analysis failed: {result.get('error', 'Unknown error')}")
            
            print(f"   Status: {status} - {result.get('progress', 'Processing...')}")
            await asyncio.sleep(5)
        
        raise TimeoutError(f"Analysis timed out after {timeout} seconds")
    
    async def close(self):
        """Close the HTTP session"""
        await self.session.aclose()


async def print_analysis_report(result: dict):
    """Print a formatted analysis report"""
    print("\n" + "="*80)
    print("🎯 AI THREAT ANALYSIS REPORT")
    print("="*80)
    
    ioc = result.get("ioc", {})
    print(f"📊 IOC: {ioc.get('type', 'unknown').upper()} - {ioc.get('value', 'unknown')}")
    print(f"🏷️  Verdict: {result.get('verdict', 'Unknown')}")
    print(f"📈 Confidence: {result.get('confidence', 0.0):.1%}")
    print(f"⏱️  Duration: {result.get('analysis_duration', 0.0):.1f} seconds")
    print(f"🔧 Tools Used: {', '.join(result.get('tools_used', []))}")
    
    print(f"\n📝 Executive Summary:")
    print(f"   {result.get('executive_summary', 'No summary available')}")
    
    evidence = result.get("evidence", [])
    if evidence:
        print(f"\n🔍 Evidence ({len(evidence)} findings):")
        for i, item in enumerate(evidence, 1):
            severity_icon = {
                "low": "🟢",
                "medium": "🟡", 
                "high": "🟠",
                "critical": "🔴"
            }.get(item.get("severity", "low"), "⚪")
            
            print(f"   {i}. {severity_icon} {item.get('finding', 'Unknown finding')}")
            print(f"      Source: {item.get('source', 'Unknown')}")
    
    actions = result.get("recommended_actions", [])
    if actions:
        print(f"\n📋 Recommended Actions ({len(actions)}):")
        for i, action in enumerate(actions, 1):
            print(f"   {i}. {action}")
    
    # Show excerpt of full report
    full_report = result.get("full_report", "")
    if full_report:
        print(f"\n📄 Full Report (excerpt):")
        lines = full_report.split('\n')[:10]
        for line in lines:
            print(f"   {line}")
        if len(full_report.split('\n')) > 10:
            print("   ... (truncated)")
    
    print("="*80)


async def test_single_ioc(client: AgentsAPITester, ioc_type: str, ioc_value: str) -> bool:
    """Test analysis of a single IOC"""
    print(f"\n🚀 Testing {ioc_type.upper()} analysis: {ioc_value}")
    print("-" * 60)
    
    try:
        # Submit analysis
        print("📤 Submitting analysis request...")
        submission = await client.submit_analysis(ioc_type, ioc_value)
        task_id = submission["task_id"]
        print(f"✅ Task submitted: {task_id}")
        
        # Wait for completion
        print("⏳ Waiting for AI analysis to complete...")
        result = await client.wait_for_completion(task_id)
        
        # Print results
        await print_analysis_report(result)
        
        # Validate result structure
        required_fields = ["task_id", "ioc", "verdict", "confidence", "executive_summary"]
        missing_fields = [field for field in required_fields if field not in result]
        
        if missing_fields:
            print(f"⚠️  Warning: Missing fields in result: {missing_fields}")
            return False
        
        print(f"✅ Analysis completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False


async def main():
    """Main test function"""
    print("🧠 Open Security Agents - AI Threat Analysis Test")
    print("="*80)
    
    client = AgentsAPITester()
    
    try:
        # Health check
        print("🏥 Checking API health...")
        health = await client.health_check()
        print(f"   Status: {health['status']}")
        print(f"   Services: {health['services']}")
        
        if health["status"] != "healthy":
            print("⚠️  API is not healthy - some tests may fail")
        
        # Get initial stats
        print("\n📊 Getting service statistics...")
        stats = await client.get_stats()
        print(f"   Total analyses: {stats['total_analyses']}")
        print(f"   Running tasks: {stats['running_tasks']}")
        print(f"   Pending tasks: {stats['pending_tasks']}")
        
        # Test cases for different IOC types
        test_cases = [
            ("ipv4", "8.8.8.8"),                           # Google DNS (should be benign)
            ("domain", "example.com"),                      # Example domain (should be benign)
            ("url", "https://httpbin.org/get"),            # Test URL (should be benign)
            # Add more test cases as needed
        ]
        
        print(f"\n🎯 Running {len(test_cases)} test cases...")
        
        successful_tests = 0
        total_tests = len(test_cases)
        
        for ioc_type, ioc_value in test_cases:
            success = await test_single_ioc(client, ioc_type, ioc_value)
            if success:
                successful_tests += 1
            
            # Small delay between tests
            await asyncio.sleep(2)
        
        # Final summary
        print(f"\n🎉 TEST SUMMARY")
        print("="*80)
        print(f"✅ Successful: {successful_tests}/{total_tests}")
        print(f"❌ Failed: {total_tests - successful_tests}/{total_tests}")
        
        if successful_tests == total_tests:
            print("\n🚀 All tests passed! Open Security Agents is working correctly!")
            return True
        else:
            print(f"\n⚠️  {total_tests - successful_tests} test(s) failed")
            return False
    
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        return False
    
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)
