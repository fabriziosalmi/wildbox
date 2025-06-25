#!/usr/bin/env python3
"""
Basic test script to verify the Responder components work correctly
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.models import Playbook, PlaybookStep, PlaybookTrigger, TriggerType
from app.playbook_parser import PlaybookParser

def test_models():
    """Test Pydantic models"""
    print("🧪 Testing Pydantic models...")
    
    # Test PlaybookTrigger
    trigger = PlaybookTrigger(type=TriggerType.API)
    assert trigger.type == "api"
    print("  ✅ PlaybookTrigger model works")
    
    # Test PlaybookStep
    step = PlaybookStep(
        name="test_step",
        action="api.run_tool",
        input={"tool_name": "nmap", "target": "{{ trigger.ip }}"}
    )
    assert step.name == "test_step"
    assert step.action == "api.run_tool"
    print("  ✅ PlaybookStep model works")
    
    # Test complete Playbook
    playbook = Playbook(
        playbook_id="test_playbook",
        name="Test Playbook",
        trigger=trigger,
        steps=[step]
    )
    assert playbook.playbook_id == "test_playbook"
    assert len(playbook.steps) == 1
    print("  ✅ Playbook model works")
    
    print("  ✅ All models work correctly!")

def test_playbook_parser():
    """Test playbook parser"""
    print("\n🧪 Testing playbook parser...")
    
    parser = PlaybookParser("./playbooks")
    
    # Test loading playbooks
    try:
        playbooks = parser.load_playbooks()
        print(f"  ✅ Loaded {len(playbooks)} playbooks")
        
        for playbook_id, playbook in playbooks.items():
            print(f"    📚 {playbook_id}: {playbook.name} ({len(playbook.steps)} steps)")
            
            # Validate each step
            for step in playbook.steps:
                assert '.' in step.action, f"Step {step.name} has invalid action format"
                print(f"      🔧 {step.name}: {step.action}")
        
        print("  ✅ All playbooks loaded and validated successfully!")
        
    except Exception as e:
        print(f"  ❌ Playbook parsing failed: {e}")
        return False
    
    return True

def test_template_rendering():
    """Test template rendering"""
    print("\n🧪 Testing template rendering...")
    
    # We'll test this when we have the workflow engine running
    # For now, just test basic Jinja2 functionality
    from jinja2 import Environment, DictLoader
    
    env = Environment(loader=DictLoader({}))
    template = env.from_string("Hello {{ name }}!")
    result = template.render(name="Wildbox")
    
    assert result == "Hello Wildbox!"
    print("  ✅ Template rendering works")

def main():
    """Main test function"""
    print("🚀 Open Security Responder - Basic Component Test")
    print("=" * 50)
    
    try:
        # Test models
        test_models()
        
        # Test playbook parser
        if not test_playbook_parser():
            return False
        
        # Test template rendering
        test_template_rendering()
        
        print("\n" + "=" * 50)
        print("🎉 ALL TESTS PASSED! The Responder components are working correctly.")
        print("=" * 50)
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
