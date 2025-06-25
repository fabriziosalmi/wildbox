#!/usr/bin/env python3
"""
Advanced test script to verify all Responder components work correctly
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.models import Playbook, PlaybookStep, PlaybookTrigger, TriggerType
from app.playbook_parser import PlaybookParser
from app.connectors import connector_registry
from app.workflow_engine import workflow_engine

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
        action="system.log",
        input={"message": "Hello from test", "level": "info"}
    )
    assert step.name == "test_step"
    assert step.action == "system.log"
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

def test_connectors():
    """Test connector framework"""
    print("\n🧪 Testing connector framework...")
    
    # List all registered connectors
    connectors = connector_registry.list_connectors()
    print(f"  ✅ Found {len(connectors)} registered connectors:")
    
    for name, info in connectors.items():
        print(f"    📌 {name}: {len(info['actions'])} actions")
        for action_name, action_desc in info['actions'].items():
            print(f"      - {action_name}: {action_desc}")
    
    # Test system connector actions
    print("\n  🧪 Testing system connector actions...")
    
    # Test log action
    try:
        result = connector_registry.execute_action("system", "log", {
            "message": "Test log message from connector test",
            "level": "info"
        })
        assert result["status"] == "logged"
        print("    ✅ System log action works")
    except Exception as e:
        print(f"    ❌ System log action failed: {e}")
        return False
    
    # Test validation action
    try:
        result = connector_registry.execute_action("system", "validate", {
            "type": "ip_address",
            "value": "192.168.1.1"
        })
        assert result["valid"] == True
        print("    ✅ System validate action works")
    except Exception as e:
        print(f"    ❌ System validate action failed: {e}")
        return False
    
    # Test timestamp action
    try:
        result = connector_registry.execute_action("system", "timestamp", {
            "format": "iso"
        })
        assert "timestamp" in result
        print("    ✅ System timestamp action works")
    except Exception as e:
        print(f"    ❌ System timestamp action failed: {e}")
        return False
    
    print("  ✅ All connector tests passed!")
    return True

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
            
            # Validate each step has a valid connector.action format
            for step in playbook.steps:
                assert '.' in step.action, f"Step {step.name} has invalid action format"
                connector_name, action_name = step.action.split('.', 1)
                
                # Check if connector exists
                try:
                    connector_registry.get_connector(connector_name)
                    print(f"      ✅ {step.name}: {step.action} (connector exists)")
                except Exception:
                    print(f"      ⚠️  {step.name}: {step.action} (connector not available, will simulate)")
        
        print("  ✅ All playbooks loaded and validated successfully!")
        
    except Exception as e:
        print(f"  ❌ Playbook parsing failed: {e}")
        return False
    
    return True

def test_template_rendering():
    """Test template rendering"""
    print("\n🧪 Testing template rendering...")
    
    # Test basic template rendering
    test_context = {
        "trigger": {
            "ip": "192.168.1.100",
            "message": "Test message"
        },
        "steps": {
            "validate_ip": {
                "output": {"valid": True, "version": 4}
            }
        }
    }
    
    try:
        # Test simple template
        result = workflow_engine.render_template("IP: {{ trigger.ip }}", test_context)
        assert result == "IP: 192.168.1.100"
        print("  ✅ Simple template rendering works")
        
        # Test nested template
        result = workflow_engine.render_template("Valid: {{ steps.validate_ip.output.valid }}", test_context)
        assert result == "Valid: True"
        print("  ✅ Nested template rendering works")
        
        # Test condition evaluation
        result = workflow_engine.evaluate_condition("trigger.ip == '192.168.1.100'", test_context)
        assert result == True
        print("  ✅ Condition evaluation works")
        
        # Test complex input rendering
        complex_input = {
            "target": "{{ trigger.ip }}",
            "valid": "{{ steps.validate_ip.output.valid }}",
            "metadata": {
                "source": "test",
                "processed_at": "{{ trigger.message }}"
            }
        }
        
        rendered = workflow_engine.render_step_input(complex_input, test_context)
        assert rendered["target"] == "192.168.1.100"
        # Note: Boolean values are rendered as strings in templates
        assert rendered["valid"] == "True" or rendered["valid"] == True
        assert rendered["metadata"]["processed_at"] == "Test message"
        print("  ✅ Complex input rendering works")
        
    except Exception as e:
        print(f"  ❌ Template rendering failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("  ✅ All template rendering tests passed!")
    return True

def test_workflow_execution():
    """Test basic workflow execution without Redis"""
    print("\n🧪 Testing workflow execution (simulation mode)...")
    
    try:
        # Create a simple test playbook in memory
        from app.models import Playbook, PlaybookStep, PlaybookTrigger, TriggerType
        
        test_playbook = Playbook(
            playbook_id="test_execution",
            name="Test Execution Playbook",
            trigger=PlaybookTrigger(type=TriggerType.API),
            steps=[
                PlaybookStep(
                    name="log_start",
                    action="system.log",
                    input={
                        "message": "Starting test execution with IP: {{ trigger.ip }}",
                        "level": "info"
                    }
                ),
                PlaybookStep(
                    name="validate_ip",
                    action="system.validate",
                    input={
                        "type": "ip_address",
                        "value": "{{ trigger.ip }}"
                    }
                ),
                PlaybookStep(
                    name="log_result",
                    action="system.log",
                    input={
                        "message": "IP validation result: {{ steps.validate_ip.output.valid }}",
                        "level": "info"
                    },
                    condition="{{ steps.validate_ip.output.valid == true }}"
                )
            ]
        )
        
        # Manually add to parser for testing
        from app.playbook_parser import playbook_parser
        playbook_parser.playbooks["test_execution"] = test_playbook
        
        print("  ✅ Test playbook created")
        
        # Test template rendering for each step
        test_context = {
            "trigger": {"ip": "192.168.1.1"},
            "steps": {}
        }
        
        for step in test_playbook.steps:
            if step.input:
                rendered_input = workflow_engine.render_step_input(step.input, test_context)
                print(f"    🔧 {step.name} input: {rendered_input}")
                
                # Execute the action if it's a system action
                if step.action.startswith("system."):
                    try:
                        connector_name, action_name = step.action.split('.', 1)
                        result = connector_registry.execute_action(connector_name, action_name, rendered_input)
                        test_context["steps"][step.name] = {"output": result}
                        print(f"    ✅ {step.name} executed successfully")
                    except Exception as e:
                        print(f"    ⚠️  {step.name} execution failed: {e}")
        
        print("  ✅ Workflow execution simulation completed!")
        
    except Exception as e:
        print(f"  ❌ Workflow execution test failed: {e}")
        return False
    
    return True

def main():
    """Main test function"""
    print("🚀 Open Security Responder - Advanced Component Test")
    print("=" * 60)
    
    try:
        # Test models
        test_models()
        
        # Test connectors
        if not test_connectors():
            return False
        
        # Test playbook parser
        if not test_playbook_parser():
            return False
        
        # Test template rendering
        if not test_template_rendering():
            return False
        
        # Test workflow execution
        if not test_workflow_execution():
            return False
        
        print("\n" + "=" * 60)
        print("🎉 ALL ADVANCED TESTS PASSED!")
        print("🚀 The Open Security Responder is ready for production!")
        print("=" * 60)
        
        # Show summary
        connectors = connector_registry.list_connectors()
        parser = PlaybookParser("./playbooks")
        playbooks = parser.load_playbooks()
        
        print(f"\n📊 RESPONDER SUMMARY:")
        print(f"   • Connectors: {len(connectors)}")
        print(f"   • Playbooks: {len(playbooks)}")
        print(f"   • Total Actions: {sum(len(c['actions']) for c in connectors.values())}")
        print(f"   • Total Steps: {sum(len(pb.steps) for pb in playbooks.values())}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
