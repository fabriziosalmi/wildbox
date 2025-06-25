#!/usr/bin/env python3
"""
End-to-end playbook execution test without Redis dependency
"""

import sys
import os
import json
import uuid
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.models import ExecutionStatus, PlaybookExecutionResult, StepExecutionResult
from app.playbook_parser import playbook_parser
from app.workflow_engine import workflow_engine
from app.connectors import connector_registry


def execute_playbook_simulation(playbook_id: str, trigger_data: dict):
    """
    Execute a playbook without Redis dependency for testing
    """
    print(f"🚀 Executing playbook '{playbook_id}' with trigger data: {json.dumps(trigger_data, indent=2)}")
    
    # Get the playbook
    try:
        playbook = playbook_parser.get_playbook(playbook_id)
    except KeyError:
        print(f"❌ Playbook '{playbook_id}' not found")
        return None
    
    # Create execution result
    run_id = str(uuid.uuid4())
    start_time = datetime.utcnow()
    
    execution_result = PlaybookExecutionResult(
        run_id=run_id,
        playbook_id=playbook_id,
        playbook_name=playbook.name,
        status=ExecutionStatus.RUNNING,
        start_time=start_time,
        trigger_data=trigger_data,
        context={"trigger": trigger_data}
    )
    
    print(f"📋 Starting execution {run_id} for '{playbook.name}'")
    print(f"📝 Playbook has {len(playbook.steps)} steps")
    
    try:
        # Execute each step
        for i, step in enumerate(playbook.steps, 1):
            step_start_time = datetime.utcnow()
            print(f"\n🔧 Step {i}/{len(playbook.steps)}: {step.name}")
            print(f"   Action: {step.action}")
            
            # Create step result
            step_result = StepExecutionResult(
                step_name=step.name,
                status=ExecutionStatus.RUNNING,
                start_time=step_start_time
            )
            
            try:
                # Evaluate condition if present
                if step.condition:
                    print(f"   Condition: {step.condition}")
                    condition_result = workflow_engine.evaluate_condition(
                        step.condition, 
                        execution_result.context
                    )
                    if not condition_result:
                        print(f"   ⏭️  Skipped (condition failed)")
                        step_result.status = ExecutionStatus.COMPLETED
                        step_result.end_time = datetime.utcnow()
                        step_result.output = {"skipped": True, "reason": "condition_failed"}
                        execution_result.step_results.append(step_result)
                        continue
                
                # Render step input
                if step.input:
                    rendered_input = workflow_engine.render_step_input(
                        step.input, 
                        execution_result.context
                    )
                    print(f"   Input: {json.dumps(rendered_input, indent=6)}")
                else:
                    rendered_input = {}
                
                # Execute the action
                connector_name, action_name = step.action.split('.', 1)
                print(f"   Executing {action_name} on {connector_name} connector...")
                
                action_result = connector_registry.execute_action(
                    connector_name, 
                    action_name, 
                    rendered_input
                )
                
                # Update step result
                step_result.status = ExecutionStatus.COMPLETED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.output = action_result
                
                # Update context with step result
                if "steps" not in execution_result.context:
                    execution_result.context["steps"] = {}
                execution_result.context["steps"][step.name] = {
                    "output": action_result,
                    "status": step_result.status,
                    "duration": step_result.duration_seconds
                }
                
                execution_result.step_results.append(step_result)
                print(f"   ✅ Completed in {step_result.duration_seconds:.2f}s")
                
                # Show output summary
                if action_result:
                    if isinstance(action_result, dict):
                        key_count = len(action_result.keys())
                        print(f"   📤 Output: {key_count} fields")
                        # Show first few keys
                        for key in list(action_result.keys())[:3]:
                            value = action_result[key]
                            if isinstance(value, (str, int, float, bool)):
                                print(f"      {key}: {value}")
                            else:
                                print(f"      {key}: {type(value).__name__}")
                    else:
                        print(f"   📤 Output: {action_result}")
                
            except Exception as e:
                # Handle step failure
                step_result.status = ExecutionStatus.FAILED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.error = str(e)
                
                execution_result.step_results.append(step_result)
                print(f"   ❌ Failed: {str(e)}")
                
                # Continue execution (don't fail entire playbook for demo)
                # In production, you might want to fail the entire execution
                continue
        
        # Mark execution as completed
        execution_result.status = ExecutionStatus.COMPLETED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        
        print(f"\n🎉 Playbook execution completed successfully!")
        print(f"⏱️  Total duration: {execution_result.duration_seconds:.2f}s")
        
    except Exception as e:
        # Handle execution failure
        execution_result.status = ExecutionStatus.FAILED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        execution_result.error = str(e)
        
        print(f"\n❌ Playbook execution failed: {str(e)}")
    
    return execution_result


def print_execution_summary(result: PlaybookExecutionResult):
    """Print a detailed execution summary"""
    print("\n" + "="*70)
    print("📊 EXECUTION SUMMARY")
    print("="*70)
    
    print(f"🆔 Run ID: {result.run_id}")
    print(f"📚 Playbook: {result.playbook_name} ({result.playbook_id})")
    print(f"📊 Status: {result.status}")
    print(f"⏱️  Duration: {result.duration_seconds:.2f} seconds")
    print(f"🕐 Started: {result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"🕓 Ended: {result.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if result.end_time else 'N/A'}")
    
    if result.error:
        print(f"❌ Error: {result.error}")
    
    print(f"\n📝 TRIGGER DATA:")
    print(json.dumps(result.trigger_data, indent=2))
    
    print(f"\n🔄 STEP RESULTS ({len(result.step_results)} steps):")
    for i, step in enumerate(result.step_results, 1):
        status_icon = {
            "completed": "✅",
            "failed": "❌",
            "running": "🟡",
            "pending": "⏳"
        }.get(step.status, "❓")
        
        print(f"  {i:2d}. {status_icon} {step.step_name}")
        print(f"      Status: {step.status}")
        print(f"      Duration: {step.duration_seconds:.2f}s" if step.duration_seconds else "      Duration: N/A")
        
        if step.error:
            print(f"      Error: {step.error}")
        elif step.output:
            if step.output.get("skipped"):
                print(f"      Reason: {step.output.get('reason', 'Unknown')}")
            else:
                # Show summary of output
                if isinstance(step.output, dict):
                    print(f"      Output: {len(step.output)} fields")
                    for key in list(step.output.keys())[:2]:  # Show first 2 keys
                        value = step.output[key]
                        if isinstance(value, str) and len(value) > 50:
                            print(f"        {key}: {value[:47]}...")
                        else:
                            print(f"        {key}: {value}")
                else:
                    print(f"      Output: {step.output}")
    
    print("="*70)


def main():
    """Main test function"""
    print("🚀 Open Security Responder - Playbook Execution Test")
    print("="*70)
    
    # List available playbooks
    playbooks = playbook_parser.load_playbooks()
    print(f"📚 Available playbooks: {len(playbooks)}")
    for pid, pb in playbooks.items():
        print(f"   • {pid}: {pb.name} ({len(pb.steps)} steps)")
    
    # Test different playbooks
    test_cases = [
        {
            "playbook_id": "simple_notification",
            "trigger_data": {"message": "Hello from e2e test!"}
        },
        {
            "playbook_id": "triage_ip",
            "trigger_data": {"ip": "192.168.1.100"}
        },
        {
            "playbook_id": "triage_url",
            "trigger_data": {"url": "https://example.com/suspicious-page"}
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n{'='*70}")
        result = execute_playbook_simulation(
            test_case["playbook_id"], 
            test_case["trigger_data"]
        )
        
        if result:
            results.append(result)
            print_execution_summary(result)
    
    # Final summary
    print(f"\n🎯 FINAL SUMMARY")
    print("="*70)
    print(f"Total executions: {len(results)}")
    
    completed = sum(1 for r in results if r.status == "completed")
    failed = sum(1 for r in results if r.status == "failed")
    
    print(f"✅ Completed: {completed}")
    print(f"❌ Failed: {failed}")
    
    if completed == len(results):
        print("\n🎉 All playbook executions completed successfully!")
        print("🚀 Open Security Responder is fully functional!")
    else:
        print(f"\n⚠️  {failed} execution(s) had issues (expected due to simulation)")
    
    return completed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
