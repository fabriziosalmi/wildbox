from typing import Dict, Any, List
import asyncio
import random
import importlib
import sys
import os
from datetime import datetime, timedelta

try:
    from schemas import (
        AutomationWorkflowInput,
        SecurityAutomationOutput,
        WorkflowStep,
        WorkflowExecution,
        AutomationMetrics
    )
except ImportError:
    from schemas import (
        AutomationWorkflowInput,
        SecurityAutomationOutput,
        WorkflowStep,
        WorkflowExecution,
        AutomationMetrics
    )

class SecurityAutomationOrchestrator:
    """Security Automation Orchestrator - Advanced workflow automation and orchestration"""
    
    name = "Security Automation Orchestrator"
    description = "Advanced security automation platform for orchestrating complex security workflows"
    category = "automation"
    
    def __init__(self):
        # Updated list of available tools with proper module names
        self.available_tools = [
            "network_port_scanner", "ssl_analyzer", "dns_enumerator", "dns_security_checker",
            "threat_hunting_platform", "incident_response_automation", "compliance_checker",
            "network_scanner", "api_security_tester", "email_harvester", "password_generator",
            "hash_generator", "jwt_analyzer", "base64_tool", "metadata_extractor",
            "directory_bruteforcer", "cookie_scanner", "header_analyzer"
        ]
        
        self.workflow_templates = {
            "security_assessment": "Comprehensive security assessment workflow",
            "incident_response": "Automated incident response workflow",
            "compliance_audit": "Automated compliance audit workflow",
            "threat_hunting": "Proactive threat hunting workflow",
            "vulnerability_management": "Vulnerability management workflow"
        }

    async def execute_workflow(self, workflow_input: AutomationWorkflowInput) -> SecurityAutomationOutput:
        """Execute security automation workflow"""
        
        execution_id = f"EXEC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(100, 999)}"
        start_time = datetime.now()
        
        # Create workflow execution
        workflow_execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_name=workflow_input.workflow_name,
            status="running",
            start_time=start_time,
            end_time=None,
            total_steps=len(workflow_input.workflow_steps),
            completed_steps=0,
            failed_steps=0,
            execution_logs=[],
            step_results=[]
        )
        
        # Execute workflow steps
        workflow_execution = await self._execute_workflow_steps(workflow_input, workflow_execution)
        
        # Generate automation metrics
        metrics = await self._generate_automation_metrics()
        
        # Determine final status
        workflow_execution.end_time = datetime.now()
        if workflow_execution.failed_steps == 0:
            workflow_execution.status = "completed"
        else:
            workflow_execution.status = "failed"
        
        return SecurityAutomationOutput(
            success=workflow_execution.status == "completed",
            execution_id=execution_id,
            workflow_execution=workflow_execution,
            automation_metrics=metrics,
            recommendations=self._generate_recommendations(workflow_execution),
            next_scheduled_run=self._calculate_next_run(workflow_input.trigger_type)
        )

    async def _execute_workflow_steps(self, workflow_input: AutomationWorkflowInput, execution: WorkflowExecution) -> WorkflowExecution:
        """Execute individual workflow steps"""
        
        # Create workflow steps
        steps = []
        for i, step_config in enumerate(workflow_input.workflow_steps):
            step = WorkflowStep(
                step_id=f"step_{i+1}",
                step_name=step_config.get("name", f"Step {i+1}"),
                tool_name=step_config.get("tool", "unknown_tool"),
                parameters=step_config.get("parameters", {}),
                execution_order=i+1,
                dependencies=step_config.get("dependencies", []),
                timeout_minutes=step_config.get("timeout", 10),
                retry_count=0,
                status="pending",
                start_time=None,
                end_time=None,
                output=None,
                error_message=None
            )
            steps.append(step)
        
        execution.step_results = steps
        
        # Execute steps based on execution mode
        if workflow_input.execution_mode == "sequential":
            await self._execute_sequential(execution)
        elif workflow_input.execution_mode == "parallel":
            await self._execute_parallel(execution)
        else:  # conditional
            await self._execute_conditional(execution)
        
        return execution

    async def _execute_sequential(self, execution: WorkflowExecution):
        """Execute steps sequentially"""
        
        for step in execution.step_results:
            await self._execute_single_step(step, execution)
            
            if step.status == "failed":
                execution.failed_steps += 1
                execution.execution_logs.append(f"Step {step.step_id} failed: {step.error_message}")
                break
            else:
                execution.completed_steps += 1
                execution.execution_logs.append(f"Step {step.step_id} completed successfully")

    async def _execute_parallel(self, execution: WorkflowExecution):
        """Execute steps in parallel"""
        
        # Group steps by dependencies
        independent_steps = [s for s in execution.step_results if not s.dependencies]
        
        # Execute independent steps in parallel
        tasks = []
        for step in independent_steps:
            task = asyncio.create_task(self._execute_single_step(step, execution))
            tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks)
        
        # Update counters
        for step in execution.step_results:
            if step.status == "completed":
                execution.completed_steps += 1
            elif step.status == "failed":
                execution.failed_steps += 1

    async def _execute_conditional(self, execution: WorkflowExecution):
        """Execute steps with conditional logic"""
        
        # For simplicity, execute like sequential but with condition checks
        for step in execution.step_results:
            # Check if dependencies are met
            if self._check_dependencies(step, execution.step_results):
                await self._execute_single_step(step, execution)
                
                if step.status == "completed":
                    execution.completed_steps += 1
                else:
                    execution.failed_steps += 1
            else:
                step.status = "skipped"
                step.error_message = "Dependencies not met"

    async def _execute_single_step(self, step: WorkflowStep, execution: WorkflowExecution):
        """Execute a single workflow step"""
        
        step.start_time = datetime.now()
        step.status = "running"
        
        try:
            # REAL tool execution - import and call actual tool modules
            if step.tool_name in self.available_tools:
                # Dynamically import and execute the actual tool
                tool_result = await self._execute_real_tool(step.tool_name, step.parameters)
                
                if tool_result.get("success", False):
                    step.status = "completed"
                    step.output = tool_result
                else:
                    step.status = "failed"
                    step.error_message = tool_result.get("error", "Tool execution failed")
            else:
                step.status = "failed"
                step.error_message = f"Tool {step.tool_name} not available"
                
        except Exception as e:
            step.status = "failed"
            step.error_message = str(e)
        
        step.end_time = datetime.now()

    def _check_dependencies(self, step: WorkflowStep, all_steps: List[WorkflowStep]) -> bool:
        """Check if step dependencies are satisfied"""
        
        if not step.dependencies:
            return True
        
        for dep_id in step.dependencies:
            dep_step = next((s for s in all_steps if s.step_id == dep_id), None)
            if not dep_step or dep_step.status != "completed":
                return False
        
        return True

    async def _execute_real_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute real tool with proper validation and error handling"""
        import importlib
        import sys
        import os
        
        try:
            # Validate tool name against whitelist
            if tool_name not in self.available_tools:
                return {"success": False, "error": f"Tool {tool_name} not authorized"}
            
            # Validate parameters for security
            if not self._validate_tool_parameters(tool_name, parameters):
                return {"success": False, "error": "Invalid or unsafe parameters"}
            
            # Dynamic import of the tool module
            tool_module_path = f"app.tools.{tool_name}.main"
            
            if tool_module_path not in sys.modules:
                tool_module = importlib.import_module(tool_module_path)
            else:
                tool_module = sys.modules[tool_module_path]
            
            # Execute the tool's main function
            if hasattr(tool_module, 'execute_tool'):
                # Create proper input schema for the tool
                tool_input = self._create_tool_input(tool_name, parameters)
                result = await tool_module.execute_tool(tool_input)
                
                return {
                    "success": True,
                    "result": result,
                    "tool_name": tool_name,
                    "execution_time": datetime.now().isoformat()
                }
            else:
                return {"success": False, "error": f"Tool {tool_name} missing execute_tool function"}
                
        except ImportError as e:
            return {"success": False, "error": f"Failed to import tool {tool_name}: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Tool execution failed: {str(e)}"}
    
    def _validate_tool_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> bool:
        """Validate tool parameters for security"""
        # Basic security validation
        if not isinstance(parameters, dict):
            return False
        
        # Check for dangerous patterns in parameter values
        dangerous_patterns = [
            "; rm -rf", "DROP TABLE", "../../", "javascript:", "eval(",
            "<script>", "cmd.exe", "/etc/passwd", "system(", "exec("
        ]
        
        for key, value in parameters.items():
            if isinstance(value, str):
                for pattern in dangerous_patterns:
                    if pattern.lower() in value.lower():
                        return False
        
        return True
    
    def _create_tool_input(self, tool_name: str, parameters: Dict[str, Any]):
        """Create appropriate input schema for the tool"""
        # Import the tool's schema
        try:
            schema_module = importlib.import_module(f"app.tools.{tool_name}.schemas")
            
            # Get the input schema class (usually ends with Input)
            input_class = None
            for attr_name in dir(schema_module):
                if attr_name.endswith("Input"):
                    input_class = getattr(schema_module, attr_name)
                    break
            
            if input_class:
                return input_class(**parameters)
            else:
                # Fallback to generic dict if no schema found
                return parameters
                
        except ImportError:
            return parameters

    def _remove_mock_output_method(self):
        """This method replaces the old mock output generation"""
        pass

    async def _generate_automation_metrics(self) -> AutomationMetrics:
        """Generate real automation metrics from execution history"""
        # TODO: Implement real metrics from database/logs
        # For now, return minimal metrics with real data structure
        return AutomationMetrics(
            total_executions=0,  # Should come from database
            successful_executions=0,  # Should come from database  
            failed_executions=0,  # Should come from database
            average_execution_time="0 minutes",  # Should be calculated from real data
            most_used_tools=[],  # Should come from usage statistics
            error_patterns=[]  # Should come from error log analysis
        )

    def _generate_recommendations(self, execution: WorkflowExecution) -> List[str]:
        """Generate recommendations based on execution results"""
        
        recommendations = []
        
        if execution.failed_steps > 0:
            recommendations.append("Review failed steps and implement error handling")
            recommendations.append("Consider adding retry logic for failed steps")
        
        if execution.completed_steps == execution.total_steps:
            recommendations.append("Workflow executed successfully - consider scheduling regular runs")
        
        recommendations.extend([
            "Monitor workflow performance and optimize step timing",
            "Implement logging and alerting for critical failures",
            "Consider adding parallel execution for independent steps",
            "Review and update workflow parameters based on results"
        ])
        
        return recommendations

    def _calculate_next_run(self, trigger_type: str) -> str:
        """Calculate next scheduled run time"""
        
        if trigger_type == "schedule":
            next_run = datetime.now() + timedelta(days=1)
            return next_run.strftime("%Y-%m-%d %H:%M:%S")
        elif trigger_type == "event":
            return "Based on event triggers"
        else:
            return "Manual execution only"

# Required async function for tool execution
async def execute_tool(tool_input: AutomationWorkflowInput) -> SecurityAutomationOutput:
    """Execute the Security Automation Orchestrator tool"""
    orchestrator = SecurityAutomationOrchestrator()
    return await orchestrator.execute_workflow(tool_input)

# Tool metadata for registration
TOOL_INFO = {
    "name": "Security Automation Orchestrator",
    "description": "Advanced security automation platform for orchestrating complex security workflows",
    "category": "automation",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": AutomationWorkflowInput,
    "output_schema": SecurityAutomationOutput,
    "tool_class": SecurityAutomationOrchestrator
}
