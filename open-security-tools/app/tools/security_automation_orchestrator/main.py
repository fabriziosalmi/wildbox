from typing import Dict, Any, List
import asyncio
import importlib
import inspect
import sys
import os
from datetime import datetime

from fastapi import HTTPException

from ...execution_manager import tool_acts_for_caller
from ...target_policy import TargetRefused, enforce_target_policy
from ...tool_loader import find_schema_classes
from .schemas import (
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
        # A workflow step may name any discovered tool; this list is only the
        # curated default set the orchestrator advertises. The four fabricated
        # tools that used to appear here (threat_hunting_platform,
        # incident_response_automation, compliance_checker,
        # security_compliance_checker) were removed from the service.
        self.available_tools = [
            "network_port_scanner", "ssl_analyzer", "dns_security_checker",
            "api_security_tester", "email_harvester", "jwt_analyzer",
            "metadata_extractor", "cookie_scanner", "header_analyzer",
            "ct_log_scanner", "email_security_analyzer", "pki_certificate_manager",
            "vulnerability_db_scanner",
        ]
        
        self.workflow_templates = {
            "security_assessment": "Comprehensive security assessment workflow",
            "vulnerability_management": "Vulnerability management workflow",
        }

    async def execute_workflow(self, workflow_input: AutomationWorkflowInput) -> SecurityAutomationOutput:
        """Execute security automation workflow"""
        
        execution_id = f"EXEC-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
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
                
        except HTTPException as e:
            # A refused step (SSRF target, tool acting for a caller, invalid
            # input) fails the step; it does not abort the whole workflow.
            step.status = "failed"
            step.error_message = str(e.detail)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
        """Run one workflow step through the API's pre-execution checks.

        A step calls another tool's execute_tool directly, so it must apply
        what the API applies before a tool runs (#610):

        * the input is validated by the tool's own input model;
        * the target policy (``app.target_policy.enforce_target_policy``)
          checks every URL in that validated input (SSRF guard) and the
          tool's network target fields (#614);
        * a tool that acts on behalf of a caller (its execute_tool declares
          ``user_id``, #563/#564) is refused: the orchestrator has no
          authenticated caller to authorize, so such a tool must be called
          through the API, where ``authorize_tool_call`` runs.
        """
        
        # Validate tool name against whitelist
        if tool_name not in self.available_tools:
            raise HTTPException(
                status_code=403,
                detail=f"Tool '{tool_name}' not authorized. Available tools: {', '.join(self.available_tools)}"
            )
        
        # Validate parameters for security
        if not self._validate_tool_parameters(tool_name, parameters):
            raise HTTPException(
                status_code=400,
                detail="Invalid or unsafe parameters detected"
            )
        
        try:
            # Dynamic import of the tool module
            tool_module_path = f"app.tools.{tool_name}.main"
            
            if tool_module_path not in sys.modules:
                tool_module = importlib.import_module(tool_module_path)
            else:
                tool_module = sys.modules[tool_module_path]
            
            # Execute the tool's main function
            if not hasattr(tool_module, 'execute_tool'):
                raise HTTPException(
                    status_code=501,
                    detail=f"Tool '{tool_name}' missing execute_tool function"
                )
            
            execute_func = tool_module.execute_tool
            if tool_acts_for_caller(execute_func):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Tool '{tool_name}' acts on behalf of a caller and cannot run "
                        "as a workflow step; call it through the API"
                    ),
                )

            # Validate the parameters with the tool's input model, then
            # apply the target policy the API applies: the SSRF guard on
            # every URL and the network target policy on the tool's host,
            # address and range fields (#614). It resolves names, so it runs
            # in a thread.
            tool_input = self._create_tool_input(tool_name, parameters)
            try:
                await asyncio.to_thread(enforce_target_policy, tool_name, tool_input)
            except TargetRefused as e:
                raise HTTPException(status_code=400, detail=f"Blocked target: {e}")

            result = execute_func(tool_input)
            if inspect.isawaitable(result):
                result = await result

            return {
                "success": True,
                "result": result,
                "tool_name": tool_name,
                "execution_time": datetime.now().isoformat()
            }
                
        except HTTPException:
            raise
        except ImportError as e:
            raise HTTPException(
                status_code=404,
                detail=f"Tool '{tool_name}' not found: {str(e)}"
            )
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(
                status_code=422,
                detail=f"Tool execution failed due to invalid input: {str(e)}"
            )
        except (ConnectionError, TimeoutError) as e:
            raise HTTPException(
                status_code=503,
                detail=f"Tool execution failed due to service unavailability: {str(e)}"
            )
        except Exception as e:
            # Log unexpected errors and re-raise as 500
            import logging
            logging.error(f"Unexpected error executing tool {tool_name}: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Internal error executing tool: {type(e).__name__}"
            )
    
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
        """Validate ``parameters`` with the tool's input model.

        The model is found the way the API finds it: a pydantic model in the
        tool's schemas module whose name contains "input" or "request",
        other than the shared ``BaseToolInput``. This used to take the first
        name ending in "Input", which is ``BaseToolInput`` for every tool
        that imports it, and fell back to the raw dict when nothing matched;
        either way the tool's own field validation did not run.
        """
        try:
            schema_module = importlib.import_module(f"app.tools.{tool_name}.schemas")
        except ImportError as e:
            raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' has no input schema: {e}")

        # The model the tool's own endpoint validates with, found the same way
        # (#611).
        input_class, _ = find_schema_classes(schema_module)

        if input_class is None:
            raise HTTPException(status_code=422, detail=f"Tool '{tool_name}' has no input schema")
        try:
            return input_class(**parameters)
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid parameters for '{tool_name}': {e}")

    def _remove_mock_output_method(self):
        """This method replaces the old mock output generation"""
        pass

    async def _generate_automation_metrics(self) -> AutomationMetrics:
        """Generate real automation metrics from execution history"""
        # This service keeps no execution history (no database/log store), so
        # cross-run metrics cannot be computed. Return zeros rather than
        # fabricated counts, so a consumer sees "no history available", not a
        # made-up throughput figure.
        return AutomationMetrics(
            total_executions=0,
            successful_executions=0,
            failed_executions=0,
            average_execution_time="not tracked (no execution history store)",
            most_used_tools=[],
            error_patterns=[],
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
        """Describe when this workflow would run again.

        This service has no scheduler: it executes a workflow on request and
        returns. Rather than invent a next-run timestamp (the previous code
        returned now + 1 day for "schedule"), state plainly that scheduling
        must be driven externally.
        """
        return (
            "This service does not schedule runs; trigger the workflow "
            "externally (cron, CI, or the responder service)."
        )

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
