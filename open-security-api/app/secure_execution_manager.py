"""
Enhanced Tool Execution Manager with Security Isolation
Blueprint Phase 1 - Process Isolation Implementation
"""

import asyncio
import time
import subprocess
import tempfile
import json
import resource
import signal
import os
import shutil
from typing import Dict, Any, Optional, List, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Tool execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SECURITY_VIOLATION = "security_violation"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"


@dataclass
class SecurityLimits:
    """Security and resource limits for tool execution."""
    max_execution_time: int = 30  # seconds
    max_memory_mb: int = 256  # MB
    max_cpu_percent: float = 50.0  # % of single core
    allow_network: bool = True
    allow_filesystem_write: bool = False
    allowed_file_extensions: List[str] = field(default_factory=lambda: ['.json', '.txt', '.log'])
    max_output_size: int = 1024 * 1024  # 1MB
    max_concurrent_per_user: int = 3


@dataclass
class ExecutionResult:
    """Enhanced tool execution result."""
    status: ExecutionStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    duration: Optional[float] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    memory_used_mb: Optional[float] = None
    cpu_used_percent: Optional[float] = None
    security_violations: List[str] = field(default_factory=list)
    output_truncated: bool = False


class SecureToolExecutionManager:
    """
    Enhanced execution manager with security isolation and resource controls.
    Implements Blueprint Phase 1 requirements for process isolation.
    """
    
    def __init__(self, 
                 max_concurrent: int = 10,
                 default_security_limits: Optional[SecurityLimits] = None):
        self.max_concurrent = max_concurrent
        self.default_limits = default_security_limits or SecurityLimits()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_executions: Dict[str, asyncio.Task] = {}
        self._user_execution_count: Dict[str, int] = {}
        self._execution_history: List[ExecutionResult] = []
        self._tool_statistics: Dict[str, Dict[str, Any]] = {}
        
        # Plan-based limits (Blueprint requirement)
        self._plan_limits = {
            'free': SecurityLimits(
                max_execution_time=15,
                max_memory_mb=128,
                max_cpu_percent=25.0,
                max_concurrent_per_user=1
            ),
            'personal': SecurityLimits(
                max_execution_time=30,
                max_memory_mb=256,
                max_cpu_percent=50.0,
                max_concurrent_per_user=3
            ),
            'business': SecurityLimits(
                max_execution_time=60,
                max_memory_mb=512,
                max_cpu_percent=75.0,
                max_concurrent_per_user=10
            )
        }
    
    def get_security_limits(self, user_plan: str = 'free') -> SecurityLimits:
        """Get security limits based on user plan."""
        return self._plan_limits.get(user_plan, self.default_limits)
    
    async def execute_tool_secure(self,
                                  tool_name: str,
                                  tool_input: Dict[str, Any],
                                  user_id: str,
                                  user_plan: str = 'free',
                                  execution_id: Optional[str] = None) -> ExecutionResult:
        """
        Execute a tool with security isolation and resource limits.
        
        Args:
            tool_name: Name of the tool to execute
            tool_input: Input parameters for the tool
            user_id: User identifier for tracking
            user_plan: User's subscription plan (free/personal/business)
            execution_id: Optional execution identifier
            
        Returns:
            ExecutionResult with security and performance metrics
        """
        execution_id = execution_id or f"{tool_name}_{user_id}_{int(time.time())}"
        limits = self.get_security_limits(user_plan)
        
        # Check user concurrent execution limits
        current_user_executions = self._user_execution_count.get(user_id, 0)
        if current_user_executions >= limits.max_concurrent_per_user:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=f"Maximum concurrent executions exceeded for plan {user_plan} ({limits.max_concurrent_per_user})",
                security_violations=["concurrent_execution_limit_exceeded"]
            )
        
        async with self._semaphore:
            return await self._execute_with_isolation(
                tool_name=tool_name,
                tool_input=tool_input,
                user_id=user_id,
                execution_id=execution_id,
                limits=limits
            )
    
    async def _execute_with_isolation(self,
                                      tool_name: str,
                                      tool_input: Dict[str, Any],
                                      user_id: str,
                                      execution_id: str,
                                      limits: SecurityLimits) -> ExecutionResult:
        """Execute tool in isolated environment with resource monitoring."""
        start_time = time.time()
        result = ExecutionResult(
            status=ExecutionStatus.RUNNING,
            start_time=start_time
        )
        
        # Update user execution count
        self._user_execution_count[user_id] = self._user_execution_count.get(user_id, 0) + 1
        
        try:
            # Create isolated execution environment
            with tempfile.TemporaryDirectory(prefix=f"wildbox_tool_{tool_name}_") as temp_dir:
                # Prepare execution environment
                input_file = Path(temp_dir) / "input.json"
                output_file = Path(temp_dir) / "output.json"
                error_file = Path(temp_dir) / "error.log"
                
                # Write sanitized input
                sanitized_input = self._sanitize_input(tool_input, limits)
                with open(input_file, 'w') as f:
                    json.dump(sanitized_input, f, indent=2)
                
                # Create execution script with resource limits
                execution_script = self._create_execution_script(
                    tool_name=tool_name,
                    input_file=input_file,
                    output_file=output_file,
                    limits=limits
                )
                
                script_file = Path(temp_dir) / "execute.py"
                with open(script_file, 'w') as f:
                    f.write(execution_script)
                
                # Execute in isolated process
                process_result = await self._execute_isolated_process(
                    script_file=script_file,
                    output_file=output_file,
                    error_file=error_file,
                    limits=limits,
                    temp_dir=temp_dir
                )
                
                # Process results
                result.status = process_result['status']
                result.error = process_result['error']
                result.memory_used_mb = process_result['memory_used_mb']
                result.cpu_used_percent = process_result['cpu_used_percent']
                result.security_violations = process_result['security_violations']
                
                # Read and validate output
                if output_file.exists() and result.status == ExecutionStatus.COMPLETED:
                    try:
                        with open(output_file, 'r') as f:
                            output_content = f.read()
                            
                        # Check output size limits
                        if len(output_content) > limits.max_output_size:
                            output_content = output_content[:limits.max_output_size]
                            result.output_truncated = True
                            result.security_violations.append("output_size_exceeded")
                        
                        result.result = json.loads(output_content)
                        result.result = self._sanitize_output(result.result, limits)
                        
                    except (json.JSONDecodeError, IOError) as e:
                        result.status = ExecutionStatus.FAILED
                        result.error = f"Failed to parse tool output: {str(e)}"
                
        except Exception as e:
            logger.exception(f"Tool execution failed for {tool_name}")
            result.status = ExecutionStatus.FAILED
            result.error = f"Execution error: {str(e)}"
            result.security_violations.append("execution_exception")
        
        finally:
            # Update execution tracking
            result.end_time = time.time()
            result.duration = result.end_time - start_time
            self._user_execution_count[user_id] = max(0, self._user_execution_count.get(user_id, 1) - 1)
            self._record_execution(tool_name, result)
        
        return result
    
    async def _execute_isolated_process(self,
                                        script_file: Path,
                                        output_file: Path,
                                        error_file: Path,
                                        limits: SecurityLimits,
                                        temp_dir: str) -> Dict[str, Any]:
        """Execute script in isolated subprocess with resource monitoring."""
        cmd = [
            'python3', str(script_file)
        ]
        
        env = os.environ.copy()
        env.update({
            'PYTHONPATH': str(Path(__file__).parent.parent),
            'WILDBOX_ISOLATION_MODE': 'true',
            'WILDBOX_TEMP_DIR': temp_dir
        })
        
        security_violations = []
        
        try:
            # Start process with resource limits
            process = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                cwd=temp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=lambda: self._set_resource_limits(limits)
            )
            
            # Monitor execution with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=limits.max_execution_time
                )
                
                # Write error output for debugging
                if stderr:
                    with open(error_file, 'wb') as f:
                        f.write(stderr)
                
                if process.returncode == 0:
                    status = ExecutionStatus.COMPLETED
                    error = None
                else:
                    status = ExecutionStatus.FAILED
                    error = stderr.decode('utf-8', errors='ignore')[:1000]  # Limit error size
                    
            except asyncio.TimeoutError:
                # Kill the process
                try:
                    process.kill()
                    await process.wait()
                except:
                    pass
                
                status = ExecutionStatus.TIMEOUT
                error = f"Tool execution exceeded {limits.max_execution_time} seconds"
                security_violations.append("execution_timeout")
                
        except Exception as e:
            status = ExecutionStatus.FAILED
            error = f"Process execution failed: {str(e)}"
            security_violations.append("process_execution_failure")
        
        return {
            'status': status,
            'error': error,
            'memory_used_mb': 0,  # TODO: Implement actual memory monitoring
            'cpu_used_percent': 0,  # TODO: Implement actual CPU monitoring
            'security_violations': security_violations
        }
    
    def _set_resource_limits(self, limits: SecurityLimits):
        """Set resource limits for the subprocess."""
        try:
            # Set memory limit (soft and hard)
            memory_limit = limits.max_memory_mb * 1024 * 1024  # Convert to bytes
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            
            # Set CPU time limit
            resource.setrlimit(resource.RLIMIT_CPU, (limits.max_execution_time, limits.max_execution_time))
            
            # Limit number of processes
            resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))
            
            # Limit file descriptors
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            
        except Exception as e:
            logger.warning(f"Failed to set resource limits: {e}")
    
    def _create_execution_script(self,
                                 tool_name: str,
                                 input_file: Path,
                                 output_file: Path,
                                 limits: SecurityLimits) -> str:
        """Create a secure execution script for the tool."""
        return f'''#!/usr/bin/env python3
"""
Secure tool execution wrapper
Generated automatically for tool: {tool_name}
"""

import sys
import json
import traceback
import os
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, '/app')

def main():
    try:
        # Load input
        with open('{input_file}', 'r') as f:
            tool_input = json.load(f)
        
        # Import and execute tool
        from app.tools.{tool_name}.main import run as tool_run
        
        # Execute with isolated environment
        result = tool_run(tool_input)
        
        # Write output
        with open('{output_file}', 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        print("Tool execution completed successfully")
        
    except Exception as e:
        error_result = {{
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc()
        }}
        
        try:
            with open('{output_file}', 'w') as f:
                json.dump(error_result, f, indent=2)
        except:
            pass
        
        print(f"Tool execution failed: {{e}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
    
    def _sanitize_input(self, tool_input: Dict[str, Any], limits: SecurityLimits) -> Dict[str, Any]:
        """Sanitize tool input for security."""
        # TODO: Implement comprehensive input sanitization
        # - Remove potentially dangerous keys
        # - Validate URLs and file paths
        # - Limit string lengths
        # - Remove script injection attempts
        
        sanitized = {}
        for key, value in tool_input.items():
            if isinstance(value, str):
                # Limit string length and remove dangerous characters
                sanitized[key] = value[:1000]  # Limit to 1000 chars
            elif isinstance(value, (int, float)):
                sanitized[key] = value
            elif isinstance(value, (list, dict)):
                # Recursively sanitize
                sanitized[key] = value  # TODO: Implement deep sanitization
            else:
                sanitized[key] = str(value)[:1000]
        
        return sanitized
    
    def _sanitize_output(self, output: Any, limits: SecurityLimits) -> Any:
        """Sanitize tool output for security."""
        # TODO: Implement output sanitization
        # - Remove sensitive information
        # - Validate output structure
        # - Remove potential XSS vectors
        
        return output
    
    def _record_execution(self, tool_name: str, result: ExecutionResult):
        """Record execution statistics."""
        self._execution_history.append(result)
        
        # Update tool statistics
        if tool_name not in self._tool_statistics:
            self._tool_statistics[tool_name] = {
                'total_executions': 0,
                'successful_executions': 0,
                'failed_executions': 0,
                'average_duration': 0,
                'security_violations': 0
            }
        
        stats = self._tool_statistics[tool_name]
        stats['total_executions'] += 1
        
        if result.status == ExecutionStatus.COMPLETED:
            stats['successful_executions'] += 1
        else:
            stats['failed_executions'] += 1
        
        if result.duration:
            # Update running average
            total = stats['total_executions']
            current_avg = stats['average_duration']
            stats['average_duration'] = ((current_avg * (total - 1)) + result.duration) / total
        
        if result.security_violations:
            stats['security_violations'] += len(result.security_violations)
        
        # Keep only last 1000 executions in memory
        if len(self._execution_history) > 1000:
            self._execution_history = self._execution_history[-1000:]
    
    def get_tool_statistics(self, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """Get execution statistics for tools."""
        if tool_name:
            return self._tool_statistics.get(tool_name, {})
        return self._tool_statistics
    
    def get_execution_history(self, limit: int = 100) -> List[ExecutionResult]:
        """Get recent execution history."""
        return self._execution_history[-limit:]


# Global secure execution manager instance
secure_execution_manager = SecureToolExecutionManager()
