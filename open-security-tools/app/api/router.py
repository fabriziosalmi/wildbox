"""Main API router for security tools."""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import Dict, Any, List
from open_security_shared.errors import field_errors
from open_security_shared.gateway_auth import GatewayUser
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.auth import require_tools_execute, verify_api_key
from app.execution_manager import execution_manager
from app.logging_config import get_logger
from app.security.rate_limit import UNAVAILABLE_MESSAGE, RateLimitUnavailable
from app.target_policy import TargetRefused, enforce_target_policy
from app.tool_loader import find_schema_classes

logger = get_logger(__name__)

# The process's one execution manager (app.execution_manager), the same
# object app.main reads for /health and cancels at shutdown. This module used
# to build a second ToolExecutionManager of its own, so every tool ran
# through a manager that /health never looked at: active_executions was
# always 0, and shutdown cancelled nothing (#646).

# Create the main API router
router = APIRouter(prefix="/api", tags=["Security Tools"])

# This will be populated by the main application with discovered tools
DISCOVERED_TOOLS: Dict[str, Any] = {}


@router.get("/tools", response_model=List[Dict[str, Any]])
async def list_tools(request: Request, api_key: str = Depends(verify_api_key)):
    """
    List all available security tools.
    
    Returns:
        List of available tools with their metadata
    """
    logger.info("Listing available security tools")
    
    tools_list = []
    for tool_name, tool_module in DISCOVERED_TOOLS.items():
        tool_info = getattr(tool_module, 'TOOL_INFO', {})
        tools_list.append({
            "name": tool_name,
            "display_name": tool_info.get("display_name", tool_name.replace("_", " ").title()),
            "description": tool_info.get("description", "No description available"),
            "version": tool_info.get("version", "unknown"),
            "author": tool_info.get("author", "unknown"),
            "category": tool_info.get("category", "general"),
            "endpoint": f"/api/tools/{tool_name}"
        })
    
    return tools_list


@router.get("/tools/{tool_name}/info")
async def get_tool_info(tool_name: str, request: Request, api_key: str = Depends(verify_api_key)):
    """
    Get detailed information about a specific tool.
    
    Args:
        tool_name: Name of the tool to get information for
        
    Returns:
        Detailed tool information including schemas
    """
    if tool_name not in DISCOVERED_TOOLS:
        logger.warning(f"Tool not found: {tool_name}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_name}' not found"
        )
    
    tool_module = DISCOVERED_TOOLS[tool_name]
    # Metadata only: some tools also list their classes here ("tool_class",
    # "input_schema"), which cannot be serialised, so their /info was a 500
    # and the dashboard could not build their form (#611).
    tool_info = {
        key: value
        for key, value in getattr(tool_module, 'TOOL_INFO', {}).items()
        if not isinstance(value, type) and not callable(value)
    }

    # Get schema information if available
    schemas_module = getattr(tool_module, 'schemas', None)
    input_schema = None
    output_schema = None
    
    if schemas_module:
        # The same models the tool endpoint validates and answers with (#611).
        input_cls, output_cls = find_schema_classes(schemas_module)
        if input_cls is not None:
            input_schema = input_cls.model_json_schema()
        if output_cls is not None:
            output_schema = output_cls.model_json_schema()
    
    return {
        **tool_info,
        "name": tool_name,
        "endpoint": f"/api/tools/{tool_name}",
        "input_schema": input_schema,
        "output_schema": output_schema
    }


def register_tool_endpoint(app, tool_name: str, tool_module: Any):
    """
    Dynamically register an endpoint for a tool.
    
    Args:
        app: FastAPI application instance
        tool_name: Name of the tool
        tool_module: Tool module containing the implementation
    """
    
    # Get the schemas
    schemas_module = getattr(tool_module, 'schemas', None)
    if not schemas_module:
        logger.error(f"No schemas module found for tool: {tool_name}")
        return
    
    # Find input and output schema classes
    input_schema_class, output_schema_class = find_schema_classes(schemas_module)

    logger.info(f"Tool {tool_name}: Found Input={input_schema_class.__name__ if input_schema_class else None}, Output={output_schema_class.__name__ if output_schema_class else None}")
    
    if not input_schema_class or not output_schema_class:
        logger.error(f"Could not find input/output schemas for tool: {tool_name}")
        return
    
    # Get the execute function
    execute_func = getattr(tool_module, 'execute_tool', None)
    if not execute_func:
        logger.error(f"No execute_tool function found for tool: {tool_name}")
        return
    
    # Create the endpoint function using Body for explicit JSON parsing
    from fastapi import Body
    
    async def tool_endpoint(
        request: Request,
        input_data: dict = Body(...),
        # Running a tool: tools:execute, checked here as at the gateway (#637).
        caller: GatewayUser = Depends(require_tools_execute)
    ):
        """Dynamically created endpoint for the security tool."""
        
        # Validate input data using the schema
        try:
            validated_input = input_schema_class(**input_data)
        except ValidationError as e:
            # Which fields failed and why, so a client can point at them
            # (#585). The submitted values are not echoed back: a field may
            # hold a credential. The reduction is the one every service
            # shares (open_security_shared.errors.field_errors); this module
            # had a copy of its own (#735). The log gets the same reduction:
            # str() of the error, which it used to get, quotes every value
            # that was refused.
            errors = field_errors(e.errors())
            logger.error(
                f"Input validation failed for {tool_name}",
                extra={"tool": tool_name, "errors": errors},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "reason": "Input validation failed",
                    "errors": errors,
                },
            )
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            # The class, not the text: the text of an error raised while a
            # model is built can quote what it was built from.
            logger.error(
                f"Input validation failed for {tool_name}: {type(e).__name__}"
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Input validation failed"
            )

        # Target policy: refuse to let a tool connect to private, internal or
        # cloud-metadata targets, whether it fetches a URL (SSRF guard) or
        # scans a host, address or range (#614), before the tool runs. It
        # resolves names, so it runs off the event loop.
        try:
            await run_in_threadpool(enforce_target_policy, tool_name, validated_input)
        except TargetRefused as e:
            logger.warning(f"Refused target for {tool_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

        logger.info(f"Executing tool: {tool_name}", extra={
            "tool": tool_name,
            "input": validated_input.model_dump(),
            "request_id": getattr(request.state, 'request_id', 'unknown')
        })
        
        try:
            # Execute tool with the execution manager
            execution_result = await execution_manager.execute_tool(
                tool_func=execute_func,
                input_data=validated_input,
                tool_name=tool_name,
                timeout=getattr(validated_input, 'timeout', None),
                # Tie the execution to the request so logs, metrics and the
                # execution registry share one id (WILDBO-CONC-01/OBS-05).
                execution_id=getattr(request.state, 'request_id', None),
                # The caller the request authenticated as. Tools that act on a
                # caller's behalf receive it and are authorized for it; they
                # refused every API execution while it was not passed (#563).
                user_id=str(caller.user_id),
            )
            
            if execution_result.status.value == "completed":
                logger.info(f"Tool execution completed: {tool_name}", extra={
                    "tool": tool_name,
                    "status": execution_result.status.value,
                    "duration": execution_result.duration,
                    "request_id": getattr(request.state, 'request_id', 'unknown')
                })
                
                # Enrich result with tool metadata
                result_data = execution_result.result
                if hasattr(result_data, 'model_dump'):
                    # Pydantic model - update fields
                    result_dict = result_data.model_dump()
                    result_dict['tool_name'] = tool_name
                    result_dict['execution_time'] = execution_result.duration
                    return output_schema_class(**result_dict)
                elif isinstance(result_data, dict):
                    # Dict - add metadata
                    result_data['tool_name'] = tool_name
                    result_data['execution_time'] = execution_result.duration
                    return output_schema_class(**result_data)
                else:
                    # Unknown type, return as is
                    return result_data
            elif execution_result.status.value == "refused":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=execution_result.error
                )
            elif execution_result.status.value == "timeout":
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="Tool execution timed out"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Tool execution failed"
                )
                
        except HTTPException:
            raise
        except RateLimitUnavailable as e:
            # The caller's hourly allowance is counted in Redis and Redis did
            # not answer. The tool was not started: a run that cannot be
            # counted is refused, and the caller can retry (#721).
            logger.error(f"Rate limit unavailable for {tool_name}: {e.reason}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=UNAVAILABLE_MESSAGE,
            )
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Tool execution failed: {tool_name}", extra={
                "tool": tool_name,
                "error": str(e),
                "request_id": getattr(request.state, 'request_id', 'unknown')
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tool execution failed"
            )
    
    # Add the endpoint to the router
    tool_info = getattr(tool_module, 'TOOL_INFO', {})
    router.post(
        f"/tools/{tool_name}",
        response_model=output_schema_class,
        summary=f"Execute {tool_info.get('display_name', tool_name)}",
        description=tool_info.get('description', f'Execute the {tool_name} security tool'),
        tags=[tool_info.get('category', 'general')]
    )(tool_endpoint)
