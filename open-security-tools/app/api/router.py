"""Main API router for security tools."""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import Dict, Any, List
from app.auth import verify_api_key
from app.execution_manager import ToolExecutionManager
from app.logging_config import get_logger

logger = get_logger(__name__)

# Initialize the execution manager
execution_manager = ToolExecutionManager()

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
    tool_info = getattr(tool_module, 'TOOL_INFO', {})
    
    # Get schema information if available
    schemas_module = getattr(tool_module, 'schemas', None)
    input_schema = None
    output_schema = None
    
    if schemas_module:
        # Try to get input and output schemas
        for attr_name in dir(schemas_module):
            attr = getattr(schemas_module, attr_name)
            if hasattr(attr, '__name__') and 'Input' in attr.__name__:
                input_schema = attr.model_json_schema() if hasattr(attr, 'model_json_schema') else None
            elif hasattr(attr, '__name__') and 'Output' in attr.__name__:
                output_schema = attr.model_json_schema() if hasattr(attr, 'model_json_schema') else None
    
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
    input_schema_class = None
    output_schema_class = None
    
    # Import BaseModel for isinstance check
    from pydantic import BaseModel
    
    for attr_name in dir(schemas_module):
        try:
            attr = getattr(schemas_module, attr_name)
            # Check if it's a Pydantic BaseModel subclass (not the base class itself)
            if (isinstance(attr, type) and 
                issubclass(attr, BaseModel) and 
                attr is not BaseModel):
                attr_name_lower = attr.__name__.lower()
                # Prioritize tool-specific schemas
                if 'input' in attr_name_lower or 'request' in attr_name_lower:
                    # Skip base classes
                    if attr.__name__ not in ('BaseToolInput',):
                        input_schema_class = attr
                elif 'output' in attr_name_lower or 'response' in attr_name_lower:
                    # Skip base classes
                    if attr.__name__ not in ('BaseToolOutput',):
                        output_schema_class = attr
        except (TypeError, AttributeError):
            # Skip non-class attributes
            continue
    
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
        api_key: str = Depends(verify_api_key)
    ):
        """Dynamically created endpoint for the security tool."""
        
        # Validate input data using the schema
        try:
            validated_input = input_schema_class(**input_data)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Input validation failed for {tool_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Input validation failed: {str(e)}"
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
                timeout=getattr(validated_input, 'timeout', None)
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
            elif execution_result.status.value == "timeout":
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Tool execution timed out: {execution_result.error}"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Tool execution failed: {execution_result.error}"
                )
                
        except HTTPException:
            raise
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Tool execution failed: {tool_name}", extra={
                "tool": tool_name,
                "error": str(e),
                "request_id": getattr(request.state, 'request_id', 'unknown')
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Tool execution failed: {str(e)}"
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
