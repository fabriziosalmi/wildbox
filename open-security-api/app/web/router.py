"""Web interface router for the security API."""

from fastapi import APIRouter, Request, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from typing import Dict, Any
from app.logging_config import get_logger
from app.config import settings

logger = get_logger(__name__)

# Create router for web interface
router = APIRouter(tags=["Web Interface"])

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="app/web/templates")

# This will be populated by the main application
DISCOVERED_TOOLS: Dict[str, Any] = {}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Main dashboard showing available security tools.
    
    Args:
        request: FastAPI request object
        
    Returns:
        HTML response with the main dashboard
    """
    logger.info("Serving main dashboard")
    
    # Prepare tools data for template
    tools_data = []
    for tool_name, tool_module in DISCOVERED_TOOLS.items():
        tool_info = getattr(tool_module, 'TOOL_INFO', {})
        tools_data.append({
            "name": tool_name,
            "display_name": tool_info.get("display_name", tool_name.replace("_", " ").title()),
            "description": tool_info.get("description", "No description available"),
            "version": tool_info.get("version", "unknown"),
            "author": tool_info.get("author", "unknown"),
            "category": tool_info.get("category", "general"),
            "url": f"/tools/{tool_name}"
        })
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "tools": tools_data,
        "title": "Wildbox Security API",
        "api_key": settings.get_api_key()
    })


@router.get("/tools/{tool_name}", response_class=HTMLResponse)
async def tool_page(request: Request, tool_name: str):
    """
    Individual tool interaction page.
    
    Args:
        request: FastAPI request object
        tool_name: Name of the security tool
        
    Returns:
        HTML response with tool interaction form
    """
    if tool_name not in DISCOVERED_TOOLS:
        logger.warning(f"Tool not found: {tool_name}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_name}' not found"
        )
    
    tool_module = DISCOVERED_TOOLS[tool_name]
    tool_info = getattr(tool_module, 'TOOL_INFO', {})
    
    # Get input schema for form generation
    schemas_module = getattr(tool_module, 'schemas', None)
    input_schema = None
    
    if schemas_module:
        for attr_name in dir(schemas_module):
            attr = getattr(schemas_module, attr_name)
            if (hasattr(attr, '__bases__') and 
                any(base.__name__ == 'BaseModel' for base in attr.__bases__) and
                'Input' in attr.__name__):
                input_schema = attr.schema() if hasattr(attr, 'schema') else None
                break
    
    logger.info(f"Serving tool page: {tool_name}")
    
    return templates.TemplateResponse("tool.html", {
        "request": request,
        "tool_name": tool_name,
        "tool_info": tool_info,
        "input_schema": input_schema,
        "title": f"{tool_info.get('display_name', tool_name)} - Wildbox Security API",
        "api_key": settings.get_api_key()
    })


@router.get("/docs", response_class=HTMLResponse)
async def documentation(request: Request):
    """
    Documentation page with API usage examples.
    
    Args:
        request: FastAPI request object
        
    Returns:
        HTML response with documentation
    """
    logger.info("Serving documentation page")
    
    return templates.TemplateResponse("docs.html", {
        "request": request,
        "title": "API Documentation - Wildbox Security API"
    })
