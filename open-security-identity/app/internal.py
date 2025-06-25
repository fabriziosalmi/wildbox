"""
Internal API endpoints for service-to-service communication.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .database import get_db
from .models import User, Team, TeamMembership, ApiKey, Subscription
from .schemas import AuthorizationResponse
from .auth import authenticate_api_key

router = APIRouter()


@router.post("/authorize", response_model=AuthorizationResponse)
async def authorize_request(
    auth_data: dict = Depends(authenticate_api_key)
):
    """
    Internal endpoint for API Gateway to authorize requests.
    
    This endpoint validates API keys and returns user/team information
    with permissions and rate limits for the API Gateway to make decisions.
    
    Returns:
        Authorization response with user info, permissions, and rate limits
    """
    return AuthorizationResponse(**auth_data)
