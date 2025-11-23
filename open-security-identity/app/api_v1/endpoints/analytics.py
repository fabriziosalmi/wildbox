"""
Analytics endpoints for system-wide metrics and usage statistics.
"""

from datetime import datetime, timedelta
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload

from ...database import get_db
from ...models import User, Team, TeamMembership, ApiKey, Subscription, TeamRole
from ...user_manager import current_active_user
from ...schemas import UserResponse

router = APIRouter()


@router.get("/admin/system-stats")
async def get_system_analytics(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze")
):
    """
    Get system-wide analytics and usage statistics.
    
    Requires: Super admin access
    """
    # Check if user is superuser
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    
    # Calculate date ranges
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    yesterday = now - timedelta(days=1)
    last_week = now - timedelta(days=7)
    last_month = now - timedelta(days=30)
    
    try:
        # User Analytics
        total_users = await db.execute(select(func.count(User.id)))
        total_users = total_users.scalar() or 0
        
        active_users = await db.execute(
            select(func.count(User.id)).filter(User.is_active == True)
        )
        active_users = active_users.scalar() or 0
        
        super_admins = await db.execute(
            select(func.count(User.id)).filter(User.is_superuser == True)
        )
        super_admins = super_admins.scalar() or 0
        
        # New users this week
        new_users_week = await db.execute(
            select(func.count(User.id)).filter(User.created_at >= last_week)
        )
        new_users_week = new_users_week.scalar() or 0
        
        # New users today
        new_users_today = await db.execute(
            select(func.count(User.id)).filter(User.created_at >= yesterday)
        )
        new_users_today = new_users_today.scalar() or 0
        
        # Team Analytics
        total_teams = await db.execute(select(func.count(Team.id)))
        total_teams = total_teams.scalar() or 0
        
        # Active teams (teams with active subscriptions)
        active_teams = await db.execute(
            select(func.count(Team.id.distinct())).select_from(Team)
            .join(Subscription, Team.id == Subscription.team_id)
            .filter(Subscription.status == 'active')
        )
        active_teams = active_teams.scalar() or 0
        
        # API Key Analytics
        total_api_keys = await db.execute(select(func.count(ApiKey.id)))
        total_api_keys = total_api_keys.scalar() or 0
        
        active_api_keys = await db.execute(
            select(func.count(ApiKey.id)).filter(ApiKey.is_active == True)
        )
        active_api_keys = active_api_keys.scalar() or 0
        
        # API keys used in last 24 hours
        api_keys_used_today = await db.execute(
            select(func.count(ApiKey.id)).filter(
                and_(
                    ApiKey.is_active == True,
                    ApiKey.last_used_at >= yesterday
                )
            )
        )
        api_keys_used_today = api_keys_used_today.scalar() or 0
        
        # Subscription Analytics
        subscription_stats = await db.execute(
            select(
                Subscription.plan_id,
                func.count(Subscription.id).label('count')
            ).filter(
                Subscription.status == 'active'
            ).group_by(Subscription.plan_id)
        )
        
        plan_distribution = {}
        for plan, count in subscription_stats:
            plan_distribution[plan] = count
        
        # Growth metrics (compare with previous period)
        prev_period_start = start_date - timedelta(days=days)
        
        prev_users = await db.execute(
            select(func.count(User.id)).filter(User.created_at < start_date)
        )
        prev_users = prev_users.scalar() or 0
        
        user_growth_rate = 0.0
        if prev_users > 0:
            current_period_users = total_users - prev_users
            user_growth_rate = (current_period_users / prev_users) * 100
        
        # Team member statistics
        team_membership_stats = await db.execute(
            select(
                TeamMembership.role,
                func.count(TeamMembership.user_id).label('count')
            ).group_by(TeamMembership.role)
        )
        
        role_distribution = {}
        for role, count in team_membership_stats:
            role_name = role.value if hasattr(role, 'value') else str(role)
            role_distribution[role_name] = count
        
        # Recent activity metrics
        recent_logins = await db.execute(
            select(func.count(User.id.distinct())).filter(
                User.updated_at >= yesterday  # Approximation for recent login activity
            )
        )
        recent_logins = recent_logins.scalar() or 0
        
        # System health indicators
        inactive_users = total_users - active_users
        inactive_percentage = (inactive_users / max(total_users, 1)) * 100
        
        # API usage approximation (based on key activity)
        estimated_api_requests_today = api_keys_used_today * 50  # Rough estimate
        estimated_api_requests_week = active_api_keys * 200  # Rough estimate
        
        return {
            "period_days": days,
            "generated_at": now.isoformat(),
            
            # User metrics
            "users": {
                "total": total_users,
                "active": active_users,
                "inactive": inactive_users,
                "super_admins": super_admins,
                "new_this_week": new_users_week,
                "new_today": new_users_today,
                "growth_rate_percent": round(user_growth_rate, 2),
                "inactive_percentage": round(inactive_percentage, 2),
                "recent_logins": recent_logins
            },
            
            # Team metrics
            "teams": {
                "total": total_teams,
                "active": active_teams,
                "average_members": round(total_users / max(total_teams, 1), 1)
            },
            
            # API metrics
            "api_usage": {
                "total_keys": total_api_keys,
                "active_keys": active_api_keys,
                "keys_used_today": api_keys_used_today,
                "estimated_requests_today": estimated_api_requests_today,
                "estimated_requests_week": estimated_api_requests_week
            },
            
            # Subscription metrics
            "subscriptions": {
                "plan_distribution": plan_distribution,
                "total_active": sum(plan_distribution.values())
            },
            
            # Role distribution
            "roles": {
                "distribution": role_distribution
            },
            
            # System health
            "health": {
                "user_activation_rate": round(((active_users / max(total_users, 1)) * 100), 2),
                "api_key_utilization": round(((api_keys_used_today / max(active_api_keys, 1)) * 100), 2),
                "team_engagement": round(((active_teams / max(total_teams, 1)) * 100), 2)
            }
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate analytics: {str(e)}"
        )


@router.get("/admin/user-activity")
async def get_user_activity_metrics(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
    days: int = Query(7, ge=1, le=30, description="Number of days to analyze")
):
    """
    Get detailed user activity metrics.
    
    Requires: Super admin access
    """
    # Check if user is superuser
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    
    # Calculate date ranges
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    
    try:
        # Daily user registration over the period
        daily_registrations = await db.execute(
            select(
                func.date(User.created_at).label('date'),
                func.count(User.id).label('count')
            ).filter(
                User.created_at >= start_date
            ).group_by(func.date(User.created_at))
            .order_by(func.date(User.created_at))
        )
        
        registration_timeline = []
        for date, count in daily_registrations:
            registration_timeline.append({
                "date": date.isoformat(),
                "registrations": count
            })
        
        # Most active teams (by member count)
        active_teams = await db.execute(
            select(
                Team.name,
                func.count(TeamMembership.user_id).label('member_count')
            ).select_from(Team)
            .join(TeamMembership, Team.id == TeamMembership.team_id)
            .group_by(Team.id, Team.name)
            .order_by(func.count(TeamMembership.user_id).desc())
            .limit(10)
        )
        
        top_teams = []
        for team_name, member_count in active_teams:
            top_teams.append({
                "team_name": team_name,
                "member_count": member_count
            })
        
        return {
            "period_days": days,
            "generated_at": now.isoformat(),
            "registration_timeline": registration_timeline,
            "top_teams": top_teams
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate user activity metrics: {str(e)}"
        )


@router.get("/admin/usage-summary")
async def get_usage_summary(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a quick usage summary for dashboard display.
    
    Requires: Super admin access
    """
    # Check if user is superuser
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    
    # Calculate date ranges
    now = datetime.utcnow()
    today = now - timedelta(days=1)
    
    try:
        # Quick stats for dashboard
        total_users = await db.execute(select(func.count(User.id)))
        total_users = total_users.scalar() or 0
        
        active_users = await db.execute(
            select(func.count(User.id)).filter(User.is_active == True)
        )
        active_users = active_users.scalar() or 0
        
        total_teams = await db.execute(select(func.count(Team.id)))
        total_teams = total_teams.scalar() or 0
        
        active_api_keys = await db.execute(
            select(func.count(ApiKey.id)).filter(
                and_(
                    ApiKey.is_active == True,
                    ApiKey.last_used_at >= today
                )
            )
        )
        active_api_keys = active_api_keys.scalar() or 0
        
        # Estimate API requests (active keys * average usage)
        estimated_requests_today = active_api_keys * 75  # Conservative estimate
        
        return {
            "generated_at": now.isoformat(),
            "summary": {
                "total_users": total_users,
                "active_users": active_users,
                "total_teams": total_teams,
                "api_requests_today": estimated_requests_today,
                "api_keys_active": active_api_keys
            }
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate usage summary: {str(e)}"
        )
