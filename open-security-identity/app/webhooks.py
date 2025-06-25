"""
Stripe webhook handlers.
"""

import json
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_db
from .models import Subscription, Team, SubscriptionStatus, SubscriptionPlan
from .billing import billing_service

router = APIRouter()


@router.post("/stripe")
async def handle_stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle Stripe webhook events.
    
    Processes subscription events and updates our database accordingly.
    """
    # Get the payload and signature
    payload = await request.body()
    signature = request.headers.get('stripe-signature')
    
    if not signature:
        raise HTTPException(status_code=400, detail="Missing Stripe signature")
    
    # Verify the webhook signature
    event = billing_service.verify_webhook_signature(payload, signature)
    
    # Handle different event types
    event_type = event['type']
    event_data = event['data']['object']
    
    try:
        if event_type == 'checkout.session.completed':
            await handle_checkout_completed(event_data, db)
        
        elif event_type == 'customer.subscription.created':
            await handle_subscription_created(event_data, db)
        
        elif event_type == 'customer.subscription.updated':
            await handle_subscription_updated(event_data, db)
        
        elif event_type == 'customer.subscription.deleted':
            await handle_subscription_deleted(event_data, db)
        
        elif event_type == 'invoice.payment_succeeded':
            await handle_payment_succeeded(event_data, db)
        
        elif event_type == 'invoice.payment_failed':
            await handle_payment_failed(event_data, db)
        
        else:
            # Log unknown event type but don't fail
            print(f"Unhandled webhook event type: {event_type}")
    
    except Exception as e:
        print(f"Error processing webhook {event_type}: {str(e)}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")
    
    return {"status": "success"}


async def handle_checkout_completed(session_data: dict, db: AsyncSession):
    """Handle successful checkout session completion."""
    team_id = session_data.get('metadata', {}).get('team_id')
    plan_id = session_data.get('metadata', {}).get('plan_id')
    subscription_id = session_data.get('subscription')
    
    if not all([team_id, plan_id, subscription_id]):
        print("Missing required metadata in checkout session")
        return
    
    # Update subscription in our database
    result = await db.execute(
        select(Subscription).where(Subscription.team_id == team_id)
    )
    subscription = result.scalar_one_or_none()
    
    if subscription:
        subscription.stripe_subscription_id = subscription_id
        subscription.plan_id = plan_id
        subscription.status = SubscriptionStatus.ACTIVE
        await db.commit()
    else:
        print(f"Subscription not found for team {team_id}")


async def handle_subscription_created(subscription_data: dict, db: AsyncSession):
    """Handle new subscription creation."""
    subscription_id = subscription_data.get('id')
    customer_id = subscription_data.get('customer')
    status = subscription_data.get('status')
    current_period_end = datetime.fromtimestamp(
        subscription_data.get('current_period_end', 0)
    )
    
    # Find the subscription by customer ID (through team owner)
    result = await db.execute(
        select(Subscription, Team)
        .join(Team, Subscription.team_id == Team.id)
        .join(Team.owner)
        .where(Team.owner.has(stripe_customer_id=customer_id))
    )
    row = result.first()
    
    if row:
        subscription, team = row
        subscription.stripe_subscription_id = subscription_id
        subscription.status = SubscriptionStatus(status)
        subscription.current_period_end = current_period_end
        await db.commit()


async def handle_subscription_updated(subscription_data: dict, db: AsyncSession):
    """Handle subscription updates (plan changes, status changes)."""
    subscription_id = subscription_data.get('id')
    status = subscription_data.get('status')
    current_period_end = datetime.fromtimestamp(
        subscription_data.get('current_period_end', 0)
    )
    
    # Find subscription by Stripe ID
    result = await db.execute(
        select(Subscription)
        .where(Subscription.stripe_subscription_id == subscription_id)
    )
    subscription = result.scalar_one_or_none()
    
    if subscription:
        subscription.status = SubscriptionStatus(status)
        subscription.current_period_end = current_period_end
        await db.commit()


async def handle_subscription_deleted(subscription_data: dict, db: AsyncSession):
    """Handle subscription cancellation."""
    subscription_id = subscription_data.get('id')
    
    # Find and cancel subscription
    result = await db.execute(
        select(Subscription)
        .where(Subscription.stripe_subscription_id == subscription_id)
    )
    subscription = result.scalar_one_or_none()
    
    if subscription:
        subscription.status = SubscriptionStatus.CANCELED
        # Downgrade to free plan
        subscription.plan_id = SubscriptionPlan.FREE
        await db.commit()


async def handle_payment_succeeded(invoice_data: dict, db: AsyncSession):
    """Handle successful payment."""
    subscription_id = invoice_data.get('subscription')
    
    if subscription_id:
        # Update subscription status to active
        result = await db.execute(
            select(Subscription)
            .where(Subscription.stripe_subscription_id == subscription_id)
        )
        subscription = result.scalar_one_or_none()
        
        if subscription:
            subscription.status = SubscriptionStatus.ACTIVE
            await db.commit()


async def handle_payment_failed(invoice_data: dict, db: AsyncSession):
    """Handle failed payment."""
    subscription_id = invoice_data.get('subscription')
    
    if subscription_id:
        # Update subscription status
        result = await db.execute(
            select(Subscription)
            .where(Subscription.stripe_subscription_id == subscription_id)
        )
        subscription = result.scalar_one_or_none()
        
        if subscription:
            subscription.status = SubscriptionStatus.PAST_DUE
            await db.commit()
            
        # Here you might want to send notification to the user
        # about the failed payment
