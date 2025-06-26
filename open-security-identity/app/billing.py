"""
Stripe billing integration service.
"""

import stripe
from typing import Dict, Any, Optional
from fastapi import HTTPException

from .config import settings
from .models import User, Team, Subscription, SubscriptionPlan

# Configure Stripe
stripe.api_key = settings.stripe_secret_key


class StripeBillingService:
    """Service class for managing Stripe billing operations."""
    
    def __init__(self):
        self.webhook_secret = settings.stripe_webhook_secret
        
        # Plan configuration - in production this should come from database
        self.plans = {
            SubscriptionPlan.PRO: {
                "price_id": "price_pro_monthly",  # Replace with actual Stripe price ID
                "name": "Pro Plan",
                "amount": 2900,  # $29.00 in cents
            },
            SubscriptionPlan.BUSINESS: {
                "price_id": "price_business_monthly",  # Replace with actual Stripe price ID  
                "name": "Business Plan",
                "amount": 9900,  # $99.00 in cents
            }
        }
    
    async def create_customer(self, user: User) -> str:
        """
        Create a Stripe customer for the user.
        
        Args:
            user: User object
            
        Returns:
            Stripe customer ID
            
        Raises:
            HTTPException: If Stripe operation fails
        """
        try:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={
                    "user_id": str(user.id),
                }
            )
            return customer.id
        except stripe.error.InvalidRequestError as e:
            raise HTTPException(status_code=400, detail=f"Invalid request to Stripe: {str(e)}")
        except stripe.error.AuthenticationError as e:
            raise HTTPException(status_code=500, detail="Stripe authentication failed")
        except stripe.error.APIConnectionError as e:
            raise HTTPException(status_code=503, detail="Unable to connect to Stripe")
        except stripe.error.StripeError as e:
            raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error creating customer: {str(e)}")
    
    async def create_checkout_session(
        self, 
        team: Team, 
        plan_id: SubscriptionPlan,
        success_url: str,
        cancel_url: str
    ) -> str:
        """
        Create a Stripe Checkout session for subscription.
        
        Args:
            team: Team object
            plan_id: Subscription plan ID
            success_url: URL to redirect on successful payment
            cancel_url: URL to redirect on cancelled payment
            
        Returns:
            Checkout session URL
        """
        if plan_id not in self.plans:
            raise HTTPException(status_code=400, detail="Invalid plan ID")
        
        plan = self.plans[plan_id]
        
        try:
            # Ensure team owner has a Stripe customer ID
            if not team.owner.stripe_customer_id:
                raise HTTPException(
                    status_code=400, 
                    detail="Customer not set up for billing"
                )
            
            session = stripe.checkout.Session.create(
                customer=team.owner.stripe_customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': plan['price_id'],
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'team_id': str(team.id),
                    'plan_id': plan_id.value,
                }
            )
            
            return session.url
            
        except stripe.error.StripeError as e:
            raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    
    async def create_customer_portal_session(self, team: Team, return_url: str) -> str:
        """
        Create a Stripe Customer Portal session.
        
        Args:
            team: Team object
            return_url: URL to return to after managing subscription
            
        Returns:
            Customer portal URL
        """
        try:
            if not team.owner.stripe_customer_id:
                raise HTTPException(
                    status_code=400,
                    detail="Customer not set up for billing"
                )
            
            session = stripe.billing_portal.Session.create(
                customer=team.owner.stripe_customer_id,
                return_url=return_url,
            )
            
            return session.url
            
        except stripe.error.StripeError as e:
            raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    
    async def report_usage(self, subscription_item_id: str, quantity: int) -> None:
        """
        Report usage for metered billing.
        
        Args:
            subscription_item_id: Stripe subscription item ID
            quantity: Usage quantity to report
        """
        try:
            stripe.SubscriptionItem.create_usage_record(
                subscription_item_id,
                quantity=quantity,
                action='increment',  # or 'set' for absolute values
            )
        except stripe.error.StripeError as e:
            raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """
        Verify Stripe webhook signature and return the event.
        
        Args:
            payload: Request payload bytes
            signature: Stripe signature header
            
        Returns:
            Stripe event dictionary
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
            return event
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")
    
    def get_plan_permissions(self, plan_id: SubscriptionPlan) -> list[str]:
        """
        Get permissions based on subscription plan.
        
        Args:
            plan_id: Subscription plan ID
            
        Returns:
            List of permission strings
        """
        permissions = ["tool:basic", "api:read"]  # Base permissions for all plans
        
        if plan_id == SubscriptionPlan.PRO:
            permissions.extend([
                "tool:advanced",
                "feed:premium", 
                "cspm:scan",
                "api:write"
            ])
        elif plan_id == SubscriptionPlan.BUSINESS:
            permissions.extend([
                "tool:advanced",
                "tool:enterprise",
                "feed:premium",
                "feed:enterprise", 
                "cspm:scan",
                "cspm:advanced",
                "api:write",
                "api:admin"
            ])
        
        return permissions
    
    def get_rate_limits(self, plan_id: SubscriptionPlan) -> dict[str, str]:
        """
        Get rate limits based on subscription plan.
        
        Args:
            plan_id: Subscription plan ID
            
        Returns:
            Dictionary of rate limit configurations
        """
        if plan_id == SubscriptionPlan.FREE:
            return {
                "default": "100/hour",
                "api_calls": "50/hour",
                "tool_executions": "10/hour"
            }
        elif plan_id == SubscriptionPlan.PRO:
            return {
                "default": "1000/hour", 
                "api_calls": "500/hour",
                "tool_executions": "100/hour"
            }
        elif plan_id == SubscriptionPlan.BUSINESS:
            return {
                "default": "10000/hour",
                "api_calls": "5000/hour", 
                "tool_executions": "1000/hour"
            }
        
        return {"default": "100/hour"}


# Global billing service instance
billing_service = StripeBillingService()
