"""
FastAPI Users configuration and user management logic.
"""

import uuid
from typing import Optional

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession
import jwt

from .database import get_db
from .models import User, Team, TeamMembership, Subscription, TeamRole, SubscriptionPlan, SubscriptionStatus
from .config import settings
from .billing import billing_service


# Custom JWT Strategy with debug logging
class DebugJWTStrategy(JWTStrategy):
    async def read_token(self, token: Optional[str], user_manager) -> Optional[uuid.UUID]:
        """Override to add debug logging for token validation."""
        print(f"\n[DEBUG] ========== TOKEN VALIDATION ATTEMPT ==========")
        print(f"[DEBUG] Token received: {token[:50] if token else 'None'}... (truncated)")
        print(f"[DEBUG] Secret being used: {self.secret[:20]}... (truncated)")

        try:
            # Manually decode to see what's inside
            if token:
                decoded = jwt.decode(
                    token,
                    self.secret,
                    algorithms=["HS256"],
                    audience=self.token_audience
                )
                print(f"[DEBUG] Token successfully decoded!")
                print(f"[DEBUG] Token payload: {decoded}")

            # Call parent implementation
            result = await super().read_token(token, user_manager)
            print(f"[DEBUG] Token validation result: {result}")
            print(f"[DEBUG] ===============================================\n")
            return result

        except jwt.ExpiredSignatureError as e:
            print(f"[DEBUG] ❌ Token expired: {e}")
            raise
        except jwt.InvalidTokenError as e:
            print(f"[DEBUG] ❌ Invalid token: {e}")
            raise
        except Exception as e:
            print(f"[DEBUG] ❌ Unexpected error during token validation: {type(e).__name__}: {e}")
            raise


# 1. Database Adapter
async def get_user_db(session: AsyncSession = Depends(get_db)):
    yield SQLAlchemyUserDatabase(session, User)


# 2. Bearer Transport (come vengono passati i token)
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


# 3. JWT Strategy (come vengono creati e letti i token)
def get_jwt_strategy() -> DebugJWTStrategy:
    """
    Creates a new JWT strategy instance for each request.
    This function is called by FastAPI Users as a dependency.
    """
    # DEBUG: Log the JWT secret being used
    print(f"[DEBUG] ========== JWT STRATEGY CREATED ==========")
    print(f"[DEBUG] Secret (first 20 chars): {settings.jwt_secret_key[:20]}...")
    print(f"[DEBUG] Algorithm: HS256")
    print(f"[DEBUG] Lifetime: {settings.jwt_access_token_expire_minutes * 60} seconds")
    print(f"[DEBUG] ============================================")
    
    strategy = DebugJWTStrategy(
        secret=settings.jwt_secret_key,
        lifetime_seconds=settings.jwt_access_token_expire_minutes * 60,
        token_audience=["fastapi-users:auth"]  # Required for token validation
    )
    return strategy


# 4. Authentication Backend
auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)


# 5. User Manager con logica custom
class UserManager(BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.jwt_secret_key
    verification_token_secret = settings.jwt_secret_key

    def parse_id(self, value):
        """Parse the user ID from string to UUID."""
        try:
            return uuid.UUID(value)
        except ValueError:
            raise ValueError(f"Invalid UUID format: {value}")

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        """
        Logica da eseguire dopo la registrazione di un utente.
        Qui creiamo il Team, la Subscription e il customer su Stripe.
        """
        print(f"User {user.email} has registered. Running post-registration logic.")
        
        # Ottieni la sessione DB dalla request
        if not request or not hasattr(request.state, 'db'):
            print("Warning: No database session found in request state")
            return
            
        db: AsyncSession = request.state.db

        # Crea Stripe customer
        try:
            stripe_customer_id = await billing_service.create_customer(user)
            user.stripe_customer_id = stripe_customer_id
            db.add(user)
        except Exception as e:
            print(f"Warning: Failed to create Stripe customer for {user.email}: {e}")

        # Crea team con l'utente come owner
        team = Team(
            name=f"{user.email}'s Team",
            owner_id=user.id
        )
        db.add(team)
        await db.flush()  # Per ottenere team.id

        # Crea team membership
        membership = TeamMembership(
            user_id=user.id,
            team_id=team.id,
            role=TeamRole.OWNER
        )
        db.add(membership)

        # Crea free subscription
        subscription = Subscription(
            team_id=team.id,
            plan_id=SubscriptionPlan.FREE,
            status=SubscriptionStatus.ACTIVE
        )
        db.add(subscription)
        
        # Commit delle modifiche
        await db.commit()
        print(f"Team, membership, and subscription created for user {user.email}.")


async def get_user_manager(user_db: SQLAlchemyUserDatabase = Depends(get_user_db)):
    yield UserManager(user_db)


# 6. Istanza principale di FastAPIUsers
fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)

# 7. Dependencies per ottenere l'utente autenticato
current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)
current_verified_user = fastapi_users.current_user(active=True, verified=True)
