"""
FastAPI Users configuration and user management logic.
"""

import logging
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .models import User, Team, TeamMembership, TeamRole
from .config import settings


# 1. Database Adapter
async def get_user_db(session: AsyncSession = Depends(get_db)):
    yield SQLAlchemyUserDatabase(session, User)


# 2. Bearer Transport (come vengono passati i token)
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


# 3. JWT Strategy (come vengono creati e letti i token)
def get_jwt_strategy() -> JWTStrategy:
    """
    Creates a new JWT strategy instance for each request.
    This function is called by FastAPI Users as a dependency.
    """
    return JWTStrategy(
        secret=settings.jwt_secret_key,
        lifetime_seconds=settings.jwt_access_token_expire_minutes * 60,
        token_audience=["fastapi-users:auth"]
    )


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
        Qui creiamo il Team e la membership (owner).
        """
        logger.info(f"User {user.email} has registered. Running post-registration logic.")
        
        # Ottieni la sessione DB dalla request
        if not request or not hasattr(request.state, 'db'):
            logger.warning("No database session found in request state")
            return
            
        # Use fastapi-users' own session — the one `user` is attached to.
        # request.state.db is a *separate* session (set by db_session_middleware);
        # adding the already-attached `user` to it raises InvalidRequestError.
        db: AsyncSession = self.user_db.session

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

        # Commit delle modifiche
        await db.commit()
        logger.info(f"Team and membership (owner) created for user {user.email}.")


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
