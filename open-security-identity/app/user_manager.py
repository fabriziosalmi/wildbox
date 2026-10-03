"""
FastAPI Users configuration and user management logic.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt as pyjwt

logger = logging.getLogger(__name__)

from fastapi import Depends, HTTPException, Request, status
from fastapi_users import BaseUserManager, FastAPIUsers, exceptions
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users.jwt import decode_jwt, generate_jwt
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import verify_password
from .database import get_db
from .models import User, Team, TeamMembership, TeamRole
from .config import settings
from .logout import revoke_token
from .token_blacklist import (
    clear_failed_logins,
    is_account_locked,
    is_token_blacklisted,
    record_failed_login,
)


def _lockout_key(email: Optional[str]) -> str:
    """The login lockout counter's key: the normalised email (#509)."""
    return (email or "").strip().lower()


def account_locked_error() -> HTTPException:
    """What a locked account answers, at login and wherever its password is checked."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many failed login attempts. Try again later.",
        headers={"Retry-After": str(settings.account_lockout_minutes * 60)},
    )


async def verify_current_password(
    user,
    password: Optional[str],
    wrong_detail: str = "Incorrect current password",
) -> None:
    """Check a signed-in user's password against the login lockout (#569).

    Changing the password, the email or deleting the account asks for the
    current password. Those checks answered 400 on a wrong one and counted
    nothing, so a session -- a stolen token is enough -- could guess the
    password without limit, the login lockout (#509) notwithstanding. A wrong
    password here counts towards the same per-account counter as a failed
    login, a locked account is refused like a locked login (429, even with
    the right password), and a right one clears the counter, as a login does.
    """
    key = _lockout_key(user.email)
    if await is_account_locked(key):
        raise account_locked_error()
    if not password or not verify_password(password, user.hashed_password):
        await record_failed_login(key)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=wrong_detail)
    await clear_failed_logins(key)


async def require_current_password(user, password: Optional[str], what: str) -> None:
    """Re-authenticate a change to the caller's own account (#569).

    A request without the password is refused without counting towards the
    lockout: it is a client that did not ask, not a guess.
    """
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Your current password is required to change {what}",
        )
    await verify_current_password(user, password)


# 1. Database Adapter
async def get_user_db(session: AsyncSession = Depends(get_db)):
    yield SQLAlchemyUserDatabase(session, User)


# 2. Bearer Transport (come vengono passati i token)
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


# 3. JWT Strategy (come vengono creati e letti i token)
class RevocableJWTStrategy(JWTStrategy):
    """fastapi-users' JWT strategy, with tokens that logout can actually revoke.

    The stock strategy writes {sub, aud, exp} and nothing else, and its
    destroy_token() raises "A JWT can't be invalidated". So the tokens the
    login endpoint hands out had no jti for the blacklist to key on:
    POST /auth/logout answered 400 for every one of them, POST /auth/jwt/logout
    (what the dashboard's logout hook calls) revoked nothing, and a session
    stayed open for the token's whole lifetime after the user logged out. With
    exp in whole seconds, two logins in the same second also returned the very
    same token, so they could not be told apart either.

    Here every token gets a random jti and an iat; read_token() refuses a
    blacklisted jti, so identity's own routes honour revocation as the gateway
    already does (/internal/authorize); destroy_token() revokes.
    """

    async def write_token(self, user) -> str:
        data = {
            "sub": str(user.id),
            "aud": self.token_audience,
            "jti": uuid.uuid4().hex,
            "iat": datetime.now(timezone.utc),
        }
        return generate_jwt(data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm)

    async def read_token(self, token, user_manager):
        if token is None:
            return None
        try:
            data = decode_jwt(token, self.decode_key, self.token_audience, algorithms=[self.algorithm])
        except pyjwt.PyJWTError:
            return None
        jti = data.get("jti")
        if jti and await is_token_blacklisted(jti):
            return None
        return await super().read_token(token, user_manager)

    async def destroy_token(self, token: str, user) -> None:
        await revoke_token(token)


def get_jwt_strategy() -> JWTStrategy:
    """
    Creates a new JWT strategy instance for each request.
    This function is called by FastAPI Users as a dependency.
    """
    return RevocableJWTStrategy(
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

    async def authenticate(self, credentials):
        """Password login with a per-account lockout (#509).

        token_blacklist.py had record_failed_login / is_account_locked and
        config had max_failed_login_attempts and account_lockout_minutes, but
        nothing called them: every account accepted unlimited password
        attempts. The counter is keyed by the normalised email whether or not
        the account exists, so the 429 does not reveal which emails are
        registered. A lock refuses even the correct password until it expires;
        a successful login clears the counter.
        """
        email = _lockout_key(credentials.username)
        if await is_account_locked(email):
            raise account_locked_error()
        user = await super().authenticate(credentials)
        if user is None:
            await record_failed_login(email)
            return None
        await clear_failed_logins(email)
        return user

    # Where a signed-in user changes their own password. It verifies the
    # current one; the self-service update below refuses to.
    CHANGE_PASSWORD_ROUTE = "POST /api/v1/admin/me/change-password"

    async def update(self, user_update, user, safe: bool = False, request=None):
        """Re-authenticate the changes a stolen session could take an account with.

        fastapi-users' PATCH /api/v1/users/me (the gateway's /auth/users/me)
        calls this with safe=True and applied what it was given without
        asking for the current password, so a session token alone was enough
        to take the account over:

        * a `password` was set as it was (#559). It is refused here; a user
          changes their password through the change-password route, which
          verifies the current one first;
        * an `email` was changed as well (#569), after which forgot-password
          sends the reset link to the new address. It now needs
          `current_password`, checked against the login lockout.

        The superuser update (PATCH /api/v1/users/{id}, safe=False) is an
        administrator's change to another account and is left as it is.
        `current_password` is never written to the user.
        """
        current_password = getattr(user_update, "current_password", None)
        if "current_password" in user_update.model_fields_set:
            user_update = type(user_update)(
                **user_update.model_dump(
                    exclude_unset=True, exclude={"current_password"}
                )
            )

        if safe:
            if getattr(user_update, "password", None) is not None:
                raise exceptions.InvalidPasswordException(
                    reason=(
                        "The password cannot be changed here. Use "
                        f"{self.CHANGE_PASSWORD_ROUTE} with your current password."
                    )
                )
            new_email = getattr(user_update, "email", None)
            if new_email is not None and new_email != user.email:
                await require_current_password(user, current_password, "the email address")
        return await super().update(user_update, user, safe=safe, request=request)

    async def forgot_password(self, user, request=None) -> None:
        """Issue a reset token bound to the account's current email (#569).

        fastapi-users' token carries the user id and a fingerprint of the
        password hash, so a password change invalidates it but an email change
        does not: a link already sent to the old address kept working after the
        owner moved the account to a new one. The token here also carries the
        email, and reset_password() refuses it once the email has changed.
        """
        if not user.is_active:
            raise exceptions.UserInactive()
        token = generate_jwt(
            {
                "sub": str(user.id),
                "email": user.email,
                "password_fgpt": self.password_helper.hash(user.hashed_password),
                "aud": self.reset_password_token_audience,
            },
            self.reset_password_token_secret,
            self.reset_password_token_lifetime_seconds,
        )
        await self.on_after_forgot_password(user, token, request)

    async def reset_password(self, token: str, password: str, request=None):
        """Refuse a reset token issued for an email the account no longer has."""
        try:
            data = decode_jwt(
                token,
                self.reset_password_token_secret,
                [self.reset_password_token_audience],
            )
            user = await self.get(self.parse_id(data["sub"]))
        except (
            pyjwt.PyJWTError,
            KeyError,
            ValueError,
            exceptions.InvalidID,
            exceptions.UserNotExists,
        ):
            raise exceptions.InvalidResetPasswordToken()
        if data.get("email") != user.email:
            raise exceptions.InvalidResetPasswordToken()
        return await super().reset_password(token, password, request)

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
