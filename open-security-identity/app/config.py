"""
Configuration management for Open Security Identity service.
"""

import hmac
import json
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode

# API_KEY_HASH_SECRET strength. generate_secrets.py writes 64 hex characters;
# an upgraded deployment seeds it from JWT_SECRET_KEY, which identity already
# requires to be 32 characters or more. The distinct-character floor rejects
# values such as "a" * 32 without tripping on random hex (16 symbols).
API_KEY_HASH_SECRET_MIN_LENGTH = 32
API_KEY_HASH_SECRET_MIN_UNIQUE_CHARS = 10
# GUARDIAN_CONTACTS_SECRET, held to the same standard.
GUARDIAN_CONTACTS_SECRET_MIN_LENGTH = 32
# Markers of the values shipped in .env.example and the documentation. Matched
# as substrings; none can plausibly occur in a random hex or URL-safe value.
_PLACEHOLDER_MARKERS = ("generate-with", "change-me", "change-this", "changeme")


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
        # Application settings
    app_name: str = "Wildbox Identity Service"
    app_version: str = "0.1.6"
    debug: bool = False
    port: int = 8001
    
    # "production" makes API_KEY_HASH_SECRET mandatory (see below).
    environment: str = "development"

    # Database
    database_url: str = Field(..., description="Database connection URL")
    
    # JWT Authentication
    jwt_secret_key: str = Field(..., description="JWT secret key for token signing", min_length=32)

    # Keys the HMAC used to store API-key digests. Kept separate from the JWT
    # signing key so that rotating one does not invalidate the other
    # (WILDBO-SEC-01). Required when ENVIRONMENT=production. It used to be
    # optional with a silent fallback to jwt_secret_key, and compose never
    # passed it, so every digest stayed keyed by the JWT secret and a JWT
    # rotation invalidated every API key (#648). Outside production an unset
    # value still falls back to jwt_secret_key, with a warning at start-up.
    api_key_hash_secret: Optional[str] = Field(
        default=None,
        description="Secret keying the HMAC for stored API keys",
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Redis (for token blacklist and rate limiting)
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # Account lockout
    max_failed_login_attempts: int = 5
    account_lockout_minutes: int = 15
    
    
    # API Configuration
    api_v1_prefix: str = "/api/v1"
    internal_api_prefix: str = "/internal"

    # Gateway secret for service-to-service authentication
    gateway_internal_secret: Optional[str] = Field(None, description="Shared secret for gateway-to-identity communication")

    # What guardian's worker presents to POST /internal/team-contacts to
    # learn who may be e-mailed about a team (#705, app/team_contacts.py).
    # A secret of its own: the worker holds no GATEWAY_INTERNAL_SECRET, and
    # must not be handed it under another name. Unset, the route answers
    # 503 and guardian sends no e-mail.
    guardian_contacts_secret: Optional[str] = Field(
        default=None,
        description="Secret guardian's worker presents to read a team's contacts",
    )

    # CORS - SECURITY: Restrict origins in production
    #
    # NoDecode: pydantic-settings would otherwise read a list[str] from the
    # environment as JSON only, and CORS_ORIGINS is comma-separated in .env
    # and for every other service. identity exited at import on that value
    # and crash-looped (#531). _parse_cors_origins accepts both forms.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000", "https://wildbox.local", "https://dashboard.wildbox.local"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_allow_headers: list[str] = ["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"]
    
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, value: Any) -> Any:
        """Accept a JSON list or a comma-separated string of origins.

        '["https://a.example", "https://b.example"]' and
        'https://a.example, https://b.example' give the same list. An empty
        value gives an empty list, which allows no cross-origin requests: the
        dashboard reaches identity through the gateway on its own origin.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            # Invalid JSON raises ValueError, which pydantic reports as a
            # validation error naming the field.
            return json.loads(text)
        return [origin.strip() for origin in text.split(",") if origin.strip()]

    @field_validator("api_key_hash_secret", mode="before")
    @classmethod
    def _blank_hash_secret_is_unset(cls, value: Any) -> Any:
        """Read an empty API_KEY_HASH_SECRET as unset.

        Compose renders an undefined variable as an empty string, which
        must take the same path as an absent one rather than fail as a
        too-short secret.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("api_key_hash_secret")
    @classmethod
    def _hash_secret_is_strong(cls, value: Optional[str]) -> Optional[str]:
        """Refuse a short, placeholder or low-entropy API_KEY_HASH_SECRET.

        The messages name the variable but never echo its value.
        """
        if value is None:
            return value
        if len(value) < API_KEY_HASH_SECRET_MIN_LENGTH:
            raise ValueError(
                f"API_KEY_HASH_SECRET must be at least "
                f"{API_KEY_HASH_SECRET_MIN_LENGTH} characters; generate one "
                f"with 'make generate-secrets'"
            )
        lowered = value.lower()
        if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
            raise ValueError(
                "API_KEY_HASH_SECRET is a placeholder from .env.example; "
                "generate one with 'make generate-secrets'"
            )
        if len(set(value)) < API_KEY_HASH_SECRET_MIN_UNIQUE_CHARS:
            raise ValueError(
                "API_KEY_HASH_SECRET has too little entropy (too few distinct "
                "characters); generate one with 'make generate-secrets'"
            )
        return value

    @field_validator("guardian_contacts_secret", mode="before")
    @classmethod
    def _blank_contacts_secret_is_unset(cls, value: Any) -> Any:
        """Read an empty GUARDIAN_CONTACTS_SECRET as unset.

        Compose passes it as ``${GUARDIAN_CONTACTS_SECRET:-}``: empty for a
        deployment that has not switched guardian's e-mail on.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("guardian_contacts_secret")
    @classmethod
    def _contacts_secret_is_strong(cls, value: Optional[str]) -> Optional[str]:
        """Refuse a short, placeholder or low-entropy GUARDIAN_CONTACTS_SECRET.

        It guards the e-mail addresses of every team's members. The messages
        name the variable but never echo its value.
        """
        if value is None:
            return value
        if len(value) < GUARDIAN_CONTACTS_SECRET_MIN_LENGTH:
            raise ValueError(
                f"GUARDIAN_CONTACTS_SECRET must be at least "
                f"{GUARDIAN_CONTACTS_SECRET_MIN_LENGTH} characters; generate "
                f"one with 'openssl rand -hex 32'"
            )
        lowered = value.lower()
        if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
            raise ValueError(
                "GUARDIAN_CONTACTS_SECRET is a placeholder from .env.example; "
                "generate one with 'openssl rand -hex 32'"
            )
        if len(set(value)) < API_KEY_HASH_SECRET_MIN_UNIQUE_CHARS:
            raise ValueError(
                "GUARDIAN_CONTACTS_SECRET has too little entropy (too few "
                "distinct characters); generate one with 'openssl rand -hex 32'"
            )
        return value

    @model_validator(mode="after")
    def _contacts_secret_is_its_own(self) -> "Settings":
        """Refuse a GUARDIAN_CONTACTS_SECRET that is another secret's value.

        guardian's worker holds it. Equal to GATEWAY_INTERNAL_SECRET, it
        would hand the worker the secret that lets its holder speak as any
        user to every service; equal to a signing key, that key.
        """
        if self.guardian_contacts_secret is None:
            return self
        for name in ("gateway_internal_secret", "jwt_secret_key", "api_key_hash_secret"):
            other = getattr(self, name)
            if other and hmac.compare_digest(
                self.guardian_contacts_secret.encode("utf-8"), other.encode("utf-8")
            ):
                raise ValueError(
                    f"GUARDIAN_CONTACTS_SECRET must not be the value of "
                    f"{name.upper()}: generate a separate one with "
                    f"'openssl rand -hex 32'"
                )
        return self

    @model_validator(mode="after")
    def _hash_secret_required_in_production(self) -> "Settings":
        """Refuse to start in production without API_KEY_HASH_SECRET."""
        if (
            self.environment.strip().lower() == "production"
            and self.api_key_hash_secret is None
        ):
            raise ValueError(
                "API_KEY_HASH_SECRET is required when ENVIRONMENT=production. "
                "On an existing deployment run "
                "'./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET "
                "--init' so that existing API keys keep working (see "
                "UPGRADING.md); on a fresh install run 'make generate-secrets'."
            )
        return self

    class Config:
        env_file = ".env"
        case_sensitive = False
        # A validation error otherwise prints input_value: the settings
        # being validated, secrets included, into the start-up traceback
        # and so into the container log.
        hide_input_in_errors = True


# Global settings instance
settings = Settings()
