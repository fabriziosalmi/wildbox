"""
Configuration management for Open Security Agents

Uses Pydantic Settings for environment-based configuration.
"""

import os
from typing import Optional
from urllib.parse import urlsplit

from limits import parse_many
from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings

# The tools that return data Wildbox holds for the caller's team, as opposed
# to what a lookup of the IOC finds outside: the team's threat indicators in
# the data service, and the vulnerabilities Guardian records on its assets.
# The model is given one only when AGENT_TEAM_DATA_TOOLS names it (see
# Settings.agent_team_data_tools). Defined here, not with the tools, because
# the settings are validated before anything else is imported.
TEAM_DATA_TOOLS = ("threat_intel_query_tool", "vulnerability_search_tool")


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    
    # Anthropic / Claude Configuration (optional — the worker imports without it;
    # analysis tasks fail gracefully when it's missing instead of crash-looping)
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-opus-4-8"
    anthropic_temperature: float = 0.1
    anthropic_max_tokens: int = 4096
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # Celery Configuration
    celery_broker_url: str = Field(default="redis://localhost:6379/0", env="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/0", env="CELERY_RESULT_BACKEND")
    
    # Wildbox services. The agent's tools call them directly, on the internal
    # network, as the user who submitted the analysis
    # (app/tools/wildbox_client.py). The defaults are the services' addresses
    # in docker-compose.yml, which also sets them. They were localhost, which
    # inside the agents container is the agents container, and the data
    # default named port 8001, identity's (#652). Each must be an absolute
    # http(s) URL, or the service does not start.
    wildbox_api_url: str = "http://api:8000"
    wildbox_data_url: str = "http://open-security-data:8002"
    wildbox_guardian_url: str = "http://open-security-guardian:8013"
    # No tool calls the responder. Kept so that an env file which sets it
    # still loads: the settings refuse unknown keys from a .env file.
    wildbox_responder_url: str = "http://open-security-responder:8018"

    @field_validator(
        "wildbox_api_url",
        "wildbox_data_url",
        "wildbox_guardian_url",
        "wildbox_responder_url",
    )
    @classmethod
    def _service_url(cls, value: str, info: ValidationInfo) -> str:
        """An absolute http(s) URL with a host, without a trailing slash."""
        value = (value or "").strip()
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(
                f"{info.field_name.upper()} must be an absolute http(s) URL "
                f"with a host, such as http://open-security-data:8002; got {value!r}"
            )
        if parts.query or parts.fragment:
            raise ValueError(
                f"{info.field_name.upper()} must not carry a query or a fragment"
            )
        return value.rstrip("/")

    # Security
    # No longer read (#567): the client sent it as X-API-Key when it had no
    # caller identity, and the tools service stopped accepting that in #566.
    # Kept only so that a .env file which still sets INTERNAL_API_KEY loads.
    internal_api_key: str = Field(default="", env="INTERNAL_API_KEY")
    # REQUIRED. Proof-of-origin secret sent with the caller's gateway identity
    # (X-Wildbox-* headers) on every internal call (#175); without it internal
    # tool calls fail.
    gateway_internal_secret: str = Field(default="", env="GATEWAY_INTERNAL_SECRET")
    
    # The team-data tools the model is given: a comma-separated list of names
    # from TEAM_DATA_TOOLS above. Empty, the default, gives it neither: an
    # analysis then runs on lookups of the IOC alone, and nothing Wildbox
    # holds for the team enters the conversation.
    #
    # Naming a tool here is a decision about data, and it is the operator's:
    # - what the tool returns (the team's threat indicators, or the
    #   vulnerabilities Guardian records on the team's assets, with asset
    #   names) is sent to the model provider like every tool output;
    # - it then sits in the model's context beside text the other tools
    #   fetched from the internet, and the model holds tools that reach
    #   outside (URL analysis, DNS, WHOIS). A page or a record written to
    #   instruct the model can ask it to pass that data out in a tool
    #   argument. The prompt tells the model not to; a prompt is not a
    #   control.
    #
    # A name that is not one of TEAM_DATA_TOOLS stops the service at start:
    # a typo must neither enable a tool nor be mistaken for having done so.
    agent_team_data_tools: str = ""

    @field_validator("agent_team_data_tools")
    @classmethod
    def _known_team_data_tools(cls, value: str) -> str:
        value = (value or "").strip()
        unknown = sorted(
            {name.strip() for name in value.split(",") if name.strip()}
            - set(TEAM_DATA_TOOLS)
        )
        if unknown:
            raise ValueError(
                f"AGENT_TEAM_DATA_TOOLS names no team-data tool: {', '.join(unknown)}. "
                f"It takes any of: {', '.join(TEAM_DATA_TOOLS)}"
            )
        return value

    def team_data_tool_names(self) -> frozenset:
        """The team-data tools AGENT_TEAM_DATA_TOOLS gives the model."""
        return frozenset(
            name.strip() for name in self.agent_team_data_tools.split(",") if name.strip()
        )

    # Analysis Settings
    max_analysis_time_minutes: int = 10
    max_concurrent_tasks: int = 5
    
    # Task Settings
    task_result_expires: int = 3600  # 1 hour
    task_timeout: int = 600  # 10 minutes

    # Rate limits on POST /v1/analyze (#651), in the `limits` notation
    # ("5/minute", "5/minute;50/day"). ANALYZE_RATE_LIMIT applies to each
    # authenticated user. ANALYZE_TEAM_RATE_LIMIT, when set, is a ceiling
    # for all the users of one team together; empty means no ceiling.
    analyze_rate_limit: str = "5/minute"
    analyze_team_rate_limit: str = ""
    # Where the limiter keeps its counters. Empty, the default, is the
    # service's Redis (REDIS_URL): the counters survive a restart and are
    # shared by every process that serves the API. They were in the memory
    # of one process, so a restart handed every user a new budget, which
    # matters for a limit per day. "memory://" keeps them in the process;
    # the unit tests use it. Anything else stops the service at start.
    analyze_rate_limit_storage_uri: str = ""

    @field_validator("analyze_rate_limit_storage_uri")
    @classmethod
    def _valid_rate_limit_storage(cls, value: str) -> str:
        value = (value or "").strip()
        if value and value != "memory://" and urlsplit(value).scheme not in (
            "redis",
            "rediss",
        ):
            raise ValueError(
                "ANALYZE_RATE_LIMIT_STORAGE_URI must be empty (use REDIS_URL), "
                "memory:// or a redis:// or rediss:// URL"
            )
        return value

    def rate_limit_storage_uri(self) -> str:
        """The storage the analysis limiter counts in."""
        return self.analyze_rate_limit_storage_uri or self.redis_url

    @field_validator("analyze_rate_limit", "analyze_team_rate_limit")
    @classmethod
    def _valid_rate_limit(cls, value: str, info: ValidationInfo) -> str:
        # slowapi logs a limit it cannot parse and then does not apply it,
        # so a typo would silently remove the limit. Refuse to start instead.
        value = (value or "").strip()
        if not value:
            if info.field_name == "analyze_rate_limit":
                raise ValueError("ANALYZE_RATE_LIMIT must not be empty")
            return value
        try:
            items = parse_many(value)
        except ValueError as e:
            raise ValueError(f"invalid rate limit {value!r}: {e}") from e
        if not items or any(item.amount < 1 for item in items):
            raise ValueError(f"invalid rate limit {value!r}: amounts must be 1 or more")
        return value

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
