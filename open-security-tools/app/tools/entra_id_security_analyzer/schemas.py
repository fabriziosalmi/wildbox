from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput


class EntraIDSecurityAnalyzerInput(BaseToolInput):
    """Input schema for the Entra ID Security Analyzer tool"""

    tenant_id: Optional[str] = Field(
        None,
        description=(
            "Entra ID (Azure AD) tenant ID. Falls back to the "
            "ENTRA_TENANT_ID environment variable if not provided."
        ),
    )
    client_id: Optional[str] = Field(
        None,
        description=(
            "App registration client ID with admin-consented "
            "User.Read.All, AuditLog.Read.All and Reports.Read.All "
            "application permissions. Falls back to ENTRA_CLIENT_ID."
        ),
    )
    client_secret: Optional[str] = Field(
        None,
        description=(
            "App registration client secret. Falls back to "
            "ENTRA_CLIENT_SECRET. Never echoed back in the output."
        ),
    )
    stale_threshold_days: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Number of days of inactivity before an account is flagged as stale",
    )
    check_stale_accounts: bool = Field(
        default=True, description="Enumerate accounts with no recent sign-in activity"
    )
    check_mfa_gaps: bool = Field(
        default=True,
        description="Enumerate enabled accounts that are not registered for MFA",
    )
    include_disabled_accounts: bool = Field(
        default=False,
        description="Include disabled accounts in the stale-account and MFA results",
    )
    max_users: int = Field(
        default=999,
        ge=1,
        le=5000,
        description="Maximum number of users to retrieve from Microsoft Graph",
    )


class StaleAccount(BaseModel):
    user_principal_name: str
    display_name: Optional[str] = None
    account_enabled: bool
    last_sign_in_date_time: Optional[str] = None
    days_inactive: Optional[int] = None
    severity: str  # Critical, High, Medium, Low


class MfaGap(BaseModel):
    user_principal_name: str
    is_mfa_registered: bool
    is_mfa_capable: bool
    is_sspr_registered: bool
    is_admin: bool = False
    severity: str  # Critical, High, Medium, Low


class EntraIDSecurityAnalyzerOutput(BaseToolOutput):
    """Output schema for the Entra ID Security Analyzer tool"""

    tenant_id: Optional[str] = None
    total_users_scanned: int = 0
    stale_accounts: List[StaleAccount] = Field(default_factory=list)
    mfa_gaps: List[MfaGap] = Field(default_factory=list)
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    recommendations: List[str] = Field(default_factory=list)
