"""
Entra ID Security Analyzer

Connects to Microsoft Graph using an app-registration's client-credentials
flow and flags two common identity hygiene gaps in Microsoft Entra ID
(Azure AD) tenants:

  * Stale accounts - enabled users with no sign-in activity within a
    configurable threshold (or no recorded sign-in at all).
  * MFA gaps - enabled users who are not registered for multi-factor
    authentication.

Required Microsoft Graph **application** permissions on the app
registration (admin consent required):
  * User.Read.All
  * AuditLog.Read.All
  * Reports.Read.All

Credentials can be supplied per-request or via the ENTRA_TENANT_ID,
ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET environment variables.
"""

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

try:
    from schemas import (
        EntraIDSecurityAnalyzerInput,
        EntraIDSecurityAnalyzerOutput,
        MfaGap,
        StaleAccount,
    )
except ImportError:
    from schemas import (
        EntraIDSecurityAnalyzerInput,
        EntraIDSecurityAnalyzerOutput,
        MfaGap,
        StaleAccount,
    )

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
LOGIN_BASE_URL = "https://login.microsoftonline.com"


class EntraIDSecurityAnalyzer:
    """Queries Microsoft Graph for stale accounts and MFA registration gaps."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, verify_ssl: bool = True):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl

    async def _get_access_token(self, session: aiohttp.ClientSession) -> str:
        """Authenticate via the OAuth2 client-credentials grant."""
        token_url = f"{LOGIN_BASE_URL}/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }

        async with session.post(token_url, data=payload, ssl=self.verify_ssl) as response:
            body = await response.json()
            if response.status != 200:
                error_description = body.get("error_description", "Unknown error")
                raise RuntimeError(f"Failed to authenticate with Microsoft Graph: {error_description}")
            return body["access_token"]

    async def _get_paginated(
        self, session: aiohttp.ClientSession, url: str, headers: Dict[str, str], max_items: int
    ) -> List[Dict[str, Any]]:
        """Follow @odata.nextLink until max_items is reached or pages run out."""
        items: List[Dict[str, Any]] = []
        next_url: Optional[str] = url

        while next_url and len(items) < max_items:
            async with session.get(next_url, headers=headers, ssl=self.verify_ssl) as response:
                body = await response.json()
                if response.status != 200:
                    error_message = body.get("error", {}).get("message", "Unknown error")
                    raise RuntimeError(f"Microsoft Graph request failed ({response.status}): {error_message}")

                items.extend(body.get("value", []))
                next_url = body.get("@odata.nextLink")

        return items[:max_items]

    async def get_users_with_signin_activity(
        self, session: aiohttp.ClientSession, headers: Dict[str, str], max_users: int
    ) -> List[Dict[str, Any]]:
        select = "id,userPrincipalName,displayName,accountEnabled,signInActivity"
        url = f"{GRAPH_BASE_URL}/users?$select={select}&$top=999"
        return await self._get_paginated(session, url, headers, max_users)

    async def get_mfa_registration_details(
        self, session: aiohttp.ClientSession, headers: Dict[str, str], max_users: int
    ) -> List[Dict[str, Any]]:
        url = f"{GRAPH_BASE_URL}/reports/authenticationMethods/userRegistrationDetails?$top=999"
        return await self._get_paginated(session, url, headers, max_users)


def _classify_stale_severity(days_inactive: Optional[int], threshold: int) -> str:
    if days_inactive is None:
        return "Medium"
    if days_inactive >= threshold * 3:
        return "Critical"
    if days_inactive >= threshold * 2:
        return "High"
    return "Medium"


def _classify_mfa_severity(is_admin: bool) -> str:
    return "Critical" if is_admin else "High"


def _build_stale_accounts(
    users: List[Dict[str, Any]], threshold_days: int, include_disabled: bool
) -> List[StaleAccount]:
    stale_accounts: List[StaleAccount] = []
    now = datetime.now(timezone.utc)

    for user in users:
        if not include_disabled and not user.get("accountEnabled", True):
            continue

        sign_in_activity = user.get("signInActivity") or {}
        last_sign_in = sign_in_activity.get("lastSignInDateTime")

        days_inactive: Optional[int] = None
        if last_sign_in:
            last_sign_in_dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
            days_inactive = (now - last_sign_in_dt).days

        is_stale = days_inactive is None or days_inactive >= threshold_days
        if not is_stale:
            continue

        stale_accounts.append(
            StaleAccount(
                user_principal_name=user.get("userPrincipalName", "unknown"),
                display_name=user.get("displayName"),
                account_enabled=user.get("accountEnabled", True),
                last_sign_in_date_time=last_sign_in,
                days_inactive=days_inactive,
                severity=_classify_stale_severity(days_inactive, threshold_days),
            )
        )

    return stale_accounts


def _build_mfa_gaps(registration_details: List[Dict[str, Any]]) -> List[MfaGap]:
    mfa_gaps: List[MfaGap] = []

    for detail in registration_details:
        if detail.get("isMfaRegistered"):
            continue

        is_admin = bool(detail.get("isAdmin", False))
        mfa_gaps.append(
            MfaGap(
                user_principal_name=detail.get("userPrincipalName", "unknown"),
                is_mfa_registered=False,
                is_mfa_capable=bool(detail.get("isMfaCapable", False)),
                is_sspr_registered=bool(detail.get("isSsprRegistered", False)),
                is_admin=is_admin,
                severity=_classify_mfa_severity(is_admin),
            )
        )

    return mfa_gaps


def _generate_recommendations(stale_accounts: List[StaleAccount], mfa_gaps: List[MfaGap]) -> List[str]:
    recommendations: List[str] = []

    admin_mfa_gaps = [gap for gap in mfa_gaps if gap.is_admin]
    if admin_mfa_gaps:
        recommendations.append(
            "URGENT: Enforce MFA for privileged/admin accounts that are not currently registered"
        )
    if mfa_gaps:
        recommendations.append(
            "Enable an Entra ID Conditional Access policy requiring MFA for all users"
        )
        recommendations.append("Use Entra ID Identity Protection to drive MFA registration campaigns")

    if stale_accounts:
        recommendations.append(
            "Review and disable or remove accounts with no recent sign-in activity"
        )
        recommendations.append("Set up an access review workflow to periodically re-certify account activity")

    if not stale_accounts and not mfa_gaps:
        recommendations.append("No stale accounts or MFA gaps detected within the configured thresholds")

    return recommendations


async def execute_tool(data: EntraIDSecurityAnalyzerInput) -> EntraIDSecurityAnalyzerOutput:
    start_time = time.time()

    tenant_id = data.tenant_id or os.getenv("ENTRA_TENANT_ID")
    client_id = data.client_id or os.getenv("ENTRA_CLIENT_ID")
    client_secret = data.client_secret or os.getenv("ENTRA_CLIENT_SECRET")

    if not tenant_id or not client_id or not client_secret:
        return EntraIDSecurityAnalyzerOutput(
            success=False,
            tool_name="entra_id_security_analyzer",
            tenant_id=tenant_id,
            error_message=(
                "Missing Entra ID credentials. Provide tenant_id, client_id and "
                "client_secret, or set ENTRA_TENANT_ID, ENTRA_CLIENT_ID and "
                "ENTRA_CLIENT_SECRET environment variables."
            ),
            execution_time=time.time() - start_time,
        )

    analyzer = EntraIDSecurityAnalyzer(tenant_id, client_id, client_secret, verify_ssl=data.verify_ssl)

    try:
        timeout = aiohttp.ClientTimeout(total=data.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            access_token = await analyzer._get_access_token(session)
            headers = {"Authorization": f"Bearer {access_token}"}

            stale_accounts: List[StaleAccount] = []
            mfa_gaps: List[MfaGap] = []
            users: List[Dict[str, Any]] = []

            if data.check_stale_accounts:
                users = await analyzer.get_users_with_signin_activity(session, headers, data.max_users)
                stale_accounts = _build_stale_accounts(
                    users, data.stale_threshold_days, data.include_disabled_accounts
                )

            if data.check_mfa_gaps:
                registration_details = await analyzer.get_mfa_registration_details(
                    session, headers, data.max_users
                )
                mfa_gaps = _build_mfa_gaps(registration_details)
                if not users:
                    users = registration_details

            critical_issues = len([s for s in stale_accounts if s.severity == "Critical"])
            critical_issues += len([g for g in mfa_gaps if g.severity == "Critical"])
            high_issues = len([s for s in stale_accounts if s.severity == "High"])
            high_issues += len([g for g in mfa_gaps if g.severity == "High"])
            medium_issues = len([s for s in stale_accounts if s.severity == "Medium"])
            low_issues = len([s for s in stale_accounts if s.severity == "Low"])

            return EntraIDSecurityAnalyzerOutput(
                success=True,
                tool_name="entra_id_security_analyzer",
                tenant_id=tenant_id,
                total_users_scanned=len(users),
                stale_accounts=stale_accounts,
                mfa_gaps=mfa_gaps,
                critical_issues=critical_issues,
                high_issues=high_issues,
                medium_issues=medium_issues,
                low_issues=low_issues,
                recommendations=_generate_recommendations(stale_accounts, mfa_gaps),
                summary=(
                    f"Scanned {len(users)} users: {len(stale_accounts)} stale account(s), "
                    f"{len(mfa_gaps)} MFA registration gap(s)"
                ),
                execution_time=time.time() - start_time,
            )

    except (RuntimeError, ValueError, KeyError, TypeError, ConnectionError, TimeoutError, aiohttp.ClientError) as e:
        return EntraIDSecurityAnalyzerOutput(
            success=False,
            tool_name="entra_id_security_analyzer",
            tenant_id=tenant_id,
            error_message=f"Entra ID analysis failed: {str(e)}",
            execution_time=time.time() - start_time,
        )


# Tool metadata
TOOL_INFO = {
    "name": "entra_id_security_analyzer",
    "display_name": "Entra ID Security Analyzer",
    "description": (
        "Connects to Microsoft Graph to find stale accounts and MFA "
        "registration gaps in a Microsoft Entra ID (Azure AD) tenant"
    ),
    "category": "identity_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["entra-id", "azure-ad", "identity", "mfa", "microsoft-graph", "iam"],
}
