"""The cloud providers cspm can scan, derived from the code (#612).

A scan needs two things from its provider: a session factory, which turns
the scan's credentials into an authenticated client for the worker, and
checks that use that client. A provider is supported when it has both: a
factory in SESSION_FACTORIES and at least one enabled, implemented check
loaded by the check runner. Nothing else lists providers, so the scan
endpoints, ``GET /api/v1/providers`` and the dashboard's scan form cannot
drift from what the worker can run.

The API used to accept GCP and Azure scans, which the worker then failed
every time, because only the AWS session was implemented.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import boto3

from .checks.framework import CloudProvider
from .checks.runner import CheckRunner, check_runner


class MalformedCredentialsError(ValueError):
    """Credentials that cannot be valid, refused before any call to the provider.

    The message never contains the credentials.
    """


# IAM's own constraint on an access key id: 16 to 128 word characters.
_AWS_ACCESS_KEY_ID = re.compile(r"\w{16,128}", re.ASCII)
_AWS_ROLE_ARN = re.compile(r"arn:aws[a-z-]*:iam::\d{12}:role/\S+", re.ASCII)


def _validate_aws_credentials(credentials: Dict[str, Any]) -> str:
    """Return the auth method, or refuse credentials AWS could never accept.

    Runs before any boto3 session or client exists, so a malformed key
    fails the scan without a request to AWS.
    """
    auth_method = credentials.get("auth_method", "access_key")
    if auth_method not in ("access_key", "assume_role"):
        raise MalformedCredentialsError(f"Unsupported AWS auth method: {auth_method}")
    access_key_id = credentials.get("access_key_id")
    if not isinstance(access_key_id, str) or not _AWS_ACCESS_KEY_ID.fullmatch(
        access_key_id
    ):
        raise MalformedCredentialsError("The AWS access key id is malformed")
    secret_access_key = credentials.get("secret_access_key")
    if not isinstance(secret_access_key, str) or not secret_access_key:
        raise MalformedCredentialsError("The AWS secret access key is missing")
    if auth_method == "assume_role":
        role_arn = credentials.get("role_arn")
        if not isinstance(role_arn, str) or not _AWS_ROLE_ARN.fullmatch(role_arn):
            raise MalformedCredentialsError("assume_role needs the ARN of an IAM role")
    return auth_method


def create_aws_session(credentials: Dict[str, Any]) -> boto3.Session:
    """Create an AWS session from a scan's credentials."""
    auth_method = _validate_aws_credentials(credentials)
    region = credentials.get("region") or "us-east-1"

    if auth_method == "access_key":
        return boto3.Session(
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            region_name=region,
        )

    base_session = boto3.Session(
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        region_name=region,
    )
    assume_role_args = {
        "RoleArn": credentials["role_arn"],
        "RoleSessionName": f"wildbox-cspm-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
    }
    if credentials.get("external_id"):
        assume_role_args["ExternalId"] = credentials["external_id"]
    assumed = base_session.client("sts").assume_role(**assume_role_args)["Credentials"]
    return boto3.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
        region_name=region,
    )


@dataclass(frozen=True)
class ProviderBackend:
    """What cspm has for one provider: its display name and session factory."""

    name: str
    create_session: Callable[[Dict[str, Any]], Any]


# One entry per provider whose sessions cspm can open. Add a provider here
# only together with its checks.
SESSION_FACTORIES: Dict[CloudProvider, ProviderBackend] = {
    CloudProvider.AWS: ProviderBackend("Amazon Web Services", create_aws_session),
}


def supported_providers(runner: Optional[CheckRunner] = None) -> List[Dict[str, Any]]:
    """The providers a scan can be submitted for, with their check counts.

    A provider is listed when it has a session factory and at least one
    enabled check the runner loaded (implemented checks only; scaffolding
    is kept out of ``loaded_checks``). ``checks`` is the number a scan of
    the provider runs when it names no check ids.
    """
    runner = runner or check_runner
    supported = []
    for provider, backend in SESSION_FACTORIES.items():
        checks = [
            check
            for check in runner.loaded_checks.get(provider, [])
            if check.metadata.enabled
        ]
        if checks:
            supported.append(
                {
                    "provider": provider.value,
                    "name": backend.name,
                    "checks": len(checks),
                }
            )
    return supported


def supported_provider_ids(runner: Optional[CheckRunner] = None) -> List[str]:
    """The ids of supported_providers(), e.g. ``["aws"]``."""
    return [entry["provider"] for entry in supported_providers(runner)]


def create_session(provider: CloudProvider, credentials: Dict[str, Any]) -> Any:
    """Open a session for ``provider``, or refuse a provider without a factory."""
    backend = SESSION_FACTORIES.get(provider)
    if backend is None:
        raise ValueError(f"cspm cannot scan {provider.value}: no session factory")
    return backend.create_session(credentials)
