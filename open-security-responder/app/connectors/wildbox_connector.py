"""
Wildbox connector for Open Security Responder

Calls the other Wildbox services -- tools, data, guardian and agents -- as
the user who started the run (app/caller.py).

Every action calls a route its service serves, with the body that service
validates (#616):

- ``run_tool``: tools ``POST /api/tools/{tool}``, the tool's input as body.
- ``query_threat_intel``: data ``GET /api/v1/indicators/search``.
- ``get_vulnerabilities``: guardian ``GET /api/v1/vulnerabilities/``.
- ``create_vulnerability``: guardian ``POST /api/v1/vulnerabilities/``,
  against the asset Guardian knows by the name or address given.
- ``get_asset_info``: guardian ``GET /api/v1/assets/assets/{id}/``.
- ``analyze_ioc``: agents ``POST /v1/analyze``, which queues an analysis
  and answers its task, not a verdict.

Three actions are gone because no service serves what they called:
``add_to_blacklist`` (data has no blacklist), ``isolate_endpoint`` (no
service isolates an endpoint; the sensor has no such route) and
``create_ticket`` (Guardian's remediation tickets mirror tickets of an
external ticketing system and need that system's ticket id). They failed
every time they ran; a step naming one now fails as an unknown action,
before any request is sent.
"""

import re
from typing import Any, Dict, List, Optional

import httpx

from .api_connector import run_tool_request
from .base import BaseConnector, ConnectorError, call_service
from ..config import settings

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# The values the agents service accepts (open-security-agents/app/schemas.py).
AGENTS_IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email")
AGENTS_PRIORITIES = ("low", "normal", "high")
# Guardian's Vulnerability.severity choices.
GUARDIAN_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _uuid_path(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _UUID.match(value):
        raise ConnectorError(f"Invalid {what} {value!r}: a UUID is expected")
    return value


def _results(page: Any) -> List[Dict[str, Any]]:
    """The items of a Guardian list response, paginated or not."""
    if isinstance(page, dict):
        return list(page.get("results") or [])
    if isinstance(page, list):
        return page
    return []


class WildboxConnector(BaseConnector):
    """Connector for integrating with Wildbox microservices"""

    def __init__(self):
        super().__init__("wildbox", {
            "api_url": settings.wildbox_api_url,
            "data_url": settings.wildbox_data_url,
            "guardian_url": settings.wildbox_guardian_url,
            "agents_url": settings.wildbox_agents_url
        })

        # Initialize HTTP client. No retries: a call is sent once.
        self.client = httpx.Client(timeout=30.0)
        self.logger.info(f"Initialized Wildbox connector with services: {list(self.config.keys())}")

    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the Wildbox connector"""
        return {
            "run_tool": "Run a security tool in the tools service and return its result",
            "query_threat_intel": "Search the threat indicators of the data service",
            "get_vulnerabilities": "List vulnerabilities from Guardian",
            "create_vulnerability": "Record a vulnerability in Guardian against a known asset",
            "analyze_ioc": "Queue an AI analysis of an IOC in the agents service; returns the task",
            "get_asset_info": "Get an asset from Guardian"
        }

    def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a security tool in the tools service.

        Args:
            tool_name: Name of the tool, as the tools service lists it
            params: The tool's input, as its input schema defines it

        Returns:
            The tool's result
        """
        return run_tool_request(self.client, self.config["api_url"], tool_name, params)

    def query_threat_intel(
        self, query: str, indicator_type: Optional[str] = None, limit: int = 100
    ) -> Dict[str, Any]:
        """
        Search threat indicators in the data service.

        The data service answers with the indicators of the caller's team and
        the global feeds.

        Args:
            query: Text to search the indicators' values for
            indicator_type: One of the data service's indicator types
                (ip_address, domain, url, file_hash, email, certificate,
                asn, vulnerability)
            limit: Maximum number of indicators (1 to 10000)

        Returns:
            ``indicators``, ``total``, ``limit``, ``offset``, ``query_time``
        """
        params: Dict[str, Any] = {"q": query, "limit": limit}
        if indicator_type:
            params["indicator_type"] = indicator_type
        return call_service(
            self.client,
            "GET",
            f"{self.config['data_url']}/api/v1/indicators/search",
            what=f"search threat intelligence for '{query}'",
            params=params,
        )

    def get_vulnerabilities(
        self, asset_id: Optional[str] = None, severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List vulnerabilities from Guardian.

        Guardian shows a member the vulnerabilities assigned to or created by
        them, and an owner or admin all of them.

        Args:
            asset_id: Only those of this asset (its UUID)
            severity: Only those of this severity

        Returns:
            Guardian's page: ``count``, ``results`` and the page links
        """
        params: Dict[str, Any] = {}
        if asset_id:
            params["asset_id"] = _uuid_path(asset_id, "asset id")
        if severity:
            params["severity"] = severity
        return call_service(
            self.client,
            "GET",
            f"{self.config['guardian_url']}/api/v1/vulnerabilities/",
            what="list vulnerabilities",
            params=params,
        )

    def get_asset_info(self, asset_id: str) -> Dict[str, Any]:
        """
        Get an asset from Guardian.

        Args:
            asset_id: The asset's UUID

        Returns:
            The asset, as Guardian details it
        """
        asset = _uuid_path(asset_id, "asset id")
        return call_service(
            self.client,
            "GET",
            f"{self.config['guardian_url']}/api/v1/assets/assets/{asset}/",
            what=f"get asset '{asset}'",
        )

    def analyze_ioc(
        self, ioc_type: str, ioc_value: str, priority: str = "normal"
    ) -> Dict[str, Any]:
        """
        Queue an AI analysis of an IOC in the agents service.

        The agents service answers 202 with a task, not a verdict: the
        analysis runs in the background, and its report is read later from
        the task's ``result_url`` (``GET /v1/analyze/{task_id}``) by the user
        the run acts for, who owns the task. A step cannot wait for it.

        Args:
            ioc_type: ipv4, ipv6, domain, url, md5, sha1, sha256 or email
            ioc_value: The IOC to analyze
            priority: low, normal or high

        Returns:
            The task: ``task_id``, ``status``, ``created_at``, ``result_url``
        """
        if ioc_type not in AGENTS_IOC_TYPES:
            raise ConnectorError(
                f"Invalid IOC type {ioc_type!r}: one of {', '.join(AGENTS_IOC_TYPES)}"
            )
        if priority not in AGENTS_PRIORITIES:
            raise ConnectorError(
                f"Invalid priority {priority!r}: one of {', '.join(AGENTS_PRIORITIES)}"
            )
        return call_service(
            self.client,
            "POST",
            f"{self.config['agents_url']}/v1/analyze",
            what=f"queue an AI analysis of {ioc_type} '{ioc_value}'",
            json={"ioc": {"type": ioc_type, "value": ioc_value}, "priority": priority},
            expect=(202,),
        )

    def create_vulnerability(
        self,
        title: str,
        description: str,
        severity: str,
        asset_name: str,
        cve_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record a vulnerability in Guardian.

        A Guardian vulnerability belongs to an asset. The asset is the one
        Guardian knows by the name or IP address ``asset_name``; when there
        is none, or more than one, the step fails and nothing is created.
        Guardian lets owners and admins create vulnerabilities, so the step
        fails with 403 when the run's caller is a member.

        Args:
            title: Vulnerability title
            description: Detailed description
            severity: critical, high, medium, low or info
            asset_name: Name or IP address of the affected asset in Guardian
            cve_id: CVE identifier, if there is one

        Returns:
            The vulnerability Guardian created
        """
        if severity not in GUARDIAN_SEVERITIES:
            raise ConnectorError(
                f"Invalid severity {severity!r}: one of {', '.join(GUARDIAN_SEVERITIES)}"
            )
        asset_id = self._find_asset(asset_name)
        payload: Dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "asset": asset_id,
            "priority": "p1" if severity in ("critical", "high") else "p2",
            "metadata": {"source": "responder"},
        }
        if cve_id:
            payload["cve_id"] = cve_id
        return call_service(
            self.client,
            "POST",
            f"{self.config['guardian_url']}/api/v1/vulnerabilities/",
            what=f"create vulnerability '{title}'",
            json=payload,
            expect=(201,),
        )

    def _find_asset(self, asset_name: str) -> str:
        """The id of the one Guardian asset named or addressed ``asset_name``."""
        page = call_service(
            self.client,
            "GET",
            f"{self.config['guardian_url']}/api/v1/assets/assets/",
            what=f"find asset '{asset_name}'",
            params={"search": asset_name},
        )
        # search matches substrings of several fields; keep exact matches.
        matches = [
            asset
            for asset in _results(page)
            if asset_name in (asset.get("name"), asset.get("ip_address"))
        ]
        if not matches:
            raise ConnectorError(
                f"Guardian has no asset named or addressed '{asset_name}' that "
                "the run's caller can see; no vulnerability was created"
            )
        if len(matches) > 1:
            raise ConnectorError(
                f"{len(matches)} Guardian assets are named or addressed "
                f"'{asset_name}'; no vulnerability was created"
            )
        return str(matches[0]["id"])

    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
