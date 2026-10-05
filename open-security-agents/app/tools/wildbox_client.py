"""
Wildbox API Client for accessing other microservices

Provides authenticated access to the Wildbox security toolkit.
"""

import asyncio
import logging
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Mapping, Optional
import httpx
from open_security_shared.scopes import AUTH_TYPE_HEADER, AUTH_TYPE_SERVICE

from ..config import settings

logger = logging.getLogger(__name__)

# Identity of the user on whose behalf internal tool calls are made (#175).
#
# A ContextVar, so it follows the task's own context: asyncio tasks (the
# agent's concurrent tool calls go through asyncio.gather) and LangChain's
# run_in_executor (which runs a sync tool under copy_context()) both see the
# value of the context they were started from. That same property is why it
# must be scoped: a Celery worker runs one task after another in the same
# thread, hence the same context, so a value set and never reset is still
# there for the next task (#594). Set it through caller_identity(), which
# validates the caller first and restores the previous value on exit.
_caller_identity: ContextVar[Optional[Dict[str, str]]] = ContextVar(
    "wildbox_caller_identity", default=None
)


class CallerIdentityUnavailable(RuntimeError):
    """An internal call has no caller identity or no gateway secret to send.

    The services the client calls accept gateway-authenticated requests only:
    the caller's X-Wildbox-* identity with the GATEWAY_INTERNAL_SECRET proof
    of origin. There is nothing else to send. The client used to fall back to
    the static INTERNAL_API_KEY as X-API-Key, which the tools service has not
    accepted since #566 (it answers 401), so the fallback only turned a
    configuration error into an unexplained authentication failure (#567).

    Also raised when a task is handed a caller that is missing, or lacks a
    user or team id: such a task must not start, let alone call a tool (#594).
    """


def require_caller_identity(caller: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Return the identity to forward for ``caller``, or refuse it.

    A complete caller has a non-blank ``user_id`` and ``team_id``; ``role``
    defaults to ``member``. Anything less cannot be forwarded, and is refused
    rather than completed from somewhere else.

    Raises:
        CallerIdentityUnavailable: ``caller`` is missing or incomplete.
    """
    if not isinstance(caller, Mapping):
        raise CallerIdentityUnavailable("the task has no caller identity")
    user_id = str(caller.get("user_id") or "").strip()
    team_id = str(caller.get("team_id") or "").strip()
    missing = [
        name
        for name, value in (("user_id", user_id), ("team_id", team_id))
        if not value
    ]
    if missing:
        raise CallerIdentityUnavailable(
            "the task's caller identity is incomplete: no " + " and no ".join(missing)
        )
    role = str(caller.get("role") or "").strip() or "member"
    return {"user_id": user_id, "team_id": team_id, "role": role}


def set_caller_identity(user_id: str, team_id: str, role: str = "member") -> Token:
    """Make this identity the one internal calls forward, in this context.

    Returns the ContextVar token, to pass to reset_caller_identity() in a
    ``finally``. Prefer caller_identity(), which does both.

    Raises:
        CallerIdentityUnavailable: ``user_id`` or ``team_id`` is blank.
    """
    identity = require_caller_identity(
        {"user_id": user_id, "team_id": team_id, "role": role}
    )
    return _caller_identity.set(identity)


def reset_caller_identity(token: Token) -> None:
    """Restore the identity that was current before set_caller_identity()."""
    _caller_identity.reset(token)


@contextmanager
def caller_identity(caller: Optional[Mapping[str, Any]]) -> Iterator[Dict[str, str]]:
    """Run a block with ``caller`` as the identity its internal calls send.

    The caller is validated before anything is set, so a missing or partial
    caller raises CallerIdentityUnavailable before the block runs. On exit,
    normal or not, the previous identity is restored, so nothing set here is
    visible to whatever runs next in the same context (#594).
    """
    identity = require_caller_identity(caller)
    token = _caller_identity.set(identity)
    try:
        yield identity
    finally:
        _caller_identity.reset(token)


class ToolInputError(ValueError):
    """A tool was given an argument the service it calls would refuse.

    Raised before any request is built, with a message the model can act on
    (it names the accepted values). The client turns it into an error result.
    """


# What an analysis calls an IOC type (app/schemas.py IOCType), and the short
# names a model tends to use, mapped to the names the services use.
#
# The data service's Indicator.indicator_type (open-security-data
# app/models.py IndicatorType).
DATA_INDICATOR_TYPES = {
    "ipv4": "ip_address",
    "ipv6": "ip_address",
    "ip": "ip_address",
    "ip_address": "ip_address",
    "domain": "domain",
    "url": "url",
    "md5": "file_hash",
    "sha1": "file_hash",
    "sha256": "file_hash",
    "hash": "file_hash",
    "file_hash": "file_hash",
    "email": "email",
}
# The tools service's threat_intelligence_aggregator indicator_type.
REPUTATION_INDICATOR_TYPES = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "ip_address": "ip",
    "domain": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "file_hash": "hash",
    "email": "email",
}
# The tools service's dns_enumerator RecordType.
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV")

# How many records of a search an agent is handed. The services page or cap
# their answers far higher; a model needs the best matches, and is told the
# total so it knows when there were more.
MAX_SEARCH_RESULTS = 25

# The fields of a data-service indicator and of a Guardian vulnerability the
# agent is given. Internal ids, team ids and metadata blobs stay out.
INDICATOR_FIELDS = (
    "indicator_type",
    "value",
    "threat_types",
    "confidence",
    "severity",
    "description",
    "tags",
    "first_seen",
    "last_seen",
    "active",
)
VULNERABILITY_FIELDS = (
    "title",
    "cve_id",
    "severity",
    "status",
    "priority",
    "risk_score",
    "cvss_v3_score",
    "asset_name",
    "asset_type",
    "due_date",
    "is_overdue",
    "created_at",
)


def _mapped_type(value: Optional[str], mapping: Mapping[str, str], what: str) -> str:
    key = str(value or "").strip().lower()
    if key not in mapping:
        raise ToolInputError(
            f"Unknown {what} {value!r}: use one of {', '.join(sorted(mapping))}"
        )
    return mapping[key]


def _error_detail(response: httpx.Response, limit: int = 300) -> str:
    """The service's own error message, short enough for a tool result."""
    try:
        body = response.json()
    except ValueError:
        return (response.text or response.reason_phrase or "")[:limit]
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and "message" in error:
            message = str(error["message"])
            # The tools service says which fields it refused and why, without
            # their values (#585): what the model needs to correct a call.
            details = error.get("details")
            failures = details.get("errors") if isinstance(details, dict) else None
            if isinstance(failures, list) and failures:
                message += " (" + "; ".join(str(f) for f in failures) + ")"
            return message[:limit]
        for key in ("detail", "error", "message"):
            if key in body:
                return str(body[key])[:limit]
    return str(body)[:limit]


def _service_error(service: str, error: httpx.HTTPError) -> Dict[str, Any]:
    """The error result of a call the service refused or never received.

    It names the service and what it answered, never its address: the
    result is read by the model and can be quoted in the report the user
    gets, and str() of an httpx error carries the full internal URL.
    """
    if isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        return {
            "success": False,
            "error": (
                f"The {service} answered {status_code}: "
                f"{_error_detail(error.response)}"
            ),
            "status_code": status_code,
        }
    return {
        "success": False,
        "error": f"The {service} could not be reached ({type(error).__name__})",
    }


class WildboxAPIClient:
    """Client for the Wildbox services the agent's tools call.

    Every request goes to a service directly, on the internal network, and
    carries the gateway identity of the user who submitted the analysis with
    the X-Gateway-Secret proof of origin: the same headers the gateway puts on
    a request it forwards for that user, and the only authentication the
    tools, data and guardian services accept. The services therefore answer
    for that user and that team, exactly as they would through the gateway.
    The client has no identity of its own and no key that sees every team
    (#175, #567, #652). The responder's connectors do the same
    (open-security-responder/app/caller.py, #616).
    """

    # The tools-service tools the agent may run: internal name -> the tool's
    # name in the tools service. A fixed allowlist, so a tool name the model
    # (or a prompt injected through an IOC) chooses can never become a raw
    # URL path component. Each method below builds the body the tool's input
    # schema validates; tests/unit/test_tool_contracts.py checks every one
    # against the schema in the tools service's source.
    TOOL_ENDPOINT_MAP = {
        "whois_lookup": "whois_lookup",
        "dns_lookup": "dns_enumerator",
        "geolocation_lookup": "ip_geolocation",
        "network_port_scanner": "network_port_scanner",
        "reputation_check": "threat_intelligence_aggregator",
        "hash_lookup": "malware_hash_checker",
        "url_analyzer": "url_analyzer",
    }

    # The routes the data-lake and vulnerability tools call. They were
    # /api/v1/threat-intel/query and /api/v1/vulnerabilities/search, which
    # neither service serves (#652).
    DATA_INDICATOR_SEARCH_PATH = "/api/v1/indicators/search"
    GUARDIAN_VULNERABILITIES_PATH = "/api/v1/vulnerabilities/"

    def __init__(self):
        self.api_url = settings.wildbox_api_url
        self.data_url = settings.wildbox_data_url
        self.guardian_url = settings.wildbox_guardian_url
        self.responder_url = settings.wildbox_responder_url
        self.gateway_secret = settings.gateway_internal_secret
        if not self.gateway_secret:
            logger.error(
                "GATEWAY_INTERNAL_SECRET is not set: every internal tool call "
                "will fail, because the services accept gateway-authenticated "
                "requests only."
            )

        # HTTP client configuration
        self.timeout = httpx.Timeout(30.0, connect=10.0)

    def _request_headers(self) -> Dict[str, str]:
        """Build auth headers per call.

        Forwards the caller's gateway identity (X-Wildbox-*) with the
        proof-of-origin secret (#175), so downstream services apply the user's
        real team scope and role. Without both there is no way to authenticate,
        and the call fails here, saying which is missing, instead of reaching
        the service and coming back 401.

        Raises:
            CallerIdentityUnavailable: no caller identity was set for this
                task, or GATEWAY_INTERNAL_SECRET is not configured.
        """
        caller = _caller_identity.get()
        missing = []
        if not caller or not caller.get("user_id") or not caller.get("team_id"):
            missing.append("no caller identity was set for this task (set_caller_identity)")
        if not self.gateway_secret:
            missing.append("GATEWAY_INTERNAL_SECRET is not set")
        if missing:
            message = "Cannot authenticate an internal call: " + "; ".join(missing)
            logger.error(message)
            raise CallerIdentityUnavailable(message)
        return {
            "User-Agent": "Open-Security-Agents/1.0",
            "Content-Type": "application/json",
            "X-Wildbox-User-ID": caller["user_id"],
            "X-Wildbox-Team-ID": caller["team_id"],
            "X-Wildbox-Role": caller["role"],
            # What this call is (#637): a Wildbox service acting for the
            # caller, whose own credential the gateway checked on the route
            # that started the analysis. The services refuse a request that
            # needs a scope and does not say what its credential is.
            AUTH_TYPE_HEADER: AUTH_TYPE_SERVICE,
            "X-Gateway-Secret": self.gateway_secret,
            # As the gateway sends it (nginx/includes/proxy_params.conf): the
            # analysis was submitted over HTTPS, and TLS ends at the gateway.
            # Guardian redirects a plain-HTTP request that does not say so to
            # https:// on its own port, where nothing listens
            # (SECURE_SSL_REDIRECT with SECURE_PROXY_SSL_HEADER), so without
            # this header every Guardian call was answered 301.
            "X-Forwarded-Proto": "https",
        }

    async def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a tool of the tools service, as the caller.

        Args:
            tool_name: Internal name of the tool, a key of TOOL_ENDPOINT_MAP
            params: The tool's input, with the field names of its input schema

        Returns:
            The tool's result, or ``{"success": False, "error": ...}``
        """
        # SSRF protection: only call explicitly-allowlisted tool endpoints.
        # An LLM-chosen (or prompt-injected) tool_name must never become a
        # raw URL path component — f"{api_url}/api/tools/{tool_name}" would
        # otherwise let a crafted IOC steer the agent to arbitrary internal
        # paths. Reject anything not in the fixed endpoint map.
        endpoint_name = self.TOOL_ENDPOINT_MAP.get(tool_name)
        if endpoint_name is None:
            logger.warning(f"Rejected unmapped tool '{tool_name}' (not in allowlist)")
            return {"error": f"Unknown tool: {tool_name}", "success": False}

        url = f"{self.api_url}/api/tools/{endpoint_name}"
        # Built before the first attempt: without an identity nothing is sent.
        headers = self._request_headers()

        # Retry with exponential backoff, on a rate limit only.
        max_retries = 3
        retry_delay = 1.0
        try:
            for attempt in range(max_retries + 1):
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    logger.debug(
                        f"Running tool '{endpoint_name}' "
                        f"(attempt {attempt + 1}/{max_retries + 1})"
                    )
                    response = await client.post(url, json=params, headers=headers)

                if response.status_code == 429 and attempt < max_retries:
                    logger.warning(
                        f"Rate limited on tool '{endpoint_name}', "
                        f"retrying in {retry_delay}s"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue

                response.raise_for_status()
                result = response.json()
                logger.debug(f"Tool '{endpoint_name}' completed")
                return result
        except httpx.HTTPError as e:
            logger.error(f"Tool '{endpoint_name}' failed: {type(e).__name__}: {e}")
            return _service_error("tools service", e)
        except ValueError as e:
            logger.error(f"Tool '{endpoint_name}' answered something that is not JSON: {e}")
            return {
                "success": False,
                "error": "The tools service answered something that is not JSON",
            }
        return {"success": False, "error": "The tools service kept answering 429"}

    async def _get_json(
        self, service: str, url: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """GET ``url`` on a Wildbox service as the caller.

        Returns ``{"success": True, "body": <the JSON object>}``, or an error
        result. Sent once: a failure is the tool's answer, not retried.

        Raises:
            CallerIdentityUnavailable: there is no caller or no gateway
                secret to send. Nothing is sent.
        """
        headers = self._request_headers()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as e:
            logger.error(f"Call to the {service} failed: {type(e).__name__}: {e}")
            return _service_error(service, e)
        except ValueError as e:
            logger.error(f"The {service} answered something that is not JSON: {e}")
            return {
                "success": False,
                "error": f"The {service} answered something that is not JSON",
            }
        if not isinstance(body, dict):
            return {
                "success": False,
                "error": f"The {service} answered something unexpected",
            }
        return {"success": True, "body": body}

    async def search_threat_intel(
        self, ioc_value: str, ioc_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Search the data service's threat indicators for an IOC.

        Calls ``GET {WILDBOX_DATA_URL}/api/v1/indicators/search`` as the
        caller. The data service answers with the indicators of the caller's
        team and of the feeds shared by every team, and nobody else's.

        Args:
            ioc_value: Text to look for in the indicators' values and
                descriptions (a substring match)
            ioc_type: Optional type to restrict the search to: an IOC type
                (ipv4, ipv6, domain, url, md5, sha1, sha256, email) or one
                of ip, hash

        Returns:
            ``total`` matching indicators, the first ``returned`` of them in
            ``indicators`` (each marked ``exact_match`` when its value is the
            IOC itself), or ``{"success": False, "error": ...}``
        """
        query = str(ioc_value or "").strip()
        try:
            if not query:
                raise ToolInputError("An IOC value to search for is required")
            params: Dict[str, Any] = {"q": query, "limit": MAX_SEARCH_RESULTS}
            if ioc_type:
                params["indicator_type"] = _mapped_type(
                    ioc_type, DATA_INDICATOR_TYPES, "IOC type"
                )
        except ToolInputError as e:
            return {"success": False, "error": str(e)}

        answer = await self._get_json(
            "data service", f"{self.data_url}{self.DATA_INDICATOR_SEARCH_PATH}", params
        )
        if not answer["success"]:
            return answer
        body = answer["body"]
        found = body.get("indicators")
        if not isinstance(found, list) or not isinstance(body.get("total"), int):
            return {
                "success": False,
                "error": "The data service answered something unexpected",
            }

        wanted = query.lower()
        indicators = []
        for item in found[:MAX_SEARCH_RESULTS]:
            if not isinstance(item, dict):
                continue
            indicator = {name: item.get(name) for name in INDICATOR_FIELDS}
            indicator["exact_match"] = wanted in (
                str(item.get("value") or "").lower(),
                str(item.get("normalized_value") or "").lower(),
            )
            indicators.append(indicator)
        return {
            "success": True,
            "source": "Wildbox data service: your team's indicators and the shared feeds",
            "query": query,
            "indicator_type": params.get("indicator_type"),
            "total": body["total"],
            "returned": len(indicators),
            "indicators": indicators,
        }

    async def search_vulnerabilities(self, query: str) -> Dict[str, Any]:
        """
        Search the vulnerabilities Guardian records for the caller's team.

        Calls ``GET {WILDBOX_GUARDIAN_URL}/api/v1/vulnerabilities/?search=``
        as the caller. Guardian matches the text against title, description,
        CVE id and asset name, within the caller's team; a member sees the
        vulnerabilities assigned to or created by them, an owner or admin all
        of the team's.

        Args:
            query: Text to search for: a CVE id, a product, an asset name

        Returns:
            ``total`` matching vulnerabilities and the first ``returned`` of
            them, or ``{"success": False, "error": ...}``
        """
        text = str(query or "").strip()
        if not text:
            return {"success": False, "error": "A text to search for is required"}

        answer = await self._get_json(
            "guardian service",
            f"{self.guardian_url}{self.GUARDIAN_VULNERABILITIES_PATH}",
            {"search": text},
        )
        if not answer["success"]:
            return answer
        body = answer["body"]
        found = body.get("results")
        if not isinstance(found, list) or not isinstance(body.get("count"), int):
            return {
                "success": False,
                "error": "The guardian service answered something unexpected",
            }

        # Guardian's `next` and `previous` links are left out: they are of no
        # use to the model.
        vulnerabilities = [
            {name: item.get(name) for name in VULNERABILITY_FIELDS}
            for item in found[:MAX_SEARCH_RESULTS]
            if isinstance(item, dict)
        ]
        return {
            "success": True,
            "source": "Guardian: the vulnerabilities recorded for your team's assets",
            "query": text,
            "total": body["count"],
            "returned": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

    async def get_reputation(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Look an IOC up in the tools service's threat intelligence aggregator.

        Args:
            ioc_value: The IOC to check
            ioc_type: Its type: an IOC type (ipv4, ipv6, domain, url, md5,
                sha1, sha256, email) or one of ip, hash

        Returns:
            The aggregator's result
        """
        try:
            indicator_type = _mapped_type(ioc_type, REPUTATION_INDICATOR_TYPES, "IOC type")
        except ToolInputError as e:
            return {"success": False, "error": str(e)}
        return await self.run_tool(
            "reputation_check",
            {"indicator": ioc_value, "indicator_type": indicator_type},
        )

    async def port_scan(self, ip_address: str, ports: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan the TCP ports of a host.

        Args:
            ip_address: Target IP address or hostname
            ports: Ports to scan ("1-1000", "80,443,22")

        Returns:
            Port scan results
        """
        return await self.run_tool(
            "network_port_scanner",
            {"target": ip_address, "ports": ports or "1-1000", "scan_type": "tcp"},
        )

    async def whois_lookup(self, target: str) -> Dict[str, Any]:
        """
        Look up the registration of a domain.

        Args:
            target: Domain name

        Returns:
            WHOIS data
        """
        return await self.run_tool("whois_lookup", {"domain": target})

    async def dns_lookup(self, domain: str, record_type: str = "A") -> Dict[str, Any]:
        """
        Resolve DNS records of a domain.

        Args:
            domain: Domain to look up
            record_type: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR or SRV

        Returns:
            DNS lookup results
        """
        wanted = str(record_type or "A").strip().upper()
        if wanted not in DNS_RECORD_TYPES:
            return {
                "success": False,
                "error": (
                    f"Unknown DNS record type {record_type!r}: "
                    f"use one of {', '.join(DNS_RECORD_TYPES)}"
                ),
            }
        return await self.run_tool(
            "dns_lookup",
            {
                "target_domain": domain,
                "record_types": [wanted],
                # A lookup: no subdomain brute force and no zone transfer
                # attempt against the domain's name servers.
                "enumeration_mode": "basic",
                "check_zone_transfer": False,
            },
        )

    async def url_analysis(self, url: str) -> Dict[str, Any]:
        """
        Follow a URL's redirect chain and report where it leads.

        Args:
            url: URL to analyze, with its scheme

        Returns:
            The redirect chain, the final URL and the tool's security analysis
        """
        return await self.run_tool(
            "url_analyzer", {"shortened_url": url, "follow_redirects": True}
        )

    async def hash_lookup(self, hash_value: str) -> Dict[str, Any]:
        """
        Check a file hash against the tools service's malware hash checker.

        Args:
            hash_value: File hash (MD5, SHA1, SHA256 or SHA512)

        Returns:
            Hash reputation data
        """
        return await self.run_tool("hash_lookup", {"hash_value": hash_value})

    async def geolocation_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Get geolocation information for an IP

        Args:
            ip_address: IP address to locate

        Returns:
            Geolocation data
        """
        return await self.run_tool("geolocation_lookup", {"ip_address": ip_address})

    async def health_check(self) -> Dict[str, str]:
        """
        Check health of all Wildbox services

        Returns:
            Health status of each service
        """
        services = {
            "api": self.api_url,
            "data": self.data_url,
            "guardian": self.guardian_url,
            "responder": self.responder_url
        }

        health_status = {}

        for service_name, service_url in services.items():
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                    # /health is public on every service, and a health check
                    # runs outside any user's task, so it sends no identity.
                    response = await client.get(
                        f"{service_url}/health",
                        headers={"User-Agent": "Open-Security-Agents/1.0"},
                    )
                    if response.status_code == 200:
                        health_status[service_name] = "healthy"
                    else:
                        health_status[service_name] = f"unhealthy ({response.status_code})"

            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                health_status[service_name] = f"error ({str(e)})"

        return health_status


# Global client instance
wildbox_client = WildboxAPIClient()
