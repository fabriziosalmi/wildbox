"""
Certificate Transparency Log Scanner

Queries the public Certificate Transparency logs (via the crt.sh index) for
certificates issued for a domain, and derives subdomain, issuer, timeline and
security analysis from what is actually there.

Every value in the output comes from a real CT log entry. Fields the CT index
does not carry (key algorithm, key size, signature algorithm, fingerprint) are
reported as "unknown" rather than guessed: an invented key size on a
certificate report is worse than an absent one.
"""

import asyncio
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import aiohttp

from schemas import CertificateInfo, CTLogScannerInput, CTLogScannerOutput

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Certificate Transparency Log Scanner",
    "description": (
        "Search the public Certificate Transparency logs for certificates "
        "issued for a domain, and analyse the resulting hostnames, issuers "
        "and issuance timeline. Data source: crt.sh (no credentials needed)."
    ),
    "version": "2.0.0",
    "author": "Wildbox Security",
    "category": "reconnaissance",
    "tags": ["certificates", "ct-logs", "ssl", "tls", "osint"],
}

CRT_SH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 30
# crt.sh answers 5xx under load fairly often; one retry covers the transient
# case without letting a worker hang on a dead endpoint.
MAX_ATTEMPTS = 2


class CTLogLookupError(RuntimeError):
    """Raised when the CT log index cannot be queried."""


def _parse_ct_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse a crt.sh timestamp ('2026-01-31T12:00:00', with or without micros)."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.warning("Unparsable CT timestamp: %r", value)
    return None


def _split_name_value(name_value: Optional[str]) -> List[str]:
    """crt.sh packs the SANs into a newline-separated name_value field."""
    if not name_value:
        return []
    return sorted({n.strip().lower() for n in name_value.split("\n") if n.strip()})


def _issuer_organisation(issuer_name: str) -> str:
    """Extract O= from an RFC4514 issuer DN, falling back to the raw DN."""
    match = re.search(r"O=([^,]+)", issuer_name or "")
    return match.group(1).strip().strip('"') if match else (issuer_name or "unknown")


async def fetch_ct_entries(domain: str, include_subdomains: bool) -> List[Dict[str, Any]]:
    """Fetch raw CT log entries for a domain from crt.sh."""
    query = f"%.{domain}" if include_subdomains else domain
    params = {"q": query, "output": "json"}
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    last_error: Optional[str] = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(CRT_SH_URL, params=params) as response:
                    if response.status == 200:
                        # crt.sh sometimes answers 200 with an HTML error page.
                        try:
                            return await response.json(content_type=None)
                        except (ValueError, aiohttp.ContentTypeError) as exc:
                            last_error = f"malformed response from crt.sh: {exc}"
                    else:
                        last_error = f"crt.sh returned HTTP {response.status}"
        except asyncio.TimeoutError:
            last_error = f"crt.sh timed out after {REQUEST_TIMEOUT}s"
        except aiohttp.ClientError as exc:
            last_error = f"cannot reach crt.sh: {exc}"

        if attempt < MAX_ATTEMPTS:
            await asyncio.sleep(2)

    raise CTLogLookupError(last_error or "unknown error querying crt.sh")


def to_certificate_info(entry: Dict[str, Any], now: datetime) -> Optional[CertificateInfo]:
    """Map one crt.sh entry onto the tool's certificate model."""
    not_before = _parse_ct_timestamp(entry.get("not_before"))
    not_after = _parse_ct_timestamp(entry.get("not_after"))
    if not_after is None:
        return None

    sans = _split_name_value(entry.get("name_value"))
    subject = entry.get("common_name") or ""

    return CertificateInfo(
        serial_number=str(entry.get("serial_number") or "unknown"),
        issuer=_issuer_organisation(entry.get("issuer_name", "")),
        subject=subject or (sans[0] if sans else "unknown"),
        subject_alt_names=sans,
        not_before=not_before.isoformat() if not_before else "unknown",
        not_after=not_after.isoformat(),
        is_expired=not_after < now,
        # A CT-logged certificate chains to a trusted root by construction:
        # the logs do not accept self-signed certificates.
        is_self_signed=False,
        # Not carried by the crt.sh index. Reported honestly instead of
        # invented — use the ssl_analyzer tool against a live host for these.
        key_algorithm="unknown",
        signature_algorithm="unknown",
        key_size=None,
        fingerprint_sha256="unknown",
        ct_log_entry_id=str(entry.get("id") or "unknown"),
        log_timestamp=(
            _parse_ct_timestamp(entry.get("entry_timestamp")) or not_after
        ).isoformat(),
    )


def analyze_subdomains(certificates: List[CertificateInfo], domain: str) -> Dict[str, Any]:
    """Aggregate the distinct hostnames the CT logs expose for this domain."""
    hostnames = {
        name
        for cert in certificates
        for name in cert.subject_alt_names
        if name == domain or name.endswith("." + domain)
    }
    wildcards = sorted(n for n in hostnames if n.startswith("*."))
    concrete = sorted(n for n in hostnames if not n.startswith("*."))
    return {
        "unique_hostnames": len(hostnames),
        "wildcard_certificates": len(wildcards),
        "wildcards": wildcards,
        "subdomains": concrete,
    }


def analyze_issuers(certificates: List[CertificateInfo]) -> Dict[str, Any]:
    """Count certificates per issuing CA."""
    counts = Counter(cert.issuer for cert in certificates)
    return {
        "distinct_issuers": len(counts),
        "certificates_per_issuer": dict(counts.most_common()),
        "primary_issuer": counts.most_common(1)[0][0] if counts else None,
    }


def analyze_timeline(certificates: List[CertificateInfo], now: datetime) -> Dict[str, Any]:
    """Summarise issuance and expiry across the returned certificates."""
    issued = sorted(c.not_before for c in certificates if c.not_before != "unknown")
    expiring_soon = [
        c.subject
        for c in certificates
        if not c.is_expired
        and datetime.fromisoformat(c.not_after) < now + timedelta(days=30)
    ]
    return {
        "first_seen": issued[0] if issued else None,
        "last_seen": issued[-1] if issued else None,
        "active_certificates": sum(1 for c in certificates if not c.is_expired),
        "expired_certificates": sum(1 for c in certificates if c.is_expired),
        "expiring_within_30_days": expiring_soon,
    }


def detect_suspicious_patterns(
    certificates: List[CertificateInfo], domain: str, now: datetime
) -> List[str]:
    """Flag patterns that are genuinely observable from CT data alone."""
    findings: List[str] = []
    hostnames = {n for c in certificates for n in c.subject_alt_names}

    # A label embedding the domain without being a subdomain of it is a
    # common phishing-infrastructure signal.
    base = domain.split(".")[0]
    lookalikes = sorted(
        n for n in hostnames
        if base in n and not (n == domain or n.endswith("." + domain))
    )
    if lookalikes:
        findings.append(
            f"{len(lookalikes)} hostname(s) embed '{base}' without being a "
            f"subdomain of {domain}: {', '.join(lookalikes[:5])}"
        )

    recent = [
        c for c in certificates
        if c.not_before != "unknown"
        and datetime.fromisoformat(c.not_before) > now - timedelta(days=7)
    ]
    if len(recent) > 10:
        findings.append(
            f"{len(recent)} certificates issued in the last 7 days — confirm "
            "they are all expected"
        )

    issuers = {c.issuer for c in certificates}
    if len(issuers) > 5:
        findings.append(
            f"certificates issued by {len(issuers)} different CAs — a broad "
            "issuer set can indicate unmanaged or unauthorised issuance"
        )

    return findings


def generate_recommendations(
    subdomain_analysis: Dict[str, Any],
    timeline: Dict[str, Any],
    suspicious: List[str],
) -> List[str]:
    """Recommendations derived from the observed data, not from a template."""
    recommendations: List[str] = []

    if timeline["expiring_within_30_days"]:
        recommendations.append(
            f"{len(timeline['expiring_within_30_days'])} certificate(s) expire "
            "within 30 days — schedule renewal"
        )
    if subdomain_analysis["wildcard_certificates"]:
        recommendations.append(
            "Wildcard certificates are in use: one key compromise covers every "
            "hostname under it — prefer per-host certificates for sensitive "
            "services"
        )
    if suspicious:
        recommendations.append(
            "Review the flagged issuance patterns above; CAA records constrain "
            "which CAs may issue for this domain"
        )
    if subdomain_analysis["unique_hostnames"] > 50:
        recommendations.append(
            f"{subdomain_analysis['unique_hostnames']} hostnames are publicly "
            "visible through CT — confirm none of them expose internal systems"
        )
    if not recommendations:
        recommendations.append(
            "No issues observable from CT data alone. Run the SSL analyzer "
            "against live hosts to inspect key strength and protocol support."
        )
    return recommendations


async def execute_tool(request: CTLogScannerInput) -> CTLogScannerOutput:
    """Search the Certificate Transparency logs and analyse the results."""
    now = datetime.now(timezone.utc)
    search_timestamp = now.isoformat()
    domain = (request.domain or "").strip().lower().rstrip(".")

    empty: Dict[str, Any] = {
        "domain": domain,
        "certificates_found": [],
        "subdomain_analysis": {},
        "issuer_analysis": {},
        "timeline_analysis": {},
        "security_insights": {},
        "suspicious_patterns": [],
        "recommendations": [],
        "total_certificates": 0,
        "search_timestamp": search_timestamp,
    }

    if not domain or " " in domain or "/" in domain:
        return CTLogScannerOutput(
            **empty, success=False, message="A single valid domain name is required"
        )

    try:
        entries = await fetch_ct_entries(domain, request.include_subdomains)
    except CTLogLookupError as exc:
        logger.warning("CT lookup failed for %s: %s", domain, exc)
        return CTLogScannerOutput(
            **empty,
            success=False,
            message=f"Certificate Transparency lookup failed: {exc}",
        )

    cutoff = now - timedelta(days=request.days_back)
    certificates: List[CertificateInfo] = []
    for entry in entries:
        cert = to_certificate_info(entry, now)
        if cert is None:
            continue
        if cert.not_before != "unknown" and datetime.fromisoformat(cert.not_before) < cutoff:
            continue
        if cert.is_expired and not request.include_expired:
            continue
        certificates.append(cert)

    # Newest first, so a truncated result set keeps the relevant end.
    certificates.sort(key=lambda c: c.not_after, reverse=True)
    total_matching = len(certificates)
    certificates = certificates[: request.max_results]

    subdomain_analysis = analyze_subdomains(certificates, domain)
    issuer_analysis = analyze_issuers(certificates)
    timeline_analysis = analyze_timeline(certificates, now)
    suspicious = detect_suspicious_patterns(certificates, domain, now)

    security_insights = {
        "data_source": "crt.sh Certificate Transparency index",
        "certificates_matching_query": total_matching,
        "certificates_returned": len(certificates),
        "truncated": total_matching > len(certificates),
        "attack_surface_hostnames": subdomain_analysis["unique_hostnames"],
        "note": (
            "Key algorithm, key size, signature algorithm and SHA-256 "
            "fingerprint are not carried by the CT index and are reported as "
            "'unknown'. Use the SSL analyzer against a live host for those."
        ),
    }

    return CTLogScannerOutput(
        domain=domain,
        certificates_found=certificates,
        subdomain_analysis=subdomain_analysis,
        issuer_analysis=issuer_analysis,
        timeline_analysis=timeline_analysis,
        security_insights=security_insights,
        suspicious_patterns=suspicious,
        recommendations=generate_recommendations(
            subdomain_analysis, timeline_analysis, suspicious
        ),
        total_certificates=total_matching,
        search_timestamp=search_timestamp,
        success=True,
        message=(
            f"Found {total_matching} certificate(s) for {domain} in the CT logs"
            if total_matching
            else f"No certificates found for {domain} in the CT logs"
        ),
    )
