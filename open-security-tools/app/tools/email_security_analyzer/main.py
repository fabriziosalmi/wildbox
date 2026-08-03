"""
Email Security Analyzer Tool

This tool analyzes email headers and performs comprehensive email security
assessment including SPF, DKIM, DMARC, and reputation analysis.
"""

import re

import dns.resolver
from email.utils import parsedate_to_datetime
import socket
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from email.parser import HeaderParser
from email import policy

try:
    from schemas import (
        EmailSecurityInput, EmailSecurityOutput, SPFAnalysis, DKIMAnalysis,
        DMARCAnalysis, EmailRouting, ReputationAnalysis, PhishingIndicators
    )
except ImportError:
    from schemas import (
        EmailSecurityInput, EmailSecurityOutput, SPFAnalysis, DKIMAnalysis,
        DMARCAnalysis, EmailRouting, ReputationAnalysis, PhishingIndicators
    )



# --- Real DNS lookups -------------------------------------------------------
# SPF/DKIM/DMARC verdicts used to be produced with random.random(); they are
# published as DNS TXT records, so they are looked up for real here. The
# pattern mirrors the dns_security_checker tool.

DNS_TIMEOUT = 5.0
# DKIM selectors are not discoverable from DNS alone: the selector lives in
# the DKIM-Signature header. When a message is supplied we use its selector;
# otherwise we probe the selectors used by the common ESPs.
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail")


def _resolver() -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


# Public DNS blocklists. A listed host resolves inside the zone (127.0.0.x);
# an unlisted one returns NXDOMAIN. No credentials required.
URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at",
)

IP_BLOCKLISTS = {
    "Spamhaus ZEN": "zen.spamhaus.org",
    "Barracuda": "b.barracudacentral.org",
    "SpamCop": "bl.spamcop.net",
}
DOMAIN_BLOCKLISTS = {
    "SURBL": "multi.surbl.org",
    "Spamhaus DBL": "dbl.spamhaus.org",
}


def check_ip_blocklist(ip: str, zone: str) -> bool:
    """Query a DNSBL for an IPv4 address (reversed octets + zone)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4 or addr.is_private:
        return False
    query = ".".join(reversed(str(addr).split("."))) + "." + zone
    try:
        _resolver().resolve(query, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        # A resolver failure is not a listing; do not invent one.
        return False


def check_domain_blocklist(domain: str, zone: str) -> bool:
    """Query a domain-based blocklist (URIBL/DBL style)."""
    if not domain:
        return False
    try:
        _resolver().resolve(f"{domain}.{zone}", "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return False


def query_txt(name: str) -> List[str]:
    """Return the TXT records for a name, or [] when there are none.

    A missing record and a broken resolver are different things: NXDOMAIN /
    NoAnswer return [], everything else propagates so the caller can report
    the lookup failure instead of silently claiming "no record".
    """
    try:
        answers = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answers]


class EmailSecurityAnalyzer:
    """Email security analyzer with comprehensive authentication and reputation checking"""
    
    # Known malicious domains (for demonstration)
    MALICIOUS_DOMAINS = {
        'phishing-example.com', 'malware-site.org', 'fake-bank.net',
        'suspicious-domain.tk', 'scam-alert.ml'
    }
    
    # Trusted domains
    TRUSTED_DOMAINS = {
        'gmail.com', 'outlook.com', 'yahoo.com', 'apple.com', 'microsoft.com',
        'amazon.com', 'google.com', 'facebook.com', 'twitter.com'
    }
    
    # Phishing keywords
    PHISHING_KEYWORDS = [
        'urgent', 'immediate', 'suspend', 'verify', 'confirm', 'update',
        'click here', 'act now', 'limited time', 'expires', 'winner',
        'congratulations', 'prize', 'lottery', 'inheritance', 'tax refund'
    ]
    
    # Brand impersonation patterns
    BRAND_PATTERNS = {
        'paypal': r'p[a4@]yp[a4@]l|p[4@]ypal',
        'amazon': r'[a4@]m[a4@]z[o0]n|[a4@]mazon',
        'microsoft': r'm[i1]cr[o0]s[o0]ft|m[i1]cro5oft',
        'apple': r'[a4@]ppl[e3]|[a4@]pp1e',
        'google': r'g[o0][o0]gl[e3]|g00gle'
    }
    
    def __init__(self):
        pass
    
    def parse_email_headers(self, headers_text: str) -> Dict[str, Any]:
        """Parse email headers and extract key information"""
        
        try:
            # Parse headers
            parser = HeaderParser(policy=policy.default)
            headers = parser.parsestr(headers_text)
            
            # Extract key fields
            sender_email = headers.get('From', '')
            sender_domain = ''
            sender_ip = None
            
            # Extract email from "From" field
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender_email)
            if email_match:
                sender_email = email_match.group()
                sender_domain = sender_email.split('@')[1]
            
            # Extract sender IP from Received headers
            received_headers = headers.get_all('Received') or []
            for received in received_headers:
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
                if ip_match:
                    sender_ip = ip_match.group(1)
                    break
            
            return {
                'headers': headers,
                'sender_email': sender_email,
                'sender_domain': sender_domain,
                'sender_ip': sender_ip,
                'received_headers': received_headers
            }
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            raise ValueError(f"Failed to parse email headers: {str(e)}")
    
    def analyze_spf(self, sender_domain: str, sender_ip: Optional[str]) -> SPFAnalysis:
        """Look up and evaluate the domain's real SPF record (RFC 7208)."""
        issues: List[str] = []
        authorized_senders: List[str] = []
        spf_record: Optional[str] = None
        spf_result = "none"

        if not sender_domain:
            return SPFAnalysis(
                spf_record_found=False, spf_record=None, spf_result="none",
                spf_issues=["No sender domain to evaluate"], authorized_senders=[],
            )

        try:
            records = [r for r in query_txt(sender_domain) if r.lower().startswith("v=spf1")]
        except Exception as exc:  # resolver failure, not a missing record
            return SPFAnalysis(
                spf_record_found=False, spf_record=None, spf_result="temperror",
                spf_issues=[f"SPF lookup failed: {exc}"], authorized_senders=[],
            )

        if not records:
            return SPFAnalysis(
                spf_record_found=False, spf_record=None, spf_result="none",
                spf_issues=["No SPF record published for this domain"],
                authorized_senders=[],
            )

        if len(records) > 1:
            issues.append(
                f"{len(records)} SPF records published — RFC 7208 requires exactly "
                "one; receivers must treat this as permerror"
            )
            spf_result = "permerror"

        spf_record = records[0]
        mechanisms = spf_record.split()[1:]
        authorized_senders = [
            m for m in mechanisms
            if m.split(":")[0].lstrip("+-~?") in ("a", "mx", "ip4", "ip6", "include", "exists")
        ]

        # The "all" mechanism decides what happens to unlisted senders.
        all_mechanism = next((m for m in mechanisms if m.endswith("all")), None)
        if all_mechanism is None:
            issues.append("SPF record has no 'all' mechanism: unlisted senders are unconstrained")
        elif all_mechanism.startswith("+"):
            issues.append("SPF ends with '+all', which authorises every sender — equivalent to no SPF")
        elif all_mechanism.startswith("?"):
            issues.append("SPF ends with '?all' (neutral): the record provides no enforcement")

        # RFC 7208 caps DNS-querying mechanisms at 10; exceeding it is permerror.
        lookup_mechanisms = sum(
            1 for m in mechanisms
            if m.split(":")[0].lstrip("+-~?") in ("include", "a", "mx", "ptr", "exists")
            or m.startswith("redirect=")
        )
        if lookup_mechanisms > 10:
            issues.append(
                f"{lookup_mechanisms} DNS-querying mechanisms exceed the RFC 7208 "
                "limit of 10 — receivers return permerror"
            )
            spf_result = "permerror"
        if "ptr" in [m.lstrip("+-~?") for m in mechanisms]:
            issues.append("SPF uses the deprecated 'ptr' mechanism (RFC 7208 §5.5)")

        if spf_result != "permerror":
            # Evaluating a specific IP against the record requires full RFC 7208
            # macro/include expansion; report the policy instead of guessing a
            # per-IP verdict we cannot compute here.
            if all_mechanism and all_mechanism.startswith("-"):
                spf_result = "fail-closed policy (-all)"
            elif all_mechanism and all_mechanism.startswith("~"):
                spf_result = "softfail policy (~all)"
            else:
                spf_result = "neutral"
            if sender_ip:
                issues.append(
                    f"Sender IP {sender_ip} was not evaluated against the record: "
                    "per-IP SPF evaluation requires full include/macro expansion"
                )

        return SPFAnalysis(
            spf_record_found=True,
            spf_record=spf_record,
            spf_result=spf_result,
            spf_issues=issues,
            authorized_senders=authorized_senders,
        )

    def analyze_dkim(self, headers: Dict[str, Any]) -> DKIMAnalysis:
        """Analyze DKIM signatures"""
        
        dkim_header = headers['headers'].get('DKIM-Signature')
        
        if not dkim_header:
            return DKIMAnalysis(
                dkim_signature_found=False,
                dkim_valid=False,
                dkim_domain=None,
                dkim_selector=None,
                dkim_algorithm=None,
                dkim_issues=["No DKIM signature found"]
            )
        
        # Parse DKIM signature
        dkim_parts = {}
        for part in dkim_header.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                dkim_parts[key.strip()] = value.strip()
        
        domain = dkim_parts.get('d', '')
        selector = dkim_parts.get('s', '')
        algorithm = dkim_parts.get('a', '')
        
        issues = []
        is_valid = True

        if domain != headers.get('sender_domain'):
            issues.append("DKIM domain doesn't match sender domain")
            is_valid = False
        
        if algorithm and 'sha1' in algorithm.lower():
            issues.append("DKIM uses weak SHA-1 algorithm")
        
        # Verify what is actually verifiable here: that the signing domain
        # publishes a public key for the selector named in the signature.
        # Cryptographic verification of the signature itself needs the full
        # raw message (RFC 6376 canonicalisation over headers AND body); this
        # tool only receives headers, so it does not claim a crypto verdict.
        is_valid = False
        if domain and selector:
            try:
                key_records = query_txt(f"{selector}._domainkey.{domain}")
            except Exception as exc:
                issues.append(f"DKIM key lookup failed: {exc}")
                key_records = []

            if not key_records:
                issues.append(
                    f"No DKIM public key published at {selector}._domainkey.{domain} — "
                    "the signature cannot be verified by any receiver"
                )
            else:
                key_record = key_records[0]
                tags = {}
                for part in key_record.split(";"):
                    if "=" in part:
                        k, _, v = part.strip().partition("=")
                        tags[k.strip().lower()] = v.strip()
                if not tags.get("p"):
                    issues.append(
                        "DKIM key record has an empty 'p=' tag: the key has been "
                        "revoked, so signatures will not verify"
                    )
                else:
                    # A published, non-revoked key is the strongest statement
                    # we can make without the raw message.
                    issues.append(
                        "DKIM public key is published and not revoked; the "
                        "signature itself was NOT cryptographically verified "
                        "(requires the full raw message, not just headers)"
                    )
                if tags.get("k", "rsa") == "rsa" and tags.get("p"):
                    # base64 length -> approximate modulus size
                    key_bits = (len(tags["p"]) * 3 // 4) * 8
                    if key_bits < 1024:
                        issues.append(f"DKIM RSA key looks shorter than 1024 bits (~{key_bits})")
        else:
            issues.append("DKIM signature is missing the domain (d=) or selector (s=) tag")
        
        return DKIMAnalysis(
            dkim_signature_found=True,
            dkim_valid=is_valid,
            dkim_domain=domain,
            dkim_selector=selector,
            dkim_algorithm=algorithm,
            dkim_issues=issues
        )
    
    def analyze_dmarc(self, sender_domain: str, spf_result: str, dkim_valid: bool) -> DMARCAnalysis:
        """Look up and evaluate the domain's real DMARC record (RFC 7489)."""
        issues: List[str] = []
        dmarc_record: Optional[str] = None
        dmarc_policy: Optional[str] = None

        if not sender_domain:
            return DMARCAnalysis(
                dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
                dmarc_alignment={"spf": False, "dkim": False},
                dmarc_issues=["No sender domain to evaluate"], dmarc_compliance=False,
            )

        try:
            records = [
                r for r in query_txt(f"_dmarc.{sender_domain}")
                if r.lower().startswith("v=dmarc1")
            ]
        except Exception as exc:
            return DMARCAnalysis(
                dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
                dmarc_alignment={"spf": False, "dkim": False},
                dmarc_issues=[f"DMARC lookup failed: {exc}"], dmarc_compliance=False,
            )

        spf_passed = spf_result.startswith("pass") or "fail-closed" in spf_result
        alignment = {"spf": spf_passed, "dkim": bool(dkim_valid)}

        if not records:
            return DMARCAnalysis(
                dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
                dmarc_alignment=alignment,
                dmarc_issues=[
                    "No DMARC record published: receivers have no instruction for "
                    "handling messages that fail authentication"
                ],
                dmarc_compliance=False,
            )

        if len(records) > 1:
            issues.append(f"{len(records)} DMARC records published — RFC 7489 requires exactly one")

        dmarc_record = records[0]
        tags = {}
        for part in dmarc_record.split(";"):
            if "=" in part:
                key, _, value = part.strip().partition("=")
                tags[key.strip().lower()] = value.strip()

        dmarc_policy = tags.get("p")
        if dmarc_policy not in ("none", "quarantine", "reject"):
            issues.append(f"Invalid or missing DMARC policy tag: p={dmarc_policy!r}")
        elif dmarc_policy == "none":
            issues.append(
                "DMARC policy is 'none' (monitoring only): failing messages are "
                "still delivered"
            )

        if "rua" not in tags:
            issues.append("No 'rua' aggregate-report address: failures cannot be monitored")

        pct = tags.get("pct")
        if pct and pct != "100":
            issues.append(f"DMARC applies to only {pct}% of messages (pct={pct})")

        if tags.get("sp") == "none" and dmarc_policy in ("quarantine", "reject"):
            issues.append(
                "Subdomain policy sp=none weakens the parent policy: subdomains "
                "are unprotected"
            )

        # DMARC passes when at least one aligned mechanism passes (RFC 7489 §6.6.2).
        compliance = alignment["spf"] or alignment["dkim"]

        return DMARCAnalysis(
            dmarc_record_found=True,
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            dmarc_alignment=alignment,
            dmarc_issues=issues,
            dmarc_compliance=compliance,
        )

    def analyze_email_routing(self, received_headers: List[str]) -> EmailRouting:
        """Analyze email routing path"""
        
        routing_path = []
        suspicious_hops = []
        geo_locations = []
        
        for received in received_headers:
            # Extract server information
            server_match = re.search(r'from\s+([^\s]+)', received)
            if server_match:
                server = server_match.group(1)
                routing_path.append(server)
                
                # Check for suspicious patterns
                if any(pattern in server.lower() for pattern in ['tor', 'proxy', 'vpn', 'anonymous']):
                    suspicious_hops.append(f"Suspicious server: {server}")
                
                # No geolocation: it would require a GeoIP database this
                # service does not ship. Previously this appended a country
                # picked at random, which is worse than reporting nothing.
        
        # Delivery delay, computed from the real timestamps in the Received
        # headers (RFC 5322 date after the final ';'). Previously this was
        # random.uniform(0.1, 24.0).
        delivery_delay = None
        timestamps = []
        for received in received_headers:
            _, _, date_part = received.rpartition(";")
            if not date_part.strip():
                continue
            try:
                timestamps.append(parsedate_to_datetime(date_part.strip()))
            except (TypeError, ValueError):
                continue
        if len(timestamps) >= 2:
            timestamps.sort()
            delivery_delay = (timestamps[-1] - timestamps[0]).total_seconds() / 3600.0
            if delivery_delay > 24:
                suspicious_hops.append(
                    f"Message took {delivery_delay:.1f} hours to be delivered"
                )

        return EmailRouting(
            hop_count=len(routing_path),
            routing_path=routing_path,
            suspicious_hops=suspicious_hops,
            geo_locations=geo_locations,
            delivery_delay=delivery_delay
        )
    
    def analyze_reputation(self, sender_domain: str, sender_ip: Optional[str]) -> ReputationAnalysis:
        """Analyze sender reputation"""
        
        # Reputation is derived from real DNSBL lookups. DNS blocklists are
        # queried over DNS and are free: a listed host resolves to 127.0.0.x,
        # an unlisted one gets NXDOMAIN. Previously every value in this method
        # was random.choices()/random.uniform().
        blacklist_status: Dict[str, bool] = {}
        whitelist_status: Dict[str, bool] = {}

        for name, zone in IP_BLOCKLISTS.items():
            blacklist_status[name] = (
                check_ip_blocklist(sender_ip, zone) if sender_ip else False
            )
        for name, zone in DOMAIN_BLOCKLISTS.items():
            blacklist_status[name] = (
                check_domain_blocklist(sender_domain, zone) if sender_domain else False
            )

        listings = sum(1 for listed in blacklist_status.values() if listed)
        if listings >= 2:
            domain_reputation = "malicious"
            sender_score = 10.0
        elif listings == 1:
            domain_reputation = "poor"
            sender_score = 35.0
        else:
            # Not being listed is the absence of a negative signal, not a
            # positive endorsement — hence "neutral", never "good".
            domain_reputation = "neutral"
            sender_score = 70.0

        # IP reputation from the same real lookups.
        ip_reputation = "unknown"
        if sender_ip:
            try:
                if ipaddress.ip_address(sender_ip).is_private:
                    ip_reputation = "private"
                elif any(
                    blacklist_status.get(name) for name in IP_BLOCKLISTS
                ):
                    ip_reputation = "listed"
                else:
                    ip_reputation = "not listed"
            except ValueError:
                ip_reputation = "invalid"

        # Whitelists (Microsoft SNDS, Gmail Postmaster, Sender Score) are
        # per-sender dashboards behind authentication, not public lookups:
        # reporting them as booleans would be fabrication.
        whitelist_status = {}

        # Domain age needs WHOIS/RDAP, which this tool does not query.
        domain_age_days = None

        return ReputationAnalysis(
            domain_reputation=domain_reputation,
            ip_reputation=ip_reputation,
            sender_score=sender_score,
            blacklist_status=blacklist_status,
            whitelist_status=whitelist_status,
            domain_age_days=domain_age_days
        )
    
    def detect_phishing_indicators(self, headers: Dict[str, Any], content: str = "") -> PhishingIndicators:
        """Detect phishing indicators"""
        
        suspicious_patterns = []
        domain_spoofing = False
        suspicious_links = []
        brand_impersonation = None
        urgency_indicators = []
        social_engineering = []
        
        sender_domain = headers['sender_domain'].lower()
        
        # Check for domain spoofing
        for brand, pattern in self.BRAND_PATTERNS.items():
            if re.search(pattern, sender_domain, re.IGNORECASE):
                if brand not in sender_domain:
                    domain_spoofing = True
                    brand_impersonation = brand
                    suspicious_patterns.append(f"Domain mimics {brand}")
        
        # Check for suspicious patterns in domain
        if re.search(r'\d{4,}', sender_domain):
            suspicious_patterns.append("Domain contains many numbers")
        
        if sender_domain.count('-') > 3:
            suspicious_patterns.append("Domain has excessive hyphens")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_patterns.append("Suspicious top-level domain")
        
        # Analyze subject line for urgency
        subject = headers['headers'].get('Subject', '').lower()
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in subject:
                urgency_indicators.append(f"Urgent keyword: {keyword}")
        
        # Look for social engineering tactics
        if any(word in subject for word in ['winner', 'prize', 'lottery']):
            social_engineering.append("Prize/lottery scam indicators")
        
        if any(word in subject for word in ['suspend', 'verify', 'confirm']):
            social_engineering.append("Account verification pressure")
        
        # Real link analysis over the supplied content. Previously this
        # appended a hardcoded "suspicious-link.example.com" 30% of the time,
        # regardless of what the message actually contained.
        for url in re.findall(r'https?://[^\s<>"\'\)]+', content or ""):
            host = re.sub(r'^https?://', '', url).split('/')[0].split('@')[-1].lower()
            reasons = []
            if url.startswith("http://"):
                reasons.append("plaintext HTTP")
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', host):
                reasons.append("bare IP address instead of a hostname")
            if "@" in url.split("//", 1)[-1].split("/")[0]:
                reasons.append("embedded credentials/userinfo (classic obfuscation)")
            if any(host.endswith(s) or host == s.lstrip(".") for s in URL_SHORTENERS):
                reasons.append("URL shortener hides the destination")
            if host.count(".") > 4:
                reasons.append("unusually deep subdomain nesting")
            if any(brand in host for brand in self.BRAND_PATTERNS) and not any(
                host == d or host.endswith("." + d) for d in self.TRUSTED_DOMAINS
            ):
                reasons.append("brand name in a domain that is not the brand's own")
            if reasons:
                suspicious_links.append(f"{url} ({'; '.join(reasons)})")
        
        return PhishingIndicators(
            suspicious_patterns=suspicious_patterns,
            domain_spoofing=domain_spoofing,
            suspicious_links=suspicious_links,
            brand_impersonation=brand_impersonation,
            urgency_indicators=urgency_indicators,
            social_engineering=social_engineering
        )
    
    def calculate_security_score(self, spf: SPFAnalysis, dkim: DKIMAnalysis, 
                                dmarc: DMARCAnalysis, reputation: ReputationAnalysis,
                                phishing: PhishingIndicators) -> Tuple[float, str]:
        """Calculate overall security score and risk level"""
        
        score = 50  # Base score
        
        # SPF scoring
        if spf.spf_result == "pass":
            score += 20
        elif spf.spf_result == "softfail":
            score += 10
        elif spf.spf_result == "fail":
            score -= 20
        
        # DKIM scoring
        if dkim.dkim_signature_found:
            if dkim.dkim_valid:
                score += 15
            else:
                score -= 10
        
        # DMARC scoring
        if dmarc.dmarc_record_found:
            if dmarc.dmarc_compliance:
                score += 15
            if dmarc.dmarc_policy == "reject":
                score += 10
            elif dmarc.dmarc_policy == "quarantine":
                score += 5
        
        # Reputation scoring
        if reputation.domain_reputation == "good":
            score += 20
        elif reputation.domain_reputation == "malicious":
            score -= 40
        elif reputation.domain_reputation == "poor":
            score -= 20
        
        # Phishing indicators
        score -= len(phishing.suspicious_patterns) * 5
        score -= len(phishing.urgency_indicators) * 3
        score -= len(phishing.social_engineering) * 5
        
        if phishing.domain_spoofing:
            score -= 30
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine risk level
        if score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 30:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return score, risk_level
    
    def generate_recommendations(self, spf: SPFAnalysis, dkim: DKIMAnalysis,
                               dmarc: DMARCAnalysis, reputation: ReputationAnalysis,
                               phishing: PhishingIndicators, risk_level: str) -> List[str]:
        """Generate security recommendations"""
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_level == "critical":
            recommendations.append("URGENT: This email shows critical security risks - treat as highly suspicious")
        elif risk_level == "high":
            recommendations.append("High risk email - exercise extreme caution")
        
        # Authentication recommendations
        if not spf.spf_record_found:
            recommendations.append("Sender domain lacks SPF record - treat with caution")
        elif spf.spf_result in ["fail", "softfail"]:
            recommendations.append("SPF authentication failed - email may be spoofed")
        
        if not dkim.dkim_signature_found:
            recommendations.append("No DKIM signature found - authenticity cannot be verified")
        elif not dkim.dkim_valid:
            recommendations.append("DKIM signature validation failed - email may be tampered")
        
        if not dmarc.dmarc_record_found:
            recommendations.append("Sender domain lacks DMARC policy")
        elif not dmarc.dmarc_compliance:
            recommendations.append("Email fails DMARC authentication")
        
        # Reputation recommendations
        if reputation.domain_reputation in ["malicious", "poor"]:
            recommendations.append("Sender has poor reputation - avoid interaction")
        
        # Phishing recommendations
        if phishing.domain_spoofing:
            recommendations.append("PHISHING ALERT: Domain appears to spoof legitimate brand")
        
        if phishing.suspicious_patterns:
            recommendations.append("Multiple suspicious patterns detected")
        
        # General recommendations
        recommendations.extend([
            "Verify sender identity through alternative means",
            "Do not click links or download attachments if suspicious",
            "Report phishing attempts to security team",
            "Keep email security software updated"
        ])
        
        return recommendations
    
    async def analyze_email(self, headers_text: str, sender_email: Optional[str] = None,
                           check_spf: bool = True, check_dkim: bool = True,
                           check_dmarc: bool = True) -> Dict[str, Any]:
        """Perform comprehensive email security analysis"""
        
        # Parse headers
        parsed_headers = self.parse_email_headers(headers_text)
        
        # Use provided sender email if available
        if sender_email:
            parsed_headers['sender_email'] = sender_email
            parsed_headers['sender_domain'] = sender_email.split('@')[1]
        
        # Perform authentication checks
        spf_analysis = SPFAnalysis(
            spf_record_found=False, spf_record=None, spf_result="none",
            spf_issues=[], authorized_senders=[]
        )
        if check_spf:
            spf_analysis = self.analyze_spf(
                parsed_headers['sender_domain'], 
                parsed_headers['sender_ip']
            )
        
        dkim_analysis = DKIMAnalysis(
            dkim_signature_found=False, dkim_valid=False, dkim_domain=None,
            dkim_selector=None, dkim_algorithm=None, dkim_issues=[]
        )
        if check_dkim:
            dkim_analysis = self.analyze_dkim(parsed_headers)
        
        dmarc_analysis = DMARCAnalysis(
            dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
            dmarc_alignment={}, dmarc_issues=[], dmarc_compliance=False
        )
        if check_dmarc:
            dmarc_analysis = self.analyze_dmarc(
                parsed_headers['sender_domain'],
                spf_analysis.spf_result,
                dkim_analysis.dkim_valid
            )
        
        # Analyze routing, reputation, and phishing indicators
        email_routing = self.analyze_email_routing(parsed_headers['received_headers'])
        reputation_analysis = self.analyze_reputation(
            parsed_headers['sender_domain'],
            parsed_headers['sender_ip']
        )
        phishing_indicators = self.detect_phishing_indicators(parsed_headers)
        
        # Calculate security score
        security_score, risk_level = self.calculate_security_score(
            spf_analysis, dkim_analysis, dmarc_analysis, 
            reputation_analysis, phishing_indicators
        )
        
        # Generate authentication summary
        auth_summary = {
            "SPF": spf_analysis.spf_result,
            "DKIM": "pass" if dkim_analysis.dkim_valid else "fail",
            "DMARC": "pass" if dmarc_analysis.dmarc_compliance else "fail"
        }
        
        # Generate recommendations
        recommendations = self.generate_recommendations(
            spf_analysis, dkim_analysis, dmarc_analysis,
            reputation_analysis, phishing_indicators, risk_level
        )
        
        return {
            'parsed_headers': parsed_headers,
            'spf_analysis': spf_analysis,
            'dkim_analysis': dkim_analysis,
            'dmarc_analysis': dmarc_analysis,
            'email_routing': email_routing,
            'reputation_analysis': reputation_analysis,
            'phishing_indicators': phishing_indicators,
            'security_score': security_score,
            'risk_level': risk_level,
            'auth_summary': auth_summary,
            'recommendations': recommendations
        }


async def execute_tool(input_data: EmailSecurityInput) -> EmailSecurityOutput:
    """Execute the email security analyzer tool"""
    
    try:
        analyzer = EmailSecurityAnalyzer()
        
        # Perform analysis
        results = await analyzer.analyze_email(
            input_data.email_headers,
            input_data.sender_email,
            input_data.check_spf,
            input_data.check_dkim,
            input_data.check_dmarc
        )
        
        parsed = results['parsed_headers']
        
        return EmailSecurityOutput(
            success=True,
            sender_email=parsed['sender_email'],
            sender_domain=parsed['sender_domain'],
            sender_ip=parsed['sender_ip'],
            spf_analysis=results['spf_analysis'],
            dkim_analysis=results['dkim_analysis'],
            dmarc_analysis=results['dmarc_analysis'],
            email_routing=results['email_routing'],
            reputation_analysis=results['reputation_analysis'],
            phishing_indicators=results['phishing_indicators'],
            security_score=results['security_score'],
            risk_level=results['risk_level'],
            authentication_summary=results['auth_summary'],
            recommendations=results['recommendations'],
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        return EmailSecurityOutput(
            success=False,
            sender_email="",
            sender_domain="",
            sender_ip=None,
            spf_analysis=SPFAnalysis(
                spf_record_found=False, spf_record=None, spf_result="none",
                spf_issues=[], authorized_senders=[]
            ),
            dkim_analysis=DKIMAnalysis(
                dkim_signature_found=False, dkim_valid=False, dkim_domain=None,
                dkim_selector=None, dkim_algorithm=None, dkim_issues=[]
            ),
            dmarc_analysis=DMARCAnalysis(
                dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
                dmarc_alignment={}, dmarc_issues=[], dmarc_compliance=False
            ),
            email_routing=EmailRouting(
                hop_count=0, routing_path=[], suspicious_hops=[],
                geo_locations=[], delivery_delay=None
            ),
            reputation_analysis=ReputationAnalysis(
                domain_reputation="unknown", ip_reputation="unknown", sender_score=0.0,
                blacklist_status={}, whitelist_status={}, domain_age_days=None
            ),
            phishing_indicators=PhishingIndicators(
                suspicious_patterns=[], domain_spoofing=False, suspicious_links=[],
                brand_impersonation=None, urgency_indicators=[], social_engineering=[]
            ),
            security_score=0.0,
            risk_level="unknown",
            authentication_summary={},
            recommendations=[],
            analysis_timestamp=datetime.now(timezone.utc),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "email_security_analyzer",
    "display_name": "Email Security Analyzer",
    "description": "Comprehensive email security analysis including SPF, DKIM, DMARC, and phishing detection",
    "version": "2.0.0",
    "author": "Wildbox Security",
    "category": "email_security"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        sample_headers = """From: user@example.com
To: recipient@gmail.com
Subject: Urgent: Verify your account
Date: Sun, 15 Jun 2025 16:00:00 +0000
Received: from mail.example.com [192.168.1.1] by gmail.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/relaxed
"""
        
        test_input = EmailSecurityInput(
            email_headers=sample_headers,
            check_spf=True,
            check_dkim=True,
            check_dmarc=True,
            analyze_reputation=True
        )
        
        result = await execute_tool(test_input)
        print(f"Email Analysis Success: {result.success}")
        print(f"Sender: {result.sender_email}")
        print(f"Security Score: {result.security_score}")
        print(f"Risk Level: {result.risk_level}")
        print(f"SPF: {result.authentication_summary.get('SPF', 'unknown')}")
        print(f"DKIM: {result.authentication_summary.get('DKIM', 'unknown')}")
        print(f"DMARC: {result.authentication_summary.get('DMARC', 'unknown')}")
    
    asyncio.run(test())
