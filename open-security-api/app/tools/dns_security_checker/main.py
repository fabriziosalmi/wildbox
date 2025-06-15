"""
DNS Security Checker Tool

This tool performs comprehensive DNS security analysis including DNSSEC,
email security records (SPF, DMARC, DKIM), and other DNS-based security checks.
"""

import asyncio
import dns.resolver
import dns.name
import dns.dnssec
import dns.query
import dns.zone
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

try:
    from .schemas import DNSSecurityInput, DNSSecurityOutput, DNSRecord, SecurityCheck
except ImportError:
    from schemas import DNSSecurityInput, DNSSecurityOutput, DNSRecord, SecurityCheck


class DNSSecurityChecker:
    """DNS Security Analysis Tool"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
    
    async def check_dns_security(self, domain: str, **checks) -> Dict[str, Any]:
        """Perform comprehensive DNS security analysis"""
        
        dns_records = {}
        security_checks = []
        recommendations = []
        
        try:
            # Normalize domain
            domain = domain.lower().strip()
            if not domain.endswith('.'):
                domain = domain + '.'
            
            # Get basic DNS records
            dns_records = await self._get_dns_records(domain)
            
            # Perform security checks
            if checks.get('check_dnssec', True):
                dnssec_result = await self._check_dnssec(domain)
                security_checks.append(dnssec_result)
            
            if checks.get('check_spf', True):
                spf_result = await self._check_spf(domain, dns_records)
                security_checks.append(spf_result)
            
            if checks.get('check_dmarc', True):
                dmarc_result = await self._check_dmarc(domain)
                security_checks.append(dmarc_result)
            
            if checks.get('check_dkim', True):
                dkim_result = await self._check_dkim(domain)
                security_checks.append(dkim_result)
            
            if checks.get('check_mx_security', True):
                mx_result = await self._check_mx_security(domain, dns_records)
                security_checks.append(mx_result)
            
            if checks.get('check_caa', True):
                caa_result = await self._check_caa(domain, dns_records)
                security_checks.append(caa_result)
            
            # Additional security checks
            security_checks.extend(await self._check_additional_security(domain, dns_records))
            
            # Calculate overall score and generate recommendations
            overall_score = self._calculate_security_score(security_checks)
            risk_level = self._determine_risk_level(overall_score)
            recommendations = self._generate_recommendations(security_checks)
            
            return {
                'dns_records': dns_records,
                'security_checks': security_checks,
                'overall_score': overall_score,
                'risk_level': risk_level,
                'recommendations': recommendations
            }
            
        except Exception as e:
            raise Exception(f"DNS security check failed: {str(e)}")
    
    async def _get_dns_records(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """Get basic DNS records for the domain"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [
                    DNSRecord(
                        record_type=record_type,
                        value=str(rdata),
                        ttl=answers.ttl
                    ) for rdata in answers
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[record_type] = []
            except Exception:
                records[record_type] = []
        
        return records
    
    async def _check_dnssec(self, domain: str) -> SecurityCheck:
        """Check DNSSEC validation"""
        try:
            # Try to get DNSKEY record
            try:
                dnskey_answer = self.resolver.resolve(domain, 'DNSKEY')
                if dnskey_answer:
                    return SecurityCheck(
                        check_name="DNSSEC",
                        passed=True,
                        severity="info",
                        message="DNSSEC is enabled and DNSKEY records found",
                        details=f"Found {len(dnskey_answer)} DNSKEY record(s)"
                    )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Check for DS record at parent
            parent_domain = '.'.join(domain.split('.')[1:])
            if parent_domain and parent_domain != '.':
                try:
                    ds_answer = self.resolver.resolve(domain.rstrip('.'), 'DS')
                    if ds_answer:
                        return SecurityCheck(
                            check_name="DNSSEC",
                            passed=True,
                            severity="info",
                            message="DNSSEC DS record found at parent",
                            details="Domain has DNSSEC delegation"
                        )
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
            
            return SecurityCheck(
                check_name="DNSSEC",
                passed=False,
                severity="medium",
                message="DNSSEC is not configured",
                details="No DNSKEY or DS records found"
            )
            
        except Exception as e:
            return SecurityCheck(
                check_name="DNSSEC",
                passed=False,
                severity="low",
                message="Could not check DNSSEC status",
                details=str(e)
            )
    
    async def _check_spf(self, domain: str, dns_records: Dict) -> SecurityCheck:
        """Check SPF record configuration"""
        txt_records = dns_records.get('TXT', [])
        spf_records = [r for r in txt_records if r.value.startswith('v=spf1')]
        
        if not spf_records:
            return SecurityCheck(
                check_name="SPF",
                passed=False,
                severity="medium",
                message="No SPF record found",
                details="Domain lacks email authentication via SPF"
            )
        
        if len(spf_records) > 1:
            return SecurityCheck(
                check_name="SPF",
                passed=False,
                severity="high",
                message="Multiple SPF records found",
                details="Multiple SPF records can cause authentication failures"
            )
        
        spf_record = spf_records[0].value
        
        # Check for common SPF issues
        issues = []
        if '~all' not in spf_record and '-all' not in spf_record:
            issues.append("Missing enforcement mechanism (~all or -all)")
        
        if '+all' in spf_record:
            issues.append("Permissive +all mechanism (security risk)")
        
        # Count DNS lookups (should be ≤ 10)
        lookup_mechanisms = len(re.findall(r'\b(include:|a:|mx:|exists:|redirect=)', spf_record))
        if lookup_mechanisms > 10:
            issues.append(f"Too many DNS lookups ({lookup_mechanisms}/10)")
        
        if issues:
            return SecurityCheck(
                check_name="SPF",
                passed=False,
                severity="medium",
                message="SPF record has issues",
                details="; ".join(issues)
            )
        
        return SecurityCheck(
            check_name="SPF",
            passed=True,
            severity="info",
            message="SPF record is properly configured",
            details=spf_record
        )
    
    async def _check_dmarc(self, domain: str) -> SecurityCheck:
        """Check DMARC policy"""
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            txt_answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(r) for r in txt_answers if str(r).startswith('v=DMARC1')]
            
            if not dmarc_records:
                return SecurityCheck(
                    check_name="DMARC",
                    passed=False,
                    severity="medium",
                    message="No DMARC record found",
                    details="Domain lacks DMARC email authentication policy"
                )
            
            if len(dmarc_records) > 1:
                return SecurityCheck(
                    check_name="DMARC",
                    passed=False,
                    severity="high",
                    message="Multiple DMARC records found",
                    details="Multiple DMARC records cause policy conflicts"
                )
            
            dmarc_record = dmarc_records[0]
            
            # Check DMARC policy strictness
            if 'p=none' in dmarc_record:
                severity = "low"
                message = "DMARC policy is in monitoring mode (p=none)"
            elif 'p=quarantine' in dmarc_record:
                severity = "info"
                message = "DMARC policy quarantines suspicious emails"
            elif 'p=reject' in dmarc_record:
                severity = "info"
                message = "DMARC policy rejects suspicious emails (recommended)"
            else:
                severity = "medium"
                message = "DMARC policy is unclear"
            
            return SecurityCheck(
                check_name="DMARC",
                passed=True,
                severity=severity,
                message=message,
                details=dmarc_record
            )
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return SecurityCheck(
                check_name="DMARC",
                passed=False,
                severity="medium",
                message="No DMARC record found",
                details="Domain lacks DMARC email authentication policy"
            )
        except Exception as e:
            return SecurityCheck(
                check_name="DMARC",
                passed=False,
                severity="low",
                message="Could not check DMARC policy",
                details=str(e)
            )
    
    async def _check_dkim(self, domain: str) -> SecurityCheck:
        """Check for common DKIM selectors"""
        common_selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 'dkim', 'mail']
        found_selectors = []
        
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                txt_answers = self.resolver.resolve(dkim_domain, 'TXT')
                if any('k=' in str(r) or 'p=' in str(r) for r in txt_answers):
                    found_selectors.append(selector)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                continue
        
        if found_selectors:
            return SecurityCheck(
                check_name="DKIM",
                passed=True,
                severity="info",
                message=f"DKIM records found for selectors: {', '.join(found_selectors)}",
                details="Domain has DKIM email authentication configured"
            )
        else:
            return SecurityCheck(
                check_name="DKIM",
                passed=False,
                severity="low",
                message="No DKIM records found",
                details="Could not find DKIM records with common selectors"
            )
    
    async def _check_mx_security(self, domain: str, dns_records: Dict) -> SecurityCheck:
        """Check MX record security"""
        mx_records = dns_records.get('MX', [])
        
        if not mx_records:
            return SecurityCheck(
                check_name="MX Security",
                passed=False,
                severity="low",
                message="No MX records found",
                details="Domain does not accept email"
            )
        
        issues = []
        
        # Check for MX records pointing to localhost or private IPs
        for mx_record in mx_records:
            mx_host = mx_record.value.split()[-1]  # Get hostname from "priority hostname"
            if 'localhost' in mx_host or '127.0.0' in mx_host:
                issues.append(f"MX record points to localhost: {mx_host}")
        
        # Check if MX records have corresponding A records
        for mx_record in mx_records:
            mx_host = mx_record.value.split()[-1].rstrip('.')
            try:
                self.resolver.resolve(mx_host, 'A')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                issues.append(f"MX record {mx_host} has no A record")
            except Exception:
                pass
        
        if issues:
            return SecurityCheck(
                check_name="MX Security",
                passed=False,
                severity="medium",
                message="MX record security issues found",
                details="; ".join(issues)
            )
        
        return SecurityCheck(
            check_name="MX Security",
            passed=True,
            severity="info",
            message="MX records appear secure",
            details=f"Found {len(mx_records)} MX record(s)"
        )
    
    async def _check_caa(self, domain: str, dns_records: Dict) -> SecurityCheck:
        """Check CAA (Certificate Authority Authorization) records"""
        caa_records = dns_records.get('CAA', [])
        
        if not caa_records:
            return SecurityCheck(
                check_name="CAA",
                passed=False,
                severity="low",
                message="No CAA records found",
                details="Domain lacks certificate authority restrictions"
            )
        
        # Analyze CAA record policies
        policies = []
        for caa_record in caa_records:
            policies.append(caa_record.value)
        
        return SecurityCheck(
            check_name="CAA",
            passed=True,
            severity="info",
            message="CAA records configured",
            details=f"Found {len(caa_records)} CAA record(s): {', '.join(policies)}"
        )
    
    async def _check_additional_security(self, domain: str, dns_records: Dict) -> List[SecurityCheck]:
        """Perform additional DNS security checks"""
        checks = []
        
        # Check for wildcard DNS
        try:
            wildcard_domain = f"nonexistent-subdomain-test.{domain}"
            self.resolver.resolve(wildcard_domain, 'A')
            checks.append(SecurityCheck(
                check_name="Wildcard DNS",
                passed=False,
                severity="medium",
                message="Wildcard DNS detected",
                details="Domain responds to all subdomains (potential security risk)"
            ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            checks.append(SecurityCheck(
                check_name="Wildcard DNS",
                passed=True,
                severity="info",
                message="No wildcard DNS detected",
                details="Domain properly rejects non-existent subdomains"
            ))
        except Exception:
            pass
        
        # Check NS record security
        ns_records = dns_records.get('NS', [])
        if len(ns_records) < 2:
            checks.append(SecurityCheck(
                check_name="NS Redundancy",
                passed=False,
                severity="medium",
                message="Insufficient NS records",
                details="Domain should have at least 2 authoritative nameservers"
            ))
        else:
            checks.append(SecurityCheck(
                check_name="NS Redundancy",
                passed=True,
                severity="info",
                message="Adequate NS record redundancy",
                details=f"Found {len(ns_records)} nameserver(s)"
            ))
        
        return checks
    
    def _calculate_security_score(self, security_checks: List[SecurityCheck]) -> int:
        """Calculate overall security score"""
        total_points = 0
        max_points = 0
        
        for check in security_checks:
            if check.severity == "critical":
                points = 25 if check.passed else 0
                max_points += 25
            elif check.severity == "high":
                points = 20 if check.passed else 0
                max_points += 20
            elif check.severity == "medium":
                points = 15 if check.passed else 0
                max_points += 15
            elif check.severity == "low":
                points = 10 if check.passed else 0
                max_points += 10
            else:  # info
                points = 5 if check.passed else 0
                max_points += 5
            
            total_points += points
        
        return int((total_points / max_points * 100)) if max_points > 0 else 0
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine overall risk level based on score"""
        if score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "critical"
    
    def _generate_recommendations(self, security_checks: List[SecurityCheck]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        for check in security_checks:
            if not check.passed:
                if check.check_name == "DNSSEC":
                    recommendations.append("Configure DNSSEC to protect against DNS spoofing")
                elif check.check_name == "SPF":
                    recommendations.append("Configure SPF record to prevent email spoofing")
                elif check.check_name == "DMARC":
                    recommendations.append("Configure DMARC policy for email authentication")
                elif check.check_name == "DKIM":
                    recommendations.append("Configure DKIM for email authentication")
                elif check.check_name == "CAA":
                    recommendations.append("Configure CAA records to restrict certificate issuance")
                elif check.check_name == "MX Security":
                    recommendations.append("Review MX record configuration for security issues")
                elif check.check_name == "Wildcard DNS":
                    recommendations.append("Disable wildcard DNS to prevent subdomain abuse")
                elif check.check_name == "NS Redundancy":
                    recommendations.append("Configure additional authoritative nameservers")
        
        return recommendations


async def execute_tool(params: DNSSecurityInput) -> DNSSecurityOutput:
    """Main entry point for the DNS security checker tool"""
    checker = DNSSecurityChecker()
    
    try:
        # Set resolver timeout
        checker.resolver.timeout = params.timeout
        
        # Perform DNS security analysis
        result = await checker.check_dns_security(
            domain=params.domain,
            check_dnssec=params.check_dnssec,
            check_dmarc=params.check_dmarc,
            check_spf=params.check_spf,
            check_dkim=params.check_dkim,
            check_mx_security=params.check_mx_security,
            check_caa=params.check_caa
        )
        
        return DNSSecurityOutput(
            success=True,
            domain=params.domain,
            dns_records=result['dns_records'],
            security_checks=result['security_checks'],
            overall_score=result['overall_score'],
            risk_level=result['risk_level'],
            recommendations=result['recommendations'],
            timestamp=datetime.now(),
            error=None
        )
        
    except Exception as e:
        return DNSSecurityOutput(
            success=False,
            domain=params.domain,
            dns_records={},
            security_checks=[],
            overall_score=0,
            risk_level="unknown",
            recommendations=[],
            timestamp=datetime.now(),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "dns_security_checker",
    "display_name": "DNS Security Checker",
    "description": "Comprehensive DNS security analysis including DNSSEC, SPF, DMARC, DKIM, and more",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "network_security"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = DNSSecurityInput(
            domain="example.com",
            check_dnssec=True,
            check_dmarc=True,
            check_spf=True
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            print(f"Overall Score: {result.overall_score}")
            print(f"Risk Level: {result.risk_level}")
            print(f"Security Checks: {len(result.security_checks)}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
