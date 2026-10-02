"""Certificate analyzers report an untrusted certificate as a finding (#495).

ssl_analyzer, ca_analyzer and pki_certificate_manager complete an unverified
handshake on purpose, because their job is to read and report on whatever
certificate a host presents. They must still say when that certificate does
not verify; these tests pin that down with a real self-signed server.
"""

import asyncio
import re

from app.tools.ca_analyzer import main as ca_analyzer
from app.tools.ca_analyzer.schemas import CAAnalyzerInput
from app.tools.pki_certificate_manager import main as pki
from app.tools.pki_certificate_manager.schemas import PKICertificateManagerInput
from app.tools.ssl_analyzer import main as ssl_analyzer
from app.tools.ssl_analyzer.schemas import SSLAnalyzerInput

SELF_SIGNED = re.compile(r"self[- ]signed", re.IGNORECASE)


def _ssl_analyze(server):
    return ssl_analyzer.execute_tool(
        SSLAnalyzerInput(target=server.host, port=server.port, timeout=5)
    )


def _ca_analyze(server):
    return asyncio.run(
        ca_analyzer.execute_tool(
            CAAnalyzerInput(target=server.host, port=server.port, timeout=5)
        )
    )


def _pki_analyze(server):
    return asyncio.run(
        pki.execute_tool(
            PKICertificateManagerInput(domain=f"{server.host}:{server.port}")
        )
    )


def test_ssl_analyzer_reports_untrusted_certificate(https_server):
    result = _ssl_analyze(https_server)

    assert result.success is True
    untrusted = [v for v in result.vulnerabilities if v.name == "Untrusted Certificate"]
    assert len(untrusted) == 1
    assert untrusted[0].severity == "high"
    assert SELF_SIGNED.search(untrusted[0].description)


def test_ssl_analyzer_trusted_certificate_has_no_trust_finding(
    https_server, trust_server_certificate
):
    result = _ssl_analyze(https_server)

    assert result.success is True
    assert "Untrusted Certificate" not in {v.name for v in result.vulnerabilities}


def test_ca_analyzer_reports_untrusted_certificate(https_server):
    result = _ca_analyze(https_server)

    assert result.success is True
    assert result.chain_analysis.is_valid_chain is False
    issues = [
        i
        for i in result.chain_analysis.chain_issues
        if i.startswith("Certificate verification failed")
    ]
    assert len(issues) == 1
    assert SELF_SIGNED.search(issues[0])


def test_ca_analyzer_trusted_certificate_has_valid_chain(
    https_server, trust_server_certificate
):
    result = _ca_analyze(https_server)

    assert result.success is True
    assert result.chain_analysis.is_valid_chain is True
    assert result.chain_analysis.chain_issues == []


def test_pki_manager_reports_untrusted_certificate(https_server):
    result = _pki_analyze(https_server)

    assert result.success is True
    validation = result.validation_results
    assert validation.is_valid is False
    assert validation.trusted_root is False
    issues = [
        i for i in validation.issues if i.startswith("Certificate verification failed")
    ]
    assert len(issues) == 1
    assert SELF_SIGNED.search(issues[0])


def test_pki_manager_trusted_certificate_has_no_trust_issue(
    https_server, trust_server_certificate
):
    result = _pki_analyze(https_server)

    assert result.success is True
    assert not any(
        i.startswith("Certificate verification failed")
        for i in result.validation_results.issues
    )
