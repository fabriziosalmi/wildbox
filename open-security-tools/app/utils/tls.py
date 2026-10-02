"""
TLS certificate verification helpers shared by the tools.

Verification is on by default. A tool that fetches content from a target
verifies the certificate the target presents, and when verification fails it
reports that failure to the caller instead of retrying without verification.
Accepting an unverified certificate is only possible when the caller sets
``verify_ssl=False`` on that scan's input.

Tools whose purpose is to inspect a certificate (ssl_analyzer, ca_analyzer,
pki_certificate_manager) still have to complete a handshake with a host whose
certificate is broken, otherwise there is nothing to report on. They use
``probe_certificate_trust`` to turn the result of a verified handshake into a
finding.
"""

import socket
import ssl
from typing import Optional, Union

# Description of the per-scan opt-out, shown by the schema/OpenAPI mechanism.
VERIFY_SSL_DESCRIPTION = (
    "Verify the target's TLS certificate (default true). When false, the scan "
    "accepts invalid or self-signed certificates; results may come from an "
    "intercepted connection."
)


def client_ssl(verify: bool) -> Union[ssl.SSLContext, bool]:
    """Value for aiohttp's ``ssl=`` argument.

    With ``verify`` it is a default context: chain and hostname are verified
    and TLS 1.2 is the minimum. ``False`` is returned only when the caller
    explicitly opted out for this scan.
    """
    if verify:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    return False


def certificate_error_message(exc: BaseException, url: Optional[str] = None) -> str:
    """Human-readable reason for a certificate verification failure."""
    reason = None
    cert_error = getattr(exc, "certificate_error", exc)
    if isinstance(cert_error, ssl.SSLCertVerificationError):
        reason = cert_error.verify_message or cert_error.reason
    if not reason:
        reason = str(cert_error) or type(cert_error).__name__
    if url:
        target = f" for {url}"
    elif getattr(exc, "host", None):
        target = f" for {exc.host}:{exc.port}"
    else:
        target = ""
    return f"TLS certificate could not be verified{target}: {reason}"


def probe_certificate_trust(host: str, port: int, timeout: float) -> Optional[str]:
    """Complete a verified TLS handshake with ``host:port``.

    Returns ``None`` when the certificate chain and the hostname verify against
    the system trust store, or the verification error message when they do not.
    Errors that are not about the certificate (refused connection, timeout,
    protocol failure) propagate to the caller.
    """
    context = ssl.create_default_context()
    # A host that only offers TLS 1.0/1.1 is reported as "trust not
    # determined" (the handshake error propagates); ssl_analyzer reports the
    # protocol version itself.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return None
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or exc.reason or str(exc)
