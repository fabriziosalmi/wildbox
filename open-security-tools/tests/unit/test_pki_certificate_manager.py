"""Unit tests for the PKI Certificate Manager.

The tests build real X.509 certificates with `cryptography` and feed them to
the parser, so they run offline while still exercising genuine certificate
handling. The previous implementation generated issuer, serial, validity,
algorithm, key size and both fingerprints with `random`, and decided
revocation with a 5% coin flip.
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "pki_certificate_manager"

sys.path.insert(0, str(APP_DIR))


def _load(name, path, extra_modules=None):
    """Load a tool module under a unique name (see test_ct_log_scanner)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    injected = list((extra_modules or {}).items())
    for key, value in injected:
        sys.modules[key] = value
    try:
        spec.loader.exec_module(module)
    finally:
        for key, _ in injected:
            sys.modules.pop(key, None)
    return module


_std = _load("pki_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load(
    "pki_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std}
)
pki = _load("pki_main", TOOL_DIR / "main.py", {"schemas": _schemas})


def build_certificate(
    *,
    common_name="test.example.com",
    issuer_cn=None,
    sans=("test.example.com", "www.test.example.com"),
    key="rsa2048",
    days_valid=90,
    is_ca=False,
    ocsp_url=None,
    hash_alg=None,
):
    """Build a real certificate so the parser has genuine input to read."""
    if key == "rsa2048":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key == "rsa1024":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)]
    )

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]
            ),
            critical=False,
        )

    certificate = builder.sign(private_key, hash_alg or hashes.SHA256())
    return certificate, certificate.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def manager():
    return pki.PKICertificateManager()


class TestRealCertificateParsing:
    def test_reads_every_field_from_the_certificate(self, manager):
        certificate, pem = build_certificate(issuer_cn="Test CA")
        info = asyncio.run(manager._parse_certificate_pem(pem))

        assert info.subject["CN"] == "test.example.com"
        assert info.issuer["CN"] == "Test CA"
        assert info.serial_number == format(0x1234ABCD, "x")
        assert info.public_key_algorithm == "RSA"
        assert info.key_size == 2048
        assert info.signature_algorithm == "sha256WithRSAEncryption"
        assert set(info.san_names) == {"test.example.com", "www.test.example.com"}
        assert info.is_ca is False

    def test_fingerprints_match_the_certificate(self, manager):
        certificate, pem = build_certificate()
        info = asyncio.run(manager._parse_certificate_pem(pem))
        # The old implementation returned random hex here.
        assert info.fingerprint_sha256 == certificate.fingerprint(hashes.SHA256()).hex()
        assert info.fingerprint_sha1 == certificate.fingerprint(hashes.SHA1()).hex()

    def test_detects_a_self_signed_certificate(self, manager):
        _, self_signed = build_certificate()                       # issuer == subject
        _, ca_issued = build_certificate(issuer_cn="Some Real CA")
        assert asyncio.run(manager._parse_certificate_pem(self_signed)).is_self_signed is True
        assert asyncio.run(manager._parse_certificate_pem(ca_issued)).is_self_signed is False

    def test_reads_elliptic_curve_key_size(self, manager):
        _, pem = build_certificate(key="ec256")
        info = asyncio.run(manager._parse_certificate_pem(pem))
        assert info.public_key_algorithm == "ECC"
        assert info.key_size == 256

    def test_reports_a_weak_rsa_key_truthfully(self, manager):
        _, pem = build_certificate(key="rsa1024")
        assert asyncio.run(manager._parse_certificate_pem(pem)).key_size == 1024

    def test_certificate_without_san_yields_an_empty_list(self, manager):
        _, pem = build_certificate(sans=())
        assert asyncio.run(manager._parse_certificate_pem(pem)).san_names == []

    def test_ca_certificate_is_marked(self, manager):
        _, pem = build_certificate(is_ca=True)
        assert asyncio.run(manager._parse_certificate_pem(pem)).is_ca is True

    def test_garbage_input_raises_instead_of_returning_invented_data(self, manager):
        with pytest.raises(ValueError):
            asyncio.run(manager._parse_certificate_pem("not a certificate"))
        with pytest.raises(ValueError):
            asyncio.run(manager._parse_certificate_pem(""))


class TestRevocationAndCTHonesty:
    def test_ocsp_responders_come_from_the_aia_extension(self, manager):
        _, pem = build_certificate(ocsp_url="http://ocsp.test-ca.example/")
        info = asyncio.run(manager._parse_certificate_pem(pem))
        assert manager._ocsp_responders(info) == ["http://ocsp.test-ca.example/"]

    def test_no_aia_extension_means_no_responders(self, manager):
        _, pem = build_certificate()
        info = asyncio.run(manager._parse_certificate_pem(pem))
        assert manager._ocsp_responders(info) == []

    def test_ct_entries_are_empty_when_the_certificate_carries_no_scts(self, manager):
        _, pem = build_certificate()
        info = asyncio.run(manager._parse_certificate_pem(pem))
        # Previously this returned two hardcoded log names with random ids 80%
        # of the time, whatever the certificate actually contained.
        assert asyncio.run(manager._check_ct_logs(info)) == []


class TestDomainFetchInputHandling:
    def test_rejects_an_empty_domain(self, manager):
        with pytest.raises(ValueError):
            asyncio.run(manager._fetch_domain_certificate(""))

    def test_unresolvable_host_raises_rather_than_returning_a_certificate(self, manager):
        with pytest.raises(Exception):
            asyncio.run(
                manager._fetch_domain_certificate("no-such-host.invalid")
            )
