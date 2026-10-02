"""The SAML analyzer must parse untrusted responses with defusedxml.

A SAML response is attacker-controlled input. With the standard library
parser, a DTD in the response is honored: internal entities expand (the
"billion laughs" denial of service) before any of the analyzer's own checks
run. These tests feed such payloads to the tool and assert that they are
refused before parsing and reported as a critical finding.
"""

import asyncio
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tools.saml_analyzer.main import execute_tool  # noqa: E402
from app.tools.saml_analyzer.schemas import SAMLAnalyzerInput  # noqa: E402

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

# A small, harmless instance of the entity-expansion attack: each level
# multiplies the previous one by ten. The standard library parser expands it.
ENTITY_EXPANSION = f"""<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}">
  <saml:Issuer>&c;</saml:Issuer>
</samlp:Response>"""

EXTERNAL_ENTITY = f"""<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}">
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>"""

PLAIN = f"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</samlp:Response>"""


def _input(xml: str) -> SAMLAnalyzerInput:
    encoded = base64.b64encode(xml.encode()).decode()
    return SAMLAnalyzerInput(saml_response=encoded)


@pytest.mark.parametrize("payload", [ENTITY_EXPANSION, EXTERNAL_ENTITY])
def test_entity_declarations_are_refused_before_parsing(payload):
    result = asyncio.run(execute_tool(_input(payload)))

    assert result.is_valid is False
    assert result.issuer is None
    titles = [f.title for f in result.findings]
    assert titles == ["Forbidden XML Construct"]
    assert result.findings[0].severity == "Critical"


def test_plain_response_is_still_parsed():
    result = asyncio.run(execute_tool(_input(PLAIN)))

    assert result.issuer == "https://idp.example.com"
    assert "Forbidden XML Construct" not in [f.title for f in result.findings]
