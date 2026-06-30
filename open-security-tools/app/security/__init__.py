# Security module. Re-export the auth dependency for convenience.
# NOTE: verify_api_key_optional / verify_api_key_header / RateLimiter were
# removed from app.auth in the gateway-auth consolidation (#173/#174) and are
# no longer re-exported here; importing them broke `import app.security.*`
# (the SSRF validator, authorization manager) at runtime. RateLimiter lives in
# app.utils.tool_utils.
from ..auth import verify_api_key

__all__ = ["verify_api_key"]
