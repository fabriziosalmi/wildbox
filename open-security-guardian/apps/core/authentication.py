"""
Core Authentication - gateway-authenticated requests only

The Guardian: Proactive Vulnerability Management

guardian keeps no credentials of its own. Its former ``APIKeyAuthentication``
accepted guardian ``APIKey`` rows beside the gateway, bypassing identity,
revocation and team scoping (#629); it was removed with the model.
"""

from rest_framework import authentication


class GatewayHeaderAuthentication(authentication.BaseAuthentication):
    """Surface the user already authenticated by GatewayAuthMiddleware to DRF.

    The gateway validates the JWT / API key and injects trusted X-Wildbox-*
    headers; GatewayAuthMiddleware turns those into a real auth.User on
    request.user. This class simply exposes that user to DRF *without* CSRF
    enforcement — there is no browser session, requests are gateway-authed, so
    DRF's SessionAuthentication (which enforces CSRF) wrongly rejected every
    write with "CSRF Failed: CSRF cookie not set".
    """

    def authenticate(self, request):
        user = getattr(request._request, "user", None)
        if user is not None and user.is_authenticated:
            return (user, None)
        return None
