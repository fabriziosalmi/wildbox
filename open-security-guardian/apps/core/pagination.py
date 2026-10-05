"""Pagination whose links a client of the gateway can follow (#643).

Clients reach guardian through the gateway, which serves guardian's
``/api/v1/<x>`` as ``/api/v1/guardian/<x>`` and presents guardian its own
container name as ``Host`` (Django checks ``Host`` against ALLOWED_HOSTS).
DRF's paginator builds ``next`` and ``previous`` with
``request.build_absolute_uri()``, so every list of more than one page
answered ``https://open-security-guardian/api/v1/...``: a name no client
resolves, without the gateway's path, and a disclosure of the internal
topology.

The links are relative references instead: the path and query of the next
page, under the path the gateway serves guardian at, with no scheme and no
host. A client resolves one against the URL it requested, as it would a
redirect (``urllib.parse.urljoin``, ``new URL(next, response.url)``).

Why not absolute links from the forwarded headers:

* The host could only come from ``X-Forwarded-Host``, which the gateway
  fills with the ``Host`` the caller sent. Its TLS server answers for any
  name, so that is a value the caller chooses, and guardian would write it
  into response bodies. ``USE_X_FORWARDED_HOST`` would also put it through
  ALLOWED_HOSTS, which then has to list every name the gateway is reached
  by: the coupling the gateway's fixed ``Host`` was introduced to remove.
* The gateway knows neither the port nor the scheme the client used when
  it is published on another port or sits behind a load balancer.

A relative reference has none of these to get wrong. The one thing guardian
cannot know by itself is the gateway's path, so the gateway states it:
``X-Forwarded-Prefix: /api/v1/guardian``, a literal in the guardian location
of ``wildbox_gateway.conf``, which replaces whatever the caller sent under
that name. It is read only on a request GatewayAuthMiddleware authenticated,
that is one that carried the gateway's secret, and only when it is a plain
path. Without it the links are guardian's own paths.

``FORCE_SCRIPT_NAME`` does not fit: it prepends a prefix to every path,
whereas the gateway replaces guardian's ``/api/v1`` with its own
``/api/v1/guardian``.
"""

import logging
import re

from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)

# The root of guardian's API (guardian/urls.py): what the gateway's
# X-Forwarded-Prefix stands for. A unit test compares both with the
# guardian location of wildbox_gateway.conf.
API_ROOT = "/api/v1"

FORWARDED_PREFIX_HEADER = "HTTP_X_FORWARDED_PREFIX"

# One or more segments of letters, digits, "-" and "_": no empty segment
# (so no "//host"), no dot (so no ".."), no scheme, query or trailing slash.
_PREFIX = re.compile(r"(?:/[A-Za-z0-9_-]+)+")
_PREFIX_MAX_LENGTH = 200


def forwarded_prefix(request):
    """The path the gateway serves ``API_ROOT`` under, or None.

    None for a request that did not come through the gateway, for a missing
    header and for a value that is not a plain path.
    """
    if getattr(request, "gateway_user", None) is None:
        return None
    value = request.META.get(FORWARDED_PREFIX_HEADER)
    if value is None:
        return None
    if len(value) > _PREFIX_MAX_LENGTH or not _PREFIX.fullmatch(value):
        # The gateway writes a literal: this is a misconfigured gateway.
        logger.warning(
            "Ignoring X-Forwarded-Prefix: not a plain path (%d characters)",
            len(value),
        )
        return None
    return value


def public_uri(request):
    """The path and query of ``request`` as the gateway's client wrote them.

    A relative reference: ``/api/v1/guardian/assets/assets/?page=2`` for
    guardian's ``/api/v1/assets/assets/?page=2``.
    """
    uri = request.get_full_path()
    prefix = forwarded_prefix(request)
    if prefix is None or not uri.startswith(API_ROOT + "/"):
        return uri
    return prefix + uri[len(API_ROOT) :]


class _PublicLinks:
    """The request, as the paginator uses it: the URL its links start from.

    DRF builds ``next``, ``previous`` and the HTML page controls from
    ``self.request.build_absolute_uri()``; this answers the relative
    reference instead, in the one place all three read.
    """

    def __init__(self, request):
        self._request = request

    def build_absolute_uri(self, location=None):
        return public_uri(self._request)

    def __getattr__(self, name):
        return getattr(self._request, name)


class GatewayPageNumberPagination(PageNumberPagination):
    """Page-number pagination with links relative to the gateway's path.

    ``?page_size=N`` sets the size of the page, from 1 to ``max_page_size``;
    a larger N is served ``max_page_size`` rows, and anything that is not a
    positive whole number the default (settings' ``PAGE_SIZE``). guardian
    ignored the parameter: the dashboard asked for one row to read a count,
    and for the three newest vulnerabilities, and was sent fifty each time
    (#724). The maximum bounds what one request can make guardian serialize.
    """

    page_size_query_param = "page_size"
    max_page_size = 200

    def paginate_queryset(self, queryset, request, view=None):
        page = super().paginate_queryset(queryset, request, view=view)
        self.request = _PublicLinks(request)
        return page

    def get_paginated_response_schema(self, schema):
        """The OpenAPI schema: the links are references, not absolute URIs."""
        paginated = super().get_paginated_response_schema(schema)
        for name, number in (("next", 4), ("previous", 2)):
            paginated["properties"][name].update(
                format="uri-reference",
                example=f"/api/v1/guardian/assets/assets/?{self.page_query_param}={number}",
            )
        return paginated
