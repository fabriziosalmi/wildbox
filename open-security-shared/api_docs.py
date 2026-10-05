"""
When a service publishes its OpenAPI schema and its documentation pages.

One rule for every FastAPI service: `/openapi.json`, `/docs` and `/redoc` are
served when the environment is `development`, and in no other. The schema maps
every route of a service, admin and internal ones included, so it is a
development aid and not something a deployment should answer with.

Each service used to decide for itself, and they disagreed (#679): data turned
the two pages off and left the schema on, tools served the schema in every
environment, identity, agents and responder turned all three off only for the
exact value `production` (so `staging`, or a misspelt `Production`, published
them), and cspm followed `DEBUG` whatever the environment.

The test is for `development`, not against `production`: an environment the
rule does not know is closed, not open.

    app = FastAPI(title=..., **api_docs_urls(settings.environment))
"""

from typing import Dict, Optional

DEVELOPMENT = "development"

_ENABLED: Dict[str, Optional[str]] = {
    "docs_url": "/docs",
    "redoc_url": "/redoc",
    "openapi_url": "/openapi.json",
}
_DISABLED: Dict[str, Optional[str]] = {
    "docs_url": None,
    "redoc_url": None,
    "openapi_url": None,
}


def api_docs_enabled(environment: Optional[str]) -> bool:
    """True only when `environment` names the development environment.

    Case and surrounding whitespace are ignored, as the services ignore them
    when they read `ENVIRONMENT`. Anything else is False: `production`,
    `staging`, an empty or missing value, a value that is not a string.
    """
    return isinstance(environment, str) and environment.strip().lower() == DEVELOPMENT


def api_docs_urls(environment: Optional[str]) -> Dict[str, Optional[str]]:
    """The `docs_url`, `redoc_url` and `openapi_url` arguments for `FastAPI()`.

    FastAPI registers no route for an argument that is None, so outside
    development the three paths answer 404 like any path that does not exist.
    Turning off `openapi_url` alone would be enough to take the pages down with
    it, but all three are returned so the result reads the same as the routes.
    """
    return dict(_ENABLED if api_docs_enabled(environment) else _DISABLED)
