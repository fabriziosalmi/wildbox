"""
What the name of an environment means, decided in one place.

A service reads ``ENVIRONMENT`` and does two kinds of thing with it: it turns
conveniences on (the API schema and documentation pages, a reloader), and it
turns requirements on (a secret that must be set, a debug flag that must be
off). Both follow one rule:

    only an environment that says ``development`` is a development one.

So the conveniences are for ``development`` and for nothing else, and the
requirements are for everything else: ``production``, ``staging``, a name
that was misspelt, and an environment that was not declared at all.

The requirements used to ask the opposite question. identity required
``API_KEY_HASH_SECRET``, data ``SECRET_KEY`` and ``DEBUG`` off, tools a real
API key, *when the environment was exactly ``production``*: a deployment
called ``staging``, one whose ``.env`` said ``Production`` (data and tools
compared case-sensitively), or one that set no ``ENVIRONMENT`` ran without
them, and nothing said so (#736). ``open_security_shared.api_docs`` has asked
the question this way round since #679.

    if production_checks_apply(settings.environment):
        ...refuse to start without the secret...

The module needs the standard library only: every service can import it.
"""

from typing import Optional

DEVELOPMENT = "development"


def is_development(environment: Optional[str]) -> bool:
    """True only when ``environment`` names the development environment.

    Case and surrounding whitespace are ignored. Anything else is False:
    ``production``, ``staging``, ``dev``, an empty or missing value, a value
    that is not a string.
    """
    return isinstance(environment, str) and environment.strip().lower() == DEVELOPMENT


def production_checks_apply(environment: Optional[str]) -> bool:
    """True for every environment that is not explicitly development.

    The predicate for a start-up check that a development stack may skip and
    nothing else may: a required secret, a debug flag that must be off.
    """
    return not is_development(environment)
