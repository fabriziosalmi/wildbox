"""What a log line may say about a request: its shape, never its content (#755).

A tool's input is whatever the tool takes: a password to grade, a token to
decode, a key to test, a URL with a credential in it. The service used to put
the whole validated input in the record of every run. A log is read by more
people, kept for longer and copied to more places than the request it
describes, so nothing a caller submits goes into one by value. A line says
which tool, for whom, under which request id, and which fields were present.

Three reductions, used wherever the service or a tool logs something that
comes from a request:

* ``field_names``: the names of the fields a caller set, as the tool's own
  model declares them;
* ``error_site``: the class of an exception and where it was raised, without
  its text (a ``ValueError`` quotes the value it refuses, an HTTP client's
  error the URL it could not fetch);
* ``host_of``: the host of a target, without the user, password, path and
  query a URL carries.
"""

import traceback
from pathlib import PurePath
from typing import Any, List
from urllib.parse import urlsplit

NO_HOST = "(no host)"


def field_names(validated_input: Any) -> List[str]:
    """The fields of a validated input that the caller set, by name.

    Only names the model declares: a body's own keys are the caller's text
    (``{"<anything>": 1}``) and a model that allows extra fields keeps them,
    so they are counted out here.
    """
    declared = getattr(type(validated_input), "model_fields", None)
    if not isinstance(declared, dict):
        return []
    provided = getattr(validated_input, "model_fields_set", None) or set()
    return sorted(name for name in provided if name in declared)


def error_site(error: BaseException) -> str:
    """``ValueError at main.py:42 in scan``: what failed and where, not why.

    The text of an exception raised while a tool works on a caller's input
    can hold that input. The class and the line are enough to find the
    cause; the text stays out of the log.
    """
    name = type(error).__name__
    frames = traceback.extract_tb(error.__traceback__)
    if not frames:
        return name
    last = frames[-1]
    return f"{name} at {PurePath(last.filename).name}:{last.lineno} in {last.name}"


def host_of(target: Any) -> str:
    """The host a target names, for a log line.

    ``https://user:secret@example.com:8443/reset/abc?token=xyz`` is logged
    as ``example.com:8443``. A value that is no URL (a bare host name, an
    address, a range) has no part that hides a credential and is returned as
    it is, cut at the first character a host cannot contain.
    """
    text = str(target or "").strip()
    if not text:
        return NO_HOST
    if "://" in text:
        try:
            parts = urlsplit(text)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return NO_HOST
        if not host:
            return NO_HOST
        if ":" in host:
            host = f"[{host}]"
        return f"{host}:{port}" if port else host
    # host, host:port, an address or a CIDR range: stop at anything else.
    bare = text.rsplit("@", 1)[-1]
    for index, character in enumerate(bare):
        if not (character.isalnum() or character in ".-_:[]/"):
            bare = bare[:index]
            break
    bare = bare.split("/", 1)[0] if not _is_range(bare) else bare
    return bare[:253] or NO_HOST


def _is_range(text: str) -> bool:
    """``10.0.0.0/8`` and ``2001:db8::/32``: a network, not a host and a path."""
    address, slash, prefix = text.partition("/")
    return bool(slash) and prefix.isdigit() and bool(address)
