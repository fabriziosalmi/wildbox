"""
The failures a tool run reports as a result instead of raising.

A tool's ``execute_tool`` answers with its output model, ``success`` false and
the reason, when the target cannot be reached or does not answer as expected.
Most tools caught ``(ValueError, KeyError, TypeError, ConnectionError,
TimeoutError)``, which misses what their clients actually raise: a DNS failure
is ``socket.gaierror``, aiohttp raises ``aiohttp.ClientError`` subclasses,
requests raises ``requests.RequestException`` and dnspython
``dns.exception.DNSException``. Several also re-raised a bare ``Exception``
that nothing caught. Each of those escaped the tool as an unhandled error
(#611).
"""

import asyncio

import aiohttp
import dns.exception


class ToolRunError(Exception):
    """A failure a tool reports in its result (unreachable target, bad answer)."""


RUN_ERRORS = (
    ToolRunError,
    ValueError,
    KeyError,
    TypeError,
    # ConnectionError, socket.gaierror, ssl.SSLError and
    # requests.RequestException are all OSError.
    OSError,
    TimeoutError,
    asyncio.TimeoutError,
    aiohttp.ClientError,
    dns.exception.DNSException,
)
