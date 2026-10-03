"""aiohttp's default resolver works with the pinned DNS libraries.

aiohttp uses aiodns, and through it pycares, whenever aiodns is installed.
aiodns 3.2.0 called pycares' getaddrinfo with the pycares 4 signature, and the
lock resolved pycares 5, so every lookup raised TypeError and every tool that
fetched a host name through aiohttp failed before connecting. Resolving
localhost needs no network: c-ares answers it from the hosts file.
"""

import asyncio

import aiohttp


def test_the_default_resolver_resolves_a_name():
    async def resolve():
        resolver = aiohttp.resolver.DefaultResolver()
        try:
            return await resolver.resolve("localhost", 443)
        finally:
            await resolver.close()

    answers = asyncio.run(resolve())

    assert answers
    assert {answer["port"] for answer in answers} == {443}
