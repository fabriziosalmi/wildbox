"""The sources `manage.py sources add-defaults` creates: those that can run.

There used to be two lists, and no source of either could be collected
(#665, #755):

* ``manage.py`` created five sources with ``source_type`` ``txt`` or
  ``json``. Those types were registered to ``HTTPCollector``, which has no
  ``parse_item`` and so cannot be instantiated: every run ended with
  "Can't instantiate abstract class HTTPCollector".
* ``scripts/init_feeds.py`` created six with ``source_type`` ``api`` or
  ``feed``, for which no collector was registered at all, and named the
  collector it meant in ``config["collector_class"]``, which nothing read.

A default source is one a fresh deployment can collect from as it is: it has
a collector of its own, and its feed answers without a key. That is one
source today. The others the two lists offered are left out, each for a
reason checked on 6 October 2026:

* Malware Domain List: the feed answers 403; the project has stopped.
* PhishTank: the address answers 404; the feed now needs a registered
  application key in its URL.
* ThreatFox and MalwareBazaar (abuse.ch): the API answers 401 without an
  ``Auth-Key`` header.
* AbuseIPDB and URLVoid: they need an API key, and were offered with a
  placeholder for one that nothing ever replaced.

Their collectors are still registered (``app/collectors/sources.py``): a
source of one of those types runs once it is given what the feed asks for.
What is not offered is a source that fails every time it is tried.

``OPTIONAL_SOURCES`` are sources that can run as they are but are not
created for every deployment: an operator adds one by name with
``manage.py sources add-optional``.
"""

from typing import Any, Dict, List

DEFAULT_SOURCES: List[Dict[str, Any]] = [
    {
        "name": "Feodo Tracker",
        "description": "Botnet command-and-control servers tracked by abuse.ch",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "source_type": "feodo_tracker",
        "enabled": True,
        "collection_interval": 3600,  # Hourly
        "config": {},
        "headers": {},
        "auth_config": {},
    },
]

OPTIONAL_SOURCES: List[Dict[str, Any]] = [
    {
        "name": "NetAPI Honeypot",
        "description": (
            "IPv4 addresses that attacked NetAPI's honeypot sensors within "
            "the last 48 hours (CC BY 4.0, https://netapi.com/compromised-ips/)"
        ),
        "url": "https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv",
        "source_type": "netapi_honeypot",
        "enabled": True,
        "collection_interval": 3600,  # Hourly, as the feed is rebuilt
        # The collector's rate limiter counts parsed items, not requests, and
        # a source's default is 100 an hour: this feed has tens of thousands
        # of rows an hour.
        "rate_limit": 100000,
        "rate_limit_window": 3600,
        "config": {},
        "headers": {},
        "auth_config": {},
    },
]
