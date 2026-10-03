"""
Data connector for Open Security Responder

Reads threat intelligence from the data service (open-security-data), as
the user who started the run (app/caller.py). The data service answers with
the indicators of that user's team and of the global feeds.

Its actions call the routes the data service serves (#616):

- ``search_indicators``: ``GET /api/v1/indicators/search``
- ``lookup_indicators``: ``POST /api/v1/indicators/lookup``

The data service is read-only for indicators: it serves no blacklist, no
indicator creation, no reputation updates, no asset inventory and no threat
feed of the shape this connector used to ask for. The actions that called
those routes (add_to_blacklist, remove_from_blacklist, check_blacklist,
query_iocs, add_ioc, get_threat_feed, update_reputation,
get_asset_inventory) failed on every run and are gone. Assets are
Guardian's: see wildbox.get_asset_info.
"""

from typing import Any, Dict, List, Optional

import httpx

from .base import BaseConnector, ConnectorError, call_service
from ..config import settings

# The data service's IndicatorType values (open-security-data/app/models.py).
INDICATOR_TYPES = (
    "ip_address",
    "domain",
    "url",
    "file_hash",
    "email",
    "certificate",
    "asn",
    "vulnerability",
)


def _indicator_type(value: Any) -> str:
    if value not in INDICATOR_TYPES:
        raise ConnectorError(
            f"Invalid indicator type {value!r}: one of {', '.join(INDICATOR_TYPES)}"
        )
    return value


class DataConnector(BaseConnector):
    """Connector for Open Security Data service operations"""

    def __init__(self):
        super().__init__("data", {"data_url": settings.wildbox_data_url})
        # No retries: a call is sent once.
        self.client = httpx.Client(timeout=30.0)
        self.logger.info("Initialized Data connector")

    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the Data connector"""
        return {
            "search_indicators": "Search threat indicators by value, type and confidence",
            "lookup_indicators": "Look up a list of indicators and report which are known",
        }

    def search_indicators(
        self,
        query: Optional[str] = None,
        indicator_type: Optional[str] = None,
        confidence: Optional[str] = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Search threat indicators.

        Args:
            query: Text to search the indicators' values for
            indicator_type: One of INDICATOR_TYPES
            confidence: Only indicators of this confidence
            active_only: Only active indicators
            limit: Maximum number of indicators (1 to 10000)

        Returns:
            ``indicators``, ``total``, ``limit``, ``offset``, ``query_time``
        """
        params: Dict[str, Any] = {"active_only": active_only, "limit": limit}
        if query:
            params["q"] = query
        if indicator_type:
            params["indicator_type"] = _indicator_type(indicator_type)
        if confidence:
            params["confidence"] = confidence
        return call_service(
            self.client,
            "GET",
            f"{self.config['data_url']}/api/v1/indicators/search",
            what="search threat indicators",
            params=params,
        )

    def lookup_indicators(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Look up indicators by type and value.

        Args:
            indicators: Items of ``{"indicator_type": ..., "value": ...}``

        Returns:
            ``results`` (per item: ``found`` and its ``matches``),
            ``total_queried``, ``total_found``, ``query_time``
        """
        if not isinstance(indicators, list) or not indicators:
            raise ConnectorError("lookup_indicators needs a non-empty list of indicators")
        items = []
        for item in indicators:
            if not isinstance(item, dict) or not item.get("value"):
                raise ConnectorError(
                    f"Invalid indicator {item!r}: indicator_type and value are needed"
                )
            items.append(
                {
                    "indicator_type": _indicator_type(item.get("indicator_type")),
                    "value": str(item["value"]),
                }
            )
        return call_service(
            self.client,
            "POST",
            f"{self.config['data_url']}/api/v1/indicators/lookup",
            what=f"look up {len(items)} indicator(s)",
            json={"indicators": items},
        )

    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
