"""
Base connector framework for Open Security Responder

Provides abstract base class and registry for connectors.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Iterable, Optional, Type
import logging

import httpx

from ..caller import CallerIdentityUnavailable, gateway_headers

logger = logging.getLogger(__name__)


class ConnectorError(Exception):
    """Base exception for connector errors"""
    pass


def call_service(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    what: str,
    json: Any = None,
    params: Optional[Dict[str, Any]] = None,
    expect: Iterable[int] = (200,),
) -> Any:
    """Call another Wildbox service as the run's caller; return its JSON.

    Every request carries the gateway identity of the user who started the
    run, with the X-Gateway-Secret proof of origin (app/caller.py): the
    services authenticate nothing else, and authorize the request for that
    user and team (#616). A request is sent once; a failure is the step's
    failure, reported with the service's status, and never retried here.

    Args:
        client: The connector's HTTP client.
        method: HTTP method.
        url: Full URL of the route on the target service.
        what: What the call does, for error messages ("run tool 'x'").
        json: Request body, sent as JSON when not None.
        params: Query parameters.
        expect: The statuses that mean success.

    Raises:
        ConnectorError: no caller identity or gateway secret to send, the
            service could not be reached, or it answered another status.
    """
    try:
        headers = gateway_headers()
    except CallerIdentityUnavailable as e:
        raise ConnectorError(f"Cannot {what}: {e}") from e

    try:
        response = client.request(method, url, json=json, params=params, headers=headers)
    except httpx.HTTPError as e:
        raise ConnectorError(f"Cannot {what}: {type(e).__name__}: {e}") from e

    if response.status_code not in tuple(expect):
        raise ConnectorError(
            f"Cannot {what}: {method} {httpx.URL(url).path} answered "
            f"{response.status_code}: {_error_detail(response)}"
        )
    try:
        return response.json()
    except ValueError as e:
        raise ConnectorError(f"Cannot {what}: the response is not JSON") from e


def _error_detail(response: httpx.Response, limit: int = 300) -> str:
    """The service's error message, short enough for a run log."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:limit] or response.reason_phrase
    if isinstance(body, dict):
        for key in ("detail", "error", "message"):
            if key in body:
                return str(body[key])[:limit]
    return str(body)[:limit]


class BaseConnector(ABC):
    """Abstract base class for all connectors"""

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize connector
        
        Args:
            name: Name of the connector
            config: Optional configuration dictionary
        """
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    @abstractmethod
    def get_available_actions(self) -> Dict[str, str]:
        """
        Get list of available actions for this connector
        
        Returns:
            Dictionary mapping action names to descriptions
        """
        pass
    
    def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an action with the given parameters
        
        Args:
            action: Name of the action to execute
            params: Parameters for the action
            
        Returns:
            Dictionary containing action results
            
        Raises:
            ConnectorError: If action fails or doesn't exist
        """
        # Whitelist-based dispatch: only allow actions declared in get_available_actions()
        available_actions = self.get_available_actions()
        if action not in available_actions:
            raise ConnectorError(
                f"Action '{action}' not found in connector '{self.name}'. "
                f"Available actions: {list(available_actions.keys())}"
            )

        try:
            method = getattr(self, action)
            # Sanitize params before logging to avoid leaking secrets
            _sensitive_keys = {'api_key', 'password', 'secret', 'token', 'credential', 'auth'}
            safe_params = {k: '***' if k.lower() in _sensitive_keys else v for k, v in params.items()}
            self.logger.info(f"Executing action '{action}' with params: {safe_params}")
            result = method(**params)
            self.logger.info(f"Action '{action}' completed successfully")
            return result
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Action '{action}' failed: {str(e)}")
            raise ConnectorError(f"Action '{action}' failed: {str(e)}")
    
    def validate_params(self, action: str, params: Dict[str, Any]) -> bool:
        """
        Validate parameters for an action
        
        Args:
            action: Name of the action
            params: Parameters to validate
            
        Returns:
            True if parameters are valid
            
        Raises:
            ConnectorError: If parameters are invalid
        """
        # Default implementation - can be overridden by subclasses
        return True


class ConnectorRegistry:
    """Registry for managing connectors"""
    
    def __init__(self):
        self._connectors: Dict[str, BaseConnector] = {}
    
    def register(self, connector: BaseConnector):
        """
        Register a connector
        
        Args:
            connector: Connector instance to register
        """
        self._connectors[connector.name] = connector
        logger.info(f"Registered connector '{connector.name}'")
    
    def get_connector(self, name: str) -> BaseConnector:
        """
        Get a connector by name
        
        Args:
            name: Name of the connector
            
        Returns:
            Connector instance
            
        Raises:
            ConnectorError: If connector not found
        """
        if name not in self._connectors:
            available = list(self._connectors.keys())
            raise ConnectorError(
                f"Connector '{name}' not found. Available connectors: {available}"
            )
        return self._connectors[name]
    
    def list_connectors(self) -> Dict[str, Dict[str, Any]]:
        """
        List all registered connectors

        This is what GET /v1/connectors answers to any member of any team:
        each connector's name and its actions. A connector's ``config`` is
        not in it. It holds the addresses of the other services on the
        internal network (WILDBOX_*_URL), which a caller cannot reach and
        has no use for, and which describe how the deployment is laid out
        (#654).

        Returns:
            Dictionary mapping connector names to their name and actions
        """
        return {
            name: {
                "name": connector.name,
                "actions": connector.get_available_actions()
            }
            for name, connector in self._connectors.items()
        }
    
    def execute_action(self, connector_name: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an action on a specific connector
        
        Args:
            connector_name: Name of the connector
            action: Name of the action
            params: Parameters for the action
            
        Returns:
            Action results
            
        Raises:
            ConnectorError: If connector or action not found, or execution fails
        """
        connector = self.get_connector(connector_name)
        return connector.execute_action(action, params)


# Global connector registry instance
connector_registry = ConnectorRegistry()
