"""
Base connector framework for Open Security Responder

Provides abstract base class and registry for connectors.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Type
import logging

logger = logging.getLogger(__name__)


class ConnectorError(Exception):
    """Base exception for connector errors"""
    pass


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
        if not hasattr(self, action):
            available_actions = list(self.get_available_actions().keys())
            raise ConnectorError(
                f"Action '{action}' not found in connector '{self.name}'. "
                f"Available actions: {available_actions}"
            )
        
        try:
            method = getattr(self, action)
            self.logger.info(f"Executing action '{action}' with params: {params}")
            result = method(**params)
            self.logger.info(f"Action '{action}' completed successfully")
            return result
        except Exception as e:
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
        
        Returns:
            Dictionary mapping connector names to their metadata
        """
        return {
            name: {
                "name": connector.name,
                "config": connector.config,
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
