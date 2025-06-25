"""
Connector framework for Open Security Responder
"""

from .base import BaseConnector, ConnectorRegistry, connector_registry
from .wildbox_connector import WildboxConnector
from .system_connector import SystemConnector
from .data_connector import DataConnector
from .api_connector import ApiConnector

# Initialize connectors on import
def initialize_connectors():
    """Initialize and register all connectors"""
    system_connector = SystemConnector()
    wildbox_connector = WildboxConnector()
    data_connector = DataConnector()
    api_connector = ApiConnector()
    
    connector_registry.register(system_connector)
    connector_registry.register(wildbox_connector)
    connector_registry.register(data_connector)
    connector_registry.register(api_connector)
    
    return connector_registry

# Auto-initialize connectors
initialize_connectors()

__all__ = [
    "BaseConnector", 
    "ConnectorRegistry", 
    "connector_registry",
    "WildboxConnector",
    "SystemConnector", 
    "DataConnector",
    "ApiConnector",
    "initialize_connectors"
]
