"""
Data connector for Open Security Responder

Provides integration with the Open Security Data service.
"""

import httpx
from typing import Dict, Any
from datetime import datetime

from .base import BaseConnector, ConnectorError
from ..config import settings


class DataConnector(BaseConnector):
    """Connector for Open Security Data service operations"""
    
    def __init__(self):
        super().__init__("data", {"data_url": settings.wildbox_data_url})
        self.client = httpx.Client(timeout=30.0)
        self.logger.info("Initialized Data connector")
    
    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the Data connector"""
        return {
            "add_to_blacklist": "Add an IOC to the blacklist",
            "remove_from_blacklist": "Remove an IOC from the blacklist",
            "check_blacklist": "Check if an IOC is blacklisted",
            "query_iocs": "Query IOCs from the database",
            "add_ioc": "Add a new IOC to the database",
            "get_threat_feed": "Get threat feed data",
            "update_reputation": "Update reputation score for an entity",
            "get_asset_inventory": "Get asset inventory information"
        }
    
    def add_to_blacklist(self, value: str, type: str, reason: str, confidence: str = "medium", source: str = "responder") -> Dict[str, Any]:
        """
        Add an IOC to the blacklist
        
        Args:
            value: The IOC value (IP, domain, URL, hash, etc.)
            type: Type of IOC (ip, domain, url, hash, etc.)
            reason: Reason for blacklisting
            confidence: Confidence level (low, medium, high)
            source: Source of the blacklist entry
            
        Returns:
            Blacklist addition result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/blacklist"
            payload = {
                "value": value,
                "type": type,
                "reason": reason,
                "confidence": confidence,
                "source": source,
                "created_at": datetime.utcnow().isoformat(),
                "status": "active"
            }
            
            self.logger.info(f"Adding {type} '{value}' to blacklist")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Successfully added '{value}' to blacklist with ID: {result.get('id')}")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error adding '{value}' to blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to add '{value}' to blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def remove_from_blacklist(self, value: str, type: str) -> Dict[str, Any]:
        """
        Remove an IOC from the blacklist
        
        Args:
            value: The IOC value
            type: Type of IOC
            
        Returns:
            Blacklist removal result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/blacklist/{type}/{value}"
            
            self.logger.info(f"Removing {type} '{value}' from blacklist")
            response = self.client.delete(url)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Successfully removed '{value}' from blacklist")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error removing '{value}' from blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to remove '{value}' from blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def check_blacklist(self, value: str, type: str) -> Dict[str, Any]:
        """
        Check if an IOC is blacklisted
        
        Args:
            value: The IOC value
            type: Type of IOC
            
        Returns:
            Blacklist check result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/blacklist/{type}/{value}"
            
            self.logger.info(f"Checking blacklist for {type} '{value}'")
            response = self.client.get(url)
            
            if response.status_code == 404:
                return {
                    "blacklisted": False,
                    "value": value,
                    "type": type,
                    "message": "Not found in blacklist"
                }
            
            response.raise_for_status()
            result = response.json()
            
            return {
                "blacklisted": True,
                "value": value,
                "type": type,
                "details": result
            }
            
        except httpx.HTTPError as e:
            if e.response.status_code == 404:
                return {
                    "blacklisted": False,
                    "value": value,
                    "type": type,
                    "message": "Not found in blacklist"
                }
            error_msg = f"HTTP error checking blacklist for '{value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to check blacklist for '{value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def query_iocs(self, query: str, ioc_type: str = None, limit: int = 100) -> Dict[str, Any]:
        """
        Query IOCs from the database
        
        Args:
            query: Search query
            ioc_type: Optional IOC type filter
            limit: Maximum number of results
            
        Returns:
            IOC query results
        """
        try:
            url = f"{self.config['data_url']}/api/v1/iocs"
            params = {
                "q": query,
                "limit": limit
            }
            
            if ioc_type:
                params["type"] = ioc_type
            
            self.logger.info(f"Querying IOCs with query '{query}'")
            response = self.client.get(url, params=params)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Found {len(result.get('iocs', []))} IOCs")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error querying IOCs: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to query IOCs: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def add_ioc(self, value: str, type: str, source: str, confidence: str = "medium", tags: list = None) -> Dict[str, Any]:
        """
        Add a new IOC to the database
        
        Args:
            value: The IOC value
            type: Type of IOC
            source: Source of the IOC
            confidence: Confidence level
            tags: Optional tags for the IOC
            
        Returns:
            IOC creation result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/iocs"
            payload = {
                "value": value,
                "type": type,
                "source": source,
                "confidence": confidence,
                "tags": tags or [],
                "created_at": datetime.utcnow().isoformat(),
                "status": "active"
            }
            
            self.logger.info(f"Adding IOC {type} '{value}'")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Successfully added IOC with ID: {result.get('id')}")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error adding IOC '{value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to add IOC '{value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_threat_feed(self, feed_name: str = None, limit: int = 100) -> Dict[str, Any]:
        """
        Get threat feed data
        
        Args:
            feed_name: Optional specific feed name
            limit: Maximum number of results
            
        Returns:
            Threat feed data
        """
        try:
            url = f"{self.config['data_url']}/api/v1/threat-feeds"
            params = {"limit": limit}
            
            if feed_name:
                params["feed"] = feed_name
            
            self.logger.info(f"Getting threat feed data")
            response = self.client.get(url, params=params)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Retrieved {len(result.get('indicators', []))} threat indicators")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error getting threat feed: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to get threat feed: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def update_reputation(self, entity: str, entity_type: str, score: int, source: str = "responder") -> Dict[str, Any]:
        """
        Update reputation score for an entity
        
        Args:
            entity: The entity (IP, domain, etc.)
            entity_type: Type of entity
            score: Reputation score (1-10)
            source: Source of the reputation update
            
        Returns:
            Reputation update result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/reputation"
            payload = {
                "entity": entity,
                "entity_type": entity_type,
                "score": score,
                "source": source,
                "updated_at": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Updating reputation for {entity_type} '{entity}' to score {score}")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Successfully updated reputation for '{entity}'")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error updating reputation for '{entity}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to update reputation for '{entity}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_asset_inventory(self, asset_type: str = None, filter_criteria: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Get asset inventory information
        
        Args:
            asset_type: Optional asset type filter
            filter_criteria: Optional additional filters
            
        Returns:
            Asset inventory data
        """
        try:
            url = f"{self.config['data_url']}/api/v1/assets"
            params = {}
            
            if asset_type:
                params["type"] = asset_type
                
            if filter_criteria:
                params.update(filter_criteria)
            
            self.logger.info(f"Getting asset inventory")
            response = self.client.get(url, params=params)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Retrieved {len(result.get('assets', []))} assets")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error getting asset inventory: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to get asset inventory: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
