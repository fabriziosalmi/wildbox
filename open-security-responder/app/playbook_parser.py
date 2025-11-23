"""
Playbook parser for Open Security Responder

Loads and validates YAML playbook definitions from the filesystem.
"""

import os
import yaml
import logging
from typing import Dict, List, Any
from pathlib import Path
from pydantic import ValidationError

from .models import Playbook
from .config import settings

logger = logging.getLogger(__name__)


class PlaybookParseError(Exception):
    """Raised when a playbook cannot be parsed or validated"""
    pass


class PlaybookParser:
    """Handles loading and parsing of YAML playbooks"""
    
    def __init__(self, playbooks_directory: str = None):
        """Initialize parser with playbooks directory"""
        self.playbooks_directory = Path(playbooks_directory or settings.playbooks_directory)
        self.playbooks: Dict[str, Playbook] = {}
        
    def load_playbooks(self) -> Dict[str, Playbook]:
        """
        Load all playbooks from the configured directory
        
        Returns:
            Dict mapping playbook_id to Playbook objects
            
        Raises:
            PlaybookParseError: If any playbook fails to load or validate
        """
        if not self.playbooks_directory.exists():
            logger.warning(f"Playbooks directory {self.playbooks_directory} does not exist")
            return {}
        
        playbooks = {}
        errors = []
        
        # Find all YAML files in the directory
        yaml_files = list(self.playbooks_directory.glob("*.yml")) + \
                    list(self.playbooks_directory.glob("*.yaml"))
        
        if not yaml_files:
            logger.warning(f"No YAML files found in {self.playbooks_directory}")
            return {}
        
        logger.info(f"Loading {len(yaml_files)} playbook files from {self.playbooks_directory}")
        
        for yaml_file in yaml_files:
            try:
                playbook = self._load_single_playbook(yaml_file)
                if playbook.playbook_id in playbooks:
                    error_msg = f"Duplicate playbook_id '{playbook.playbook_id}' found in {yaml_file}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                    
                playbooks[playbook.playbook_id] = playbook
                logger.info(f"Loaded playbook '{playbook.playbook_id}' from {yaml_file}")
                
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                error_msg = f"Failed to load playbook from {yaml_file}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        if errors:
            raise PlaybookParseError(f"Failed to load {len(errors)} playbooks: {'; '.join(errors)}")
        
        self.playbooks = playbooks
        logger.info(f"Successfully loaded {len(playbooks)} playbooks")
        return playbooks
    
    def _load_single_playbook(self, yaml_file: Path) -> Playbook:
        """
        Load and validate a single playbook YAML file
        
        Args:
            yaml_file: Path to the YAML file
            
        Returns:
            Validated Playbook object
            
        Raises:
            PlaybookParseError: If the file cannot be loaded or validated
        """
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                raw_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise PlaybookParseError(f"Invalid YAML syntax: {str(e)}")
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            raise PlaybookParseError(f"Failed to read file: {str(e)}")
        
        if not isinstance(raw_data, dict):
            raise PlaybookParseError("Playbook must be a YAML dictionary")
        
        # Validate the data structure using Pydantic
        try:
            playbook = Playbook(**raw_data)
        except ValidationError as e:
            raise PlaybookParseError(f"Validation failed: {str(e)}")
        
        return playbook
    
    def reload_playbooks(self) -> Dict[str, Playbook]:
        """
        Reload all playbooks from disk
        
        Returns:
            Updated dictionary of playbooks
        """
        logger.info("Reloading playbooks from disk")
        return self.load_playbooks()
    
    def get_playbook(self, playbook_id: str) -> Playbook:
        """
        Get a specific playbook by ID
        
        Args:
            playbook_id: The playbook identifier
            
        Returns:
            The requested playbook
            
        Raises:
            KeyError: If playbook_id is not found
        """
        if playbook_id not in self.playbooks:
            raise KeyError(f"Playbook '{playbook_id}' not found")
        return self.playbooks[playbook_id]
    
    def list_playbooks(self) -> List[Dict[str, Any]]:
        """
        Get a list of all loaded playbooks with basic information
        
        Returns:
            List of dictionaries containing playbook metadata
        """
        return [
            {
                "playbook_id": playbook.playbook_id,
                "name": playbook.name,
                "description": playbook.description,
                "version": playbook.version,
                "author": playbook.author,
                "tags": playbook.tags,
                "steps_count": len(playbook.steps),
                "trigger_type": playbook.trigger.type
            }
            for playbook in self.playbooks.values()
        ]
    
    def validate_playbook_yaml(self, yaml_content: str) -> Playbook:
        """
        Validate a playbook YAML string without loading from file
        
        Args:
            yaml_content: Raw YAML string
            
        Returns:
            Validated Playbook object
            
        Raises:
            PlaybookParseError: If validation fails
        """
        try:
            raw_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise PlaybookParseError(f"Invalid YAML syntax: {str(e)}")
        
        if not isinstance(raw_data, dict):
            raise PlaybookParseError("Playbook must be a YAML dictionary")
        
        try:
            playbook = Playbook(**raw_data)
        except ValidationError as e:
            raise PlaybookParseError(f"Validation failed: {str(e)}")
        
        return playbook


# Global parser instance
playbook_parser = PlaybookParser()
