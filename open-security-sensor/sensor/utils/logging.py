"""
Logging configuration and setup utilities
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from sensor.core.config import LoggingConfig

def setup_logging(config: LoggingConfig) -> None:
    """Setup logging configuration"""
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config.level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(config.format)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if configured)
    if config.file:
        file_path = Path(config.file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            filename=config.file,
            maxBytes=config.max_size,
            backupCount=config.backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
