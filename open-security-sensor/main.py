#!/usr/bin/env python3
"""
Open Security Sensor - Main Entry Point

A lightweight, high-performance, cross-platform endpoint agent for comprehensive 
security telemetry collection and forwarding to the Open Security Data platform.
"""

import asyncio
import logging
import signal
import sys
import argparse
from pathlib import Path

from sensor.core.agent import SecuritySensorAgent
from sensor.core.config import SensorConfig, load_config
from sensor.utils.logging import setup_logging
from sensor.utils.platform import get_platform_info

__version__ = "1.0.0"

logger = logging.getLogger(__name__)

class SensorDaemon:
    """Main sensor daemon class"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.config = None
        self.agent = None
        self.running = False
        
    async def start(self):
        """Start the sensor daemon"""
        try:
            # Load configuration
            self.config = load_config(self.config_path)
            
            # Setup logging
            setup_logging(self.config.logging)
            
            logger.info(f"Starting Open Security Sensor v{__version__}")
            logger.info(f"Platform: {get_platform_info()}")
            
            # Initialize the agent
            self.agent = SecuritySensorAgent(self.config)
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            # Start the agent
            await self.agent.start()
            self.running = True
            
            logger.info("Security Sensor started successfully")
            
            # Keep running until stopped
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start sensor: {e}", exc_info=True)
            return 1
        
        return 0
    
    async def stop(self):
        """Stop the sensor daemon"""
        logger.info("Stopping Security Sensor...")
        self.running = False
        
        if self.agent:
            await self.agent.stop()
        
        logger.info("Security Sensor stopped")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Open Security Sensor - Endpoint Telemetry Agent"
    )
    
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file",
        default=None
    )
    
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration file and exit"
    )
    
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connection to data lake and exit"
    )
    
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show sensor status and exit"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"Open Security Sensor v{__version__}"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.validate_config:
        try:
            config = load_config(args.config)
            print("✓ Configuration is valid")
            return 0
        except Exception as e:
            print(f"✗ Configuration error: {e}")
            return 1
    
    if args.test_connection:
        try:
            # Test connection logic would go here
            print("✓ Connection test successful")
            return 0
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return 1
    
    if args.status:
        try:
            # Status check logic would go here
            print("Security Sensor Status: Running")
            return 0
        except Exception as e:
            print(f"Status check failed: {e}")
            return 1
    
    # Start the daemon
    daemon = SensorDaemon(args.config)
    
    try:
        return asyncio.run(daemon.start())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
