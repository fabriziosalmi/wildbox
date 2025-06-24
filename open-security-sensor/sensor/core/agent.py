"""
Main Security Sensor Agent

This module contains the core SecuritySensorAgent class that orchestrates
all sensor components including osquery, data collection, and forwarding.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import psutil
import json

from sensor.collectors.osquery_manager import OsqueryManager
from sensor.collectors.file_monitor import FileMonitor
from sensor.collectors.log_forwarder import LogForwarder
from sensor.pipeline.data_processor import DataProcessor
from sensor.pipeline.data_forwarder import DataForwarder
from sensor.core.config import SensorConfig
from sensor.api.local_api import LocalAPI
from sensor.utils.resource_monitor import ResourceMonitor

logger = logging.getLogger(__name__)

class SecuritySensorAgent:
    """
    Main sensor agent that coordinates all sensor components.
    
    This class manages:
    - osquery for system telemetry collection
    - File integrity monitoring
    - Log forwarding
    - Data processing and forwarding pipeline
    - Resource monitoring and throttling
    - Local management API
    """
    
    def __init__(self, config: SensorConfig):
        self.config = config
        self.running = False
        self.start_time = None
        
        # Core components
        self.osquery_manager = None
        self.file_monitor = None
        self.log_forwarder = None
        self.data_processor = None
        self.data_forwarder = None
        self.local_api = None
        self.resource_monitor = None
        
        # Statistics
        self.stats = {
            'events_collected': 0,
            'events_processed': 0,
            'events_forwarded': 0,
            'errors': 0,
            'last_activity': None,
            'uptime_seconds': 0
        }
        
        # Event queues for inter-component communication
        self.event_queue = asyncio.Queue(maxsize=self.config.performance.max_queue_size)
        self.processed_queue = asyncio.Queue(maxsize=self.config.performance.max_queue_size)
    
    async def start(self):
        """Start the sensor agent and all components"""
        logger.info("Starting Security Sensor Agent...")
        self.start_time = datetime.now(timezone.utc)
        
        try:
            # Initialize data processing pipeline
            self.data_processor = DataProcessor(
                config=self.config,
                input_queue=self.event_queue,
                output_queue=self.processed_queue
            )
            
            self.data_forwarder = DataForwarder(
                config=self.config,
                input_queue=self.processed_queue
            )
            
            # Initialize resource monitor
            self.resource_monitor = ResourceMonitor(
                config=self.config,
                stats=self.stats
            )
            
            # Initialize collectors based on configuration
            if self.config.collection.process_events or \
               self.config.collection.network_connections or \
               self.config.collection.user_events or \
               self.config.collection.system_inventory:
                
                self.osquery_manager = OsqueryManager(
                    config=self.config,
                    event_queue=self.event_queue
                )
            
            if self.config.collection.file_monitoring and self.config.fim.enabled:
                self.file_monitor = FileMonitor(
                    config=self.config,
                    event_queue=self.event_queue
                )
            
            if self.config.collection.log_forwarding:
                self.log_forwarder = LogForwarder(
                    config=self.config,
                    event_queue=self.event_queue
                )
            
            # Initialize local management API
            if self.config.network.enable_api:
                self.local_api = LocalAPI(
                    config=self.config,
                    agent=self
                )
            
            # Start all components
            await self._start_components()
            
            self.running = True
            logger.info("Security Sensor Agent started successfully")
            
            # Start monitoring and statistics tasks
            asyncio.create_task(self._update_statistics())
            asyncio.create_task(self._monitor_health())
            
        except Exception as e:
            logger.error(f"Failed to start sensor agent: {e}", exc_info=True)
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the sensor agent and all components"""
        logger.info("Stopping Security Sensor Agent...")
        self.running = False
        
        # Stop all components
        await self._stop_components()
        
        logger.info("Security Sensor Agent stopped")
    
    async def _start_components(self):
        """Start all enabled components"""
        components_to_start = []
        
        # Data processing pipeline (always required)
        components_to_start.extend([
            self.data_processor.start(),
            self.data_forwarder.start(),
            self.resource_monitor.start()
        ])
        
        # Optional components
        if self.osquery_manager:
            components_to_start.append(self.osquery_manager.start())
        
        if self.file_monitor:
            components_to_start.append(self.file_monitor.start())
        
        if self.log_forwarder:
            components_to_start.append(self.log_forwarder.start())
        
        if self.local_api:
            components_to_start.append(self.local_api.start())
        
        # Start all components concurrently
        await asyncio.gather(*components_to_start)
    
    async def _stop_components(self):
        """Stop all components gracefully"""
        stop_tasks = []
        
        if self.local_api:
            stop_tasks.append(self.local_api.stop())
        
        if self.log_forwarder:
            stop_tasks.append(self.log_forwarder.stop())
        
        if self.file_monitor:
            stop_tasks.append(self.file_monitor.stop())
        
        if self.osquery_manager:
            stop_tasks.append(self.osquery_manager.stop())
        
        if self.resource_monitor:
            stop_tasks.append(self.resource_monitor.stop())
        
        if self.data_forwarder:
            stop_tasks.append(self.data_forwarder.stop())
        
        if self.data_processor:
            stop_tasks.append(self.data_processor.stop())
        
        # Stop all components concurrently with timeout
        if stop_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=30
                )
            except asyncio.TimeoutError:
                logger.warning("Some components did not stop within timeout")
    
    async def _update_statistics(self):
        """Update agent statistics periodically"""
        while self.running:
            try:
                if self.start_time:
                    self.stats['uptime_seconds'] = int(
                        (datetime.now(timezone.utc) - self.start_time).total_seconds()
                    )
                
                self.stats['last_activity'] = datetime.now(timezone.utc).isoformat()
                
                await asyncio.sleep(60)  # Update every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error updating statistics: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(60)
    
    async def _monitor_health(self):
        """Monitor agent health and perform maintenance tasks"""
        while self.running:
            try:
                # Check queue sizes
                event_queue_size = self.event_queue.qsize()
                processed_queue_size = self.processed_queue.qsize()
                
                if event_queue_size > self.config.performance.max_queue_size * 0.8:
                    logger.warning(f"Event queue is {event_queue_size}/{self.config.performance.max_queue_size} full")
                
                if processed_queue_size > self.config.performance.max_queue_size * 0.8:
                    logger.warning(f"Processed queue is {processed_queue_size}/{self.config.performance.max_queue_size} full")
                
                # Check resource usage
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent()
                
                if memory_mb > self.config.performance.max_memory_mb:
                    logger.warning(f"Memory usage ({memory_mb:.1f}MB) exceeds limit ({self.config.performance.max_memory_mb}MB)")
                
                if cpu_percent > self.config.performance.max_cpu_percent:
                    logger.warning(f"CPU usage ({cpu_percent:.1f}%) exceeds limit ({self.config.performance.max_cpu_percent}%)")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health monitoring: {e}")
                await asyncio.sleep(30)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        status = {
            'running': self.running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'stats': self.stats.copy(),
            'config': {
                'data_lake_endpoint': self.config.data_lake.endpoint,
                'collection_enabled': {
                    'process_events': self.config.collection.process_events,
                    'network_connections': self.config.collection.network_connections,
                    'file_monitoring': self.config.collection.file_monitoring,
                    'user_events': self.config.collection.user_events,
                    'system_inventory': self.config.collection.system_inventory,
                    'log_forwarding': self.config.collection.log_forwarding
                }
            },
            'components': {
                'osquery_manager': self.osquery_manager is not None,
                'file_monitor': self.file_monitor is not None,
                'log_forwarder': self.log_forwarder is not None,
                'local_api': self.local_api is not None
            },
            'queues': {
                'event_queue_size': self.event_queue.qsize(),
                'processed_queue_size': self.processed_queue.qsize()
            }
        }
        
        # Add resource usage
        try:
            process = psutil.Process()
            status['resources'] = {
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'open_files': len(process.open_files())
            }
        except Exception as e:
            logger.debug(f"Could not get resource info: {e}")
        
        return status
    
    async def reload_config(self, new_config: SensorConfig):
        """Reload configuration (requires restart for most changes)"""
        logger.info("Reloading configuration...")
        
        # For now, most config changes require a restart
        # In the future, we could implement hot-reloading for some settings
        self.config = new_config
        
        logger.info("Configuration reloaded (restart required for most changes)")
    
    async def execute_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute a custom osquery query"""
        if not self.osquery_manager:
            raise RuntimeError("osquery manager not available")
        
        return await self.osquery_manager.execute_query(query)
    
    def increment_stat(self, stat_name: str, amount: int = 1):
        """Increment a statistics counter"""
        if stat_name in self.stats:
            self.stats[stat_name] += amount
        else:
            self.stats[stat_name] = amount
