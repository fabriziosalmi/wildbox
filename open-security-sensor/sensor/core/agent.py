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
from sensor.pipeline.delivery import take_delivery

logger = logging.getLogger(__name__)

# Seconds the events already collected get to reach the sender when the
# sensor stops, before the pipeline is stopped under them.
QUEUE_DRAIN_SECONDS = 2.0


class CountingQueue(asyncio.Queue):
    """A queue that counts what is put on it, and when the last item was.

    The collectors put their events on one of these: its count is the
    number of events collected, whatever becomes of them afterwards.
    """

    def _init(self, maxsize):
        super()._init(maxsize)
        self.total = 0
        self.last_put: Optional[datetime] = None

    def _put(self, item):
        super()._put(item)
        self.total += 1
        self.last_put = datetime.now(timezone.utc)


class SecuritySensorAgent:
    """
    Main sensor agent that coordinates all sensor components.
    
    This class manages:
    - osquery for system telemetry collection
    - File integrity monitoring
    - Log forwarding
    - Data processing and forwarding pipeline
    - Resource monitoring
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
        
        # What the resource monitor measures (memory_mb, cpu_percent,
        # over_limits). The event counters are not kept here: get_stats()
        # reads them from the components that do the counting.
        self.resources: Dict[str, Any] = {}

        # Event queues for inter-component communication
        self.event_queue = CountingQueue(maxsize=self.config.performance.max_queue_size)
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
                stats=self.resources
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
            
            # Start the monitoring task
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
        """Stop all components gracefully.

        In this order: what produces events; then, once the events already
        collected have reached the sender or QUEUE_DRAIN_SECONDS have
        passed, what carries them, so that the sender's last batches are the
        last events; then the log positions and the file monitor's baseline
        once more, for what those batches delivered.
        """
        collectors = [
            component
            for component in (
                self.local_api,
                self.log_forwarder,
                self.file_monitor,
                self.osquery_manager,
                self.resource_monitor,
            )
            if component
        ]
        pipeline = [
            component
            for component in (self.data_processor, self.data_forwarder)
            if component
        ]

        await self._stop_all(collectors)
        if self.data_processor and self.data_forwarder:
            await self._drain_queues()
        await self._stop_all(pipeline)
        self._report_left_in_queues()

        if self.log_forwarder:
            self.log_forwarder.save_positions()
        if self.file_monitor:
            self.file_monitor.save_baseline()

    @staticmethod
    async def _stop_all(components):
        if not components:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    *(component.stop() for component in components),
                    return_exceptions=True,
                ),
                timeout=15
            )
        except asyncio.TimeoutError:
            logger.warning("Some components did not stop within timeout")

    async def _drain_queues(self):
        """Give the events already collected the time to reach the sender.

        Nothing new is collected at this point. When the sender takes no
        more (its buffer is full), waiting would not help: it gives up after
        QUEUE_DRAIN_SECONDS.
        """
        try:
            await asyncio.wait_for(self._handed_over(), QUEUE_DRAIN_SECONDS)
        except asyncio.TimeoutError:
            pass

    async def _handed_over(self):
        """Return when every event collected has reached the sender, or has
        been filtered or dropped with a count on its way.

        Each queue is asked, and each answers for its reader: an event is
        unfinished from the moment it is put until whoever took it says
        ``task_done()``, which the processor does when the event is on the
        processed queue (or filtered) and the sender when it holds the event
        (or has dropped it). This used to be a look, every 20 ms, at the
        size of the two queues and at a count the processor's workers kept:
        an event a worker had taken and not counted yet was in none of the
        three, and a look at that moment ended the wait and lost the event
        (#754). In this order: the processor adds to the second queue until
        the first one is finished.
        """
        await self.event_queue.join()
        await self.processed_queue.join()

    def _report_left_in_queues(self):
        """Say what the queues, and the processor's workers, still held when
        the pipeline stopped: those events never reached the sender, which
        counts only its own."""
        left = []
        for queue in (self.event_queue, self.processed_queue):
            while not queue.empty():
                left.append(take_delivery(queue.get_nowait()))
                # Counted here: the queue has nothing unfinished left.
                queue.task_done()
        if self.data_processor:
            # And what its workers held when they were stopped.
            left.extend(self.data_processor.interrupted)
            self.data_processor.interrupted = []
        if not left:
            return
        returned = sum(
            1 for delivery in left if delivery is not None and delivery.replayable
        )
        logger.warning(
            "Stopped with %d events still on their way to the sender: %d are "
            "dropped, %d will be read again from their log source after the "
            "restart",
            len(left),
            len(left) - returned,
            returned,
        )

    def get_stats(self) -> Dict[str, Any]:
        """The sensor's counters, read where they are counted.

        They used to be a dictionary of zeros that nothing incremented.

        * events_collected: events the collectors put on the queue.
        * events_processed / events_filtered: what the processor passed on
          or filtered out.
        * events_forwarded: events the gateway accepted.
        * events_dropped: events that left the sensor unsent (the reasons
          are under data_forwarder in /api/v1/components).
        * events_in_pipeline: events waiting in the two queues and in the
          sender's buffer, and those in hand between them (a worker's, and
          the one the sender holds while its buffer is full).
        * errors: errors of the processor and of the sender (network errors
          and error answers of the gateway).
        * last_activity: when the last event was collected, or null.
        * delivery_state: "ok", or why no batch reaches the data service
          ("unauthorized", "forbidden", "rate_limited", "unavailable",
          "misconfigured", "unconfigured"), and delivery_since.
        """
        processor = self.data_processor.stats if self.data_processor else {}
        forwarder = self.data_forwarder.stats if self.data_forwarder else {}
        buffered = self.data_forwarder.held if self.data_forwarder else 0
        in_hand = self.data_processor.in_flight if self.data_processor else 0
        last_put = self.event_queue.last_put
        uptime = 0
        if self.start_time:
            uptime = int((datetime.now(timezone.utc) - self.start_time).total_seconds())
        stats = {
            'events_collected': self.event_queue.total,
            'events_processed': processor.get('events_processed', 0),
            'events_filtered': processor.get('events_filtered', 0),
            'events_forwarded': forwarder.get('events_forwarded', 0),
            'events_dropped': forwarder.get('events_dropped', 0),
            'events_in_pipeline': (
                self.event_queue.qsize()
                + in_hand
                + self.processed_queue.qsize()
                + buffered
            ),
            'errors': (
                processor.get('errors', 0)
                + forwarder.get('network_errors', 0)
                + forwarder.get('api_errors', 0)
            ),
            'last_activity': last_put.isoformat() if last_put else None,
            'uptime_seconds': uptime,
        }
        if self.data_forwarder:
            delivery = self.data_forwarder.get_status()['delivery']
            stats['delivery_state'] = delivery['state']
            stats['delivery_since'] = delivery['since']
        stats.update(self.resources)
        return stats

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
            'stats': self.get_stats(),
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
    
