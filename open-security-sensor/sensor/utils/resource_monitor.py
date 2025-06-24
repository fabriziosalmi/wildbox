"""
Resource monitoring and throttling utilities
"""

import asyncio
import logging
import psutil
import time
from typing import Dict, Any
from sensor.core.config import SensorConfig

logger = logging.getLogger(__name__)

class ResourceMonitor:
    """Monitor and control resource usage"""
    
    def __init__(self, config: SensorConfig, stats: Dict[str, Any]):
        self.config = config
        self.stats = stats
        self.running = False
        self.process = psutil.Process()
        
        # Throttling state
        self.throttled = False
        self.throttle_until = 0
        
    async def start(self):
        """Start resource monitoring"""
        self.running = True
        logger.info("Starting resource monitor")
        
        # Start monitoring task
        asyncio.create_task(self._monitor_resources())
    
    async def stop(self):
        """Stop resource monitoring"""
        self.running = False
        logger.info("Stopping resource monitor")
    
    async def _monitor_resources(self):
        """Monitor resource usage and apply throttling"""
        while self.running:
            try:
                # Get current resource usage
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                cpu_percent = self.process.cpu_percent()
                
                # Check if we need to throttle
                should_throttle = (
                    memory_mb > self.config.performance.max_memory_mb or
                    cpu_percent > self.config.performance.max_cpu_percent
                )
                
                if should_throttle and not self.throttled:
                    logger.warning(f"Resource limits exceeded (Memory: {memory_mb:.1f}MB, CPU: {cpu_percent:.1f}%) - throttling enabled")
                    self.throttled = True
                    self.throttle_until = time.time() + 30  # Throttle for 30 seconds
                    
                elif self.throttled and time.time() > self.throttle_until:
                    # Check if we can stop throttling
                    if not should_throttle:
                        logger.info("Resource usage normalized - throttling disabled")
                        self.throttled = False
                    else:
                        # Extend throttling period
                        self.throttle_until = time.time() + 30
                
                # Update stats
                self.stats.update({
                    'memory_mb': memory_mb,
                    'cpu_percent': cpu_percent,
                    'throttled': self.throttled
                })
                
                # Sleep interval based on throttling state
                sleep_time = 10 if self.throttled else 5
                await asyncio.sleep(sleep_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(5)
    
    def is_throttled(self) -> bool:
        """Check if currently throttled due to resource limits"""
        return self.throttled
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage statistics"""
        try:
            memory_info = self.process.memory_info()
            cpu_times = self.process.cpu_times()
            
            return {
                'memory': {
                    'rss_mb': memory_info.rss / 1024 / 1024,
                    'vms_mb': memory_info.vms / 1024 / 1024,
                    'percent': self.process.memory_percent()
                },
                'cpu': {
                    'percent': self.process.cpu_percent(),
                    'user_time': cpu_times.user,
                    'system_time': cpu_times.system
                },
                'threads': self.process.num_threads(),
                'open_files': len(self.process.open_files()),
                'throttled': self.throttled
            }
        except Exception as e:
            logger.error(f"Error getting resource usage: {e}")
            return {}
