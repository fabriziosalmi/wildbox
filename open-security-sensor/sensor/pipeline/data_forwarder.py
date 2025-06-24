"""
Data Forwarder

This module forwards processed telemetry data to the open-security-data platform
via secure HTTPS API calls with batching, retry logic, and error handling.
"""

import asyncio
import aiohttp
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import ssl

from sensor.core.config import SensorConfig

logger = logging.getLogger(__name__)

class DataForwarder:
    """Forward processed data to the security data lake"""
    
    def __init__(self, config: SensorConfig, input_queue: asyncio.Queue):
        self.config = config
        self.input_queue = input_queue
        self.running = False
        
        # HTTP session for connections
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Batching
        self.batch_buffer: List[Dict[str, Any]] = []
        self.last_flush_time = time.time()
        
        # Statistics
        self.stats = {
            'batches_sent': 0,
            'events_forwarded': 0,
            'events_failed': 0,
            'network_errors': 0,
            'api_errors': 0,
            'last_successful_send': None,
            'last_error': None
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Minimum seconds between requests
    
    async def start(self):
        """Start data forwarding"""
        logger.info("Starting data forwarder")
        self.running = True
        
        try:
            # Initialize HTTP session
            await self._init_session()
            
            # Start forwarding tasks
            asyncio.create_task(self._collect_events())
            asyncio.create_task(self._flush_periodically())
            
            logger.info("Data forwarder started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start data forwarder: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop data forwarding"""
        logger.info("Stopping data forwarder")
        self.running = False
        
        # Flush any remaining events
        if self.batch_buffer:
            await self._flush_batch()
        
        # Close HTTP session
        if self.session:
            await self.session.close()
    
    async def _init_session(self):
        """Initialize HTTP session with proper configuration"""
        
        # SSL context
        ssl_context = ssl.create_default_context()
        if not self.config.data_lake.tls_verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("TLS verification disabled - this is not recommended for production")
        
        # Connector configuration
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,
            limit_per_host=5,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        # Timeout configuration
        timeout = aiohttp.ClientTimeout(
            total=self.config.data_lake.timeout,
            connect=10,
            sock_read=self.config.data_lake.timeout
        )
        
        # Headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Open-Security-Sensor/1.0',
            'Authorization': f'Bearer {self.config.data_lake.api_key}'
        }
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
        
        logger.info(f"HTTP session initialized for endpoint: {self.config.data_lake.endpoint}")
    
    async def _collect_events(self):
        """Collect events from input queue and batch them"""
        while self.running:
            try:
                # Get event with timeout
                event = await asyncio.wait_for(self.input_queue.get(), timeout=1.0)
                
                # Add to batch buffer
                self.batch_buffer.append(event)
                
                # Check if we should flush the batch
                if len(self.batch_buffer) >= self.config.data_lake.batch_size:
                    await self._flush_batch()
                
            except asyncio.TimeoutError:
                # No events available, check if we should flush based on time
                if self._should_flush_by_time():
                    await self._flush_batch()
                continue
                
            except asyncio.CancelledError:
                break
                
            except Exception as e:
                logger.error(f"Error collecting events: {e}")
                await asyncio.sleep(1)
    
    async def _flush_periodically(self):
        """Flush batches periodically based on time interval"""
        while self.running:
            try:
                await asyncio.sleep(self.config.data_lake.flush_interval)
                
                if self.batch_buffer and self._should_flush_by_time():
                    await self._flush_batch()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")
    
    def _should_flush_by_time(self) -> bool:
        """Check if batch should be flushed based on time"""
        return (time.time() - self.last_flush_time) >= self.config.data_lake.flush_interval
    
    async def _flush_batch(self):
        """Flush current batch to the data lake"""
        if not self.batch_buffer:
            return
        
        batch_size = len(self.batch_buffer)
        logger.debug(f"Flushing batch of {batch_size} events")
        
        # Create batch payload
        batch_payload = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'security-sensor',
            'sensor_id': self.config.network.bind_address,  # Use as sensor identifier
            'events': self.batch_buffer.copy()
        }
        
        # Clear buffer before sending (to avoid duplication on retry)
        current_batch = self.batch_buffer.copy()
        self.batch_buffer.clear()
        self.last_flush_time = time.time()
        
        # Send batch with retries
        success = await self._send_batch_with_retries(batch_payload)
        
        if success:
            self.stats['batches_sent'] += 1
            self.stats['events_forwarded'] += batch_size
            self.stats['last_successful_send'] = datetime.now(timezone.utc).isoformat()
            logger.debug(f"Successfully forwarded batch of {batch_size} events")
        else:
            # Re-add failed events to buffer for retry (with limit to prevent memory issues)
            if len(self.batch_buffer) < self.config.performance.max_queue_size:
                self.batch_buffer.extend(current_batch[:100])  # Limit to 100 events
            
            self.stats['events_failed'] += batch_size
            logger.error(f"Failed to forward batch of {batch_size} events")
    
    async def _send_batch_with_retries(self, batch_payload: Dict[str, Any]) -> bool:
        """Send batch with retry logic"""
        
        for attempt in range(self.config.data_lake.retry_attempts):
            try:
                # Rate limiting
                await self._apply_rate_limiting()
                
                # Send HTTP request
                success = await self._send_http_request(batch_payload)
                
                if success:
                    return True
                
                # Wait before retry
                if attempt < self.config.data_lake.retry_attempts - 1:
                    wait_time = self.config.data_lake.retry_delay * (2 ** attempt)  # Exponential backoff
                    logger.debug(f"Retrying batch send in {wait_time} seconds (attempt {attempt + 1})")
                    await asyncio.sleep(wait_time)
                
            except Exception as e:
                logger.error(f"Error sending batch (attempt {attempt + 1}): {e}")
                self.stats['network_errors'] += 1
                self.stats['last_error'] = str(e)
                
                if attempt < self.config.data_lake.retry_attempts - 1:
                    await asyncio.sleep(self.config.data_lake.retry_delay)
        
        return False
    
    async def _apply_rate_limiting(self):
        """Apply rate limiting to prevent overwhelming the API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_request_time = time.time()
    
    async def _send_http_request(self, payload: Dict[str, Any]) -> bool:
        """Send HTTP request to data lake API"""
        try:
            async with self.session.post(
                self.config.data_lake.endpoint,
                json=payload
            ) as response:
                
                if response.status == 200 or response.status == 201:
                    return True
                elif response.status == 429:
                    # Rate limited
                    logger.warning("API rate limit hit, backing off")
                    await asyncio.sleep(10)
                    return False
                elif response.status >= 400 and response.status < 500:
                    # Client error - log and don't retry
                    error_text = await response.text()
                    logger.error(f"API client error {response.status}: {error_text}")
                    self.stats['api_errors'] += 1
                    return False  # Don't retry client errors
                else:
                    # Server error - can retry
                    error_text = await response.text()
                    logger.error(f"API server error {response.status}: {error_text}")
                    self.stats['api_errors'] += 1
                    return False
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            self.stats['network_errors'] += 1
            return False
        except Exception as e:
            logger.error(f"Unexpected HTTP error: {e}")
            self.stats['network_errors'] += 1
            return False
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the data lake API"""
        test_result = {
            'success': False,
            'response_time_ms': None,
            'status_code': None,
            'error': None
        }
        
        if not self.session:
            await self._init_session()
        
        try:
            start_time = time.time()
            
            # Send a simple test payload
            test_payload = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'security-sensor',
                'test': True,
                'events': []
            }
            
            async with self.session.post(
                self.config.data_lake.endpoint,
                json=test_payload
            ) as response:
                
                response_time_ms = int((time.time() - start_time) * 1000)
                test_result['response_time_ms'] = response_time_ms
                test_result['status_code'] = response.status
                
                if response.status == 200 or response.status == 201:
                    test_result['success'] = True
                else:
                    error_text = await response.text()
                    test_result['error'] = f"HTTP {response.status}: {error_text}"
                    
        except Exception as e:
            test_result['error'] = str(e)
        
        return test_result
    
    def get_status(self) -> Dict[str, Any]:
        """Get forwarder status"""
        return {
            'running': self.running,
            'endpoint': self.config.data_lake.endpoint,
            'batch_size': self.config.data_lake.batch_size,
            'flush_interval': self.config.data_lake.flush_interval,
            'current_batch_size': len(self.batch_buffer),
            'queue_size': self.input_queue.qsize(),
            'stats': self.stats.copy(),
            'session_active': self.session is not None and not self.session.closed
        }
