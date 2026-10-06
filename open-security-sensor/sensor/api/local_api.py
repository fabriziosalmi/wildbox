"""
Local API Server

Provides a local HTTP API for sensor management, configuration, and monitoring.
This API allows administrators to:
- Check sensor status
- Execute custom queries
- Update configuration
- Monitor performance
"""

import os
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from aiohttp import web, web_request
import aiohttp_cors

from sensor.core.config import SensorConfig

logger = logging.getLogger(__name__)

class LocalAPI:
    """Local HTTP API server for sensor management"""
    
    def __init__(self, config: SensorConfig, agent):
        self.config = config
        self.agent = agent  # Reference to main agent
        self.app = None
        self.runner = None
        self.site = None
        self.running = False
        
    async def start(self):
        """Start the local API server"""
        if not self.config.network.enable_api:
            logger.info("Local API is disabled")
            return
        
        logger.info("Starting local API server")
        
        try:
            # Create aiohttp application
            self.app = web.Application()
            
            # Setup CORS - restricted to localhost only
            allowed_origin = f"http://{self.config.network.bind_address}:{self.config.network.bind_port}"
            cors = aiohttp_cors.setup(self.app, defaults={
                allowed_origin: aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*"
                )
            })
            
            # Setup routes
            self._setup_routes()
            
            # Add CORS to all routes
            for route in list(self.app.router.routes()):
                cors.add(route)
            
            # Create runner
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            # Start server
            self.site = web.TCPSite(
                self.runner,
                self.config.network.bind_address,
                self.config.network.bind_port
            )
            await self.site.start()
            
            self.running = True
            logger.info(f"Local API server started on {self.config.network.bind_address}:{self.config.network.bind_port}")
            
        except Exception as e:
            logger.error(f"Failed to start local API server: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the local API server"""
        logger.info("Stopping local API server")
        self.running = False
        
        if self.site:
            await self.site.stop()
        
        if self.runner:
            await self.runner.cleanup()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Health is the only unauthenticated endpoint: container and load
        # balancer probes need it, and it exposes nothing but liveness.
        self.app.router.add_get('/health', self._health_handler)

        # Everything else requires the API key. These endpoints read host
        # telemetry, mutate the agent configuration and run osquery, so an
        # unauthenticated caller on the same network would own the endpoint.
        self.app.router.add_get('/status', self._require_auth(self._status_handler))
        self.app.router.add_get('/api/v1/status', self._require_auth(self._status_handler))

        # Configuration endpoints
        self.app.router.add_get('/api/v1/config', self._require_auth(self._get_config_handler))
        self.app.router.add_put('/api/v1/config', self._require_auth(self._update_config_handler))
        self.app.router.add_post('/api/v1/config/reload', self._require_auth(self._reload_config_handler))
        self.app.router.add_post('/api/v1/config/validate', self._require_auth(self._validate_config_handler))

        # Query endpoints
        self.app.router.add_post('/api/v1/query', self._require_auth(self._execute_query_handler))
        self.app.router.add_get('/api/v1/queries', self._require_auth(self._list_queries_handler))

        # Component endpoints
        self.app.router.add_get('/api/v1/components', self._require_auth(self._components_status_handler))
        self.app.router.add_get('/api/v1/stats', self._require_auth(self._stats_handler))

        # Dashboard endpoint
        self.app.router.add_get('/api/v1/dashboard/metrics', self._require_auth(self._dashboard_metrics_handler))

        # Control endpoints
        self.app.router.add_post('/api/v1/test-connection', self._require_auth(self._test_connection_handler))
        
        # Static documentation, in development only. The rule is the one of
        # the platform's services (open-security-shared/api_docs.py): the
        # environment must say "development". It used to be "anything but
        # production", a missing ENVIRONMENT included, and the sensor's
        # Compose files set none, so the route map of the local API was
        # served without authentication wherever the sensor ran (#722).
        if os.getenv("ENVIRONMENT", "").strip().lower() == "development":
            self.app.router.add_get('/', self._api_docs_handler)
            self.app.router.add_get('/docs', self._api_docs_handler)
    
    def _require_auth(self, handler):
        """Decorator to require API key authentication"""
        async def wrapper(request):
            if not self.config.network.api_key:
                # Fail closed. Previously a missing api_key silently disabled
                # authentication for every endpoint below.
                logger.error("Local API called but network.api_key is not configured")
                return web.json_response(
                    {'error': 'API authentication is not configured on this sensor'},
                    status=503
                )
            if True:
                auth_header = request.headers.get('Authorization', '')
                api_key = request.headers.get('X-API-Key', '')
                
                if not (auth_header.startswith('Bearer ') or api_key):
                    return web.json_response(
                        {'error': 'Authentication required'},
                        status=401
                    )
                
                import hmac
                provided_key = auth_header[7:] if auth_header.startswith('Bearer ') else api_key
                if not hmac.compare_digest(provided_key, self.config.network.api_key):
                    return web.json_response(
                        {'error': 'Invalid API key'},
                        status=403
                    )
            
            return await handler(request)
        return wrapper
    
    async def _health_handler(self, request: web_request.Request) -> web.Response:
        """Health check endpoint"""
        health_data = {
            'status': 'healthy' if self.agent.running else 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        status_code = 200 if self.agent.running else 503
        return web.json_response(health_data, status=status_code)
    
    async def _status_handler(self, request: web_request.Request) -> web.Response:
        """Get detailed agent status"""
        try:
            status = self.agent.get_status()
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return web.json_response(
                {'error': 'Failed to get status'},
                status=500
            )
    
    async def _get_config_handler(self, request: web_request.Request) -> web.Response:
        """Get current configuration"""
        try:
            # Return sanitized configuration (without sensitive data)
            config_data = {
                'data_lake': {
                    'endpoint': self.config.data_lake.endpoint,
                    'batch_size': self.config.data_lake.batch_size,
                    'flush_interval': self.config.data_lake.flush_interval,
                    'tls_verify': self.config.data_lake.tls_verify
                },
                'collection': {
                    'process_events': self.config.collection.process_events,
                    'network_connections': self.config.collection.network_connections,
                    'file_monitoring': self.config.collection.file_monitoring,
                    'user_events': self.config.collection.user_events,
                    'system_inventory': self.config.collection.system_inventory,
                    'log_forwarding': self.config.collection.log_forwarding
                },
                'fim': {
                    'enabled': self.config.fim.enabled,
                    'paths': self.config.fim.paths,
                    'exclude_patterns': self.config.fim.exclude_patterns
                },
                # null: no log_sources section, the forwarder reads the
                # platform's defaults (see /api/v1/components for those).
                'log_sources': (
                    None if self.config.log_sources is None
                    else [source.to_dict() for source in self.config.log_sources]
                ),
                'performance': {
                    'query_interval': self.config.performance.query_interval,
                    'inventory_interval': self.config.performance.inventory_interval,
                    'max_memory_mb': self.config.performance.max_memory_mb,
                    'max_cpu_percent': self.config.performance.max_cpu_percent,
                    'worker_threads': self.config.performance.worker_threads
                }
            }
            
            return web.json_response(config_data)
            
        except Exception as e:
            logger.error(f"Error getting config: {e}")
            return web.json_response(
                {'error': 'Failed to get configuration'},
                status=500
            )
    
    async def _update_config_handler(self, request: web_request.Request) -> web.Response:
        """Update configuration"""
        try:
            # This would require implementing config updates
            # For now, return not implemented
            return web.json_response(
                {'error': 'Configuration updates not yet implemented'},
                status=501
            )
            
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return web.json_response(
                {'error': 'Failed to update configuration'},
                status=500
            )
    
    async def _reload_config_handler(self, request: web_request.Request) -> web.Response:
        """Reload configuration"""
        try:
            # This would require implementing config reload
            return web.json_response(
                {'message': 'Configuration reload not yet implemented'},
                status=501
            )
            
        except Exception as e:
            logger.error(f"Error reloading config: {e}")
            return web.json_response(
                {'error': 'Failed to reload configuration'},
                status=500
            )
    
    async def _validate_config_handler(self, request: web_request.Request) -> web.Response:
        """Validate configuration"""
        try:
            errors = self.config.validate()
            
            if errors:
                return web.json_response({
                    'valid': False,
                    'errors': errors
                }, status=400)
            else:
                return web.json_response({
                    'valid': True,
                    'message': 'Configuration is valid'
                })
                
        except Exception as e:
            logger.error(f"Error validating config: {e}")
            return web.json_response(
                {'error': 'Failed to validate configuration'},
                status=500
            )
    
    async def _execute_query_handler(self, request: web_request.Request) -> web.Response:
        """Execute custom osquery"""
        try:
            data = await request.json()
            query = data.get('query')
            
            if not query:
                return web.json_response(
                    {'error': 'Query parameter is required'},
                    status=400
                )
            
            # Execute query through agent
            results = await self.agent.execute_query(query)
            
            return web.json_response({
                'query': query,
                'results': results,
                'count': len(results),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return web.json_response(
                {'error': 'Failed to execute query'},
                status=500
            )
    
    async def _list_queries_handler(self, request: web_request.Request) -> web.Response:
        """List available query packs"""
        try:
            # Get query information from osquery manager
            if self.agent.osquery_manager:
                query_info = {
                    'query_packs': list(self.agent.osquery_manager.query_packs.keys()),
                    'total_queries': sum(
                        len(pack['queries']) 
                        for pack in self.agent.osquery_manager.query_packs.values()
                    )
                }
            else:
                query_info = {
                    'query_packs': [],
                    'total_queries': 0,
                    'message': 'osquery manager not available'
                }
            
            return web.json_response(query_info)
            
        except Exception as e:
            logger.error(f"Error listing queries: {e}")
            return web.json_response(
                {'error': 'Failed to list queries'},
                status=500
            )
    
    async def _components_status_handler(self, request: web_request.Request) -> web.Response:
        """Get status of all components"""
        try:
            components = {}
            
            if self.agent.osquery_manager:
                components['osquery_manager'] = self.agent.osquery_manager.get_status()
            
            if self.agent.file_monitor:
                components['file_monitor'] = self.agent.file_monitor.get_status()
            
            if self.agent.log_forwarder:
                components['log_forwarder'] = self.agent.log_forwarder.get_status()
            
            if self.agent.data_processor:
                components['data_processor'] = self.agent.data_processor.get_status()
            
            if self.agent.data_forwarder:
                components['data_forwarder'] = self.agent.data_forwarder.get_status()
            
            return web.json_response(components)
            
        except Exception as e:
            logger.error(f"Error getting component status: {e}")
            return web.json_response(
                {'error': 'Failed to get component status'},
                status=500
            )
    
    async def _stats_handler(self, request: web_request.Request) -> web.Response:
        """Get sensor statistics"""
        try:
            stats = self.agent.get_stats()
            stats['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            return web.json_response(stats)
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return web.json_response(
                {'error': 'Failed to get statistics'},
                status=500
            )
    
    async def _dashboard_metrics_handler(self, request: web_request.Request) -> web.Response:
        """A summary of this endpoint, from what the sensor measures.

        It used to report a hostname and an operating system of "unknown",
        zeros for CPU, memory, disk, connections and processes, the current
        time as the last activity and a trend it did not compute: none of
        those was read from anything. What the sensor does not measure is
        no longer in the answer.
        """
        try:
            stats = self.agent.get_stats()
            processor = self.agent.data_processor

            # What deserves a look: errors, and the sensor using more than
            # its configured thresholds.
            alerts = 0
            if stats.get('errors', 0) > 0:
                alerts += 1
            if stats.get('over_limits'):
                alerts += 1
            # Events are collected and none reaches the data service.
            if stats.get('delivery_state', 'ok') != 'ok':
                alerts += 1

            dashboard_metrics = {
                'total_endpoints': 1,  # this sensor is one endpoint
                'online_endpoints': 1 if self.agent.running else 0,
                'alerts': alerts,
                'delivery_state': stats.get('delivery_state'),
                'last_activity': stats['last_activity'],
                'endpoint_details': {
                    'hostname': processor.hostname if processor else None,
                    'os': processor.platform_info.get('system') if processor else None,
                    'uptime_seconds': stats['uptime_seconds'],
                    # Of the sensor's own process, as the resource monitor
                    # last measured them; absent until it has.
                    'cpu_percent': stats.get('cpu_percent'),
                    'memory_mb': stats.get('memory_mb'),
                    'events_collected': stats['events_collected'],
                    'events_forwarded': stats['events_forwarded'],
                    'events_dropped': stats['events_dropped'],
                }
            }

            return web.json_response(dashboard_metrics)

        except Exception as e:
            logger.error(f"Error getting dashboard metrics: {e}")
            return web.json_response(
                {'error': 'Failed to get dashboard metrics'},
                status=500
            )

    async def _test_connection_handler(self, request: web_request.Request) -> web.Response:
        """Test connection to data lake"""
        try:
            if self.agent.data_forwarder:
                test_result = await self.agent.data_forwarder.test_connection()
                return web.json_response(test_result)
            else:
                return web.json_response(
                    {'error': 'Data forwarder not available'},
                    status=503
                )
                
        except Exception as e:
            logger.error(f"Error testing connection: {e}")
            return web.json_response(
                {'error': 'Failed to test connection'},
                status=500
            )
    
    async def _api_docs_handler(self, request: web_request.Request) -> web.Response:
        """Serve API documentation"""
        docs_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Open Security Sensor API</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1, h2 { color: #333; }
                .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
                .method { font-weight: bold; color: #007bff; }
                code { background: #e9ecef; padding: 2px 4px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>Open Security Sensor API</h1>
            <p>Local management API for the Security Sensor agent.</p>
            
            <h2>Health & Status</h2>
            <div class="endpoint">
                <span class="method">GET</span> <code>/health</code> - Health check
            </div>
            <div class="endpoint">
                <span class="method">GET</span> <code>/status</code> - Detailed status
            </div>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/status</code> - Agent status
            </div>
            
            <h2>Configuration</h2>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/config</code> - Get configuration
            </div>
            <div class="endpoint">
                <span class="method">PUT</span> <code>/api/v1/config</code> - Update configuration
            </div>
            <div class="endpoint">
                <span class="method">POST</span> <code>/api/v1/config/reload</code> - Reload configuration
            </div>
            
            <h2>Queries</h2>
            <div class="endpoint">
                <span class="method">POST</span> <code>/api/v1/query</code> - Execute custom query
            </div>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/queries</code> - List available queries
            </div>
            
            <h2>Monitoring</h2>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/components</code> - Component status
            </div>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/stats</code> - Statistics
            </div>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/v1/dashboard/metrics</code> - Dashboard metrics
            </div>
            <div class="endpoint">
                <span class="method">POST</span> <code>/api/v1/test-connection</code> - Test data lake connection
            </div>
        </body>
        </html>
        """
        return web.Response(text=docs_html, content_type='text/html')
    
    def get_status(self) -> Dict[str, Any]:
        """Get API server status"""
        return {
            'running': self.running,
            'bind_address': self.config.network.bind_address,
            'bind_port': self.config.network.bind_port,
            'enabled': self.config.network.enable_api
        }
