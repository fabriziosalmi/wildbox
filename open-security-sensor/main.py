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
        # Set when a signal, or stop(), asks the sensor to stop.
        self._stop_requested = None

    async def start(self):
        """Run the sensor until it is asked to stop, and until it has
        stopped.

        It used to return, and the process to end, as soon as a stop was
        asked for: the agent's own stopping, which sends the last batches
        and writes the log positions, was a task still running, cancelled
        with the event loop within a second.
        """
        try:
            # Load configuration. A configuration error is the operator's to
            # fix, so say what it is and stop, without a traceback; logging
            # is not set up yet at this point.
            try:
                self.config = load_config(self.config_path)
            except (FileNotFoundError, ValueError) as e:
                print(f"Security Sensor not started: {e}", file=sys.stderr)
                return 2

            # Setup logging
            setup_logging(self.config.logging)

            logger.info(f"Starting Open Security Sensor v{__version__}")
            logger.info(f"Platform: {get_platform_info()}")

            # Initialize the agent
            self.agent = SecuritySensorAgent(self.config)

            # Setup signal handlers
            self._stop_requested = asyncio.Event()
            self._setup_signal_handlers()

            # Start the agent
            await self.agent.start()
            self.running = True

            logger.info("Security Sensor started successfully")

            # Keep running until asked to stop: a signal that came while
            # the agent was starting is not lost.
            await self._stop_requested.wait()

        except Exception as e:
            logger.error(f"Failed to start sensor: {e}", exc_info=True)
            return 1

        # Here, and not in a task nobody waits for.
        await self._stop()
        return 0

    async def stop(self):
        """Ask the sensor to stop; start() returns when it has."""
        if self._stop_requested is not None:
            self._stop_requested.set()

    async def _stop(self):
        logger.info("Stopping Security Sensor...")
        self.running = False

        if self.agent:
            await self.agent.stop()

        logger.info("Security Sensor stopped")

    def _request_stop(self, signum):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self._stop_requested.set()

    def _setup_signal_handlers(self):
        """Stop on SIGINT and SIGTERM"""
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                # Wakes the event loop at once, wherever it is waiting.
                loop.add_signal_handler(signum, self._request_stop, signum)
            except (NotImplementedError, RuntimeError):
                # An event loop without signal support (Windows): the
                # handler runs outside the loop and hands over to it.
                signal.signal(
                    signum,
                    lambda received, frame: loop.call_soon_threadsafe(
                        self._request_stop, received
                    ),
                )


async def _test_connection(config: SensorConfig) -> dict:
    """One empty batch through the forwarder's own session."""
    from sensor.pipeline.data_forwarder import DataForwarder

    forwarder = DataForwarder(config, asyncio.Queue())
    try:
        return await forwarder.test_connection()
    finally:
        if forwarder.session:
            await forwarder.session.close()


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
        help="Ask the running sensor's local API for its status and exit: "
             "0 running, 1 not running, 2 cannot be told"
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
        # Posts an empty batch to the gateway's ingest route with the
        # configured key: it proves the URL, the TLS trust, the key and its
        # data:ingest scope. This used to print success without connecting.
        try:
            config = load_config(args.config)
            result = asyncio.run(_test_connection(config))
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return 1
        if result["success"]:
            print(
                f"✓ {result['endpoint']} accepted the sensor's key "
                f"(HTTP {result['status_code']}, {result['response_time_ms']} ms)"
            )
            return 0
        print(f"✗ Connection test failed for {result['endpoint']}: {result['error']}")
        return 1
    
    if args.status:
        # Asks the running sensor's local API. This used to print
        # "Security Sensor Status: Running" without looking.
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"✗ Configuration error: {e}")
            return 1
        from sensor.api.status_client import check

        code, lines = check(config)
        print("\n".join(lines))
        return code
    
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
