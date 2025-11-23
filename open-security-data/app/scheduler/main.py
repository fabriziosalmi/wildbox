"""
Data collection scheduler

Manages periodic collection from all configured sources.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from contextlib import asynccontextmanager

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.config import get_config
from app.models import Source, CollectionRun
from app.utils.database import get_db_session
from app.collectors import CollectorRegistry
# Import collectors to register them
import app.collectors.sources  # noqa: F401

logger = logging.getLogger(__name__)
config = get_config()

@dataclass
class ScheduledTask:
    """Represents a scheduled collection task"""
    source: Source
    next_run: datetime
    running: bool = False
    last_error: Optional[str] = None

class CollectionScheduler:
    """Manages scheduled data collection from sources"""
    
    def __init__(self):
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running = False
        self._shutdown_event = asyncio.Event()
    
    async def start(self):
        """Start the scheduler"""
        logger.info("Starting collection scheduler")
        self.running = True
        
        # Load sources and create initial schedule
        await self._load_sources()
        
        # Start main scheduler loop
        await self._scheduler_loop()
    
    async def stop(self):
        """Stop the scheduler"""
        logger.info("Stopping collection scheduler")
        self.running = False
        self._shutdown_event.set()
    
    async def _load_sources(self):
        """Load enabled sources from database"""
        db = get_db_session()
        try:
            sources = db.query(Source).filter(
                and_(
                    Source.enabled == True,
                    Source.status != 'error'
                )
            ).all()
            
            current_time = datetime.now(timezone.utc)
            
            for source in sources:
                # Calculate next run time
                if source.last_collection:
                    next_run = source.last_collection + timedelta(seconds=source.collection_interval)
                else:
                    # First run - spread out initial runs to avoid thundering herd
                    next_run = current_time + timedelta(seconds=hash(source.name) % 300)
                
                # If next run is in the past, schedule it soon
                if next_run <= current_time:
                    next_run = current_time + timedelta(seconds=30)
                
                self.tasks[str(source.id)] = ScheduledTask(
                    source=source,
                    next_run=next_run
                )
                
                logger.info(f"Scheduled source '{source.name}' for next run at {next_run}")
            
            logger.info(f"Loaded {len(self.tasks)} sources for collection")
            
        finally:
            db.close()
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Find tasks ready to run
                ready_tasks = [
                    task for task in self.tasks.values()
                    if task.next_run <= current_time and not task.running
                ]
                
                if ready_tasks:
                    logger.info(f"Found {len(ready_tasks)} sources ready for collection")
                    
                    # Limit concurrent collections
                    max_concurrent = config.collection.max_concurrent
                    if len(ready_tasks) > max_concurrent:
                        logger.warning(f"Too many ready tasks ({len(ready_tasks)}), limiting to {max_concurrent}")
                        ready_tasks = ready_tasks[:max_concurrent]
                    
                    # Start collection tasks
                    collection_tasks = []
                    for task in ready_tasks:
                        collection_tasks.append(self._run_collection(task))
                    
                    # Run collections concurrently
                    if collection_tasks:
                        await asyncio.gather(*collection_tasks, return_exceptions=True)
                
                # Check for shutdown
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=60.0)
                    break  # Shutdown requested
                except asyncio.TimeoutError:
                    pass  # Continue normal operation
                
                # Reload sources periodically (every 10 minutes)
                if current_time.minute % 10 == 0:
                    await self._reload_sources()
                
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                logger.error(f"Error in scheduler loop: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _run_collection(self, task: ScheduledTask):
        """Run collection for a single source"""
        source = task.source
        task.running = True
        
        try:
            logger.info(f"Starting collection for source: {source.name}")
            
            # Get appropriate collector
            collector = CollectorRegistry.get_collector(source)
            
            # Run collection with timeout
            result = await asyncio.wait_for(
                collector.run_collection(),
                timeout=source.timeout
            )
            
            # Update source status
            db = get_db_session()
            try:
                db_source = db.query(Source).filter(Source.id == source.id).first()
                if db_source:
                    db_source.last_collection = datetime.now(timezone.utc)
                    db_source.collection_count += 1
                    
                    if result.status.value == 'completed':
                        db_source.last_success = datetime.now(timezone.utc)
                        db_source.status = 'active'
                        db_source.last_error = None
                    elif result.status.value == 'rate_limited':
                        db_source.status = 'rate_limited'
                        db_source.last_error = result.error_message
                    else:
                        db_source.error_count += 1
                        db_source.status = 'error'
                        db_source.last_error = result.error_message
                    
                    db.commit()
                    
                    # Update task for next run
                    task.next_run = datetime.now(timezone.utc) + timedelta(seconds=source.collection_interval)
                    task.last_error = result.error_message
            
            finally:
                db.close()
            
            logger.info(f"Collection completed for {source.name}: {result.status.value}")
            
        except asyncio.TimeoutError:
            logger.error(f"Collection timeout for source: {source.name}")
            task.last_error = "Collection timeout"
            await self._handle_collection_error(source, "Collection timeout")
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Collection error for source {source.name}: {e}", exc_info=True)
            task.last_error = str(e)
            await self._handle_collection_error(source, str(e))
            
        finally:
            task.running = False
    
    async def _handle_collection_error(self, source: Source, error_message: str):
        """Handle collection errors"""
        db = get_db_session()
        try:
            db_source = db.query(Source).filter(Source.id == source.id).first()
            if db_source:
                db_source.error_count += 1
                db_source.last_error = error_message
                db_source.status = 'error'
                
                # Disable source if too many consecutive errors
                if db_source.error_count >= 10:
                    logger.warning(f"Disabling source {source.name} due to excessive errors")
                    db_source.enabled = False
                
                db.commit()
        finally:
            db.close()
    
    async def _reload_sources(self):
        """Reload sources from database"""
        try:
            logger.debug("Reloading sources")
            
            db = get_db_session()
            try:
                sources = db.query(Source).filter(Source.enabled == True).all()
                
                # Update existing tasks and add new ones
                current_source_ids = set(self.tasks.keys())
                db_source_ids = {str(source.id) for source in sources}
                
                # Remove tasks for deleted/disabled sources
                for source_id in current_source_ids - db_source_ids:
                    del self.tasks[source_id]
                    logger.info(f"Removed task for disabled/deleted source: {source_id}")
                
                # Add/update tasks for current sources
                for source in sources:
                    source_id = str(source.id)
                    
                    if source_id in self.tasks:
                        # Update existing task
                        self.tasks[source_id].source = source
                    else:
                        # Add new task
                        next_run = datetime.now(timezone.utc) + timedelta(seconds=30)
                        self.tasks[source_id] = ScheduledTask(
                            source=source,
                            next_run=next_run
                        )
                        logger.info(f"Added new task for source: {source.name}")
            
            finally:
                db.close()
                
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error reloading sources: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, any]:
        """Get scheduler status"""
        return {
            'running': self.running,
            'total_sources': len(self.tasks),
            'running_collections': sum(1 for task in self.tasks.values() if task.running),
            'next_runs': {
                str(source_id): task.next_run.isoformat()
                for source_id, task in self.tasks.items()
            },
            'errors': {
                str(source_id): task.last_error
                for source_id, task in self.tasks.items()
                if task.last_error
            }
        }

async def main():
    """Main scheduler entry point"""
    logging.basicConfig(
        level=getattr(logging, config.logging.level),
        format=config.logging.format
    )
    
    scheduler = CollectionScheduler()
    
    try:
        await scheduler.start()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        await scheduler.stop()

if __name__ == "__main__":
    asyncio.run(main())
