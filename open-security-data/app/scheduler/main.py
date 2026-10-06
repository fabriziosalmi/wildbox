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

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.config import get_config
from app.models import Source, CollectionRun
from app.utils.database import get_db_session, wait_for_schema
from app.utils.log_safety import code_path, describe_database_error, describe_error
from app.collectors import CollectorRegistry, NoCollector
# Import collectors to register them
import app.collectors.sources  # noqa: F401

logger = logging.getLogger(__name__)
config = get_config()

# Seconds between two looks at what is due, and the seconds the loop waits
# after a pass that failed before it makes the next.
TICK_SECONDS = 60.0
RETRY_SECONDS = 60.0

# A source is disabled when this many of its collections have failed one
# after the other (CollectionScheduler._count_failure).
MAX_FAILURES_IN_A_ROW = 10
# The errors of a database that cannot be reached: the data service's own
# failure, not a source's. By name: a collector's result carries the class of
# its error as a name (error_details["exception_type"]).
DATABASE_AWAY = ("OperationalError", "InterfaceError")
# How a run that failed is recorded (collection_runs.status).
FAILED_RUNS = ("failed", "timeout")


def _described(error: BaseException) -> str:
    """What failed, by its class: never the text of the error.

    The text of a database error holds what the database wrote, values of
    the refused row included, and the text of an HTTP error ends with the
    URL, which for a feed can hold its key (#755, #778). A database error is
    said with its driver's class and SQLSTATE, any other with its class and
    the HTTP status when it has one.
    """
    if isinstance(error, SQLAlchemyError):
        return describe_database_error(error)
    return describe_error(error)


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

        # Wait for the schema instead of creating it. The scheduler shares the
        # data service's database and can start before the API has migrated it,
        # which otherwise causes a transient "relation sources does not exist"
        # on a cold start. It must not migrate itself: two alembic runs against
        # one database race on alembic_version, and create_tables() here would
        # produce a schema no migration ever corrects (WILDBO-DOM-01).
        wait_for_schema()

        # Load sources and create initial schedule
        await self._load_sources()
        
        # Start main scheduler loop
        await self._scheduler_loop()
    
    async def stop(self):
        """Stop the scheduler"""
        logger.info("Stopping collection scheduler")
        self.running = False
        self._shutdown_event.set()
    
    @staticmethod
    def _collectable(db, sources: List[Source]) -> List[Source]:
        """The sources that can be collected; the others are disabled.

        A source nothing can collect is not scheduled, and is no longer
        offered as an enabled one (#665, #755): its row says why. Such rows
        exist where `manage.py sources add-defaults` or scripts/init_feeds.py
        ran before this release: both created sources of types that had no
        collector that could run.
        """
        collectable = []
        for source in sources:
            if CollectorRegistry.can_collect(source.source_type):
                collectable.append(source)
                continue
            reason = str(NoCollector(str(source.source_type or "").lower()))
            logger.warning(f"Source '{source.name}' is disabled: {reason}")
            source.enabled = False
            source.status = 'inactive'
            source.last_error = reason
        if len(collectable) != len(sources):
            db.commit()
        return collectable

    def _sources_to_schedule(self, db) -> List[Source]:
        """The sources the scheduler runs: enabled, and collectable (#778).

        One rule, for the start and for the periodic reload. They had two:
        the start left out a source whose status was 'error', and the
        reload, up to ten minutes later, scheduled it to run in thirty
        seconds. So a source in error was collected after every restart all
        the same, later, and whether the scheduler ran it depended on how
        long the scheduler had been up.

        The status is not what stops a failing source. One that fails keeps
        its task and is tried again at its own interval (_run_collection),
        and is disabled when ten of its collections in a row have failed
        (_count_failure): a disabled source is not scheduled, here as
        before.
        """
        enabled = db.query(Source).filter(Source.enabled == True).all()
        return self._collectable(db, enabled)

    @staticmethod
    def _count_failure(db_source: Source) -> None:
        """One more collection of this source has failed.

        The rule, one for every way a collection can fail (#788):

        - a collection that fails is counted with its source: one whose
          collector returns ``failed`` or ``timeout``, one the scheduler's
          own time limit ends, one that raises;
        - a collection that completes sets the count back to 0;
        - a collection that was rate limited is neither: the count stays;
        - at MAX_FAILURES_IN_A_ROW the source is disabled, and stays so
          until an operator enables it, which starts its count again
          (``manage.py sources enable``).

        A failure of the data service's own database (DATABASE_AWAY) says
        nothing about the source and is not counted: ten minutes of a
        database that drops connections would disable every source.

        There were two rules. A collection that raised or timed out was
        counted and disabled its source at ten; one whose collector
        returned ``failed``, the usual way for a feed to fail, was counted
        and never disabled anything; and no success ever set the count
        back, so "ten" meant ten since the row was written.
        """
        db_source.error_count = (db_source.error_count or 0) + 1
        db_source.status = 'error'
        if db_source.error_count >= MAX_FAILURES_IN_A_ROW:
            logger.warning(
                "Disabling source %s: its last %d collections have failed",
                db_source.name, db_source.error_count,
            )
            db_source.enabled = False

    @staticmethod
    def _correct_counts(db, sources: List[Source]) -> None:
        """At start: no source counts more failures than its runs show.

        A count written by a release before #788 is of every failure the
        source ever had, since no success set it back. Left as it is, one
        more failure would disable a source that had failed nine times in
        a year. The runs are on record (collection_runs): when one of the
        source's last runs completed, the count is at most the runs that
        failed after it. A count that the record does not contradict is
        left alone, and so is a source with no completed run among them.
        """
        corrected = False
        for source in sources:
            if not source.error_count:
                continue
            statuses = [
                status
                for (status,) in db.query(CollectionRun.status)
                .filter(CollectionRun.source_id == source.id)
                .order_by(CollectionRun.started_at.desc())
                .limit(MAX_FAILURES_IN_A_ROW)
            ]
            if 'completed' not in statuses:
                continue
            since = statuses[:statuses.index('completed')]
            in_a_row = sum(1 for status in since if status in FAILED_RUNS)
            if in_a_row < source.error_count:
                logger.info(
                    "Source '%s' counted %d errors, and %d of its collections "
                    "have failed since the last one that completed: its "
                    "count is %d",
                    source.name, source.error_count, in_a_row, in_a_row,
                )
                source.error_count = in_a_row
                corrected = True
        if corrected:
            db.commit()

    async def _load_sources(self):
        """Schedule the sources at start, each from its last collection"""
        db = get_db_session()
        try:
            sources = self._sources_to_schedule(db)
            self._correct_counts(db, sources)

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
    
    @staticmethod
    def _reload_due(current_time: datetime) -> bool:
        """Reload sources periodically (every 10 minutes)"""
        return current_time.minute % 10 == 0

    async def _scheduler_loop(self):
        """Main scheduler loop.

        No error of a pass ends it (#788). It caught five builtin classes,
        and a database error is none of them: the periodic reload of the
        sources, asked of a PostgreSQL that was restarting, raised
        OperationalError through this loop and out of the process, which
        ended with status 1 and a traceback. A collection that raised the
        same error did not even do that: asyncio.gather kept the exception
        as a result nobody read, and the collection failed without a line
        in the log.
        """
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

                    # Run collections concurrently. Each says its own
                    # failure (_run_collection); what one raises all the
                    # same is said here, once, and is not the others'.
                    outcomes = await asyncio.gather(
                        *(self._run_collection(task) for task in ready_tasks),
                        return_exceptions=True,
                    )
                    for task, outcome in zip(ready_tasks, outcomes):
                        if isinstance(outcome, Exception):
                            self._say_failure(task.source.name, outcome)

                # Check for shutdown
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=TICK_SECONDS)
                    break  # Shutdown requested
                except asyncio.TimeoutError:
                    pass  # Continue normal operation

                if self._reload_due(current_time):
                    await self._reload_sources()

            except Exception as e:
                logger.error(
                    "Error in scheduler loop: %s\n%s", _described(e), code_path(e)
                )
                # Wait before the next pass; a stop asked for meanwhile is
                # obeyed, where the sleep that was here ran to its end.
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=RETRY_SECONDS)
                    break
                except asyncio.TimeoutError:
                    pass

    @staticmethod
    def _say_failure(name: str, error: BaseException) -> None:
        """One line for a collection that raised: the class of the error
        and the frames it went through, not its text (see _described)."""
        logger.error(
            "Collection error for source %s: %s\n%s",
            name, _described(error), code_path(error),
        )

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
                        db_source.error_count = 0
                    elif result.status.value == 'rate_limited':
                        db_source.status = 'rate_limited'
                        db_source.last_error = result.error_message
                    else:
                        db_source.status = 'error'
                        db_source.last_error = result.error_message
                        failed_on = (result.error_details or {}).get("exception_type")
                        if failed_on not in DATABASE_AWAY:
                            self._count_failure(db_source)
                    
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
            await self._record_error(source, "Collection timeout")

        except Exception as e:
            # Whatever it is, and said once. Five builtin classes were
            # caught here: any other error, a database error among them,
            # left through asyncio.gather without a line in the log (#788).
            #
            # What failed, by its class, and the HTTP status when the error
            # has one: not its text. The text was stored as the source's
            # last_error, which `manage.py sources list` prints, and logged
            # with a traceback that ends with it; the text of an error raised
            # while a feed is fetched can hold the feed's URL, and with it
            # its key. The collector's own errors have been stored this way
            # since #755 (describe_error); the ones that reach the scheduler
            # were left (#788).
            described = _described(e)
            self._say_failure(source.name, e)
            task.last_error = described
            await self._record_error(
                source, described, counted=type(e).__name__ not in DATABASE_AWAY
            )

        finally:
            task.running = False

    async def _record_error(
        self, source: Source, error_message: str, counted: bool = True
    ):
        """Count a failed collection with its source, if the database takes
        it. When it does not, that is said, and the scheduler goes on: the
        error that failed the collection is, as a rule, the same database's."""
        try:
            await self._handle_collection_error(source, error_message, counted)
        except SQLAlchemyError as e:
            logger.error(
                "The failed collection of source %s could not be recorded: %s",
                source.name, describe_database_error(e),
            )

    async def _handle_collection_error(
        self, source: Source, error_message: str, counted: bool = True
    ):
        """Record a collection that raised or timed out; ``counted`` unless
        the failure was the database's own (_count_failure)."""
        db = get_db_session()
        try:
            db_source = db.query(Source).filter(Source.id == source.id).first()
            if db_source:
                db_source.last_error = error_message
                db_source.status = 'error'
                if counted:
                    self._count_failure(db_source)

                db.commit()
        finally:
            db.close()
    
    async def _reload_sources(self):
        """Reload sources from database"""
        try:
            logger.debug("Reloading sources")
            
            db = get_db_session()
            try:
                sources = self._sources_to_schedule(db)
                
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
                
        except Exception as e:
            # The tasks stay as they are, and the next reload asks again. A
            # database error was not among the five classes caught here: it
            # went through the loop and ended the process (#788).
            logger.error("Error reloading sources: %s\n%s", _described(e), code_path(e))
    
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
