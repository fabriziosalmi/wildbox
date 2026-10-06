"""The stop's time limits, in the order they are spent (#765, #777).

Whoever stops the sensor gives it a time to end in (Compose:
``stop_grace_period``, 30 seconds in the repository's files) and kills it
after that. Every wait of the stop has a limit, and the limits add up to
less: these four, and ``START_ABORT_SECONDS`` and ``EXIT_SECONDS`` in
``main.py``, are 28 seconds. The line the exit limit logs has a limit too
(``EXIT_LOG_SECONDS`` in ``main.py``, 1 second, #788): 29 with a log that
does not answer, which leaves one for Docker to notice the exit.
``tests/unit/test_stop_time_limits.py`` runs the worst case and holds the
sum against every Compose file that runs the sensor.

They used to be 15, 2 and 15 seconds, 32 against the 30 the sensor was given,
and the last writes had no limit at all (#777): a write of the positions
stuck in its worker thread, with a data directory that does not answer, was
waited for by the event loop itself, and nothing ended the process.

The collectors import their part from here, and the agent the rest: a
collector cannot import the agent, which imports it.
"""

# Seconds the collectors, and the local API, get to stop: the tasks that
# read are cancelled, a command that follows a log is ended, a query in
# progress is killed, a request in flight is given up.
COLLECTORS_STOP_SECONDS = 8.0
# Seconds the events already collected get to reach the sender when the
# sensor stops, before the pipeline is stopped under them.
QUEUE_DRAIN_SECONDS = 2.0
# Seconds the processor and the sender get to stop. The sender spends up to
# data_forwarder.STOP_FLUSH_SECONDS of them on its last batches; the rest is
# for closing its connections.
PIPELINE_STOP_SECONDS = 12.0
# Seconds the log positions and the file monitor's baseline get to be
# written once more, side by side, for what the last batches delivered. A
# write that has not ended by then is left to its worker thread: the sensor
# says what was not written and goes on to its end, where main.py's
# EXIT_SECONDS is the last such a thread has.
LAST_WRITES_SECONDS = 2.0

# What a collector waits for inside COLLECTORS_STOP_SECONDS. Each is a
# quarter of it, so that the longest chain of them (the log forwarder: a
# command asked to end, then killed, then the positions written) is three
# quarters, and a collector that uses all of its own still stops before the
# agent stops waiting for it. They were numbers of their own (#777): 10
# seconds for a killed osqueryi, 5 and then 5 more for a command that follows
# a log, 60 and then 60 more for a request to the local API, each alone or
# together more than the 8 the collectors have. The agent's limit held, and
# cut the collector's own tidying up short: a command left running, a pipe
# left open.
#
# Seconds a child process gets to end after it is asked to (SIGTERM),
# before it is killed.
CHILD_TERM_SECONDS = COLLECTORS_STOP_SECONDS / 4
# Seconds a killed child gets to be gone: reaped, and its output closed.
# After that its pipes are closed on the sensor's side.
CHILD_KILL_SECONDS = COLLECTORS_STOP_SECONDS / 4
# Seconds a collector's own write of its state gets when it stops. The
# agent has it written once more at the end (LAST_WRITES_SECONDS).
STATE_WRITE_SECONDS = COLLECTORS_STOP_SECONDS / 4
# Seconds the local API gives a request in flight to finish, and then as
# many again to end once it is cancelled: aiohttp spends its shutdown
# timeout twice.
API_SHUTDOWN_SECONDS = COLLECTORS_STOP_SECONDS / 4
