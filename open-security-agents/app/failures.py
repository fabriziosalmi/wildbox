"""Why an analysis failed, in words fit for the user who submitted it (#717).

An analysis that cannot run, or cannot finish, is a failed task. It used to
be reported as a completed one: the agent answered a report with the verdict
"Informational" and confidence 0 when it raised, the worker returned another
when the task body raised, and a report that could not be generated was
replaced by a verdict picked out of the narrative with a regex and one
evidence item per tool that no tool had reported. A client could not tell
any of them from an analysis that had run.

Now a failure raises AnalysisFailed, the worker records its code with the
task and lets Celery record FAILURE, and the API answers ``status: failed``
with the code's reason. The reason says which stage failed and nothing about
the server's internals; the exception that caused it goes to the log.
"""

from typing import Optional

NOT_CONFIGURED = "not_configured"
MODEL_UNAVAILABLE = "model_unavailable"
TIMED_OUT = "timed_out"
REPORT_FAILED = "report_failed"
NO_CALLER = "no_caller"
INTERNAL = "internal"

REASONS = {
    NOT_CONFIGURED: (
        "AI analysis is not configured on this server: no model API key is set."
    ),
    MODEL_UNAVAILABLE: (
        "The AI model could not be reached, or refused the request. "
        "Nothing was analyzed."
    ),
    TIMED_OUT: "The analysis did not finish within its time limit.",
    REPORT_FAILED: (
        "The investigation ran, but its report could not be generated. "
        "No verdict was produced."
    ),
    NO_CALLER: "The analysis had no user identity to act for and was not run.",
    INTERNAL: "The analysis failed because of an internal error.",
}

# What the API answered for every failure before the cause was recorded, and
# still answers for a task that failed without one (a worker killed at its
# hard time limit, a record that has expired).
GENERIC_REASON = "Analysis failed. Please retry or contact support."


class AnalysisFailed(Exception):
    """An analysis that produced no report.

    ``code`` is one of the constants above. The exception carries the code
    alone, so that Celery can store it and build it again from its argument;
    the cause is chained (``raise AnalysisFailed(code) from error``) for the
    worker's log.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in REASONS else INTERNAL

    @property
    def reason(self) -> str:
        return REASONS[self.code]


def reason_for(code: Optional[object]) -> str:
    """The reason to show for a failed task's recorded ``code``.

    ``code`` is what Redis holds for the task: bytes, a string, or nothing.
    An unknown or missing code gets the generic reason, never the raw value.
    """
    if isinstance(code, bytes):
        code = code.decode("utf-8", "replace")
    return (
        REASONS.get(code, GENERIC_REASON) if isinstance(code, str) else GENERIC_REASON
    )
