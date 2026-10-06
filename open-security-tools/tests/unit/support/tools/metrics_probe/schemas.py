"""Input and output of the probe tool."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class MetricsProbeInput(BaseModel):
    behaviour: Literal[
        "return",
        "raise",
        "quote",
        "crash",
        "crash_quote",
        "fault_before",
        "sleep",
        "hang",
        "touch",
        "die",
        "die_once",
        "sleep_once",
    ] = "return"
    seconds: float = Field(default=0.0, ge=0, le=120)
    # A file the probe writes when it starts, for the behaviours that must
    # know whether the task was started before, and for the tests to see
    # whether, and how often, the tool ran.
    marker: str = ""
    # A file the probe adds a line to each time the tool is called.
    starts: str = ""

    @model_validator(mode="after")
    def _fault_before_the_tool(self):
        # The task fails before its tool is called, with an error that is
        # none of the five classes it answers "failed" for and that repeats
        # the input: Celery retries the task, then fails it.
        if self.behaviour == "fault_before":
            raise RuntimeError(f"the checks broke over {self.marker!r}")
        return self


class MetricsProbeOutput(BaseModel):
    success: bool
