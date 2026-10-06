"""Input and output of the probe tool."""

from typing import Literal

from pydantic import BaseModel, Field


class MetricsProbeInput(BaseModel):
    behaviour: Literal[
        "return",
        "raise",
        "quote",
        "crash",
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


class MetricsProbeOutput(BaseModel):
    success: bool
