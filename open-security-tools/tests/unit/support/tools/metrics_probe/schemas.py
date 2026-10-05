"""Input and output of the probe tool."""

from typing import Literal

from pydantic import BaseModel, Field


class MetricsProbeInput(BaseModel):
    behaviour: Literal["return", "raise", "crash", "sleep", "hang", "die_once"] = (
        "return"
    )
    seconds: float = Field(default=0.0, ge=0, le=120)
    # For "die_once": a file the first attempt creates before it dies, so
    # that the second one knows it is the second.
    marker: str = ""


class MetricsProbeOutput(BaseModel):
    success: bool
