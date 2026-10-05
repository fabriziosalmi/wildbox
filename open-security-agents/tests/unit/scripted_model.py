"""A scripted chat model for running the production agent without a model API.

The agent makes two kinds of call: the tool-calling turns of the
investigation, which this answers from ``responses`` in order, and the
structured report, which it answers with ``report``. A failed analysis is no
longer turned into a report (#717), so a test that runs the whole agent needs
a model that can produce one; ``report`` set to an exception makes that call
fail instead.
"""

from typing import Any, ClassVar, List

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.runnables import RunnableLambda

SCRIPTED_REPORT = {
    "verdict": "Benign",
    "confidence": 0.5,
    "executive_summary": "Scripted report.",
    "evidence": [],
    "recommended_actions": [],
}


class ScriptedModel(FakeMessagesListChatModel):
    """Tool-calling turns from ``responses``; the report from ``report``."""

    # The names of the tools the agent last bound a model to.
    bound: ClassVar[List[str]] = []
    # The structured report's fields, or an exception for that call to raise.
    report: Any = None

    def bind_tools(self, tools, **kwargs):
        type(self).bound = [tool.name for tool in tools]
        return self

    def with_structured_output(self, schema, **kwargs):
        def produce(_messages):
            if isinstance(self.report, BaseException):
                raise self.report
            return schema(**(self.report or SCRIPTED_REPORT))

        return RunnableLambda(produce)
