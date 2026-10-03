"""
API connector for Open Security Responder

Runs security tools in the tools service (open-security-tools), as the user
who started the run.

The routes and bodies are the tools service's own (#616):

- ``POST /api/tools/{tool}`` runs a tool and answers its result. The body is
  the tool's input, validated by the tool's input schema
  (app/api/router.py, register_tool_endpoint). It used to be wrapped in a
  ``params`` envelope and posted to ``/api/v1/tools/{tool}/execute``, a
  route the service does not serve.
- ``POST /api/tools/{tool}/async`` queues a tool and answers a task, which
  belongs to the caller (app/api/async_router.py).
- ``GET`` and ``DELETE /api/tasks/{task_id}`` read and cancel such a task;
  only its owner can.

The responder calls the service directly on the internal network, with the
gateway's identity headers and secret (see app/caller.py), as the agents
service does.
"""

import re
from typing import Any, Dict

import httpx

from .base import BaseConnector, ConnectorError, call_service
from ..config import settings

# A tool name or a task id becomes part of a URL path. Only names and ids of
# the shapes the tools service issues are sent, so a rendered template cannot
# steer a call to another route.
_TOOL_NAME = re.compile(r"^[a-z0-9_]{1,64}$")
_TASK_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def tool_name_path(tool_name: Any) -> str:
    """``tool_name`` checked for use in a URL path, or ConnectorError."""
    if not isinstance(tool_name, str) or not _TOOL_NAME.match(tool_name):
        raise ConnectorError(
            f"Invalid tool name {tool_name!r}: lowercase letters, digits and "
            "underscores only"
        )
    return tool_name


def task_id_path(task_id: Any) -> str:
    """``task_id`` checked for use in a URL path, or ConnectorError."""
    if not isinstance(task_id, str) or not _TASK_ID.match(task_id):
        raise ConnectorError(f"Invalid task id {task_id!r}: a UUID is expected")
    return task_id


def run_tool_request(
    client: httpx.Client,
    api_url: str,
    tool_name: str,
    params: Dict[str, Any],
    async_execution: bool = False,
) -> Dict[str, Any]:
    """Run a tool, or queue it when ``async_execution``; see the module doc."""
    name = tool_name_path(tool_name)
    if not isinstance(params, dict):
        raise ConnectorError(
            f"The parameters of tool '{name}' must be a mapping, not "
            f"{type(params).__name__}"
        )
    if async_execution:
        return call_service(
            client,
            "POST",
            f"{api_url}/api/tools/{name}/async",
            what=f"queue tool '{name}'",
            json=params,
            expect=(202,),
        )
    return call_service(
        client,
        "POST",
        f"{api_url}/api/tools/{name}",
        what=f"run tool '{name}'",
        json=params,
    )


class ApiConnector(BaseConnector):
    """Connector for Open Security API service operations"""

    def __init__(self):
        super().__init__("api", {"api_url": settings.wildbox_api_url})
        # No retries: a tool can have side effects, and a call is sent once.
        self.client = httpx.Client(timeout=60.0)  # Longer timeout for tool execution
        self.logger.info("Initialized API connector")

    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the API connector"""
        return {
            "run_tool": "Run a security tool and return its result, or queue it (async_execution) and return the task",
            "list_tools": "List available security tools",
            "get_tool_info": "Get information about a specific tool, with its input and output schemas",
            "cancel_execution": "Cancel a queued tool task the run's caller owns",
            "get_execution_status": "Get the status and result of a queued tool task the run's caller owns"
        }

    def run_tool(
        self, tool_name: str, params: Dict[str, Any], async_execution: bool = False
    ) -> Dict[str, Any]:
        """
        Run a security tool as the run's caller.

        Args:
            tool_name: Name of the tool, as the tools service lists it
            params: The tool's input, as its input schema defines it
            async_execution: Queue the tool instead of waiting for it

        Returns:
            The tool's result; or, when queued, the task (``task_id``,
            ``status_url``) that get_execution_status reads.
        """
        return run_tool_request(
            self.client, self.config["api_url"], tool_name, params, async_execution
        )

    def list_tools(self) -> Dict[str, Any]:
        """
        List available security tools

        Returns:
            ``{"tools": [...]}``: the tools service's list, under one key
        """
        tools = call_service(
            self.client,
            "GET",
            f"{self.config['api_url']}/api/tools",
            what="list tools",
        )
        return {"tools": tools}

    def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """
        Get information about a specific tool

        Args:
            tool_name: Name of the tool

        Returns:
            Tool information, with its input and output schemas
        """
        name = tool_name_path(tool_name)
        return call_service(
            self.client,
            "GET",
            f"{self.config['api_url']}/api/tools/{name}/info",
            what=f"get the information of tool '{name}'",
        )

    def cancel_execution(self, execution_id: str) -> Dict[str, Any]:
        """
        Cancel a queued tool task

        Args:
            execution_id: The task id run_tool returned when queuing

        Returns:
            Cancellation result
        """
        task_id = task_id_path(execution_id)
        return call_service(
            self.client,
            "DELETE",
            f"{self.config['api_url']}/api/tasks/{task_id}",
            what=f"cancel task '{task_id}'",
        )

    def get_execution_status(self, execution_id: str) -> Dict[str, Any]:
        """
        Get the status of a queued tool task

        Args:
            execution_id: The task id run_tool returned when queuing

        Returns:
            Task status, and its result once finished
        """
        task_id = task_id_path(execution_id)
        return call_service(
            self.client,
            "GET",
            f"{self.config['api_url']}/api/tasks/{task_id}",
            what=f"read task '{task_id}'",
        )

    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
