"""The memory subsystem's two seams into the agent loop.

Everything else in the memory layer is self-contained; these are the only two
touch points, kept together so the tool nodes and the orchestrator reference one
implementation instead of each growing their own:

* `capture_tool_result` - the auto-update hook. Called from
  `orchestrator_helpers/nodes/execute_tool_node.py` and `execute_plan_node.py`
  once a tool's outcome is final, i.e. after the embedded-error detection and the
  error classification have run. Both nodes carry the same tail, the same reason
  the embedded-error and error-class logic is mirrored between them.
* `register_memory_tools` - attach the memory tools to a
  `PhaseAwareToolExecutor`. Called from the orchestrator, where every other tool
  surface (MCP tools, web_search, shodan, tradecraft) is wired.

Both are fail-open. Memory is an enhancement to the agent's work, and a memory
bug must never turn a working tool call into a failed turn.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def capture_tool_result(
    *,
    tool_name: str,
    phase: str = "",
    success: bool = False,
    output: str = "",
    error: str = "",
) -> bool:
    """Record one finished tool call in project memory. Returns True if stored."""
    try:
        from agent_context import current_project_id, current_session_id

        project_id = current_project_id.get()
        if not project_id:
            return False
        # fs_*/job_* are workspace housekeeping and would drown the real record;
        # a memory tool observing itself is the same problem. `auto_update`
        # enforces this too - it is the guard for every other caller.
        if tool_name.startswith(("fs_", "job_", "memory_")):
            return False

        from memory.auto_update import auto_update_tool_result

        return auto_update_tool_result(
            project_id=project_id,
            session_id=current_session_id.get(),
            tool_name=tool_name,
            phase=phase,
            success=bool(success),
            output=output or "",
            error=error or "",
        ) is not None
    except Exception as e:  # noqa: BLE001 - never break a tool call
        logger.warning(f"memory capture skipped for {tool_name}: {e}")
        return False


def register_memory_tools(tool_executor) -> int:
    """Attach the memory tools to `tool_executor`. Returns how many were added."""
    try:
        from memory_tools import build_memory_tools

        tools = build_memory_tools()
        tool_executor._all_tools.update(tools)  # noqa: SLF001 - executor-owned table
        return len(tools)
    except Exception as e:  # noqa: BLE001 - a broken store must not cost the agent its tools
        logger.warning(f"Failed to register memory tools: {e}")
        return 0


def session_context_text() -> str:
    """What this project's memory wants injected when a session starts.

    Returns "" when memory is off, empty, or broken, so the caller can prepend it
    unconditionally.
    """
    try:
        from agent_context import current_project_id
        from memory.auto_update import get_updater

        project_id = current_project_id.get()
        if not project_id:
            return ""
        return get_updater().session_start_text(project_id)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"memory session context unavailable: {e}")
        return ""


__all__ = ["capture_tool_result", "register_memory_tools", "session_context_text"]
