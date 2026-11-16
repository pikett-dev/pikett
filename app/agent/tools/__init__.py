from collections.abc import Callable
from datetime import datetime

from app.agent.masking import Masker
from app.agent.ports import Sources
from app.agent.tools.changes import change_tools
from app.agent.tools.definitions import victoria_tools
from app.agent.tools.registry import Tool, ToolRegistry, ToolResult
from app.oncall import utcnow

__all__ = ["Tool", "ToolRegistry", "ToolResult", "build_registry"]


def build_registry(sources: Sources, masker: Masker, *, clock: Callable[[], datetime] = utcnow) -> ToolRegistry:
    """One registry and one `Masker` per analysis; the masker remembers every value it replaced."""
    tools = victoria_tools(sources, clock)
    if sources.changes is not None:  # without Coolify there is nothing to read changes from
        tools += change_tools(sources.changes, clock)
    return ToolRegistry(tools, masker)
