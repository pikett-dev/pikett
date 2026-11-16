"""Errors the agent tools raise on purpose. The registry turns both into a tool result the agent can read."""


class ToolInputError(Exception):
    """The agent passed arguments the tool does not accept (bad time, too large a window, unknown value)."""


class SourceError(Exception):
    """A telemetry backend rejected the request or could not be reached. The message is safe to show the agent."""
