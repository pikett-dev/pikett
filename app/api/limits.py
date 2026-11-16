"""Request body size limits for the API routes, as a pure ASGI middleware.

A limit is checked twice: against `Content-Length` before anything is read, and while the body streams in, because
a client can send chunked data without a length or lie about it. FastAPI parses a whole body before any handler
runs, so without this a single request could fill the memory of the (256 MB) service.
"""

import json
from collections.abc import Mapping

from starlette.types import ASGIApp, Message, Receive, Scope, Send

ALERTS_LIMIT = 1024 * 1024
# The trivy report is the largest kind; the collector caps it (deploy/host-agent/ops-collect.py), the other kinds
# stay under about 0.5 MB.
HOST_REPORTS_LIMIT = 4 * 1024 * 1024
# Runner calls carry a few small fields (ResultIn: a summary of at most 20000 characters, which JSON escapes can
# stretch to 6 bytes each).
RUNNER_LIMIT = 256 * 1024
# Every other path below /api/ (a route added later) is bounded as well.
API_DEFAULT_LIMIT = 1024 * 1024

DEFAULT_LIMITS: Mapping[str, int] = {
    "/api/v2/alerts": ALERTS_LIMIT,
    "/api/v1/host-reports": HOST_REPORTS_LIMIT,
    "/api/v1/runner/": RUNNER_LIMIT,
    "/api/": API_DEFAULT_LIMIT,  # last: the first matching entry wins
}


class _TooLarge(BaseException):  # noqa: N818 (a signal, not an error)
    """Raised from `receive` once the stream passes the limit.

    A BaseException on purpose: FastAPI turns every Exception raised while it reads the body into a 400, so the
    limit would never reach this middleware as a 413.
    """


class BodyLimit:
    """Answers 413 for a request body over the limit of its path. Paths without a limit pass through."""

    def __init__(self, app: ASGIApp, limits: Mapping[str, int] = DEFAULT_LIMITS) -> None:
        self.app = app
        self.limits = limits

    def _limit_for(self, path: str) -> int | None:
        for prefix, limit in self.limits.items():
            if path == prefix or (prefix.endswith("/") and path.startswith(prefix)):
                return limit
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self._limit_for(scope["path"]) if scope["type"] == "http" else None
        if limit is None:
            await self.app(scope, receive, send)
            return

        # Every Content-Length header counts, not only the last one of a request that sends several.
        if any(
            name == b"content-length" and value.isdigit() and int(value) > limit for name, value in scope["headers"]
        ):
            await _reject(send, limit)
            return

        received = 0
        started = False

        async def counted_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except _TooLarge:
            if started:  # the answer is already on its way, the connection just ends
                raise
            await _reject(send, limit)


async def _reject(send: Send, limit: int) -> None:
    payload = json.dumps({"detail": f"request body too large (limit {limit} bytes)"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": payload})
