import hmac

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.actions.service import ActionError, ActionService

router = APIRouter(prefix="/api/v1/runner")


class PollIn(BaseModel):
    version: str = Field(default="", max_length=64)
    catalog: str = Field(default="", max_length=64)


class ResultIn(BaseModel):
    status: str = Field(max_length=16)
    summary: str = Field(default="", max_length=20000)


def _authenticate(request: Request, authorization: str) -> tuple[ActionService, str]:
    """The service and the server whose runner this is. Only the token of a server counts for that server."""
    actions: ActionService = request.app.state.action_jobs
    tokens: dict[str, str] = request.app.state.runner_tokens
    if not tokens:
        raise HTTPException(503, "the runner API is not configured (RUNNER_TOKENS)")
    presented = authorization.encode()
    host = None
    for name, token in tokens.items():  # every token is compared, so the time does not tell which one was close
        if hmac.compare_digest(presented, f"Bearer {token}".encode()):
            host = name
    if host is None:
        raise HTTPException(401, "wrong token")
    return actions, host


@router.post("/poll")
async def poll(request: Request, body: PollIn = PollIn(), authorization: str = Header(default="")) -> Response:
    """The runner asks for work. Every poll is a heartbeat; the answer is the next approved job, signed, or 204."""
    actions, host = _authenticate(request, authorization)
    await actions.heartbeat(host, body.version, body.catalog)
    try:
        envelope = await actions.claim(host)
    except ActionError as error:
        raise HTTPException(503, str(error)) from error
    if envelope is None:
        return Response(status_code=204)
    return JSONResponse(envelope)


@router.post("/jobs/{action_id}/started", status_code=204)
async def started(action_id: str, request: Request, authorization: str = Header(default="")) -> None:
    actions, host = _authenticate(request, authorization)
    try:
        await actions.started(host, action_id)
    except ActionError as error:
        raise HTTPException(409, str(error)) from error


@router.post("/jobs/{action_id}/result", status_code=204)
async def result(action_id: str, body: ResultIn, request: Request, authorization: str = Header(default="")) -> None:
    actions, host = _authenticate(request, authorization)
    try:
        await actions.finished(host, action_id, body.status, body.summary)
    except ActionError as error:
        raise HTTPException(409, str(error)) from error
