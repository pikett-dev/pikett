import hmac
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import Field

from app.incidents.schemas import MAX_ALERTS_PER_REQUEST, AlertIn
from app.incidents.service import IncidentService

log = logging.getLogger(__name__)
router = APIRouter()


def _authorize(request: Request, authorization: str = Header(default="")) -> None:
    """With ALERT_TOKEN set, only `Authorization: Bearer <token>` passes. The presented value is never logged."""
    token: str | None = request.app.state.alert_token
    if token is None:
        return
    if not hmac.compare_digest(authorization.encode(), f"Bearer {token}".encode()):
        client = request.client.host if request.client else "unknown"
        log.warning("alert webhook: rejected a request from %s (missing or wrong bearer token)", client)
        raise HTTPException(401, "wrong or missing token", headers={"WWW-Authenticate": "Bearer"})


@router.post(
    "/api/v2/alerts", dependencies=[Depends(_authorize)]
)  # a dependency runs after the body is parsed but before it is validated
async def receive_alerts(
    alerts: Annotated[list[AlertIn], Field(max_length=MAX_ALERTS_PER_REQUEST)],
    request: Request,
) -> dict[str, str]:
    """Alertmanager v2 endpoint that vmalert posts firing and resolved alerts to."""
    service: IncidentService = request.app.state.service
    await service.handle_alerts(alerts)
    return {}
