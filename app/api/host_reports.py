import hmac

from fastapi import APIRouter, Header, HTTPException, Request

from app.security.hostreports import HostReportIn
from app.security.service import SecurityService

router = APIRouter()


@router.post("/api/v1/host-reports", status_code=202)
async def receive_host_report(
    report: HostReportIn, request: Request, authorization: str = Header(default="")
) -> dict[str, str]:
    """The collector on each server posts what it read (deploy/host-agent/ops-collect.py)."""
    tokens: dict[str, str] = request.app.state.host_report_tokens
    security: SecurityService | None = request.app.state.security
    if not tokens or security is None:
        raise HTTPException(503, "host reports are not configured (HOST_REPORT_TOKENS)")
    # Only the token of the server the report names counts, so one server cannot report for the other.
    token = tokens.get(report.host)
    if token is None or not hmac.compare_digest(authorization.encode(), f"Bearer {token}".encode()):
        raise HTTPException(401, "wrong token for this host")
    if not security.knows(report.kind):
        raise HTTPException(422, f"unknown report kind {report.kind}")
    await security.ingest(report)
    return {}
