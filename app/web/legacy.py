"""The German paths of the first release. Old Slack messages link to them, so they answer 301 to the new ones."""

from urllib.parse import urlencode

from fastapi import APIRouter, Path, Request
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/ops", include_in_schema=False)

# Query parameter names of the history page that changed with the English paths. The values were English already.
RENAMED_PARAMS = {"art": "kind", "zeitraum": "period", "server": "host"}


def _moved(request: Request, path: str) -> RedirectResponse:
    """301 to the new path, with the query string: renamed parameters mapped, everything else kept."""
    pairs = request.query_params.multi_items()
    present = {key for key, _ in pairs}
    # An old name is dropped when the new one is there as well, so a parameter never appears twice.
    query = [(RENAMED_PARAMS.get(key, key), value) for key, value in pairs if RENAMED_PARAMS.get(key) not in present]
    return RedirectResponse(path + (f"?{urlencode(query)}" if query else ""), status_code=301)


@router.get("/verlauf")
async def history(request: Request) -> RedirectResponse:
    return _moved(request, "/ops/history")


@router.get("/hilfe")
async def help_page(request: Request) -> RedirectResponse:
    return _moved(request, "/ops/help")


@router.get("/aktionen/{job_id}")
async def action(request: Request, job_id: int = Path(ge=1, le=2**63 - 1)) -> RedirectResponse:
    return _moved(request, f"/ops/actions/{job_id}")
