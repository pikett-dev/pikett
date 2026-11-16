"""Reboot jobs from approvals: the Slack reboot approval becomes a job for the runner."""

import logging
from collections.abc import Callable
from datetime import datetime

from app.actions.service import ActionError, ActionService, DuplicateJob
from app.security.reboot import RebootQuestions

log = logging.getLogger(__name__)

SYSTEM = "system"


class RebootJobs:
    """An approved reboot (the Slack reboot button) becomes a job when its time has come; once per approval."""

    def __init__(self, reboots: RebootQuestions, jobs: ActionService, clock: Callable[[], datetime]) -> None:
        self._reboots, self._jobs, self._clock = reboots, jobs, clock

    async def tick(self) -> None:
        now = self._clock()
        for host in sorted(self._jobs.hosts):
            request = await self._reboots.approved_reboot(host, now)
            if request is None or request.approved_by is None or await self._jobs.reboot_job_exists(request.id):
                continue  # one job per approval; an approval stays "approved" until the reboot succeeded or expired
            try:
                await self._jobs.propose(
                    "reboot_scheduled",
                    {"reboot_request": request.id},
                    host,
                    SYSTEM,
                    approved_by=request.approved_by,
                    reboot_request_id=request.id,
                )
            except DuplicateJob:
                continue  # one job per approval, a second try is not wanted
            except ActionError as error:
                log.warning("no reboot job for %s: %s", host, error)
