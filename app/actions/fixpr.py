"""Fix pull requests: from an analysis' diff to a branch and a pull request in Bitbucket, after an approval.

The analysis may propose a fix as a diff for one repository. The service checks the diff strictly (app/actions/patch.py)
and posts a button in the incident thread. Only people on the allowlist may approve, once, within 15 minutes. The
approval then does everything in this order, so nothing half-done is left behind: read the base commit and the files,
apply the diff in memory (any mismatch stops here), create the branch `ops-fix/...`, commit to that branch, open the
pull request against the main branch. A failure after the branch exists deletes it again.

Never merged, never written to the main branch: the client has no merge call, and every call that writes refuses a
branch name without the `ops-fix/` prefix. The token (per repository, scopes repository:write and pullrequest:write)
stays on this server.
"""

import asyncio
import logging
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote

import httpx
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.actions.patch import FilePatch, PatchError, apply_patch, changed_lines, parse_diff
from app.agent.masking import Masker
from app.i18n import Locale
from app.models import ActionAudit, FixPr, Incident, IncidentAnalysis
from app.notify.base import ChatNotifier
from app.notify.blocks import approval_blocks, escape

log = logging.getLogger(__name__)

ACTION_ID = "fixpr_approve"
BRANCH_PREFIX = "ops-fix/"
VALID_FOR = timedelta(minutes=15)
MIN_TIME_TO_RUN = timedelta(minutes=1)
API = "https://api.bitbucket.org/2.0"
SYSTEM = "system"
TITLE_MAX = 90
SLACK_SECTION_LIMIT = 2600  # Slack allows 3000 characters in a section; escaping can make the text longer
APPROVED_STALE = timedelta(minutes=5)  # a creation takes seconds; an approval older than this was interrupted


class BitbucketError(Exception):
    """A Bitbucket call failed; the message holds the status, never the answer body."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class Bitbucket(Protocol):
    async def main_branch(self, repo: str) -> str: ...
    async def branch_head(self, repo: str, branch: str) -> str: ...
    async def read_file(self, repo: str, commit: str, path: str) -> str | None: ...
    async def create_branch(self, repo: str, name: str, commit: str) -> None: ...
    async def commit_files(self, repo: str, branch: str, parent: str, message: str, files: dict[str, str]) -> None: ...
    async def create_pull_request(self, repo: str, source: str, destination: str, title: str, text: str) -> str: ...
    async def delete_branch(self, repo: str, name: str) -> None: ...


def _ours(name: str) -> str:
    """Every write goes to a branch of ours; the main branch is never a target."""
    if not name.startswith(BRANCH_PREFIX) or ".." in name or len(name) > 120:
        raise BitbucketError(f"refusing to write to the branch {name[:40]!r}")
    return name


class HttpBitbucket:
    def __init__(self, client: httpx.AsyncClient, tokens: dict[str, SecretStr]) -> None:
        self._client, self._tokens = client, tokens

    async def _call(self, repo: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
        token = self._tokens.get(repo)
        if token is None:
            raise BitbucketError(f"no write token for {repo}")
        response = await self._client.request(
            method,
            f"{API}/repositories/{repo}{path}",
            headers={"Authorization": f"Bearer {token.get_secret_value()}", "Accept": "application/json"},
            timeout=30,
            follow_redirects=False,
            **kwargs,
        )
        if response.status_code >= 400:
            raise BitbucketError(
                f"Bitbucket answered {response.status_code} for {method} {path.split('?')[0][:60]}",
                response.status_code,
            )
        return response

    async def main_branch(self, repo: str) -> str:
        return str((await self._call(repo, "GET", "")).json()["mainbranch"]["name"])

    async def branch_head(self, repo: str, branch: str) -> str:
        answer = await self._call(repo, "GET", f"/refs/branches/{quote(branch, safe='')}")
        return str(answer.json()["target"]["hash"])

    async def read_file(self, repo: str, commit: str, path: str) -> str | None:
        try:
            raw = (await self._call(repo, "GET", f"/src/{commit}/{quote(path, safe='/')}")).content
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise BitbucketError(f"{path} is not valid UTF-8") from None
        except BitbucketError as error:
            if error.status == 404:
                return None
            raise

    async def create_branch(self, repo: str, name: str, commit: str) -> None:
        await self._call(repo, "POST", "/refs/branches", json={"name": _ours(name), "target": {"hash": commit}})

    async def commit_files(self, repo: str, branch: str, parent: str, message: str, files: dict[str, str]) -> None:
        form = {**files, "message": message, "branch": _ours(branch), "parents": parent}
        await self._call(repo, "POST", "/src", data=form)

    async def create_pull_request(self, repo: str, source: str, destination: str, title: str, text: str) -> str:
        body = {
            "title": title,
            "description": text,
            "source": {"branch": {"name": _ours(source)}},
            "destination": {"branch": {"name": destination}},
            "close_source_branch": True,
        }
        answer = await self._call(repo, "POST", "/pullrequests", json=body)
        url = str(answer.json()["links"]["html"]["href"])
        if not url.startswith("https://bitbucket.org/"):  # it ends up in a link in Slack and on the incident page
            raise BitbucketError("Bitbucket returned an unexpected pull request address")
        return url

    async def delete_branch(self, repo: str, name: str) -> None:
        await self._call(repo, "DELETE", f"/refs/branches/{quote(_ours(name), safe='')}")


def fix_prompt(repos: set[str]) -> str:
    """The part of the analyst's system prompt about fix pull requests (empty without a write token)."""
    if not repos:
        return ""
    return (
        "\n\nFix pull requests: if you know the lasting fix and can write it as a precise unified diff against the "
        "code on the main branch (`get_change_diff` shows code of deployed commits), put it in `fix_diff` with "
        "`fix_repo` "
        f"(one of: {', '.join(sorted(repos))}) and a short `fix_title`; otherwise leave the three fields empty. "
        "A person approves a pull request for it in Slack and reviews it; it is never merged automatically. Never "
        "invent code you have not seen: a diff that does not match the file is rejected."
    )


def _shown(diff: str) -> str:
    """The whole diff as Slack text: the person approving reads everything that will be committed."""
    return "```" + escape(diff).replace("`", "ˋ") + "```"


def message(locale: Locale, fix: FixPr, patches: list[FilePatch] | None = None) -> tuple[str, list[dict[str, Any]]]:
    """The Slack message of a fix pull request in its current state."""
    head = locale.t("fixpr.head", repo=escape(fix.repo), title=escape(fix.title))
    if patches:
        added, removed = changed_lines(patches)
        files = escape(", ".join(p.path for p in patches))
        head += "\n" + locale.t("fixpr.files", files=files, added=added, removed=removed)
        if fix.status == "proposed":
            head += "\n" + _shown(fix.diff)
    if fix.status == "proposed":
        text = locale.t("fixpr.proposed", head=head, at=locale.clock(fix.expires_at))
        confirm = locale.t("fixpr.confirm", repo=fix.repo)
        return text, approval_blocks(
            locale, text, locale.t("fixpr.button"), ACTION_ID, fix.token, locale.t("fixpr.confirm_title"), confirm
        )
    by = (
        "\n" + locale.t("fixpr.approved_by", id=fix.approved_by, at=locale.clock(fix.approved_at))
        if fix.approved_at
        else ""
    )
    if fix.status == "created":
        state = locale.t("fixpr.state.created", url=fix.pr_url, branch=fix.branch)
    elif fix.status == "failed":
        state = locale.t("fixpr.state.failed", error=escape(fix.error[:400]))
    elif fix.status == "approved":
        state = locale.t("fixpr.state.approved")
    else:
        state = locale.t("fixpr.state.expired")
    text = f"{head}{by}\n{state}"
    return text, [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]


class FixPullRequests:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        bitbucket: Bitbucket,
        chat: ChatNotifier,
        clock: Callable[[], datetime],
        repos: set[str],
        base_url: str,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions, self._bitbucket, self._chat, self._clock = sessions, bitbucket, chat, clock
        self._repos = repos  # repositories with a write token
        self._base_url = base_url.rstrip("/")

    @staticmethod
    def _audit(session: AsyncSession, fix: FixPr, at: datetime, event: str, actor: str, detail: str = "") -> None:
        session.add(ActionAudit(fix_pr_id=fix.id, at=at, event=event, actor=actor, detail=detail[:500]))

    # ---- the proposal ------------------------------------------------------------------------

    async def offer(self, analysis: IncidentAnalysis, channel: str, thread_ts: str) -> None:
        """The button for the analysis' fix, when it has a valid one. Never raises."""
        data = analysis.analysis or {}
        repo, diff = str(data.get("fix_repo") or ""), str(data.get("fix_diff") or "")
        if not repo or not diff or data.get("confidence") == "low":
            return
        try:
            if repo not in self._repos:
                raise PatchError(f"no write token for the repository {repo[:60]!r}")
            patches = parse_diff(diff)
            if len(_shown(diff)) > SLACK_SECTION_LIMIT:
                raise PatchError("the diff is too long to show in full")
        except PatchError as error:
            log.info("fix of analysis %s not offered: %s", analysis.id, error)
            return
        async with self._sessions() as session:
            incident = await session.get(Incident, analysis.incident_id)
        if incident is None or incident.status != "open":
            return  # resolved while the analysis ran, as with the runbook proposals
        raw_title = str(data.get("fix_title") or data.get("summary") or "Fix")
        title = " ".join(Masker().mask(raw_title).split())[:TITLE_MAX]  # one line: it becomes a commit subject
        now = self._clock()
        fix = FixPr(
            token=secrets.token_urlsafe(24),
            analysis_id=analysis.id,
            incident_id=analysis.incident_id,
            repo=repo,
            title=title,
            diff=diff,
            # The token makes the name unique, so it never collides with a branch of another instance or an older run.
            branch=f"{BRANCH_PREFIX}incident-{analysis.incident_id}-a{analysis.id}-{secrets.token_hex(3)}",
            status="proposed",
            created_at=now,
            expires_at=now + VALID_FOR,
        )
        try:
            async with self._sessions() as session, session.begin():
                session.add(fix)
                await session.flush()
                self._audit(session, fix, now, "created", "analysis", f"{repo}: {title}")
        except IntegrityError:  # the unique index: this analysis was offered before
            log.info("the fix of analysis %s was offered before", analysis.id)
            return
        text, blocks = message(self._locale, fix, patches)
        try:
            ts = await self._chat.reply_message(channel, thread_ts, text, blocks)
        except Exception:
            log.exception("posting the fix button of analysis %s failed", analysis.id)
            return
        async with self._sessions() as session, session.begin():
            row = await session.get(FixPr, fix.id)
            if row is not None:
                row.slack_channel, row.slack_ts, row.slack_state = channel, ts, row.status

    # ---- the approval ------------------------------------------------------------------------

    async def approve(self, token: str, user_id: str) -> str | None:
        """The button press of an allowed user: approve once, then create the branch and the pull request."""
        now = self._clock()
        async with self._sessions() as session, session.begin():
            fix = await session.scalar(select(FixPr).where(FixPr.token == token).with_for_update())
            if fix is None:
                return self._locale.t("errors.approval_unknown")
            if fix.status != "proposed":
                return self._locale.t("errors.fix_done")
            if now >= fix.expires_at - MIN_TIME_TO_RUN:
                fix.status = "expired"
                self._audit(session, fix, now, "expired", SYSTEM, "too late to approve")
                return self._locale.t("errors.approval_expired")
            fix.status, fix.approved_by, fix.approved_at = "approved", user_id, now
            self._audit(session, fix, now, "approved", user_id)
            fix_id = fix.id
        await self._run(fix_id)
        return None

    async def _run(self, fix_id: int) -> None:
        async with self._sessions() as session:
            fix = await session.get(FixPr, fix_id)
        if fix is None:
            return
        try:
            url = await self._create(fix)
        except (PatchError, BitbucketError) as error:
            await self._finish(fix_id, "failed", error=str(error))
        except Exception as error:
            log.exception("creating the fix pull request %s failed", fix_id)
            await self._finish(fix_id, "failed", error=f"unexpected error: {type(error).__name__}")
        else:
            await self._finish(fix_id, "created", url=url)

    async def _create(self, fix: FixPr) -> str:
        patches = parse_diff(fix.diff)  # the stored diff is parsed again: nothing is trusted from the first look
        main = await self._bitbucket.main_branch(fix.repo)
        base = await self._bitbucket.branch_head(fix.repo, main)
        originals = await asyncio.gather(*(self._bitbucket.read_file(fix.repo, base, p.path) for p in patches))
        files: dict[str, str] = {}
        for patch, original in zip(patches, originals, strict=True):
            # All of it in memory first: a mismatch stops here, before anything exists in Bitbucket.
            if original is None:
                raise PatchError(f"{patch.path} does not exist in {main}")
            files[patch.path] = apply_patch(original, patch)
        text = self._description(fix)
        # A failed creation deletes nothing: the name is unique, but if the call failed there may be no branch of ours.
        await self._bitbucket.create_branch(fix.repo, fix.branch, base)
        try:
            # [skip ci]: no pipeline runs on this branch before a person has reviewed the pull request.
            subject = f"ops: {fix.title} [skip ci]"
            await self._bitbucket.commit_files(fix.repo, fix.branch, base, f"{subject}\n\n{text}", files)
        except Exception:
            await self._drop_branch(fix)  # nothing was proposed yet: no branch without a pull request is left behind
            raise
        try:
            return await self._bitbucket.create_pull_request(fix.repo, fix.branch, main, f"ops: {fix.title}", text)
        except BitbucketError as error:
            # The pull request may exist even though the answer did not arrive: the branch is not deleted then.
            raise BitbucketError(f"{error} (the branch {fix.branch} stays, check Bitbucket)", error.status) from error

    async def _drop_branch(self, fix: FixPr) -> None:
        try:
            await self._bitbucket.delete_branch(fix.repo, fix.branch)
        except Exception:
            log.exception("could not delete the branch %s of %s", fix.branch, fix.repo)

    def _description(self, fix: FixPr) -> str:
        incident = f"{self._base_url}/incidents/{fix.incident_id}" if fix.incident_id else ""
        return (
            "Prepared by the ops service from an AI analysis and approved in Slack by "
            f"{fix.approved_by}. Review it like any other change; it is never merged automatically.\n\n{incident}"
        ).strip()

    async def _finish(self, fix_id: int, status: str, *, url: str | None = None, error: str = "") -> None:
        now = self._clock()
        async with self._sessions() as session, session.begin():
            fix = await session.get(FixPr, fix_id, with_for_update=True)
            if fix is None or fix.status != "approved":
                return  # the tick may have marked an interrupted run as failed already
            fix.status, fix.finished_at, fix.pr_url = status, now, url
            fix.error = Masker().mask(error)[:500]
            self._audit(session, fix, now, status, SYSTEM, fix.pr_url or fix.error)
        await self._refresh(fix_id)

    # ---- the message -------------------------------------------------------------------------

    async def tick(self) -> None:
        """Expire unapproved proposals and bring messages up to date."""
        now = self._clock()
        async with self._sessions() as session, session.begin():
            old = (
                await session.scalars(
                    select(FixPr).where(FixPr.status == "proposed", FixPr.expires_at <= now).with_for_update()
                )
            ).all()
            for fix in old:
                fix.status = "expired"
                self._audit(session, fix, now, "expired", SYSTEM, "not approved in time")
            stuck = (
                await session.scalars(
                    select(FixPr)
                    .where(FixPr.status == "approved", FixPr.approved_at <= now - APPROVED_STALE)
                    .with_for_update()
                )
            ).all()
            for fix in stuck:  # the service restarted between the approval and the result
                fix.status, fix.finished_at = "failed", now
                fix.error = self._locale.t("fixpr.interrupted")
                self._audit(session, fix, now, "failed", SYSTEM, "interrupted")
        async with self._sessions() as session:
            stale = (
                await session.scalars(
                    select(FixPr.id).where(
                        FixPr.slack_ts.is_not(None), FixPr.slack_state.is_distinct_from(FixPr.status)
                    )
                )
            ).all()
        for fix_id in stale:
            await self._refresh(fix_id)

    async def _refresh(self, fix_id: int) -> None:
        async with self._sessions() as session:
            fix = await session.get(FixPr, fix_id)
        if fix is None or fix.slack_channel is None or fix.slack_ts is None:
            return
        try:
            patches = parse_diff(fix.diff)
        except PatchError:
            patches = None
        text, blocks = message(self._locale, fix, patches)
        try:
            await self._chat.update_message(fix.slack_channel, fix.slack_ts, text, blocks)
        except Exception:
            log.exception("updating the message of the fix pull request %s failed", fix_id)
            return
        async with self._sessions() as session, session.begin():
            row = await session.get(FixPr, fix_id)
            if row is not None:
                row.slack_state = fix.status
