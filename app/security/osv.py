"""OSV scan of the repository dependencies.

Every night the service clones each repository shallow and read-only, runs osv-scanner over the checkout and
stores the result as findings (source `osv`, scope = repository). Each repository has its own Bitbucket repository
access token with the `repository` (read) scope; it goes to git through the environment, never into the URL or the
command line.
"""

import asyncio
import base64
import json
import logging
import os
import tempfile
from collections.abc import Callable
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Any, Protocol

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import last_run
from app.i18n import Locale
from app.models import Incident
from app.security.base import CheckBase, Scheduled
from app.security.findings import Finding, cve_of, normalize_severity, replace_findings
from app.security.signals import Signal, Signals

log = logging.getLogger(__name__)

SOURCE = "osv"
JOB = "osv_scan"
SCAN_FAILED = "VulnScanFailed"
SCAN_AT = time(2, 30)
CLONE_TIMEOUT_SECONDS = 300
SCAN_TIMEOUT_SECONDS = 600
# osv-scanner exit codes: 0 nothing found, 1 vulnerabilities found, 128 no package files found.
OK_EXIT_CODES = {0, 1, 128}


class ScanError(Exception):
    """A repository could not be cloned or scanned. The message is safe to show (no token)."""


class RepoScanner(Protocol):
    async def scan(self, repo: str) -> tuple[dict[str, Any], str]:
        """osv-scanner's JSON for the repository and the checkout root its paths start with."""
        ...


def _cvss_severity(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def _severity(group: dict[str, Any], vulns: list[dict[str, Any]]) -> str:
    """The group's CVSS score if osv-scanner gives one, else the advisory's own rating (GHSA: MODERATE = MEDIUM)."""
    try:
        return _cvss_severity(float(group.get("max_severity") or ""))
    except ValueError:
        pass
    for vuln in vulns:
        rating = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        if rating:
            return normalize_severity("MEDIUM" if rating == "MODERATE" else rating)
    return "UNKNOWN"


def _fixed_version(package: str, vulns: list[dict[str, Any]]) -> str:
    for vuln in vulns:
        for affected in vuln.get("affected") or []:
            if (affected.get("package") or {}).get("name") != package:
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        return str(event["fixed"])
    return ""


def parse_osv(report: dict[str, Any], root: str) -> list[Finding]:
    """One finding per package and vulnerability group (OSV groups the GHSA and CVE ids of one issue)."""
    findings = []
    for result in report.get("results") or []:
        path = str((result.get("source") or {}).get("path", ""))
        target = os.path.relpath(path, root) if path.startswith(root) else path
        for pkg in result.get("packages") or []:
            package = pkg.get("package") or {}
            name, version = str(package.get("name", "")), str(package.get("version", ""))
            by_id = {str(v.get("id")): v for v in pkg.get("vulnerabilities") or []}
            groups = pkg.get("groups") or [{"ids": [vid]} for vid in by_id]
            for group in groups:
                ids = [str(i) for i in group.get("ids") or []]
                vulns = [by_id[i] for i in ids if i in by_id]
                if not ids or not name:
                    continue
                aliases = [*ids, *(str(a) for v in vulns for a in v.get("aliases") or [])]
                findings.append(
                    Finding(
                        target=target,
                        package=name,
                        installed_version=version,
                        vuln_id=ids[0],
                        cve=cve_of(ids[0], aliases),
                        severity=_severity(group, vulns),
                        fixed_version=_fixed_version(name, vulns),
                        title=str(next((v.get("summary") for v in vulns if v.get("summary")), "")),
                    )
                )
    return findings


class OsvCliScanner:
    """Clones with git and scans with the osv-scanner binary of the image."""

    def __init__(
        self, tokens: dict[str, SecretStr], *, locale: Locale, base_url: str = "https://bitbucket.org"
    ) -> None:
        self._locale = locale
        self._tokens = tokens  # repository -> its access token
        self._base_url = base_url.rstrip("/")

    @staticmethod
    def _base_env() -> dict[str, str]:
        """Only what git and osv-scanner need: the service's own secrets (API keys, DB password) stay out."""
        return {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "SSL_CERT_FILE") if key in os.environ}

    def _git_env(self, repo: str) -> dict[str, str]:
        token = self._tokens.get(repo)
        if token is None:
            raise ScanError(self._locale.t("security.osv.no_token", repo=repo))
        basic = base64.b64encode(f"x-token-auth:{token.get_secret_value()}".encode()).decode()
        return {
            **self._base_env(),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        }

    async def _run(self, args: list[str], timeout: int, env: dict[str, str]) -> tuple[int, str, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
            )
        except FileNotFoundError as exc:
            raise ScanError(self._locale.t("security.osv.missing_binary", binary=args[0])) from exc
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ScanError(self._locale.t("security.osv.timeout", binary=args[0], timeout=timeout)) from exc
        assert process.returncode is not None  # noqa: S101 (communicate waited for the exit)
        return process.returncode, out.decode(errors="replace"), err.decode(errors="replace")

    async def scan(self, repo: str) -> tuple[dict[str, Any], str]:
        with tempfile.TemporaryDirectory(prefix="osv-") as tmp:
            checkout = str(Path(tmp) / "repo")
            url = f"{self._base_url}/{repo}.git"
            code, _, err = await self._run(
                ["git", "clone", "--depth", "1", "--quiet", url, checkout], CLONE_TIMEOUT_SECONDS, self._git_env(repo)
            )
            if code != 0:
                raise ScanError(self._locale.t("security.osv.clone_failed", url=url, error=err.strip()[-300:]))
            code, out, err = await self._run(
                ["osv-scanner", "scan", "source", "--recursive", "--format", "json", checkout],
                SCAN_TIMEOUT_SECONDS,
                self._base_env(),
            )
            if code not in OK_EXIT_CODES:
                raise ScanError(self._locale.t("security.osv.exit_code", code=code, error=err.strip()[-300:]))
            if code == 128 or not out.strip():
                return {"results": []}, checkout
            try:
                report = json.loads(out)
            except json.JSONDecodeError as exc:
                raise ScanError(self._locale.t("security.osv.not_json")) from exc
            if not isinstance(report, dict):
                raise ScanError(self._locale.t("security.osv.not_object"))
            return report, checkout


class OsvCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        signals: Signals,
        clock: Callable[[], datetime],
        repos: list[str],
        scanner: RepoScanner | None,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._signals = signals
        self._clock = clock
        self._repos = repos
        self._scanner = scanner

    def scheduled(self) -> list[Scheduled]:
        return [Scheduled(JOB, SCAN_AT, self.run)] if self._scanner and self._repos else []

    async def run(self, now: datetime) -> None:
        assert self._scanner is not None  # noqa: S101 (only scheduled with a scanner)
        for repo in self._repos:
            scope = {"source": SOURCE, "repo": repo}
            try:
                report, root = await self._scanner.scan(repo)
                findings = parse_osv(report, root)
            except ScanError as exc:
                signal = Signal(labels=scope, summary=self._locale.t("security.osv.scan_failed", repo=repo, error=exc))
                await self._signals.set(SCAN_FAILED, "P2", scope, signal)
                continue
            async with self._sessions() as session, session.begin():
                await replace_findings(session, SOURCE, repo, findings, self._clock())
            await self._signals.set(SCAN_FAILED, "P2", scope, None)

    async def daily_lines(self, now: datetime) -> list[str]:
        if not self._repos or self._scanner is None:
            return [self._locale.t("security.osv.line.disabled")]
        async with self._sessions() as session:
            last = await last_run(session, JOB)
            failing = (
                await session.scalars(
                    select(Incident).where(
                        Incident.status == "open",
                        Incident.title == SCAN_FAILED,
                        Incident.labels.contains({"source": SOURCE}),
                    )
                )
            ).all()
        lines = []
        if last is None or now - last > timedelta(hours=26):
            when = (
                self._locale.t("security.common.last", at=self._locale.day(last))
                if last
                else self._locale.t("security.common.never")
            )
            lines.append(self._locale.t("security.osv.line.not_run", when=when))
        lines += [self._locale.t("security.osv.line.repo_failed", repo=i.labels.get("repo")) for i in failing]
        return lines
