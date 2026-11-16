import base64

import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.models import VulnerabilityFinding
from app.security.osv import OsvCheck, OsvCliScanner, ScanError, parse_osv
from app.security.signals import Signals
from tests.fakes import EN
from tests.security_helpers import open_incidents

ROOT = "/work/osv-1/repo"

OSV_JSON = {
    "results": [
        {
            "source": {"path": f"{ROOT}/admin-frontend/pnpm-lock.yaml", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "next", "version": "16.0.1", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-abcd-1234",
                            "aliases": ["CVE-2026-1111"],
                            "summary": "Next.js middleware bypass",
                            "database_specific": {"severity": "MODERATE"},
                            "affected": [
                                {
                                    "package": {"name": "next", "ecosystem": "npm"},
                                    "ranges": [
                                        {"type": "SEMVER", "events": [{"introduced": "16.0.0"}, {"fixed": "16.0.4"}]}
                                    ],
                                }
                            ],
                        },
                        {"id": "CVE-2026-1111"},
                    ],
                    "groups": [{"ids": ["GHSA-abcd-1234", "CVE-2026-1111"], "max_severity": "9.1"}],
                },
                {
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {"id": "GHSA-lodash", "database_specific": {"severity": "MODERATE"}, "affected": []}
                    ],
                },
            ],
        }
    ]
}


def test_osv_json_becomes_one_finding_per_package_and_group():
    findings = parse_osv(OSV_JSON, ROOT)

    assert [(f.target, f.package, f.vuln_id, f.cve, f.severity, f.fixed_version) for f in findings] == [
        ("admin-frontend/pnpm-lock.yaml", "next", "GHSA-abcd-1234", "CVE-2026-1111", "CRITICAL", "16.0.4"),
        ("admin-frontend/pnpm-lock.yaml", "lodash", "GHSA-lodash", None, "MEDIUM", ""),
    ]
    assert findings[0].title == "Next.js middleware bypass"


class FakeScanner:
    def __init__(self, results: dict):
        self.results = results  # repo -> osv json, or a ScanError

    async def scan(self, repo):
        result = self.results[repo]
        if isinstance(result, Exception):
            raise result
        return result, ROOT


@pytest.fixture
def make_check(sessions, service, clock):
    def make(results, repos=("acme/admin-frontend", "acme/core")):
        return OsvCheck(
            sessions, Signals(sessions, service, clock), clock, list(repos), FakeScanner(results), locale=EN
        )

    return make


async def test_the_nightly_run_stores_findings_and_reports_a_repo_that_failed(make_check, sessions, clock):
    check = make_check(
        {
            "acme/admin-frontend": OSV_JSON,
            "acme/core": ScanError("git clone https://bitbucket.org/acme/core.git schlug fehl: 403"),
        }
    )

    await check.run(clock.now)

    async with sessions() as session:
        rows = (await session.scalars(select(VulnerabilityFinding))).all()
    assert {(r.source, r.scope, r.package) for r in rows} == {
        ("osv", "acme/admin-frontend", "next"),
        ("osv", "acme/admin-frontend", "lodash"),
    }
    [incident] = await open_incidents(sessions)
    assert (incident.title, incident.labels["repo"]) == ("VulnScanFailed", "acme/core")
    assert "403" in incident.annotations["summary"]


async def test_a_repo_that_scans_again_resolves_its_failure(make_check, sessions, clock):
    await make_check({"acme/core": ScanError("down")}, repos=["acme/core"]).run(clock.now)
    await make_check({"acme/core": {"results": []}}, repos=["acme/core"]).run(clock.now)

    assert await open_incidents(sessions) == []


async def test_daily_lines_name_a_scan_that_did_not_run_and_failing_repos(make_check, sessions, clock):
    check = make_check({"acme/core": ScanError("down")}, repos=["acme/core"])
    assert "did not run (never)" in (await check.daily_lines(clock.now))[0]

    await check.run(clock.now)
    lines = await check.daily_lines(clock.now)
    assert ":warning: OSV (acme/core): scan failed" in lines


async def test_without_repos_or_token_the_scan_is_off_and_says_so(sessions, service, clock):
    check = OsvCheck(sessions, Signals(sessions, service, clock), clock, ["acme/core"], None, locale=EN)

    assert check.scheduled() == []
    assert "dependencies are not checked" in (await check.daily_lines(clock.now))[0]


def test_the_token_goes_to_git_through_the_environment_only():
    scanner = OsvCliScanner({"acme/core": SecretStr("tok3n")}, locale=EN)

    env = scanner._git_env("acme/core")

    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == "Authorization: Basic " + base64.b64encode(b"x-token-auth:tok3n").decode()
    assert env["GIT_TERMINAL_PROMPT"] == "0"


async def test_a_clone_that_fails_becomes_a_scan_error_without_the_token(tmp_path):
    # A local path that does not exist: git fails fast and without network.
    scanner = OsvCliScanner({"acme/missing": SecretStr("tok3n")}, base_url=f"file://{tmp_path}", locale=EN)

    with pytest.raises(ScanError) as error:
        await scanner.scan("acme/missing")

    assert "git clone" in str(error.value)
    assert "tok3n" not in str(error.value)


def test_git_and_osv_scanner_do_not_see_the_services_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://ops:pw@db/ops")

    env = OsvCliScanner({"acme/core": SecretStr("tok3n")}, locale=EN)._git_env("acme/core")

    assert "ANTHROPIC_API_KEY" not in env and "DATABASE_URL" not in env
    assert "PATH" in env


async def test_a_repo_without_a_token_is_a_scan_error():
    with pytest.raises(ScanError, match="no token for"):
        await OsvCliScanner({"acme/core": SecretStr("x")}, locale=EN).scan("acme/other")
