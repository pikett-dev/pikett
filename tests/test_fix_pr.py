from datetime import timedelta
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.actions.fixpr import BRANCH_PREFIX, BitbucketError, FixPullRequests, HttpBitbucket, fix_prompt, message
from app.actions.patch import PatchError, apply_patch, parse_diff
from app.models import ActionAudit, FixPr, IncidentAnalysis
from app.notify.slack import ButtonActions
from tests.fakes import EN, START
from tests.test_analysis_service import open_incident

REPO = "acme/core"
ALICE = "U_ALICE"
SHA = "a" * 40
APP_PY = "def main():\n    value = 1\n    return value\n\n\nprint(main())\n"
DIFF = """--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,3 @@
 def main():
-    value = 1
+    value = 2
     return value
"""


class FakeBitbucket:
    """Records every call; the main branch must never be written."""

    def __init__(self, files: dict[str, str] | None = None, fail_at: str = "") -> None:
        self.files = files if files is not None else {"src/app.py": APP_PY}
        self.fail_at = fail_at
        self.calls: list[tuple[str, ...]] = []
        self.branches: set[str] = set()

    def _maybe_fail(self, step: str) -> None:
        if self.fail_at == step:
            raise BitbucketError(f"Bitbucket answered 500 for {step}")

    async def main_branch(self, repo: str) -> str:
        return "main"

    async def branch_head(self, repo: str, branch: str) -> str:
        self.calls.append(("branch_head", branch))
        return SHA

    async def read_file(self, repo: str, commit: str, path: str) -> str | None:
        self.calls.append(("read_file", path))
        return self.files.get(path)

    async def create_branch(self, repo: str, name: str, commit: str) -> None:
        self.calls.append(("create_branch", name))
        self._maybe_fail("create_branch")
        self.branches.add(name)

    async def commit_files(self, repo: str, branch: str, parent: str, message: str, files: dict[str, str]) -> None:
        self.calls.append(("commit", branch, *sorted(files)))
        self.committed = files
        self.messages = [*getattr(self, "messages", []), message]
        self._maybe_fail("commit")

    async def create_pull_request(self, repo: str, source: str, destination: str, title: str, text: str) -> str:
        self.calls.append(("pull_request", source, destination))
        self._maybe_fail("pull_request")
        return f"https://bitbucket.org/{repo}/pull-requests/7"

    async def delete_branch(self, repo: str, name: str) -> None:
        self.calls.append(("delete_branch", name))
        self.branches.discard(name)


@pytest.fixture
def bitbucket() -> FakeBitbucket:
    return FakeBitbucket()


@pytest.fixture
def fixes(sessions, bitbucket, chat, clock) -> FixPullRequests:
    return FixPullRequests(sessions, bitbucket, chat, clock, {REPO}, "http://ops.test", locale=EN)


@pytest.fixture
def buttons(fixes) -> ButtonActions:
    actions = ButtonActions([ALICE, "U_BOB"], EN)
    actions.fix_prs = fixes
    return actions


async def analysis_row(sessions, **fields: Any) -> IncidentAnalysis:
    base = {
        "fix_repo": REPO,
        "fix_title": "Use the right value",
        "fix_diff": DIFF,
        "summary": "x",
        "confidence": "high",
    }
    async with sessions() as session, session.begin():
        row = IncidentAnalysis(
            incident_id=1,
            requested_by="auto",
            status="done",
            started_at=START,
            finished_at=START,
            verified=True,
            analysis={**base, **fields},
        )
        session.add(row)
        await session.flush()
        return row


async def only_fix(sessions) -> FixPr:
    async with sessions() as session:
        return (await session.scalars(select(FixPr))).one()


async def audit(sessions) -> list[str]:
    async with sessions() as session:
        rows = await session.scalars(
            select(ActionAudit).where(ActionAudit.fix_pr_id.is_not(None)).order_by(ActionAudit.id)
        )
        return [r.event for r in rows]


# --- the diff -------------------------------------------------------------------------------------------------------


def test_a_diff_applies_to_the_file_it_was_made_for() -> None:
    [patch] = parse_diff(DIFF)
    assert patch.path == "src/app.py"
    assert apply_patch(APP_PY, patch) == APP_PY.replace("value = 1", "value = 2")


def test_a_diff_with_git_headers_and_two_hunks_applies() -> None:
    original = "".join(f"line{i}\n" for i in range(1, 21))
    diff = (
        "diff --git a/f.txt b/f.txt\nindex 111..222 100644\n--- a/f.txt\n+++ b/f.txt\n"
        "@@ -2,3 +2,3 @@\n line2\n-line3\n+LINE3\n line4\n@@ -18,3 +18,4 @@\n line18\n line19\n+extra\n line20\n"
    )
    result = apply_patch(original, parse_diff(diff)[0])
    assert "LINE3\n" in result and "line19\nextra\nline20\n" in result and result.endswith("line20\n")


@pytest.mark.parametrize(
    ("diff", "reason"),
    [
        ("", "empty"),
        ("--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+x\n", "creates or deletes"),
        ("--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n", "creates or deletes"),
        ("--- a/a.py\n+++ b/b.py\n@@ -1 +1 @@\n-x\n+y\n", "renaming"),
        ("rename from a.py\nrename to b.py\n", "renames"),
        ("--- a/../etc/passwd\n+++ b/../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),
        ("--- a//abs\n+++ b//abs\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),
        ("--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),
        ("--- a/message\n+++ b/message\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),  # a field name of the commit form
        ("--- a/x y\n+++ b/x y\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),
        ("--- a/bitbucket-pipelines.yml\n+++ b/bitbucket-pipelines.yml\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/deploy/run.sh\n+++ b/deploy/run.sh\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/app/Dockerfile\n+++ b/app/Dockerfile\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/scripts/x.sh\n+++ b/scripts/x.sh\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/app/./x.py\n+++ b/app/./x.py\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),
        ("--- a/Message\n+++ b/Message\n@@ -1 +1 @@\n-x\n+y\n", "unsafe path"),  # a form field name, any case
        ("--- a/compose.stack.yaml\n+++ b/compose.stack.yaml\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/core/build.gradle.kts\n+++ b/core/build.gradle.kts\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/app/runner/x.py\n+++ b/app/runner/x.py\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -1 +1 @@\n-x\n+y\n", "CI, build"),
        ("--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\u202eevil\n", "invisible"),  # bidi control
        ("--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\u2028z\n", "invisible"),  # a line separator
        ("--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\r\n-x\r\n+y\r\n", "invisible"),  # CRLF
        ("--- a/f\n+++ b/f\n", "no hunks"),
        ("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n-x\n+y\n", "number of lines"),
        ("--- a/f\n+++ b/f\n@@ nonsense @@\n-x\n", "hunk header"),
        ("hello world\n", "unexpected line"),
        ("--- a/f\n+++ b/f\n@@ -0,0 +1 @@\n+x\n", "existing line"),
        ("x" * 3000, "too large"),
    ],
)
def test_a_diff_outside_the_narrow_shape_is_refused(diff, reason) -> None:
    with pytest.raises(PatchError, match=reason):
        parse_diff(diff)


def test_too_many_or_duplicate_files_are_refused() -> None:
    one = "--- a/f{n}\n+++ b/f{n}\n@@ -1 +1 @@\n-x\n+y\n"
    with pytest.raises(PatchError, match="more than"):
        parse_diff("".join(one.format(n=n) for n in range(6)))
    with pytest.raises(PatchError, match="twice"):
        parse_diff(one.format(n=1) * 2)


def test_a_hunk_that_does_not_match_the_file_is_an_error_naming_it() -> None:
    [patch] = parse_diff(DIFF)
    with pytest.raises(PatchError, match=r"src/app.py: hunk 1 does not match the file at line 1"):
        apply_patch("def main():\n    value = 99\n    return value\n", patch)
    with pytest.raises(PatchError, match="does not match"):
        apply_patch("", patch)


def test_a_missing_final_newline_is_kept_or_set_as_the_diff_says() -> None:
    [patch] = parse_diff("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n\\ No newline at end of file\n")
    assert apply_patch("a\nb", patch) == "a\nc"
    # The old file had no final newline, the new one has: the marker after the removed line is about the old side.
    [added] = parse_diff("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n")
    assert apply_patch("a\nb", added) == "a\nb\n"


# --- the proposal and the approval ----------------------------------------------------------------------------------


async def test_a_valid_fix_becomes_a_button_with_files_and_a_dialog(service, sessions, fixes, chat) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    assert (fix.repo, fix.status, fix.branch.startswith(BRANCH_PREFIX), fix.slack_ts) == (REPO, "proposed", True, "m-1")
    text, blocks = chat.messages[0]
    assert "src/app.py" in text and "+1 / -1" in text and "never merged automatically" in text
    button = blocks[1]["elements"][0]
    assert button["value"] == fix.token and button["confirm"]["title"]["text"]
    assert await audit(sessions) == ["created"]


@pytest.mark.parametrize(
    "fields",
    [
        {"fix_diff": ""},
        {"fix_repo": ""},
        {"fix_repo": "acme/unknown"},  # no write token for it
        {"fix_diff": "--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+x\n"},
        {"confidence": "low"},
    ],
)
async def test_a_fix_that_is_not_acceptable_is_not_offered(service, sessions, fixes, chat, fields) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions, **fields), "C1", "ts-1")
    async with sessions() as session:
        assert (await session.scalars(select(FixPr))).all() == []
    assert chat.messages == []


async def test_the_same_analysis_is_offered_once(service, sessions, fixes, chat) -> None:
    await open_incident(service)
    row = await analysis_row(sessions)
    await fixes.offer(row, "C1", "ts-1")
    await fixes.offer(row, "C1", "ts-1")
    assert len(chat.messages) == 1


async def test_the_approval_creates_the_branch_commit_and_pull_request_and_never_touches_main(
    service, sessions, fixes, buttons, bitbucket, chat
) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    assert await buttons.handle_fixpr(ALICE, fix.token) is None

    done = await only_fix(sessions)
    assert (done.status, done.approved_by, done.pr_url) == (
        "created",
        ALICE,
        f"https://bitbucket.org/{REPO}/pull-requests/7",
    )
    assert bitbucket.committed == {"src/app.py": APP_PY.replace("value = 1", "value = 2")}
    steps = [c[0] for c in bitbucket.calls]
    assert steps == ["branch_head", "read_file", "create_branch", "commit", "pull_request"]
    writes = [c for c in bitbucket.calls if c[0] in ("create_branch", "commit", "pull_request")]
    assert all(c[1].startswith(BRANCH_PREFIX) for c in writes)  # every write targets our branch
    assert (
        "pull_request",
        fix.branch,
        "main",
    ) in bitbucket.calls  # the pull request goes to main, it does not touch it
    assert "merge" not in " ".join(" ".join(c) for c in bitbucket.calls).lower()
    assert "PR created" in chat.messages[0][0] and "merge it yourself" in chat.messages[0][0]
    assert await audit(sessions) == ["created", "approved", "created"]


async def test_a_diff_that_does_not_apply_makes_nothing_in_bitbucket_and_says_why(
    service, sessions, fixes, buttons, chat
) -> None:
    bitbucket = FakeBitbucket({"src/app.py": "totally different\n"})
    fixes._bitbucket = bitbucket
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    await buttons.handle_fixpr(ALICE, (await only_fix(sessions)).token)

    fix = await only_fix(sessions)
    assert fix.status == "failed" and "hunk 1 does not match" in fix.error
    assert [c[0] for c in bitbucket.calls] == ["branch_head", "read_file"]  # no branch, no commit, no PR
    assert "Not created" in chat.messages[0][0] and "hunk 1" in chat.messages[0][0]


async def test_a_file_that_does_not_exist_is_a_clear_failure(service, sessions, fixes, buttons) -> None:
    fixes._bitbucket = FakeBitbucket({})
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    await buttons.handle_fixpr(ALICE, (await only_fix(sessions)).token)
    assert "does not exist in main" in (await only_fix(sessions)).error


@pytest.mark.parametrize("step", ["commit"])
async def test_a_failure_after_the_branch_exists_deletes_the_branch(service, sessions, fixes, buttons, step) -> None:
    bitbucket = FakeBitbucket(fail_at=step)
    fixes._bitbucket = bitbucket
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    await buttons.handle_fixpr(ALICE, fix.token)
    assert (await only_fix(sessions)).status == "failed" and "500" in (await only_fix(sessions)).error
    assert ("delete_branch", fix.branch) in bitbucket.calls and bitbucket.branches == set()  # no orphan branch


async def test_only_allowed_users_approve_and_a_second_click_does_nothing(
    service, sessions, fixes, buttons, bitbucket
) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    token = (await only_fix(sessions)).token
    assert await buttons.handle_fixpr("U_STRANGER", token) == "You are not allowed to do that."
    assert (await only_fix(sessions)).status == "proposed" and bitbucket.calls == []
    assert await buttons.handle_fixpr(ALICE, token) is None
    assert await buttons.handle_fixpr("U_BOB", token) == "This fix PR is already approved or finished."
    assert [c[0] for c in bitbucket.calls].count("create_branch") == 1  # one pull request, ever
    assert await buttons.handle_fixpr(ALICE, "nope") == "Unknown approval."
    assert await ButtonActions([ALICE], EN).handle_fixpr(ALICE, "x") == "Fix PRs are not set up."


async def test_an_unapproved_fix_expires_and_its_button_goes(service, sessions, fixes, buttons, chat, clock) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    token = (await only_fix(sessions)).token
    clock.advance(timedelta(minutes=15))
    await fixes.tick()
    assert (await only_fix(sessions)).status == "expired"
    assert "deadline has passed" in chat.messages[0][0] and len(chat.messages[0][1]) == 1
    assert await buttons.handle_fixpr(ALICE, token) == "This fix PR is already approved or finished."


async def test_an_approval_with_no_time_left_is_refused(service, sessions, fixes, buttons, clock) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    clock.advance(timedelta(minutes=14, seconds=30))
    assert await buttons.handle_fixpr(ALICE, (await only_fix(sessions)).token) == "The approval has expired."


def test_the_message_escapes_the_error_text() -> None:
    fix = FixPr(
        repo=REPO, title="t", branch="ops-fix/x", status="failed", error="<!channel> boom", token="t",  # noqa: S106
        created_at=START, expires_at=START,
    )  # fmt: skip
    text, _ = message(EN, fix)
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text


def test_the_prompt_names_the_repositories_and_is_empty_without_a_token() -> None:
    assert REPO in fix_prompt({REPO}) and "never merged" in fix_prompt({REPO})
    assert fix_prompt(set()) == ""


# --- the real client against a fake Bitbucket API -------------------------------------------------------------------


def make_client(requests: list[httpx.Request], *, status: int = 200) -> HttpBitbucket:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/refs/branches/main"):
            return httpx.Response(status, json={"target": {"hash": SHA}})
        if request.method == "GET" and "/src/" in path:
            return httpx.Response(status if status != 200 else 200, text="content")
        if request.method == "GET":
            return httpx.Response(status, json={"mainbranch": {"name": "main"}})
        if request.method == "POST" and path.endswith("/pullrequests"):
            return httpx.Response(201, json={"links": {"html": {"href": "https://bitbucket.org/x/pull-requests/1"}}})
        return httpx.Response(201 if status == 200 else status, json={})

    return HttpBitbucket(httpx.AsyncClient(transport=httpx.MockTransport(handler)), {REPO: SecretStr("tok")})


async def test_the_client_sends_the_documented_requests_with_the_repository_token() -> None:
    seen: list[httpx.Request] = []
    client = make_client(seen)
    assert await client.main_branch(REPO) == "main"
    assert await client.branch_head(REPO, "main") == SHA
    assert await client.read_file(REPO, SHA, "src/app.py") == "content"
    await client.create_branch(REPO, "ops-fix/incident-1-a1", SHA)
    await client.commit_files(REPO, "ops-fix/incident-1-a1", SHA, "msg", {"src/app.py": "new"})
    assert await client.create_pull_request(REPO, "ops-fix/incident-1-a1", "main", "t", "d") == (
        "https://bitbucket.org/x/pull-requests/1"
    )
    await client.delete_branch(REPO, "ops-fix/incident-1-a1")
    assert {r.headers["Authorization"] for r in seen} == {"Bearer tok"}
    commit = next(r for r in seen if r.url.path.endswith("/src") and r.method == "POST")
    body = commit.content.decode()
    assert "src%2Fapp.py=new" in body and "branch=ops-fix%2Fincident-1-a1" in body and f"parents={SHA}" in body
    delete = seen[-1]
    assert delete.method == "DELETE" and delete.url.raw_path.endswith(b"/refs/branches/ops-fix%2Fincident-1-a1")


@pytest.mark.parametrize("name", ["main", "master", "develop", "feature/x", "ops-fix/../main", "ops-fixer", ""])
async def test_the_client_refuses_to_write_to_any_branch_that_is_not_ours(name) -> None:
    seen: list[httpx.Request] = []
    client = make_client(seen)
    with pytest.raises(BitbucketError, match="refusing"):
        await client.create_branch(REPO, name, SHA)
    with pytest.raises(BitbucketError, match="refusing"):
        await client.commit_files(REPO, name, SHA, "m", {"a": "b"})
    with pytest.raises(BitbucketError, match="refusing"):
        await client.create_pull_request(REPO, name, "main", "t", "d")
    with pytest.raises(BitbucketError, match="refusing"):
        await client.delete_branch(REPO, name)
    assert seen == []  # nothing was sent


async def test_the_client_has_no_merge_and_no_other_repository_token() -> None:
    assert not [m for m in dir(HttpBitbucket) if "merge" in m.lower()]
    with pytest.raises(BitbucketError, match="no write token"):
        await make_client([]).main_branch("acme/other")


async def test_a_missing_file_is_none_and_an_error_status_hides_the_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404 if "missing" in request.url.path else 403, text="secret details")

    client = HttpBitbucket(httpx.AsyncClient(transport=httpx.MockTransport(handler)), {REPO: SecretStr("tok")})
    assert await client.read_file(REPO, SHA, "missing.py") is None
    with pytest.raises(BitbucketError) as error:
        await client.main_branch(REPO)
    assert "403" in str(error.value) and "secret details" not in str(error.value)


def test_the_analyst_is_told_about_fix_pull_requests_when_a_write_token_exists() -> None:
    from app.config import Settings
    from app.main import create_app

    assert "fix_diff" in fix_prompt({REPO})
    create_app(Settings(bitbucket_write_tokens={REPO: SecretStr("tok")}))  # the wiring builds


async def test_the_approval_message_shows_what_is_approved_and_escapes_what_a_model_wrote(
    service, sessions, fixes, chat
) -> None:
    await open_incident(service)
    await fixes.offer(
        await analysis_row(sessions, fix_title="<!channel> approve\n\nnow <https://evil|x>"), "C1", "ts-1"
    )
    text = chat.messages[0][0]
    assert "<!channel>" not in text and "<https://evil" not in text and "&lt;!channel&gt;" in text
    assert "value = 2" in text and "```" in text  # the hunk itself, not only its size
    assert (await only_fix(sessions)).title == "<!channel> approve now <https://evil|x>"  # one line


async def test_an_approval_that_was_interrupted_is_failed_and_says_so(service, sessions, fixes, clock) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    async with sessions() as session, session.begin():
        fix = (await session.scalars(select(FixPr))).one()
        fix.status, fix.approved_by, fix.approved_at = "approved", ALICE, clock()
    await fixes.tick()
    assert (await only_fix(sessions)).status == "approved"  # a creation takes seconds: not yet stale
    clock.advance(timedelta(minutes=6))
    await fixes.tick()
    stuck = await only_fix(sessions)
    assert stuck.status == "failed" and "Interrupted" in stuck.error
    assert (await audit(sessions))[-1] == "failed"


async def test_a_pull_request_call_that_fails_keeps_the_branch_in_case_it_exists(
    service, sessions, fixes, buttons
) -> None:
    bitbucket = FakeBitbucket(fail_at="pull_request")
    fixes._bitbucket = bitbucket
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    await buttons.handle_fixpr(ALICE, fix.token)
    assert ("delete_branch", fix.branch) not in bitbucket.calls
    assert "stays" in (await only_fix(sessions)).error


async def test_a_failed_branch_creation_deletes_nothing(service, sessions, fixes, buttons) -> None:
    bitbucket = FakeBitbucket(fail_at="create_branch")
    fixes._bitbucket = bitbucket
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    await buttons.handle_fixpr(ALICE, (await only_fix(sessions)).token)
    assert not [c for c in bitbucket.calls if c[0] == "delete_branch"]  # it may be someone else's branch
    assert (await only_fix(sessions)).status == "failed"


async def test_the_branch_name_is_unique_and_the_commit_skips_ci(service, sessions, fixes, buttons, bitbucket) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    assert fix.branch.startswith("ops-fix/incident-1-a1-") and len(fix.branch) > len("ops-fix/incident-1-a1-")
    await buttons.handle_fixpr(ALICE, fix.token)
    assert bitbucket.messages[0].splitlines()[0].endswith("[skip ci]")


async def test_a_fix_for_a_resolved_incident_is_not_offered(service, sessions, fixes, chat) -> None:
    from sqlalchemy import update

    from app.models import Incident

    await open_incident(service)
    async with sessions() as session, session.begin():
        await session.execute(update(Incident).values(status="resolved"))
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    assert chat.messages == []


async def test_a_diff_too_long_to_show_in_full_is_not_offered(service, sessions, fixes, chat) -> None:
    await open_incident(service)
    long_diff = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+" + "<" * 1000 + "\n"  # escaping makes it 4x as long
    await fixes.offer(await analysis_row(sessions, fix_diff=long_diff), "C1", "ts-1")
    assert chat.messages == []


async def test_a_late_result_does_not_overwrite_an_interrupted_run(service, sessions, fixes, clock) -> None:
    await open_incident(service)
    await fixes.offer(await analysis_row(sessions), "C1", "ts-1")
    fix = await only_fix(sessions)
    async with sessions() as session, session.begin():
        row = await session.get(FixPr, fix.id)
        row.status = "failed"
    await fixes._finish(fix.id, "created", url="https://bitbucket.org/x/pull-requests/1")
    assert (await only_fix(sessions)).status == "failed"


async def test_a_file_that_is_not_utf8_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"caf\xe9")

    client = HttpBitbucket(httpx.AsyncClient(transport=httpx.MockTransport(handler)), {REPO: SecretStr("tok")})
    with pytest.raises(BitbucketError, match="not valid UTF-8"):
        await client.read_file(REPO, SHA, "a.py")
