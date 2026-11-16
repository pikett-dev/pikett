"""A strict unified-diff reader and applier for the fix pull requests.

The diff comes from an AI analysis, so it is held to a narrow shape: changes to existing files only (no new, deleted,
renamed or binary files), plain relative paths, a few small files. A hunk applies only where its context matches the
file exactly; anything else is an error, so a fix never becomes a half-applied pull request.
"""

import re
import unicodedata
from dataclasses import dataclass, field

MAX_FILES = 5
MAX_DIFF_CHARS = 2_000  # the limit of the analysis field; the person approving reads all of it in Slack
_PATH = re.compile(r"[A-Za-z0-9_@+\-][A-Za-z0-9_@+\-./]{0,199}")
_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_RESERVED = {"message", "author", "parents", "branch", "files"}  # field names of the Bitbucket commit form
# A commit on a branch can start a pipeline that runs with the repository's secrets before anyone reviews the pull
# request, so a fix may not touch the CI, container or deploy configuration (nor this runner's own code).
_FORBIDDEN_DIRS = {".github", ".bitbucket", ".circleci", ".gitlab", "deploy", "infra", "runner", ".husky", "gradle"}
_FORBIDDEN_FILES = {
    "bitbucket-pipelines.yml",
    "bitbucket-pipelines.yaml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".gitlab-ci.yml",
    "jenkinsfile",
    "containerfile",
    "makefile",
    "justfile",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "uv.lock",
    "gradlew",
    "gradlew.bat",
    "conftest.py",
}
_FORBIDDEN_PREFIXES = ("dockerfile", "docker-compose", "compose.", "build.gradle", "settings.gradle")


class PatchError(ValueError):
    """The diff is not acceptable or does not apply; the message is for the people who read the Slack thread."""


@dataclass
class Hunk:
    old_start: int
    old: list[str] = field(default_factory=list)  # context and removed lines
    new: list[str] = field(default_factory=list)  # context and added lines
    new_without_final_newline: bool = False  # the marker followed a context or added line: the new text has none
    added: int = 0
    removed: int = 0


@dataclass
class FilePatch:
    path: str
    hunks: list[Hunk]


def _safe_path(raw: str) -> str:
    path = raw.strip()
    parts = path.split("/")
    if (
        not _PATH.fullmatch(path)
        or ".." in parts
        or "." in parts
        or "" in parts
        or ".git" in parts
        or (len(parts) == 1 and path.lower() in _RESERVED)
    ):
        raise PatchError(f"unsafe path in the diff: {raw[:60]!r}")
    lowered = [part.lower() for part in parts]
    last = lowered[-1]
    if (
        any(part in _FORBIDDEN_DIRS for part in lowered[:-1])
        or last in _FORBIDDEN_FILES
        or last.startswith(_FORBIDDEN_PREFIXES)
        or last.endswith((".sh", ".dockerfile"))
        or last.startswith("test_")
    ):
        raise PatchError(f"{path}: CI, build, container, deploy, test and shell files are not changed by a fix")
    return path


def _strip(prefix: str, raw: str) -> str:
    name = raw.split("\t")[0].strip()
    if name == "/dev/null":
        raise PatchError("the diff creates or deletes a file: only changes to existing files are allowed")
    if not name.startswith(prefix):
        raise PatchError("file names in the diff need the a/ and b/ prefixes")
    return name[len(prefix) :]


def parse_diff(text: str) -> list[FilePatch]:
    if not text.strip():
        raise PatchError("the diff is empty")
    if len(text) > MAX_DIFF_CHARS:
        raise PatchError("the diff is too large")
    for char in text:
        if char != "\n" and char != "\t" and unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp"):
            raise PatchError("the diff contains control, invisible or line-separator characters")
    lines = text.split("\n")  # the same line model as apply_patch; a CR was rejected above
    if lines and lines[-1] == "":
        lines.pop()
    patches: list[FilePatch] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(("diff --git", "index ")):
            i += 1
            continue
        if line.startswith(("rename ", "new file", "deleted file", "similarity ", "Binary ", "old mode", "new mode")):
            raise PatchError("renames, new or deleted files and mode changes are not allowed")
        if not line.startswith("--- "):
            if line.strip():
                raise PatchError(f"unexpected line in the diff: {line[:60]!r}")
            i += 1
            continue
        if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
            raise PatchError("a --- line needs a +++ line")
        old, new = _safe_path(_strip("a/", line[4:])), _safe_path(_strip("b/", lines[i + 1][4:]))
        if old != new:
            raise PatchError("renaming a file is not allowed")
        i += 2
        hunks: list[Hunk] = []
        while i < len(lines) and lines[i].startswith("@@"):
            hunk, i = _hunk(lines, i)
            hunks.append(hunk)
        if not hunks:
            raise PatchError(f"{old}: no hunks")
        patches.append(FilePatch(old, hunks))
    if not patches:
        raise PatchError("the diff changes no file")
    if len(patches) > MAX_FILES:
        raise PatchError(f"the diff touches more than {MAX_FILES} files")
    if len({p.path for p in patches}) != len(patches):
        raise PatchError("the same file appears twice in the diff")
    return patches


def _hunk(lines: list[str], i: int) -> tuple[Hunk, int]:
    match = _HUNK.match(lines[i])
    if match is None:
        raise PatchError(f"bad hunk header: {lines[i][:60]!r}")
    old_start, old_count = int(match[1]), int(match[2]) if match[2] is not None else 1
    new_count = int(match[4]) if match[4] is not None else 1
    if old_count == 0 or old_start == 0:
        raise PatchError("a hunk needs at least one existing line of context or change")
    hunk = Hunk(old_start)
    i += 1
    while i < len(lines) and (len(hunk.old) < old_count or len(hunk.new) < new_count or lines[i].startswith("\\")):
        line = lines[i]
        if line.startswith("\\"):  # "\ No newline at end of file", after the line it refers to
            if i > 0 and not lines[i - 1].startswith("-"):  # after a removed line it describes the old file only
                hunk.new_without_final_newline = True
            i += 1
            continue
        tag, body = (line[:1], line[1:]) if line else (" ", "")  # an empty context line may have lost its space
        if tag == " ":
            hunk.old.append(body)
            hunk.new.append(body)
        elif tag == "-":
            hunk.old.append(body)
            hunk.removed += 1
        elif tag == "+":
            hunk.new.append(body)
            hunk.added += 1
        else:
            raise PatchError(f"bad line in a hunk: {line[:60]!r}")
        i += 1
    if len(hunk.old) != old_count or len(hunk.new) != new_count:
        raise PatchError("a hunk does not have the number of lines its header names")
    return hunk, i


def apply_patch(original: str, patch: FilePatch) -> str:
    """The file with all hunks of `patch` applied, or PatchError naming the hunk that does not match."""
    ends_with_newline = original.endswith("\n") or original == ""
    lines = original.split("\n")
    if ends_with_newline and lines and lines[-1] == "":
        lines.pop()
    result: list[str] = []
    cursor = 0  # index into `lines` of the next line not yet copied
    for number, hunk in enumerate(patch.hunks, start=1):
        start = hunk.old_start - 1
        if start < cursor or lines[start : start + len(hunk.old)] != hunk.old:
            raise PatchError(f"{patch.path}: hunk {number} does not match the file at line {hunk.old_start}")
        result += lines[cursor:start] + hunk.new
        cursor = start + len(hunk.old)
        if cursor == len(lines):  # the hunk reaches the end of the file: it decides about the final newline
            ends_with_newline = not hunk.new_without_final_newline
    result += lines[cursor:]
    return "\n".join(result) + ("\n" if ends_with_newline and result else "")


def changed_lines(patches: list[FilePatch]) -> tuple[int, int]:
    """(added, removed) line counts, for the approval message."""
    return sum(h.added for p in patches for h in p.hunks), sum(h.removed for p in patches for h in p.hunks)
