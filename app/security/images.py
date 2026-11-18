"""Image updates and the Coolify version.

Nightly, the digest of every running image (from the collector's `images` report) is compared with the digest the
registry has for the same tag now, the way Diun does it. Images built on the server (the Coolify apps) have no
registry digest and count as local. With Docker's containerd image store they do have a `RepoDigests` entry, so an
image for which the registry answers "insufficient_scope" to a valid anonymous token (unknown or private repository;
Docker Hub says the same for an unknown tag) counts as local too. Every other failure stays an error.
The update itself is an action, not part of this check.

The Coolify version comes from its API (read-only token); the newest release and its notes from GitHub.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Any, Protocol

import httpx
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.i18n import Locale
from app.models import CheckState
from app.security import hostreports
from app.security.base import CheckBase, ReportKind, Scheduled
from app.security.lines import Line
from app.security.state import load_state, save_state

log = logging.getLogger(__name__)

KIND = "images"
IMAGES_STATE = "image_updates"
COOLIFY_STATE = "coolify_version"
CHECK_AT = time(4, 30)
REPORT_EVERY = timedelta(hours=26)
DOCKER_HUB = "registry-1.docker.io"
MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ]
)
COOLIFY_RELEASES = "https://api.github.com/repos/coollabsio/coolify/releases/latest"
NOTE_LINES = 8


class RegistryError(Exception):
    pass


class NotInRegistry(RegistryError):
    """The registry does not serve this repository to an anonymous client: nothing to compare against."""


@dataclass(frozen=True)
class ImageRef:
    registry: str  # API host
    repository: str
    tag: str
    pinned: bool  # referenced by digest: there is no newer image for it by definition


def parse_ref(ref: str) -> ImageRef:
    """Docker's rules: no host part means Docker Hub, and one-part names live under library/."""
    pinned = "@" in ref
    name = ref.split("@", 1)[0]
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = DOCKER_HUB, name
    if host == "docker.io":
        host = DOCKER_HUB
    if ":" in path.rsplit("/", 1)[-1]:
        repository, tag = path.rsplit(":", 1)
    else:
        repository, tag = path, "latest"
    if host == DOCKER_HUB and "/" not in repository:
        repository = f"library/{repository}"
    return ImageRef(registry=host, repository=repository, tag=tag, pinned=pinned)


class Registry(Protocol):
    async def digest(self, ref: ImageRef) -> str:
        """The digest the registry serves for this tag now."""
        ...


class HttpRegistry:
    """HEAD on the manifest, with an anonymous token when the registry asks for one (Docker Hub, GHCR)."""

    def __init__(self, client: httpx.AsyncClient, locale: Locale) -> None:
        self._client = client
        self._locale = locale

    async def _token(self, challenge: str) -> str:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.pop("realm", "")
        if not realm:
            raise RegistryError(self._locale.t("security.images.unknown_auth", challenge=challenge[:100]))
        response = await self._client.get(realm, params=params, timeout=20)
        response.raise_for_status()
        body = response.json()
        token = str(body.get("token") or body.get("access_token") or "")
        if not token:
            raise RegistryError(self._locale.t("security.images.unknown_auth", challenge=challenge[:100]))
        return token

    async def digest(self, ref: ImageRef) -> str:
        url = f"https://{ref.registry}/v2/{ref.repository}/manifests/{ref.tag}"
        headers = {"Accept": MANIFEST_TYPES}
        try:
            response = await self._client.head(url, headers=headers, timeout=20)
            if response.status_code == 401 and "bearer" in response.headers.get("www-authenticate", "").lower():
                token = await self._token(response.headers["www-authenticate"])
                headers["Authorization"] = f"Bearer {token}"
                response = await self._client.head(url, headers=headers, timeout=20)
                # A valid anonymous token that is not enough for this repository: it does not exist or is private.
                # Docker Hub answers the same for an unknown tag. A rejected token is a real error.
                if response.status_code == 401 and 'error="insufficient_scope"' in response.headers.get(
                    "www-authenticate", ""
                ):
                    raise NotInRegistry(f"{ref.registry}/{ref.repository}:{ref.tag}: insufficient_scope")
            response.raise_for_status()
        except (httpx.HTTPError, ValueError) as exc:  # ValueError: a token answer that is not JSON
            raise RegistryError(f"{ref.registry}/{ref.repository}:{ref.tag}: {exc}") from exc
        digest = str(response.headers.get("docker-content-digest", ""))
        if not digest:
            raise RegistryError(
                self._locale.t(
                    "security.images.no_digest", registry=ref.registry, repository=ref.repository, tag=ref.tag
                )
            )
        return digest


async def image_status(registry: Registry, image: dict[str, Any]) -> dict[str, Any]:
    """current | outdated | pinned | local (built on the server, or unknown or private at the registry) | error."""
    entry = {"image": image.get("image", ""), "containers": image.get("containers", [])}
    running = {str(d).split("@", 1)[1] for d in image.get("repo_digests") or [] if "@" in str(d)}
    if not running:
        return {**entry, "status": "local"}
    ref = parse_ref(str(image.get("image", "")))
    if ref.pinned:
        return {**entry, "status": "pinned"}
    try:
        latest = await registry.digest(ref)
    except NotInRegistry:
        return {**entry, "status": "local"}
    except RegistryError as exc:
        return {**entry, "status": "error", "detail": str(exc)[:300]}
    return {**entry, "status": "current" if latest in running else "outdated", "latest": latest}


@dataclass(frozen=True)
class CoolifyRelease:
    version: str
    notes: str
    url: str


class CoolifySource(Protocol):
    async def current(self) -> str: ...

    async def latest(self) -> CoolifyRelease: ...


class HttpCoolify:
    def __init__(self, client: httpx.AsyncClient, base_url: str, token: SecretStr) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._token = token

    async def current(self) -> str:
        response = await self._client.get(
            f"{self._base_url}/api/v1/version",
            headers={"Authorization": f"Bearer {self._token.get_secret_value()}"},
            timeout=20,
        )
        response.raise_for_status()
        return response.text.strip().strip('"')

    async def latest(self) -> CoolifyRelease:
        response = await self._client.get(
            COOLIFY_RELEASES, headers={"Accept": "application/vnd.github+json"}, timeout=20
        )
        response.raise_for_status()
        body = response.json()
        return CoolifyRelease(str(body["tag_name"]), str(body.get("body") or ""), str(body.get("html_url") or ""))


def version_key(version: str) -> tuple[int, ...]:
    """v4.0.0-beta.420 → (4, 0, 0, 420): good enough to tell newer from older within Coolify's scheme."""
    return tuple(int(n) for n in re.findall(r"\d+", version))


def note_lines(notes: str) -> list[str]:
    """The first bullet points of the release notes, without links and markup."""
    bullets = [line.strip()[2:] for line in notes.splitlines() if line.strip().startswith(("- ", "* "))]
    cleaned = [re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", b).replace("**", "").strip() for b in bullets]
    return [line[:160] for line in cleaned if line][:NOTE_LINES]


class ImageUpdatesCheck(CheckBase):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Callable[[], datetime],
        hosts: list[str],
        registry: Registry,
        coolify: CoolifySource | None,
        *,
        locale: Locale,
    ) -> None:
        self._locale = locale
        self._sessions = sessions
        self._clock = clock
        self._hosts = tuple(hosts)
        self._registry = registry
        self._coolify = coolify

    def report_kinds(self) -> list[ReportKind]:
        return [ReportKind(KIND, self._hosts, REPORT_EVERY)]

    def scheduled(self) -> list[Scheduled]:
        return [Scheduled(IMAGES_STATE, CHECK_AT, self.run)]

    async def run(self, now: datetime) -> None:
        await self._check_images(now)
        await self._check_coolify(now)

    async def _check_images(self, now: datetime) -> None:
        async with self._sessions() as session:
            newest = await hostreports.latest(session, KIND)
        hosts: dict[str, Any] = {}
        cache: dict[str, dict[str, Any]] = {}  # the same image on both servers is asked for once
        for host in self._hosts:
            row = newest.get(host)
            if row is None or hostreports.error_of(row.data):
                hosts[host] = {
                    "error": hostreports.error_of(row.data) if row else self._locale.t("security.images.no_report")
                }
                continue
            statuses = []
            for image in row.data.get("images", []):
                key = f"{image.get('image')}|{sorted(image.get('repo_digests') or [])}"
                if key not in cache:
                    cache[key] = await image_status(self._registry, image)
                statuses.append({**cache[key], "containers": image.get("containers", [])})
            hosts[host] = {"seen_at": row.collected_at.isoformat(), "images": statuses}
        async with self._sessions() as session, session.begin():
            await save_state(session, IMAGES_STATE, {"hosts": hosts}, now)

    async def _check_coolify(self, now: datetime) -> None:
        if self._coolify is None:
            return
        data: dict[str, Any]
        try:
            current = await self._coolify.current()
            release = await self._coolify.latest()
            newer = version_key(release.version) > version_key(current)
            data = {"current": current, "latest": release.version, "newer": newer, "url": release.url}
            if newer:
                data["notes"] = note_lines(release.notes)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            data = {"error": str(exc)[:300]}
        async with self._sessions() as session, session.begin():
            await save_state(session, COOLIFY_STATE, data, now)

    async def weekly_lines(self, now: datetime) -> list[str]:
        async with self._sessions() as session:
            images = await load_state(session, IMAGES_STATE)
            coolify = await load_state(session, COOLIFY_STATE)
        return [*self._image_lines(images, now), *self._coolify_lines(coolify.data if coolify else None)]

    def _image_lines(self, state: CheckState | None, now: datetime) -> list[str]:
        t = self._locale.t
        if not self._hosts:
            return [t("security.images.line.no_hosts")]
        if state is None:
            return [t("security.images.line.never")]
        data = state.data
        lines = []
        if now - state.updated_at > REPORT_EVERY:
            lines.append(t("security.images.line.last_check", at=self._locale.day(state.updated_at)))
        for host in self._hosts:
            entry = data.get("hosts", {}).get(host)
            if entry is None or "error" in entry:
                reason = (entry or {}).get("error", t("security.images.no_report"))
                lines.append(t("security.images.line.not_checked", host=host, reason=reason))
                continue
            by_status: dict[str, list[dict[str, Any]]] = {}
            for image in entry["images"]:
                by_status.setdefault(image["status"], []).append(image)
            outdated = by_status.get("outdated", [])
            counts = ", ".join(
                f"{len(by_status[s])} {t(f'security.images.status.{s}')}"
                for s in ("current", "outdated", "pinned", "local", "error")
                if by_status.get(s)
            )
            lines.append(
                t("security.images.line.counts", host=host, counts=counts or t("security.images.line.no_containers"))
            )
            lines += [
                Line(
                    t("security.images.line.newer", image=i["image"], containers=", ".join(i["containers"])),
                    needs_action=True,
                )
                for i in outdated
            ]
            lines += [
                t("security.images.line.error", image=i["image"], detail=i.get("detail", ""))
                for i in by_status.get("error", [])
            ]
        return lines

    def _coolify_lines(self, data: dict[str, Any] | None) -> list[str]:
        t = self._locale.t
        if self._coolify is None:
            return [t("security.coolify.no_token")]
        if data is None:
            return [t("security.coolify.never")]
        if "error" in data:
            return [t("security.coolify.failed", error=data["error"])]
        if not data.get("newer"):
            return [t("security.coolify.current", current=data["current"])]
        lines = [t("security.coolify.newer", current=data["current"], latest=data["latest"], url=data.get("url", ""))]
        return lines + [f"• {note}" for note in data.get("notes", [])]
