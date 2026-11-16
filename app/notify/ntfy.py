import httpx
from pydantic import SecretStr

from app.config import Person
from app.i18n import Locale
from app.notify.base import IncidentView


class NtfyPager:
    """Wakes a person through a push notification. The topic is the secret, so one topic per person."""

    def __init__(self, base_url: str, token: SecretStr | None, client: httpx.AsyncClient, locale: Locale) -> None:
        self._locale = locale
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token.get_secret_value()}"} if token else {}
        self._client = client

    async def page(self, person: Person, view: IncidentView, *, escalated: bool) -> None:
        prefix = self._locale.t("ntfy.escalated") if escalated else ""
        title = f"{prefix}{view.severity} {view.title}"
        response = await self._client.post(
            self._base_url,
            headers=self._headers,
            json={
                "topic": person.ntfy_topic,
                "title": title,
                "message": view.summary or view.title,
                "priority": 5,
                "tags": ["rotating_light"],
                "click": view.url,
            },
        )
        response.raise_for_status()
