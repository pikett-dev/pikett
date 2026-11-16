from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

# Limits of one request. Real vmalert alerts carry a handful of labels and short annotations; anything near
# these numbers is a mistake or an attack, and the text reaches the analysis prompt.
MAX_ALERTS_PER_REQUEST = 100
MAX_LABELS_PER_ALERT = 64
MAX_KEY_LENGTH = 256
MAX_VALUE_LENGTH = 16 * 1024
MAX_URL_LENGTH = 2048

Key = Annotated[str, StringConstraints(max_length=MAX_KEY_LENGTH)]
Value = Annotated[str, StringConstraints(max_length=MAX_VALUE_LENGTH)]


class AlertIn(BaseModel):
    """One alert in the Alertmanager v2 format that vmalert posts."""

    labels: dict[Key, Value] = Field(max_length=MAX_LABELS_PER_ALERT)
    annotations: dict[Key, Value] = Field(default_factory=dict, max_length=MAX_LABELS_PER_ALERT)
    startsAt: datetime | None = None  # noqa: N815 (wire format)
    endsAt: datetime | None = None  # noqa: N815
    generatorURL: str | None = Field(default=None, max_length=MAX_URL_LENGTH)  # noqa: N815

    def is_resolved(self, now: datetime) -> bool:
        """Alertmanager sends the zero time (year 1) for "no end yet"; only a real past time means resolved."""
        return self.endsAt is not None and self.endsAt.year > 1 and self.endsAt <= now
