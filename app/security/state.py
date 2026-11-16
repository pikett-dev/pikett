from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CheckState


async def save_state(session: AsyncSession, name: str, data: dict[str, Any], at: datetime) -> None:
    await session.execute(
        insert(CheckState)
        .values(name=name, data=data, updated_at=at)
        .on_conflict_do_update(index_elements=["name"], set_={"data": data, "updated_at": at})
    )


async def load_state(session: AsyncSession, name: str) -> CheckState | None:
    return await session.get(CheckState, name)
