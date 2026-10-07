from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine

_ALEMBIC_CONFIG = Path(__file__).resolve().parents[1] / "alembic.ini"


def _upgrade(connection, _config_path: str) -> None:
    config = Config(_config_path)
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


async def upgrade_database(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(_upgrade, str(_ALEMBIC_CONFIG))
