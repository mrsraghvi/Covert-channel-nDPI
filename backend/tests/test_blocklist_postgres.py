import ipaddress
import os
import secrets
import unittest

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from app import main
from app.database import Base, BlockedIP
from app.schemas import BlockCreate


class BlocklistPostgresIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        database_url = os.getenv("COVERTSCOPE_TEST_DATABASE_URL")
        if not database_url:
            self.skipTest("set COVERTSCOPE_TEST_DATABASE_URL to run PostgreSQL integration tests")

        database_url_parts = database_url.split("/")
        if not database_url.startswith("postgresql+asyncpg://") or database_url_parts[-1] != "covertscope_test":
            self.fail("integration tests require a PostgreSQL async URL targeting the covertscope_test database")

        self.engine = create_async_engine(database_url, pool_pre_ping=True)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.original_session_factory = main.AsyncSessionLocal
        main.AsyncSessionLocal = self.session_factory

        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        octets = secrets.token_bytes(2)
        self.ip = str(ipaddress.IPv4Address(bytes([198, 18, *octets])))
        self.request = Request({
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/blocklist",
            "raw_path": b"/api/blocklist",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        })

    async def asyncTearDown(self):
        if not hasattr(self, "engine"):
            return

        try:
            async with self.session_factory() as session:
                await session.execute(
                    BlockedIP.__table__.delete().where(BlockedIP.ip == self.ip)
                )
                await session.commit()
            main.engine.unblock_ip(self.ip)
        finally:
            main.AsyncSessionLocal = self.original_session_factory
            await self.engine.dispose()

    async def test_block_reblock_and_unblock_persist_in_postgres(self):
        first = await main.block_ip(
            BlockCreate(ip=self.ip, reason="initial integration block"),
            self.request,
        )
        self.assertTrue(first.active)
        first_id = first.id

        async with self.session_factory() as session:
            persisted = await session.scalar(
                select(BlockedIP).where(BlockedIP.ip == self.ip)
            )
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.id, first_id)
            self.assertEqual(persisted.reason, "initial integration block")
            self.assertTrue(persisted.active)

        await main.unblock_ip(self.ip, self.request)

        async with self.session_factory() as session:
            persisted = await session.scalar(
                select(BlockedIP).where(BlockedIP.ip == self.ip)
            )
            self.assertFalse(persisted.active)

        reblocked = await main.block_ip(
            BlockCreate(ip=self.ip, reason="updated integration reason"),
            self.request,
        )
        self.assertEqual(reblocked.id, first_id)
        self.assertTrue(reblocked.active)

        active_rows = await main.list_blocklist(active_only=True, limit=1000)
        active_match = next((row for row in active_rows if row.ip == self.ip), None)
        self.assertIsNotNone(active_match)
        self.assertEqual(active_match.reason, "updated integration reason")

        await main.unblock_ip(self.ip, self.request)
        active_rows = await main.list_blocklist(active_only=True, limit=1000)
        self.assertFalse(any(row.ip == self.ip for row in active_rows))


if __name__ == "__main__":
    unittest.main()
