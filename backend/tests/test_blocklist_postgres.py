import ipaddress
import os
import secrets
import unittest

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

import app.engine as engine_module
from app import main
from app.database import BlockedIP, Flow
from app.engine import IngestEngine
from app.migrations import upgrade_database
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
        self.original_engine_session_factory = engine_module.AsyncSessionLocal
        main.AsyncSessionLocal = self.session_factory

        await upgrade_database(self.engine)

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
            engine_module.AsyncSessionLocal = self.original_engine_session_factory
            await self.engine.dispose()

    async def test_flow_ingest_persists_and_reads_postgres_inet_addresses(self):
        engine_module.AsyncSessionLocal = self.session_factory
        ingest_engine = IngestEngine(main.ws_manager)
        flow = None

        try:
            flow, _ = await ingest_engine.ingest({
                "flow_id": 987654321,
                "src": "192.0.2.11:12345",
                "dst": "198.51.100.17:443",
                "protocol": "HTTPS",
                "l4_proto": "TCP",
                "packets": 4,
                "bytes": 2400,
                "duration_ms": 1500,
                "iat_mean": 375.0,
                "iat_variance": 120.0,
                "payload_entropy": 4.2,
            })

            async with self.session_factory() as session:
                persisted = await session.get(Flow, flow.id)
                self.assertEqual(str(persisted.src_ip), "192.0.2.11")
                self.assertEqual(str(persisted.dst_ip), "198.51.100.17")

            api_flows = await main.get_flows(limit=1000)
            api_flow = next(item for item in api_flows if item.id == flow.id)
            self.assertEqual(api_flow.src_ip, "192.0.2.11")
            self.assertEqual(api_flow.dst_ip, "198.51.100.17")
        finally:
            if flow is not None:
                async with self.session_factory() as session:
                    await session.execute(Flow.__table__.delete().where(Flow.id == flow.id))
                    await session.commit()

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

        await upgrade_database(self.engine)
        async with self.session_factory() as session:
            persisted = await session.scalar(
                select(BlockedIP).where(BlockedIP.ip == self.ip)
            )
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.id, first_id)

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
