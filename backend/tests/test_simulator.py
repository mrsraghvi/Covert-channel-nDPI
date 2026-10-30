from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import patch

from app import simulator


class SimulatorTests(unittest.IsolatedAsyncioTestCase):
    def test_default_covert_ratio_is_five_percent(self):
        ratio = inspect.signature(simulator.run_simulator).parameters["covert_ratio"].default

        self.assertEqual(ratio, 0.05)

    async def test_simulator_waits_between_synthetic_flows(self):
        stop_event = asyncio.Event()
        records = []

        async def stop_after_twenty_ticks(_delay):
            if len(records) == 20:
                stop_event.set()

        with (
            patch.object(simulator.random, "uniform", side_effect=lambda low, high: (low + high) / 2),
            patch.object(simulator.asyncio, "sleep", side_effect=stop_after_twenty_ticks) as sleep,
        ):
            class Engine:
                async def ingest(self, _record):
                    records.append(_record)

            await simulator.run_simulator(Engine(), stop_event)

        self.assertEqual(len(records), 20)
        self.assertEqual([index + 1 for index, record in enumerate(records) if record["covert_flags"]], [20])
        for call in sleep.await_args_list:
            delay = call.args[0]
            self.assertGreaterEqual(delay, simulator.MIN_FLOW_INTERVAL_SECONDS)
            self.assertLessEqual(delay, simulator.MAX_FLOW_INTERVAL_SECONDS)


if __name__ == "__main__":
    unittest.main()
