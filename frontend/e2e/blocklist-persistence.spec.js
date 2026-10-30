import { test, expect } from "@playwright/test";
import { API_BASE, apiHeaders, expectUnauthenticated, installApiKey } from "./support.js";

const TEST_IP = "192.0.2.254";

test("unblocks a persisted advisory entry from Control", async ({ page, request }) => {
  await expectUnauthenticated(request);

  const beforeResponse = await request.get(`${API_BASE}/blocklist?limit=1000`, { headers: apiHeaders() });
  expect(beforeResponse.status()).toBe(200);
  const priorEntry = (await beforeResponse.json()).find((entry) => entry.ip === TEST_IP);
  const originalReason = priorEntry?.reason ?? null;

  const seeded = await request.post(`${API_BASE}/blocklist`, {
    headers: apiHeaders(),
    data: { ip: TEST_IP, reason: "CovertScope browser E2E fixture" },
  });
  expect(seeded.status()).toBe(200);

  try {
    await installApiKey(page);
    await page.goto("/control");
    await expect(page.getByRole("heading", { name: "Control" })).toBeVisible();
    await expect(page.getByText(TEST_IP, { exact: true })).toBeVisible();

    const row = page.getByText(TEST_IP, { exact: true }).locator("xpath=../..");
    await row.getByRole("button", { name: "Unblock" }).click();
    await expect(page.getByText("No IPs currently blocked.")).toBeVisible();

    const persistedResponse = await request.get(`${API_BASE}/blocklist?limit=1000`, { headers: apiHeaders() });
    expect(persistedResponse.status()).toBe(200);
    const persistedEntry = (await persistedResponse.json()).find((entry) => entry.ip === TEST_IP);
    expect(persistedEntry).toBeTruthy();
    expect(persistedEntry.active).toBe(false);
  } finally {
    if (priorEntry?.active) {
      const restored = await request.post(`${API_BASE}/blocklist`, {
        headers: apiHeaders(),
        data: { ip: TEST_IP, reason: originalReason },
      });
      expect(restored.status()).toBe(200);
    } else {
      const cleanup = await request.delete(`${API_BASE}/blocklist/${TEST_IP}`, { headers: apiHeaders() });
      expect(cleanup.status()).toBe(200);
      if (priorEntry) {
        const restored = await request.post(`${API_BASE}/blocklist`, {
          headers: apiHeaders(),
          data: { ip: TEST_IP, reason: originalReason },
        });
        expect(restored.status()).toBe(200);
        const deactivated = await request.delete(`${API_BASE}/blocklist/${TEST_IP}`, { headers: apiHeaders() });
        expect(deactivated.status()).toBe(200);
      }
    }
  }
});
