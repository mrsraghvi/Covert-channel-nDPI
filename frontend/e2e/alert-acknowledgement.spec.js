import { test, expect } from "@playwright/test";
import { API_BASE, apiKey, expectUnauthenticated } from "./support.js";

test("acknowledges an alert and reads the saved state after reload", async ({ page, request }) => {
  await expectUnauthenticated(request);
  const alertId = 910001;
  const flowId = 910101;
  let acknowledged = false;
  const alert = () => ({
    id: alertId,
    flow_id: flowId,
    covert_type: "DNS",
    stat_score: 0.9,
    ml_score: 0.7,
    final_score: 0.88,
    confidence: "HIGH",
    reason: "E2E fixture: high-entropy DNS label",
    recommendation: "Review the source and verify the DNS activity.",
    acknowledged,
    created_at: "2026-10-30T12:00:00Z",
    src_ip: "192.0.2.10",
    dst_ip: "192.0.2.53",
  });

  await page.addInitScript((key) => {
    window.sessionStorage.setItem("covertscope_api_key", key);
  }, apiKey());
  await page.route("**/api/alerts**", async (route) => {
    const requestUrl = new URL(route.request().url());
    if (route.request().method() === "POST" && requestUrl.pathname.endsWith(`/${alertId}/ack`)) {
      acknowledged = true;
      await route.fulfill({ json: { ok: true } });
      return;
    }
    await route.fulfill({ json: [alert()] });
  });

  await page.goto("/alerts");
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  await expect(page.getByText("1 active alert")).toBeVisible();

  await page.getByText(`flow #${flowId}`).click();
  await page.getByRole("button", { name: "Acknowledge alert" }).click();
  await expect(page.getByRole("button", { name: "Acknowledged" })).toBeDisabled();
  await expect(page.getByText("1 active alert")).toHaveCount(0);

  await page.reload();
  await expect(page.getByText(`flow #${flowId}`)).toBeVisible();
  await page.getByText(`flow #${flowId}`).click();
  await expect(page.getByRole("button", { name: "Acknowledged" })).toBeDisabled();
  expect(acknowledged).toBe(true);

  const protectedResponse = await request.get(`${API_BASE}/alerts`, {
    headers: { "X-API-Key": apiKey() },
  });
  expect(protectedResponse.status()).toBe(200);
});
