import { test, expect } from "@playwright/test";
import { API_BASE, apiKey, expectUnauthenticated } from "./support.js";

test("rejects an invalid API key, then connects with a valid key", async ({ page, request }) => {
  await expectUnauthenticated(request);
  await page.goto("/");

  const keyInput = page.getByPlaceholder("Paste API key");
  await expect(keyInput).toBeVisible();
  await keyInput.fill("invalid-e2e-api-key");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(keyInput).toBeVisible();

  await keyInput.fill(apiKey());
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByText("LIVE — nDPI engine")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live overview" })).toBeVisible();

  const authorized = await request.get(`${API_BASE}/stats`, {
    headers: { "X-API-Key": apiKey() },
  });
  expect(authorized.status()).toBe(200);
});
