import { test, expect } from "@playwright/test";
import { API_BASE, apiHeaders, expectUnauthenticated, installApiKey } from "./support.js";

test("starts and stops live capture while displaying the flow dashboard", async ({ page, request }) => {
  test.setTimeout(60_000);
  await expectUnauthenticated(request);

  const initialStatsResponse = await request.get(`${API_BASE}/stats`, { headers: apiHeaders() });
  expect(initialStatsResponse.status()).toBe(200);
  const initialStats = await initialStatsResponse.json();
  expect(initialStats.active_capture).toBe(false);

  const flowFixture = {
    id: 920001,
    flow_uid: 920001,
    src_ip: "192.0.2.21",
    src_port: 45678,
    dst_ip: "198.51.100.27",
    dst_port: 443,
    l4_proto: "TCP",
    ndpi_protocol: "HTTPS",
    packets: 12,
    bytes: 6400,
    duration_ms: 2400,
    iat_mean: 200,
    iat_cv: 0.12,
    payload_entropy: 4.1,
    covert_flags: 0,
    anomaly_score: 0.18,
    is_covert: false,
    blocked: false,
    created_at: "2026-10-30T12:00:00Z",
  };
  await page.route("**/api/flows**", (route) => route.fulfill({ json: [flowFixture] }));
  await page.route("**/api/stats", (route) => route.fulfill({
    json: {
      total_flows: 1,
      total_alerts: 0,
      covert_flows: 0,
      active_capture: false,
      protocol_distribution: { HTTPS: 1 },
      confidence_distribution: {},
      covert_type_distribution: {},
      avg_entropy: 4.1,
      packets_per_sec: 1,
      bytes_per_sec: 100,
    },
  }));

  await installApiKey(page);
  await page.goto("/control");
  await expect(page.getByRole("heading", { name: "Control" })).toBeVisible();

  let captureStarted = false;
  try {
    await page.getByRole("combobox").first().selectOption("live");
    const startResponsePromise = page.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname.endsWith("/api/capture/start")
    );
    await page.getByRole("button", { name: "Start capture" }).click();
    const startResponse = await startResponsePromise;
    expect(startResponse.status()).toBe(200);
    captureStarted = true;
    await expect(page.getByText(/Waiting for the nDPI C engine to connect/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Stop capture" })).toBeVisible();

    await page.getByRole("button", { name: "Stop capture" }).click();
    captureStarted = false;
    await expect(page.getByText("Capture stopped")).toBeVisible();

    const stoppedStats = await request.get(`${API_BASE}/stats`, { headers: apiHeaders() });
    expect(stoppedStats.status()).toBe(200);
    expect((await stoppedStats.json()).active_capture).toBe(false);

    await page.goto("/flows");
    await expect(page.getByRole("heading", { name: "Flows" })).toBeVisible();
    await expect(page.getByRole("row").nth(1)).toBeVisible();
    await expect(page.getByText(`${flowFixture.src_ip}:${flowFixture.src_port}`)).toBeVisible();

    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Live overview" })).toBeVisible();
    await expect.poll(async () => {
      const value = await page.getByText("Flows observed").locator("..").locator("span").first().textContent();
      return Number(value);
    }, { timeout: 12_000 }).toBeGreaterThan(0);
  } finally {
    if (captureStarted) {
      const stopResponse = await request.post(`${API_BASE}/capture/stop`, { headers: apiHeaders() });
      expect([200, 409]).toContain(stopResponse.status());
    }
  }
});
