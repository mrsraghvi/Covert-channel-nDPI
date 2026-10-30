import { expect } from "@playwright/test";

export const API_BASE = process.env.E2E_API_BASE || "http://127.0.0.1:8000/api";

export function apiKey() {
  const key = process.env.COVERTSCOPE_API_KEY;
  if (!key) {
    throw new Error("Set COVERTSCOPE_API_KEY to the running backend's API key before running E2E tests.");
  }
  return key;
}

export function apiHeaders() {
  return { "X-API-Key": apiKey() };
}

export async function installApiKey(page) {
  await page.addInitScript((key) => {
    window.sessionStorage.setItem("covertscope_api_key", key);
  }, apiKey());
}

export async function expectUnauthenticated(request) {
  const response = await request.get(`${API_BASE}/stats`);
  expect(response.status()).toBe(401);
}
