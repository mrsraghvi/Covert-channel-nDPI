import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import { useLiveData } from "./useLiveData";

vi.mock("../lib/api", () => ({
  api: { health: vi.fn().mockResolvedValue(undefined) },
  connectSocket: vi.fn(),
  ApiAuthError: class ApiAuthError extends Error {},
  getApiKey: vi.fn(() => null),
  ipFromHostPort: vi.fn((endpoint) => endpoint),
  normalizeFlow: vi.fn((flow) => flow),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("useLiveData demo flow totals", () => {
  it("paces demo flows and alerts while keeping cumulative totals and a 300-flow window", () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.99);
    const { result } = renderHook(() => useLiveData());

    act(() => result.current.useDemoInstead());

    expect(result.current.stats.total_flows).toBe(10);
    expect(result.current.flows).toHaveLength(10);
    expect(result.current.stats.total_alerts).toBe(0);
    const seedPacketRate = result.current.flows.reduce((sum, flow) => sum + flow.packets, 0) / 27;
    expect(result.current.stats.packets_per_sec).toBeCloseTo(seedPacketRate);

    act(() => vi.advanceTimersByTime(2999));
    expect(result.current.stats.total_flows).toBe(10);

    act(() => vi.advanceTimersByTime(1));

    expect(result.current.stats.total_flows).toBe(11);
    expect(result.current.stats.covert_flows).toBe(0);
    expect(result.current.stats.total_alerts).toBe(0);

    act(() => vi.advanceTimersByTime(3000 * 9));
    expect(result.current.stats.total_flows).toBe(20);
    expect(result.current.stats.covert_flows).toBe(1);
    expect(result.current.stats.total_alerts).toBe(1);
    expect(result.current.alerts).toHaveLength(1);

    act(() => vi.advanceTimersByTime(3000 * 300));

    expect(result.current.stats.total_flows).toBe(320);
    expect(result.current.flows).toHaveLength(300);
    expect(result.current.stats.total_alerts).toBe(16);
    expect(result.current.alerts).toHaveLength(16);
  });
});
