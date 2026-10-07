import { describe, expect, it } from "vitest";
import { formatEndpoint, ipFromHostPort, normalizeFlow } from "./api";
import { genAlert } from "./demoData";

describe("IP endpoint helpers", () => {
  it("formats and extracts IPv4 endpoints", () => {
    const endpoint = formatEndpoint("192.0.2.10", 443);

    expect(endpoint).toBe("192.0.2.10:443");
    expect(ipFromHostPort(endpoint)).toBe("192.0.2.10");
  });

  it("brackets IPv6 endpoints and extracts the unbracketed address", () => {
    const endpoint = formatEndpoint("2001:db8::1", 443);

    expect(endpoint).toBe("[2001:db8::1]:443");
    expect(ipFromHostPort(endpoint)).toBe("2001:db8::1");
  });

  it("normalizes IPv6 fields from the flows API response for the dashboard", () => {
    expect(normalizeFlow({
      src_ip: "2001:db8::1",
      src_port: 41000,
      dst_ip: "2001:db8::2",
      dst_port: 443,
    })).toMatchObject({
      src: "[2001:db8::1]:41000",
      dst: "[2001:db8::2]:443",
    });
  });

  it("extracts IPv6 addresses for demo alerts", () => {
    const alert = genAlert({
      id: 1,
      src: "[2001:db8::1]:443",
      dst: "[2001:db8::2]:8443",
      covert_type: "HTTP",
      anomaly_score: 0.8,
      payload_entropy: 5.2,
      iat_cv: 0.5,
      ts: 1,
    });

    expect(alert.src_ip).toBe("2001:db8::1");
    expect(alert.dst_ip).toBe("2001:db8::2");
  });
});
