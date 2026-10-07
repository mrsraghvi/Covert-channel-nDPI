export function ipFromHostPort(hostPort) {
  if (!hostPort || typeof hostPort !== "string") return hostPort;
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end >= 0 && hostPort[end + 1] === ":") return hostPort.slice(1, end);
  }
  const idx = hostPort.lastIndexOf(":");
  return idx === -1 ? hostPort : hostPort.slice(0, idx);
}

export function formatEndpoint(ip, port) {
  if (typeof ip !== "string") return "";
  if (port == null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function normalizeFlow(flow) {
  return {
    ...flow,
    src: flow.src ?? formatEndpoint(flow.src_ip, flow.src_port),
    dst: flow.dst ?? formatEndpoint(flow.dst_ip, flow.dst_port),
  };
}

const API_KEY_STORAGE = "covertscope_api_key";

function getApiBase() {
  if (typeof window === "undefined") return "/api";

  const host = window.location.hostname;
  const port = window.location.port;

  // The production Docker frontend container is static HTML on port 3000;
  // the browser cannot proxy /api to the backend container from that origin.
  // Use the backend service directly in that topology.
  if (host === "localhost" && port === "3000") {
    return "http://localhost:8000/api";
  }

  return "/api";
}

const BASE = getApiBase();

// The API key is entered by the operator at runtime (see ApiKeyGate.jsx) and
// held only in sessionStorage — it is never baked into the build, so the
// static bundle served by nginx contains no secret. sessionStorage clears on
// tab close, which is the right tradeoff for a lab tool: convenient enough
// not to re-enter the key on every page nav, but not persisted like
// localStorage would be.
export function getApiKey() {
  if (typeof window === "undefined") return "";
  try {
    return window.sessionStorage.getItem(API_KEY_STORAGE) || "";
  } catch (_) {
    return "";
  }
}

export function setApiKey(key) {
  if (typeof window === "undefined") return;
  try {
    if (key) window.sessionStorage.setItem(API_KEY_STORAGE, key);
    else window.sessionStorage.removeItem(API_KEY_STORAGE);
  } catch (_) {
    /* sessionStorage unavailable (e.g. privacy mode) — key just won't persist */
  }
}

export class ApiAuthError extends Error {
  constructor(path) {
    super(`unauthorized: ${path}`);
    this.name = "ApiAuthError";
  }
}

async function req(path, opts = {}) {
  const key = getApiKey();
  const headers = { "Content-Type": "application/json", ...opts.headers };
  if (key) headers["X-API-Key"] = key;

  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (res.status === 401) throw new ApiAuthError(path);
  if (!res.ok) throw new Error(`${opts.method || "GET"} ${path} -> ${res.status}`);
  return res.json();
}

async function uploadPcap(file) {
  const headers = {};
  const key = getApiKey();
  if (key) headers["X-API-Key"] = key;
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${BASE}/capture/replay`, {
    method: "POST",
    headers,
    body,
  });
  if (res.status === 401) throw new ApiAuthError("/capture/replay");
  if (!res.ok) {
    const detail = await res.json().catch(() => null);
    throw new Error(detail?.detail || `POST /capture/replay -> ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => req("/health"),
  stats: () => req("/stats"),
  flows: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return req(`/flows${qs ? `?${qs}` : ""}`);
  },
  alerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return req(`/alerts${qs ? `?${qs}` : ""}`);
  },
  ackAlert: (id) => req(`/alerts/${id}/ack`, { method: "POST" }),
  captureStart: (body) => req("/capture/start", { method: "POST", body: JSON.stringify(body) }),
  captureStop: () => req("/capture/stop", { method: "POST" }),
  replayPcap: uploadPcap,
  generatorStart: (body) => req("/generator/start", { method: "POST", body: JSON.stringify(body) }),
  generatorStop: () => req("/generator/stop", { method: "POST" }),
  thresholds: () => req("/thresholds"),
  putThreshold: (key, value) => req("/thresholds", { method: "PUT", body: JSON.stringify({ key, value }) }),
  report: () => req("/report"),
  wsTicket: () => req("/ws-ticket", { method: "POST" }),
  blocklist: () => req("/blocklist"),
  blockIp: (ip, reason, alertId) =>
    req("/blocklist", { method: "POST", body: JSON.stringify({ ip, reason, alert_id: alertId ?? null }) }),
  unblockIp: (ip) => req(`/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" }),
};

export async function connectSocket(onMessage) {
  if (typeof window === "undefined") return null;

  const host = window.location.hostname;
  const port = window.location.port;

  let wsBase;
  if (host === "localhost" && port === "3000") {
    wsBase = `ws://localhost:8000/ws`;
  } else {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    wsBase = `${proto}://${window.location.host}/ws`;
  }

  // Exchange the durable API key for a single-use, 30s ticket rather than
  // putting the key itself in the WS URL — a query string ends up in
  // browser history and any access logs along the way, which a short-lived
  // one-time ticket avoids. Falls back to the raw key only if the ticket
  // endpoint is unreachable (e.g. an older backend), so this still works
  // end-to-end during a rolling upgrade.
  let wsUrl;
  try {
    const { ticket } = await api.wsTicket();
    wsUrl = `${wsBase}?ticket=${encodeURIComponent(ticket)}`;
  } catch (_) {
    const key = getApiKey();
    wsUrl = key ? `${wsBase}?key=${encodeURIComponent(key)}` : wsBase;
  }

  const ws = new WebSocket(wsUrl);
  ws.onmessage = (evt) => {
    try {
      onMessage(JSON.parse(evt.data));
    } catch (_) {
      /* ignore malformed frames */
    }
  };
  return ws;
}
