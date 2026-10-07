import { useEffect, useRef, useState, useCallback } from "react";
import { api, connectSocket, ApiAuthError, getApiKey, ipFromHostPort, normalizeFlow } from "../lib/api";
import { genBenignFlow, genCovertFlow, genAlert, makeInitialHistory } from "../lib/demoData";

const MAX_FLOWS = 300;
const MAX_ALERTS = 200;

export function useLiveData() {
  const [connected, setConnected] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [needsApiKey, setNeedsApiKey] = useState(false);
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  // Map<ip, { reason, alertId, createdAt }> — the active soft-blocklist.
  // Backed by the DB in live mode (fetched once, then kept in sync over the
  // WS "blocklist" broadcast so every open tab agrees); local-state-only
  // in demo mode, same as alert acknowledgement.
  const [blockedIps, setBlockedIps] = useState(() => new Map());
  const wsRef = useRef(null);
  const demoTimer = useRef(null);
  const [attempt, setAttempt] = useState(0);
  const [skipAuth, setSkipAuth] = useState(false);

  const retry = useCallback(() => {
    setSkipAuth(false);
    setAttempt((n) => n + 1);
  }, []);

  const useDemoInstead = useCallback(() => {
    setSkipAuth(true);
    setNeedsApiKey(false);
  }, []);

  const blockIp = useCallback(async (ip, reason, alertId) => {
    if (!ip) return;
    setBlockedIps((prev) => new Map(prev).set(ip, { reason, alertId, createdAt: Date.now() }));
    try {
      await api.blockIp(ip, reason, alertId);
    } catch {
      /* demo mode / offline — local-only block still reflects in the UI;
         nothing is actually enforced anywhere in that case either way. */
    }
  }, []);

  const unblockIp = useCallback(async (ip) => {
    if (!ip) return;
    setBlockedIps((prev) => {
      const next = new Map(prev);
      next.delete(ip);
      return next;
    });
    try {
      await api.unblockIp(ip);
    } catch {
      /* demo mode / offline */
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function tryBackend() {
      if (skipAuth) {
        startDemo();
        return;
      }
      try {
        await api.health();
        if (cancelled) return;

        // The backend is reachable. If no key is stored yet, ask for one
        // before hitting any of the authenticated routes below — this is
        // the expected first-run state, not a connectivity failure, so it
        // shouldn't fall through to demo mode.
        if (!getApiKey()) {
          setNeedsApiKey(true);
          return;
        }

        const [initFlows, initAlerts, initStats, initBlocklist] = await Promise.all([
          api.flows({ limit: 100 }),
          api.alerts({ limit: 100 }),
          api.stats(),
          api.blocklist().catch(() => []),
        ]);
        if (cancelled) return;
        setNeedsApiKey(false);
        setConnected(true);
        setDemoMode(false);
        setFlows(initFlows.map(normalizeFlow).reverse());
        setAlerts(initAlerts.reverse());
        setStats(initStats);
        setBlockedIps(new Map(
          initBlocklist.filter((b) => b.active).map((b) => [b.ip, { reason: b.reason, alertId: b.alert_id, createdAt: b.created_at }])
        ));

        const ws = await connectSocket((msg) => {
          if (msg.type === "flow") {
            setFlows((prev) => [...prev.slice(-MAX_FLOWS + 1), msg.flow]);
          } else if (msg.type === "alert") {
            setAlerts((prev) => [...prev.slice(-MAX_ALERTS + 1), msg.alert]);
          } else if (msg.type === "blocklist") {
            setBlockedIps((prev) => {
              const next = new Map(prev);
              if (msg.action === "block") next.set(msg.ip, { reason: msg.reason, createdAt: msg.ts * 1000 });
              else next.delete(msg.ip);
              return next;
            });
          }
        });
        ws.onclose = () => setConnected(false);
        ws.onerror = () => setConnected(false);
        wsRef.current = ws;

        const poll = setInterval(() => {
          api.stats().then(setStats).catch(() => {});
        }, 4000);
        return () => clearInterval(poll);
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiAuthError) {
          // Backend is up but the stored key is wrong/rotated — prompt
          // again rather than silently degrading to demo mode, which would
          // mask what's actually a fixable auth problem.
          setNeedsApiKey(true);
          return;
        }
        startDemo();
      }
    }

    function startDemo() {
      setNeedsApiKey(false);
      setDemoMode(true);
      setConnected(false);
      const { flows: hf, alerts: ha } = makeInitialHistory(60);
      setFlows(hf);
      setAlerts(ha);
      demoTimer.current = setInterval(() => {
        const isCovert = Math.random() < 0.14;
        const flow = isCovert ? genCovertFlow() : genBenignFlow();
        setFlows((prev) => [...prev.slice(-MAX_FLOWS + 1), flow]);
        if (isCovert) {
          const alert = genAlert(flow);
          setAlerts((prev) => [...prev.slice(-MAX_ALERTS + 1), alert]);
        }
      }, 900);
    }

    tryBackend();

    return () => {
      cancelled = true;
      if (wsRef.current) wsRef.current.close();
      if (demoTimer.current) clearInterval(demoTimer.current);
    };
  }, [attempt, skipAuth]);

  // Annotate flows/alerts with a live `blocked` flag derived from the
  // current blocklist, so a re-offending source lights up immediately even
  // on rows that were fetched/rendered before the block was raised.
  const annotatedFlows = flows.map((f) => ({
    ...f,
    blocked: f.blocked || blockedIps.has(ipFromHostPort(f.src)) || blockedIps.has(ipFromHostPort(f.dst)),
  }));
  const annotatedAlerts = alerts.map((a) => ({
    ...a,
    src_ip: a.src_ip ?? ipFromHostPort(a.src),
    blocked: blockedIps.has(a.src_ip ?? ipFromHostPort(a.src)),
  }));

  // derive live stats in demo mode from local flow/alert history
  const derivedStats = demoMode ? deriveStats(flows, alerts) : stats;

  return {
    connected, demoMode, needsApiKey, retry, useDemoInstead,
    flows: annotatedFlows, alerts: annotatedAlerts, stats: derivedStats,
    blockedIps, blockIp, unblockIp,
  };
}

function deriveStats(flows, alerts) {
  const protocol_distribution = {};
  let entropySum = 0;
  for (const f of flows) {
    protocol_distribution[f.protocol] = (protocol_distribution[f.protocol] || 0) + 1;
    entropySum += f.payload_entropy || 0;
  }
  const confidence_distribution = {};
  const covert_type_distribution = {};
  for (const a of alerts) {
    confidence_distribution[a.confidence] = (confidence_distribution[a.confidence] || 0) + 1;
    covert_type_distribution[a.covert_type] = (covert_type_distribution[a.covert_type] || 0) + 1;
  }
  return {
    total_flows: flows.length,
    total_alerts: alerts.length,
    covert_flows: flows.filter((f) => f.is_covert).length,
    active_capture: true,
    protocol_distribution,
    confidence_distribution,
    covert_type_distribution,
    avg_entropy: flows.length ? entropySum / flows.length : 0,
    packets_per_sec: flows.slice(-10).reduce((s, f) => s + f.packets, 0) / 10,
    bytes_per_sec: flows.slice(-10).reduce((s, f) => s + f.bytes, 0) / 10,
  };
}
