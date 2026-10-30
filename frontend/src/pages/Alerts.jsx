import { useMemo, useState } from "react";
import { PageHeader, SectionLabel } from "./Dashboard";
import { ConfidenceBadge, EmptyState, BlockedBadge } from "../components/Primitives";
import BlockConfirmModal from "../components/BlockConfirmModal";
import { api } from "../lib/api";

const CONFIDENCE_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const TYPES = ["ALL", "TIMING", "DNS", "HTTP", "ICMP", "GENERIC"];

export default function Alerts({ alerts, blockedIps = new Map(), onBlock, onUnblock, onAcknowledge }) {
  const [minConfidence, setMinConfidence] = useState("LOW");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [expanded, setExpanded] = useState(null);
  const [acked, setAcked] = useState(() => new Set());
  const [blockTarget, setBlockTarget] = useState(null); // { ip, alertId, covertType }

  const filtered = useMemo(() => {
    const floor = CONFIDENCE_ORDER[minConfidence] ?? 0;
    return [...alerts]
      .reverse()
      .filter((a) => (CONFIDENCE_ORDER[a.confidence] ?? 0) >= floor)
      .filter((a) => (typeFilter === "ALL" ? true : a.covert_type === typeFilter));
  }, [alerts, minConfidence, typeFilter]);

  async function handleAck(alert) {
    setAcked((prev) => new Set(prev).add(alert.id));
    onAcknowledge?.(alert.id);
    try {
      await api.ackAlert(alert.id);
    } catch {
      /* demo mode / offline — local-only ack is fine */
    }
  }

  function openBlockConfirm(alert) {
    setBlockTarget({ ip: alert.src_ip, alertId: alert.id, covertType: alert.covert_type, confidence: alert.confidence });
  }

  function confirmBlock(reason) {
    if (blockTarget) onBlock?.(blockTarget.ip, reason, blockTarget.alertId);
    setBlockTarget(null);
  }

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of alerts) c[a.confidence] = (c[a.confidence] || 0) + 1;
    return c;
  }, [alerts]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <PageHeader
        title="Alerts"
        subtitle="Combined statistical + ML detections, tiered by confidence. Expand a card for the full reasoning and remediation guidance."
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((tier) => (
          <button
            key={tier}
            onClick={() => setMinConfidence(tier)}
            className="card focus-ring"
            style={{
              padding: "14px 16px", textAlign: "left", cursor: "pointer",
              border: minConfidence === tier ? "1px solid var(--signal-cyan)" : "1px solid var(--hairline)",
              background: "var(--panel)",
            }}
          >
            <div className="eyebrow" style={{ marginBottom: 6 }}>{tier}</div>
            <div className="mono" style={{ fontSize: 22, fontWeight: 700 }}>{counts[tier]}</div>
          </button>
        ))}
      </div>

      <div className="card" style={{ padding: 16, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <span className="eyebrow">Covert type</span>
        {TYPES.map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            className="mono focus-ring"
            style={{
              fontSize: 11.5, fontWeight: 600, padding: "5px 10px", borderRadius: 999, cursor: "pointer",
              color: typeFilter === t ? "var(--bg)" : "var(--text-secondary)",
              background: typeFilter === t ? "var(--signal-cyan)" : "var(--panel-raised)",
              border: "1px solid var(--hairline)",
            }}
          >
            {t}
          </button>
        ))}
        <div style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)" }} className="mono">
          {filtered.length} shown
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="card"><EmptyState title="No alerts match these filters" body="Try lowering the minimum confidence tier." /></div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {filtered.map((a) => {
            const isOpen = expanded === (a.id ?? a.flow_id);
            const isAcked = a.acknowledged || acked.has(a.id);
            return (
              <div key={a.id ?? `${a.flow_id}-${a.created_at}`} className="card" style={{ padding: 0, overflow: "hidden" }}>
                <button
                  onClick={() => setExpanded(isOpen ? null : (a.id ?? a.flow_id))}
                  className="focus-ring"
                  style={{
                    width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "14px 18px", background: "transparent", border: "none", cursor: "pointer", textAlign: "left",
                    opacity: isAcked ? 0.55 : 1,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 14, minWidth: 0 }}>
                    <ConfidenceBadge level={a.confidence} />
                    <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{a.covert_type}</span>
                    <span style={{ fontSize: 12.5, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      flow #{a.flow_id}
                    </span>
                    {a.src_ip && (
                      <span className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{a.src_ip}</span>
                    )}
                    {(a.blocked || blockedIps.has(a.src_ip)) && <BlockedBadge />}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--signal-amber)" }}>
                      {((a.final_score || 0) * 100).toFixed(0)}%
                    </span>
                    <span style={{ color: "var(--text-muted)", fontSize: 11 }}>{isOpen ? "▲" : "▼"}</span>
                  </div>
                </button>
                {isOpen && (
                  <div style={{ padding: "0 18px 18px", borderTop: "1px solid var(--hairline-soft)" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: 14 }}>
                      <div>
                        <SectionLabel>Detection reason</SectionLabel>
                        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, margin: 0 }}>{a.reason}</p>
                      </div>
                      <div>
                        <SectionLabel>Recommended action</SectionLabel>
                        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, margin: 0 }}>{a.recommendation}</p>
                      </div>
                    </div>
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 16 }}>
                      {a.src_ip && (blockedIps.has(a.src_ip) ? (
                        <button
                          onClick={() => onUnblock?.(a.src_ip)}
                          className="mono focus-ring"
                          style={{
                            fontSize: 12, fontWeight: 600, padding: "7px 14px", borderRadius: 7,
                            cursor: "pointer", color: "var(--text-secondary)",
                            background: "var(--panel-raised)", border: "1px solid var(--hairline)",
                          }}
                        >
                          Unblock {a.src_ip}
                        </button>
                      ) : (
                        <button
                          onClick={() => openBlockConfirm(a)}
                          className="mono focus-ring"
                          style={{
                            fontSize: 12, fontWeight: 600, padding: "7px 14px", borderRadius: 7,
                            cursor: "pointer", color: "var(--signal-red)",
                            background: "var(--signal-red)14", border: "1px solid var(--signal-red)55",
                          }}
                        >
                          Block {a.src_ip}
                        </button>
                      ))}
                      <button
                        onClick={() => handleAck(a)}
                        disabled={isAcked}
                        className="mono focus-ring"
                        style={{
                          fontSize: 12, fontWeight: 600, padding: "7px 14px", borderRadius: 7,
                          cursor: isAcked ? "default" : "pointer",
                          color: isAcked ? "var(--text-muted)" : "var(--bg)",
                          background: isAcked ? "var(--panel-raised)" : "var(--signal-cyan)",
                          border: "1px solid var(--hairline)",
                        }}
                      >
                        {isAcked ? "Acknowledged" : "Acknowledge alert"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {blockTarget && (
        <BlockConfirmModal
          ip={blockTarget.ip}
          defaultReason={`${blockTarget.covertType} covert-channel alert, confidence ${blockTarget.confidence}`}
          onConfirm={confirmBlock}
          onCancel={() => setBlockTarget(null)}
        />
      )}
    </div>
  );
}
