export function StatCard({ eyebrow, value, unit, delta, accent = "var(--signal-cyan)", trace }) {
  return (
    <div className="card" style={{ padding: "18px 20px", display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
      <div className="eyebrow">{eyebrow}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
        <span className="mono" style={{ fontSize: 28, fontWeight: 600, color: "var(--text-primary)" }}>{value}</span>
        {unit && <span style={{ fontSize: 13, color: "var(--text-muted)" }}>{unit}</span>}
      </div>
      {delta !== undefined && (
        <div style={{ fontSize: 12, color: accent, fontFamily: "var(--font-mono)" }}>{delta}</div>
      )}
      {trace}
    </div>
  );
}

const CONF_COLORS = {
  CRITICAL: "var(--signal-red)",
  HIGH: "var(--signal-amber)",
  MEDIUM: "var(--signal-violet)",
  LOW: "var(--text-muted)",
};

export function ConfidenceBadge({ level }) {
  const color = CONF_COLORS[level] || "var(--text-muted)";
  return (
    <span
      className="mono"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 9px",
        borderRadius: 999,
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: "0.04em",
        color,
        border: `1px solid ${color}55`,
        background: `${color}14`,
      }}
    >
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, display: "inline-block" }} />
      {level}
    </span>
  );
}

const PROTO_COLORS = {
  DNS: "var(--signal-amber)",
  HTTP: "var(--signal-amber)",
  HTTPS: "var(--signal-cyan)",
  TLS: "var(--signal-cyan)",
  QUIC: "var(--signal-cyan)",
  ICMP: "var(--signal-red)",
  SSH: "var(--signal-cyan)",
  NTP: "var(--text-muted)",
};

export function ProtocolPill({ protocol }) {
  const color = PROTO_COLORS[protocol] || "var(--text-secondary)";
  return (
    <span
      className="mono"
      style={{
        fontSize: 11, fontWeight: 600, color,
        border: `1px solid ${color}40`, background: `${color}10`,
        padding: "2px 8px", borderRadius: 5,
      }}
    >
      {protocol || "Unknown"}
    </span>
  );
}

export function EmptyState({ title, body }) {
  return (
    <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-muted)" }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 13 }}>{body}</div>
    </div>
  );
}

export function BlockedBadge() {
  return (
    <span
      className="mono"
      style={{
        display: "inline-flex", alignItems: "center", gap: 5,
        padding: "2px 8px", borderRadius: 5, fontSize: 10.5, fontWeight: 700,
        letterSpacing: "0.03em", color: "var(--signal-red)",
        border: "1px solid var(--signal-red)55", background: "var(--signal-red)14",
      }}
    >
      ⛔ BLOCKED
    </span>
  );
}
