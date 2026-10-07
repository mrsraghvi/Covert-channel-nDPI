import Waveform from "./Waveform";

export default function Topbar({ connected, demoMode, packetsPerSec = 0, activeAlerts = 0, onOpenApiKey }) {
  const wave = Math.min(1, (packetsPerSec || 0) / 40 + 0.15);
  return (
    <header
      style={{
        height: 60,
        borderBottom: "1px solid var(--hairline)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 24px",
        background: "rgba(10,13,19,0.7)",
        backdropFilter: "blur(6px)",
        position: "sticky",
        top: 0,
        zIndex: 10,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
        <StatusPill connected={connected} demoMode={demoMode} />
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Waveform value={wave} color="var(--signal-cyan)" width={160} height={32} />
          <span className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            {packetsPerSec.toFixed(1)} pkt/s
          </span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {activeAlerts > 0 && (
          <div
            className="mono"
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "6px 12px", borderRadius: 999,
              background: "rgba(239,83,104,0.1)", border: "1px solid rgba(239,83,104,0.35)",
              color: "var(--signal-red)", fontSize: 12, fontWeight: 600,
            }}
          >
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--signal-red)" }} />
            {activeAlerts} active alert{activeAlerts === 1 ? "" : "s"}
          </div>
        )}

        <button
          onClick={onOpenApiKey}
          title="Set/update backend API key"
          className="mono"
          style={{
            background: "transparent", border: "1px solid var(--hairline)",
            color: "var(--text-secondary)", borderRadius: 8, padding: "6px 10px",
            fontSize: 11.5, cursor: "pointer",
          }}
        >
          🔑 API key
        </button>
      </div>
    </header>
  );
}

function StatusPill({ connected, demoMode }) {
  const color = connected ? "var(--signal-cyan)" : demoMode ? "var(--signal-amber)" : "var(--signal-red)";
  const label = connected ? "LIVE — nDPI engine" : demoMode ? "DEMO — simulated feed" : "DISCONNECTED";
  return (
    <div
      className="mono"
      style={{
        display: "flex", alignItems: "center", gap: 7,
        fontSize: 11.5, fontWeight: 600, color,
        border: `1px solid ${color}45`, background: `${color}12`,
        padding: "5px 10px", borderRadius: 999,
      }}
    >
      <span
        style={{
          width: 6, height: 6, borderRadius: "50%", background: color,
          boxShadow: connected ? `0 0 8px ${color}` : "none",
        }}
      />
      {label}
    </div>
  );
}
