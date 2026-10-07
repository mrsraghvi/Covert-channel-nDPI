import { useState } from "react";

/** Confirmation modal for raising a soft/advisory block on an IP. Blocking
 * is a state-changing security action an analyst should confirm explicitly
 * rather than trigger with a stray click — this also doubles as the one
 * place that explains what "block" actually does here (see SECURITY.md):
 * CovertScope is a passive monitor, this doesn't itself drop packets. */
export default function BlockConfirmModal({ ip, defaultReason = "", onConfirm, onCancel }) {
  const [reason, setReason] = useState(defaultReason);

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 100,
        background: "rgba(6,8,12,0.72)", backdropFilter: "blur(3px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div
        style={{
          width: 420, background: "var(--panel, #12161f)", border: "1px solid var(--hairline, #232a38)",
          borderRadius: 12, padding: 24, boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
        }}
      >
        <h2 style={{ margin: "0 0 6px", fontSize: 16, color: "var(--text-primary, #e8ecf3)" }}>
          Block <span className="mono" style={{ color: "var(--signal-red, #ef5368)" }}>{ip}</span>?
        </h2>
        <p style={{ margin: "0 0 14px", fontSize: 12.5, lineHeight: 1.55, color: "var(--text-secondary, #8b93a5)" }}>
          CovertScope is a passive monitor — it classifies traffic, it doesn't
          sit inline on the network path. This won't drop any packets by
          itself. It will: flag any future flow from or to this IP so it's
          impossible to miss, and add the IP to the blocklist feed at{" "}
          <code>GET /api/blocklist</code> that a real firewall/edge device can
          poll and enforce.
        </p>
        <label style={{ display: "block", fontSize: 11.5, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6 }}>
          Reason (recorded with the block)
        </label>
        <input
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. DNS tunneling alert, confidence HIGH"
          className="mono"
          style={{
            width: "100%", boxSizing: "border-box", padding: "9px 11px",
            borderRadius: 8, border: "1px solid var(--hairline, #232a38)",
            background: "rgba(255,255,255,0.03)", color: "var(--text-primary, #e8ecf3)",
            fontSize: 12.5, marginBottom: 16,
          }}
        />
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button
            type="button"
            onClick={onCancel}
            style={{
              padding: "8px 14px", borderRadius: 8, border: "1px solid var(--hairline, #232a38)",
              background: "transparent", color: "var(--text-secondary, #8b93a5)", fontSize: 12.5, cursor: "pointer",
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm(reason.trim() || null)}
            style={{
              padding: "8px 16px", borderRadius: 8, border: "none",
              background: "var(--signal-red, #ef5368)", color: "#1a0608", fontWeight: 700,
              fontSize: 12.5, cursor: "pointer",
            }}
          >
            Confirm block
          </button>
        </div>
      </div>
    </div>
  );
}
