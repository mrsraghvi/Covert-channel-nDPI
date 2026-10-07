import { useState } from "react";
import { setApiKey } from "../lib/api";

/** Small modal for entering the backend API key. Shown on first load if no
 * key is stored yet, and reachable any time afterwards via the lock icon in
 * the Topbar so the operator can fix a wrong/rotated key without editing
 * sessionStorage by hand. */
export default function ApiKeyGate({ onSubmit, onDismiss, dismissible = true }) {
  const [value, setValue] = useState("");

  function submit(e) {
    e.preventDefault();
    setApiKey(value.trim());
    onSubmit(value.trim());
  }

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 100,
        background: "rgba(6,8,12,0.72)", backdropFilter: "blur(3px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <form
        onSubmit={submit}
        style={{
          width: 380, background: "var(--panel, #12161f)", border: "1px solid var(--hairline, #232a38)",
          borderRadius: 12, padding: 24, boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
        }}
      >
        <h2 style={{ margin: "0 0 6px", fontSize: 16, color: "var(--text-primary, #e8ecf3)" }}>
          Backend API key
        </h2>
        <p style={{ margin: "0 0 16px", fontSize: 12.5, lineHeight: 1.5, color: "var(--text-secondary, #8b93a5)" }}>
          Every CovertScope API route (except health) requires the key the
          backend was started with (<code>COVERTSCOPE_API_KEY</code>). It's
          kept only in this tab's session storage — never written to disk or
          baked into the app.
        </p>
        <input
          autoFocus
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Paste API key"
          className="mono"
          style={{
            width: "100%", boxSizing: "border-box", padding: "10px 12px",
            borderRadius: 8, border: "1px solid var(--hairline, #232a38)",
            background: "rgba(255,255,255,0.03)", color: "var(--text-primary, #e8ecf3)",
            fontSize: 13, marginBottom: 14,
          }}
        />
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          {dismissible && (
            <button
              type="button"
              onClick={onDismiss}
              style={{
                padding: "8px 14px", borderRadius: 8, border: "1px solid var(--hairline, #232a38)",
                background: "transparent", color: "var(--text-secondary, #8b93a5)", fontSize: 12.5, cursor: "pointer",
              }}
            >
              Use demo mode instead
            </button>
          )}
          <button
            type="submit"
            disabled={!value.trim()}
            style={{
              padding: "8px 16px", borderRadius: 8, border: "none",
              background: "var(--signal-cyan, #2dd4ee)", color: "#06141a", fontWeight: 600,
              fontSize: 12.5, cursor: value.trim() ? "pointer" : "not-allowed",
              opacity: value.trim() ? 1 : 0.5,
            }}
          >
            Connect
          </button>
        </div>
      </form>
    </div>
  );
}
