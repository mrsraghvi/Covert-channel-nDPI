import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div
      style={{
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        height: "100%", minHeight: 400, textAlign: "center", gap: 10,
      }}
    >
      <div className="mono" style={{ fontSize: 13, color: "var(--signal-amber)", letterSpacing: "0.1em" }}>
        404 / NO SIGNAL
      </div>
      <div style={{ fontSize: 20, fontWeight: 700 }}>This page doesn't exist</div>
      <div style={{ fontSize: 13.5, color: "var(--text-secondary)", maxWidth: 380 }}>
        Whatever you were looking for isn't at this route. It may have moved,
        or the link was mistyped.
      </div>
      <Link
        to="/"
        className="mono focus-ring"
        style={{
          marginTop: 14, padding: "9px 18px", borderRadius: 8, fontSize: 13, fontWeight: 600,
          color: "var(--bg)", background: "var(--signal-cyan)", border: "1px solid var(--hairline)",
        }}
      >
        Back to Dashboard
      </Link>
    </div>
  );
}
