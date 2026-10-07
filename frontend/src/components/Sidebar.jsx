import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/", label: "Dashboard", glyph: "◈", desc: "Live overview" },
  { to: "/flows", label: "Flows", glyph: "⇄", desc: "Classified traffic" },
  { to: "/alerts", label: "Alerts", glyph: "▲", desc: "Detections" },
  { to: "/analysis", label: "Analysis", glyph: "◎", desc: "Deep signals" },
  { to: "/control", label: "Control", glyph: "▣", desc: "Capture & tuning" },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand" style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 8px", marginBottom: 28 }}>
        <div
          style={{
            width: 30, height: 30, borderRadius: 8, flexShrink: 0,
            background: "linear-gradient(135deg, var(--signal-cyan), var(--signal-violet))",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: 14, color: "#0a0d13",
          }}
        >
          C
        </div>
        <div className="sidebar-brand-text">
          <div style={{ fontWeight: 700, fontSize: 14, letterSpacing: "-0.01em" }}>CovertScope</div>
          <div className="eyebrow" style={{ fontSize: 9.5 }}>nDPI research platform</div>
        </div>
      </div>

      <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            title={item.label}
            className="focus-ring sidebar-link"
            style={({ isActive }) => ({
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "9px 10px",
              borderRadius: 8,
              fontSize: 13.5,
              fontWeight: 600,
              color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
              background: isActive ? "var(--panel-raised)" : "transparent",
              border: isActive ? "1px solid var(--hairline)" : "1px solid transparent",
            })}
          >
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--signal-cyan)", width: 16, textAlign: "center", flexShrink: 0 }}>
              {item.glyph}
            </span>
            <span className="sidebar-link-label" style={{ flex: 1 }}>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer" style={{ marginTop: "auto", padding: "10px 8px", borderTop: "1px solid var(--hairline-soft)" }}>
        <div className="eyebrow" style={{ marginBottom: 4 }}>Research use only</div>
        <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>
          Authorized pen-testing &amp; academic use. See SECURITY.md.
        </div>
      </div>
    </aside>
  );
}
