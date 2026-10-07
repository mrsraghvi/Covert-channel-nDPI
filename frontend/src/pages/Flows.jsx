import { useMemo, useState } from "react";
import { PageHeader, SectionLabel } from "./Dashboard";
import { ProtocolPill, EmptyState, BlockedBadge } from "../components/Primitives";
import BlockConfirmModal from "../components/BlockConfirmModal";
import { ipFromHostPort } from "../lib/api";

export default function Flows({ flows, blockedIps = new Map(), onBlock, onUnblock }) {
  const [protoFilter, setProtoFilter] = useState("ALL");
  const [covertOnly, setCovertOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [blockTarget, setBlockTarget] = useState(null);

  const protocols = useMemo(() => {
    const s = new Set(flows.map((f) => f.protocol).filter(Boolean));
    return ["ALL", ...Array.from(s)];
  }, [flows]);

  const filtered = useMemo(() => {
    return [...flows]
      .reverse()
      .filter((f) => (protoFilter === "ALL" ? true : f.protocol === protoFilter))
      .filter((f) => (covertOnly ? f.is_covert : true))
      .filter((f) => (search ? `${f.src}${f.dst}`.toLowerCase().includes(search.toLowerCase()) : true))
      .slice(0, 200);
  }, [flows, protoFilter, covertOnly, search]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <PageHeader title="Flows" subtitle="Every flow classified by the nDPI engine, with live anomaly scoring." />

      <div className="card" style={{ padding: 16, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <input
          placeholder="Search src / dst…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="mono focus-ring"
          style={inputStyle}
        />
        <select value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)} className="mono focus-ring" style={inputStyle}>
          {protocols.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, color: "var(--text-secondary)", cursor: "pointer" }}>
          <input type="checkbox" checked={covertOnly} onChange={(e) => setCovertOnly(e.target.checked)} />
          Covert-flagged only
        </label>
        <div style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)" }} className="mono">
          {filtered.length} shown
        </div>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        {filtered.length === 0 ? (
          <EmptyState title="No matching flows" body="Adjust filters or start a capture from Control." />
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--hairline)" }}>
                  {["Source", "Destination", "Protocol", "Packets", "Bytes", "IAT CV", "Entropy", "Score", "Action"].map((h) => (
                    <th key={h} className="eyebrow" style={{ padding: "10px 14px", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((f) => {
                  const srcIp = ipFromHostPort(f.src);
                  const isBlocked = f.blocked || blockedIps.has(srcIp);
                  return (
                    <tr
                      key={f.id}
                      style={{
                        borderBottom: "1px solid var(--hairline-soft)",
                        background: f.is_covert ? "rgba(239,83,104,0.05)" : "transparent",
                      }}
                    >
                      <td className="mono" style={cellStyle}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          {f.src}
                          {isBlocked && <BlockedBadge />}
                        </div>
                      </td>
                      <td className="mono" style={cellStyle}>{f.dst}</td>
                      <td style={cellStyle}><ProtocolPill protocol={f.protocol} /></td>
                      <td className="mono" style={cellStyle}>{f.packets}</td>
                      <td className="mono" style={cellStyle}>{formatBytes(f.bytes)}</td>
                      <td className="mono" style={cellStyle}>{f.iat_cv?.toFixed(3) ?? "—"}</td>
                      <td className="mono" style={cellStyle}>{f.payload_entropy?.toFixed(2) ?? "—"}</td>
                      <td className="mono" style={{ ...cellStyle, color: scoreColor(f.anomaly_score), fontWeight: 700 }}>
                        {((f.anomaly_score || 0) * 100).toFixed(0)}%
                      </td>
                      <td style={cellStyle}>
                        {isBlocked ? (
                          <button
                            onClick={() => onUnblock?.(srcIp)}
                            className="mono focus-ring"
                            style={actionBtnStyle("neutral")}
                          >
                            Unblock
                          </button>
                        ) : (
                          <button
                            onClick={() => setBlockTarget({ ip: srcIp, flowId: f.id })}
                            className="mono focus-ring"
                            style={actionBtnStyle("danger")}
                          >
                            Block
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {blockTarget && (
        <BlockConfirmModal
          ip={blockTarget.ip}
          defaultReason={`Blocked from flow #${blockTarget.flowId}`}
          onConfirm={(reason) => {
            onBlock?.(blockTarget.ip, reason, null);
            setBlockTarget(null);
          }}
          onCancel={() => setBlockTarget(null)}
        />
      )}
    </div>
  );
}

const inputStyle = {
  background: "var(--panel-raised)", border: "1px solid var(--hairline)", borderRadius: 7,
  padding: "7px 10px", color: "var(--text-primary)", fontSize: 12.5, outline: "none",
};
const cellStyle = { padding: "9px 14px", whiteSpace: "nowrap" };

function actionBtnStyle(kind) {
  const danger = kind === "danger";
  return {
    fontSize: 11, fontWeight: 600, padding: "5px 10px", borderRadius: 6, cursor: "pointer",
    color: danger ? "var(--signal-red)" : "var(--text-secondary)",
    background: danger ? "var(--signal-red)14" : "var(--panel-raised)",
    border: `1px solid ${danger ? "var(--signal-red)55" : "var(--hairline)"}`,
  };
}

function scoreColor(score = 0) {
  if (score >= 0.65) return "var(--signal-red)";
  if (score >= 0.4) return "var(--signal-amber)";
  return "var(--text-muted)";
}
function formatBytes(b = 0) {
  if (b > 1e6) return `${(b / 1e6).toFixed(2)} MB`;
  if (b > 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}
