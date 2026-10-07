import { useMemo } from "react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { StatCard, ConfidenceBadge, ProtocolPill, EmptyState } from "../components/Primitives";
import Gauge from "../components/Gauge";

const PIE_COLORS = ["#45d9c4", "#eba53f", "#9b8cf0", "#ef5368", "#5b7fd6", "#4a5568", "#6ee7b7"];

export default function Dashboard({ flows, alerts, stats }) {
  const timeline = useMemo(() => buildTimeline(flows), [flows]);
  const protoData = useMemo(() => {
    const dist = stats?.protocol_distribution || {};
    return Object.entries(dist).map(([name, value]) => ({ name, value }));
  }, [stats]);

  const recentAlerts = [...alerts].slice(-6).reverse();
  const covertRate = stats?.total_flows ? (stats.covert_flows / stats.total_flows) : 0;
  const avgEntropyPct = Math.min(1, (stats?.avg_entropy || 0) / 8);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <PageHeader
        title="Live overview"
        subtitle="Real-time nDPI classification and covert-channel scoring across all observed flows."
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        <StatCard eyebrow="Flows observed" value={stats?.total_flows ?? 0} unit="total" accent="var(--signal-cyan)" />
        <StatCard eyebrow="Alerts raised" value={stats?.total_alerts ?? 0} unit="total" accent="var(--signal-amber)" />
        <StatCard eyebrow="Covert-flagged" value={stats?.covert_flows ?? 0} unit={`of ${stats?.total_flows ?? 0}`} accent="var(--signal-red)" />
        <StatCard eyebrow="Throughput" value={(stats?.packets_per_sec ?? 0).toFixed(1)} unit="pkt/s" accent="var(--signal-violet)" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Traffic &amp; anomaly timeline</SectionLabel>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline} margin={{ left: -20, top: 10 }}>
              <defs>
                <linearGradient id="gradPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#45d9c4" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#45d9c4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradAnomaly" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef5368" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#ef5368" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2532" vertical={false} />
              <XAxis dataKey="t" tick={{ fontSize: 10, fill: "#626b81" }} axisLine={{ stroke: "#1f2532" }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "#626b81" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#a8b0c3" }} />
              <Area type="monotone" dataKey="packets" stroke="#45d9c4" fill="url(#gradPackets)" strokeWidth={1.5} name="Packets" />
              <Area type="monotone" dataKey="anomaly" stroke="#ef5368" fill="url(#gradAnomaly)" strokeWidth={1.5} name="Anomaly score ×100" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card" style={{ padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          <SectionLabel>Covert-flow ratio</SectionLabel>
          <div style={{ display: "flex", justifyContent: "center", gap: 20 }}>
            <Gauge value={covertRate} label="Covert / total" sublabel="flagged flows" color="var(--signal-red)" />
            <Gauge value={avgEntropyPct} label="Payload entropy" sublabel="avg, /8 bits" color="var(--signal-violet)" />
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Protocol distribution</SectionLabel>
          {protoData.length === 0 ? (
            <EmptyState title="No traffic yet" body="Start a capture from the Control page." />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={protoData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                  {protoData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} stroke="var(--panel)" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend
                  layout="vertical" align="right" verticalAlign="middle"
                  formatter={(v) => <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Recent alerts</SectionLabel>
          {recentAlerts.length === 0 ? (
            <EmptyState title="No alerts yet" body="Covert-channel detections will stream in here in real time." />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 6 }}>
              {recentAlerts.map((a) => (
                <div
                  key={a.id ?? `${a.flow_id}-${a.ts}`}
                  style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "10px 12px", borderRadius: 8, background: "var(--panel-raised)",
                    border: "1px solid var(--hairline-soft)",
                  }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 3, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span className="mono" style={{ fontSize: 12, fontWeight: 700 }}>{a.covert_type}</span>
                      <ConfidenceBadge level={a.confidence} />
                    </div>
                    <div style={{ fontSize: 11.5, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 340 }}>
                      {a.reason}
                    </div>
                  </div>
                  <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--signal-amber)" }}>
                    {(a.final_score * 100).toFixed(0)}%
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle }) {
  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0, letterSpacing: "-0.01em" }}>{title}</h1>
      {subtitle && <p style={{ margin: "4px 0 0", fontSize: 13, color: "var(--text-muted)" }}>{subtitle}</p>}
    </div>
  );
}

export function SectionLabel({ children }) {
  return <div className="eyebrow" style={{ marginBottom: 14 }}>{children}</div>;
}

export const tooltipStyle = {
  background: "#141926", border: "1px solid #1f2532", borderRadius: 8, fontSize: 12,
};

function buildTimeline(flows) {
  return flows.slice(-40).map((f, i) => ({
    t: new Date(f.ts || Date.now()).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
    packets: f.packets || 0,
    anomaly: Math.round((f.anomaly_score || 0) * 100),
  }));
}
