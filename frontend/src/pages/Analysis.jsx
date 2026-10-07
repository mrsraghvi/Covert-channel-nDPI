import { useMemo } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  ScatterChart, Scatter, ZAxis, Cell,
} from "recharts";
import { PageHeader, SectionLabel, tooltipStyle } from "./Dashboard";
import { EmptyState } from "../components/Primitives";

const TYPE_COLORS = { TIMING: "#9b8cf0", DNS: "#eba53f", HTTP: "#eba53f", ICMP: "#ef5368", GENERIC: "#626b81" };

export default function Analysis({ flows, alerts, stats }) {
  const typeDist = useMemo(() => {
    const dist = stats?.covert_type_distribution || {};
    if (Object.keys(dist).length) return Object.entries(dist).map(([name, value]) => ({ name, value }));
    // derive locally if backend didn't supply it (demo mode)
    const local = {};
    for (const a of alerts) local[a.covert_type] = (local[a.covert_type] || 0) + 1;
    return Object.entries(local).map(([name, value]) => ({ name, value }));
  }, [stats, alerts]);

  const radarData = useMemo(() => buildProtocolRadar(flows), [flows]);
  const entropyHist = useMemo(() => buildEntropyHistogram(flows), [flows]);
  const scatterData = useMemo(
    () => flows.slice(-150).map((f) => ({
      x: f.iat_cv ?? 0,
      y: f.payload_entropy ?? 0,
      z: f.bytes || 100,
      covert: f.is_covert,
    })),
    [flows]
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <PageHeader
        title="Analysis"
        subtitle="Deeper signal views for validating detector behavior: what kinds of covert channels are firing, how protocols compare across timing/volume dimensions, and where flows land in entropy/regularity space."
      />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Covert-type distribution</SectionLabel>
          {typeDist.length === 0 ? (
            <EmptyState title="No detections yet" body="Covert-type breakdown appears once alerts start firing." />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={typeDist} margin={{ left: -20, top: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2532" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#a8b0c3" }} axisLine={{ stroke: "#1f2532" }} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#626b81" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {typeDist.map((d, i) => (
                    <Cell key={i} fill={TYPE_COLORS[d.name] || "#4a5568"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Protocol profile — packets vs. bytes vs. duration</SectionLabel>
          {radarData.length === 0 ? (
            <EmptyState title="No traffic yet" body="Radar compares the top protocols once flows arrive." />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <RadarChart data={radarData} outerRadius={85}>
                <PolarGrid stroke="#1f2532" />
                <PolarAngleAxis dataKey="metric" tick={{ fontSize: 10.5, fill: "#a8b0c3" }} />
                <PolarRadiusAxis tick={{ fontSize: 9, fill: "#626b81" }} axisLine={false} />
                {radarData.length > 0 &&
                  Object.keys(radarData[0])
                    .filter((k) => k !== "metric")
                    .map((proto, i) => (
                      <Radar
                        key={proto}
                        name={proto}
                        dataKey={proto}
                        stroke={RADAR_COLORS[i % RADAR_COLORS.length]}
                        fill={RADAR_COLORS[i % RADAR_COLORS.length]}
                        fillOpacity={0.12}
                        strokeWidth={1.6}
                      />
                    ))}
                <Tooltip contentStyle={tooltipStyle} />
              </RadarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Payload entropy histogram</SectionLabel>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={entropyHist} margin={{ left: -20, top: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2532" vertical={false} />
              <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: "#626b81" }} axisLine={{ stroke: "#1f2532" }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "#626b81" }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {entropyHist.map((d, i) => (
                  <Cell key={i} fill={d.bucket >= "7.0" ? "#ef5368" : "#45d9c4"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
            Bars at 7.2+ bits/byte cross the high-entropy detection threshold.
          </div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Anomaly scatter — IAT regularity vs. entropy</SectionLabel>
          <ResponsiveContainer width="100%" height={220}>
            <ScatterChart margin={{ left: -10, top: 10, right: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2532" />
              <XAxis
                type="number" dataKey="x" name="IAT CV" tick={{ fontSize: 10, fill: "#626b81" }}
                axisLine={{ stroke: "#1f2532" }} tickLine={false}
                label={{ value: "IAT coefficient of variation", position: "insideBottom", offset: -5, fontSize: 10, fill: "#626b81" }}
              />
              <YAxis
                type="number" dataKey="y" name="Entropy" tick={{ fontSize: 10, fill: "#626b81" }}
                axisLine={false} tickLine={false}
                label={{ value: "Entropy (bits)", angle: -90, position: "insideLeft", fontSize: 10, fill: "#626b81" }}
              />
              <ZAxis type="number" dataKey="z" range={[20, 200]} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ strokeDasharray: "3 3" }} />
              <Scatter data={scatterData}>
                {scatterData.map((d, i) => (
                  <Cell key={i} fill={d.covert ? "#ef5368" : "#45d9c4"} fillOpacity={d.covert ? 0.85 : 0.35} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
            Bottom-left cluster (low CV, high entropy) is the timing-channel signature; red = flagged.
          </div>
        </div>
      </div>
    </div>
  );
}

const RADAR_COLORS = ["#45d9c4", "#eba53f", "#9b8cf0", "#ef5368"];

function buildProtocolRadar(flows) {
  const byProto = {};
  for (const f of flows) {
    const p = f.protocol || "Unknown";
    if (!byProto[p]) byProto[p] = { packets: 0, bytes: 0, duration: 0, n: 0 };
    byProto[p].packets += f.packets || 0;
    byProto[p].bytes += f.bytes || 0;
    byProto[p].duration += f.duration_ms || 0;
    byProto[p].n += 1;
  }
  const top = Object.entries(byProto)
    .sort((a, b) => b[1].n - a[1].n)
    .slice(0, 4);
  if (top.length === 0) return [];

  const maxPackets = Math.max(...top.map(([, v]) => v.packets / v.n), 1);
  const maxBytes = Math.max(...top.map(([, v]) => v.bytes / v.n), 1);
  const maxDuration = Math.max(...top.map(([, v]) => v.duration / v.n), 1);

  return ["Avg packets", "Avg bytes", "Avg duration"].map((metric) => {
    const row = { metric };
    top.forEach(([proto, v]) => {
      if (metric === "Avg packets") row[proto] = Math.round(((v.packets / v.n) / maxPackets) * 100);
      if (metric === "Avg bytes") row[proto] = Math.round(((v.bytes / v.n) / maxBytes) * 100);
      if (metric === "Avg duration") row[proto] = Math.round(((v.duration / v.n) / maxDuration) * 100);
    });
    return row;
  });
}

function buildEntropyHistogram(flows) {
  const buckets = ["0-1", "1-2", "2-3", "3-4", "4-5", "5-6", "6-7", "7-8"];
  const counts = new Array(buckets.length).fill(0);
  for (const f of flows) {
    const e = f.payload_entropy || 0;
    const idx = Math.min(buckets.length - 1, Math.max(0, Math.floor(e)));
    counts[idx] += 1;
  }
  return buckets.map((b, i) => ({ bucket: b, count: counts[i] }));
}
