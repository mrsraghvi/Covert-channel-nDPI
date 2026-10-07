import { useEffect, useState } from "react";
import { PageHeader, SectionLabel } from "./Dashboard";
import { api } from "../lib/api";

// Mirrors backend/app/schemas.py's _IFACE_RE — Linux interface names are
// capped at 15 chars (IFNAMSIZ-1) and only ever contain these characters.
// Checking it here means a typo gets caught before a round-trip instead of
// surfacing as a raw 422 from the API.
const IFACE_RE = /^[a-zA-Z0-9_.-]{1,15}$/;

const DEFAULT_THRESHOLDS = {
  entropy_high: { value: 7.2, description: "Payload Shannon entropy threshold (bits)", min: 4, max: 8, step: 0.1 },
  dns_label_entropy: { value: 3.8, description: "DNS subdomain label entropy threshold", min: 2, max: 5, step: 0.1 },
  dns_label_len: { value: 60, description: "DNS subdomain label length threshold (chars)", min: 20, max: 100, step: 1 },
  iat_cv_low: { value: 0.05, description: "IAT coefficient of variation — regularity threshold", min: 0.01, max: 0.3, step: 0.01 },
  http_ua_entropy: { value: 4.5, description: "HTTP User-Agent entropy threshold", min: 2, max: 6, step: 0.1 },
  icmp_payload_entropy: { value: 6.0, description: "ICMP payload entropy threshold", min: 3, max: 8, step: 0.1 },
  alert_score: { value: 0.40, description: "Minimum final_score to raise an alert", min: 0.1, max: 0.9, step: 0.05 },
};

export default function Control({ demoMode, connected, blockedIps = new Map(), onUnblock }) {
  const [captureActive, setCaptureActive] = useState(false);
  const [captureMode, setCaptureMode] = useState("simulated");
  const [iface, setIface] = useState("eth0");
  const [bpf, setBpf] = useState("");
  const [labAck, setLabAck] = useState(false);
  const [generatorRunning, setGeneratorRunning] = useState(false);
  const [technique, setTechnique] = useState("all");
  const [thresholds, setThresholds] = useState(DEFAULT_THRESHOLDS);
  const [message, setMessage] = useState(null);
  const [pcapFile, setPcapFile] = useState(null);
  const [pcapReplay, setPcapReplay] = useState(null);
  const [replayingPcap, setReplayingPcap] = useState(false);

  useEffect(() => {
    if (!connected) return;
    api.thresholds().then((remote) => {
      setThresholds((prev) => {
        const next = { ...prev };
        for (const [k, v] of Object.entries(remote)) {
          if (next[k]) next[k] = { ...next[k], value: v.value, description: v.description || next[k].description };
        }
        return next;
      });
    }).catch(() => {});
  }, [connected]);

  function flash(text) {
    setMessage(text);
    setTimeout(() => setMessage(null), 4000);
  }

  const ifaceValid = captureMode !== "live" || IFACE_RE.test(iface);

  async function toggleCapture() {
    if (!captureActive && !ifaceValid) {
      flash(`"${iface}" isn't a valid interface name (letters/digits/._- , max 15 chars)`);
      return;
    }
    try {
      if (!captureActive) {
        const res = await api.captureStart({ interface: iface, bpf_filter: bpf || null, mode: captureMode });
        setCaptureActive(true);
        flash(res.note || `Capture started (${captureMode})`);
      } else {
        await api.captureStop();
        setCaptureActive(false);
        flash("Capture stopped");
      }
    } catch (e) {
      setCaptureActive((v) => !v);
      flash(demoMode ? "Demo mode: capture is always running against simulated traffic." : `Error: ${e.message}`);
    }
  }

  async function toggleGenerator() {
    try {
      if (!generatorRunning) {
        await api.generatorStart({ technique, target: "127.0.0.1", duration_s: 30 });
        setGeneratorRunning(true);
        flash(`Lab generator started (${technique}) against 127.0.0.1`);
      } else {
        await api.generatorStop();
        setGeneratorRunning(false);
        flash("Generator stopped");
      }
    } catch (e) {
      flash(demoMode ? "Demo mode: the generator only runs in the lab VM backend." : `Error: ${e.message}`);
    }
  }

  async function replayPcap() {
    if (!pcapFile) return;
    setReplayingPcap(true);
    setPcapReplay(null);
    try {
      const result = await api.replayPcap(pcapFile);
      setPcapReplay(result);
      flash(`Replay complete: ${result.flows_replayed} flows analyzed`);
    } catch (e) {
      setPcapReplay({ error: e.message });
      flash(`PCAP replay failed: ${e.message}`);
    } finally {
      setReplayingPcap(false);
    }
  }

  async function updateThreshold(key, value) {
    setThresholds((prev) => ({ ...prev, [key]: { ...prev[key], value } }));
    try {
      await api.putThreshold(key, value);
    } catch {
      /* demo mode — local-only */
    }
  }

  async function downloadReport() {
    try {
      const report = await api.report();
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "covertscope_report.json"; a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      flash(demoMode ? "Connect the backend to export a real report." : `Export failed: ${e.message}`);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <PageHeader title="Control" subtitle="Capture management, offline PCAP replay, lab-only test traffic, live threshold tuning, and report export." />

      {message && (
        <div className="card mono" style={{ padding: "10px 16px", fontSize: 12.5, color: "var(--signal-cyan)", borderColor: "var(--signal-cyan)" }}>
          {message}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>nDPI capture</SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Field label="Mode">
              <select value={captureMode} onChange={(e) => setCaptureMode(e.target.value)} disabled={captureActive} className="mono focus-ring" style={inputStyle}>
                <option value="simulated">Simulated (synthetic traffic, no capture needed)</option>
                <option value="live">Live (nDPI C engine on a real interface)</option>
              </select>
            </Field>
            {captureMode === "live" && (
              <>
                <Field label="Interface">
                  <input
                    value={iface}
                    onChange={(e) => setIface(e.target.value)}
                    disabled={captureActive}
                    className="mono focus-ring"
                    style={{ ...inputStyle, border: ifaceValid ? inputStyle.border : "1px solid var(--signal-red)" }}
                    aria-invalid={!ifaceValid}
                  />
                  {!ifaceValid && (
                    <div style={{ fontSize: 11, color: "var(--signal-red)", marginTop: 4 }}>
                      Must be letters/digits/._- only, max 15 characters (e.g. eth0, wlan0, lo)
                    </div>
                  )}
                </Field>
                <Field label="BPF filter (optional)">
                  <input value={bpf} onChange={(e) => setBpf(e.target.value)} disabled={captureActive} placeholder="not port 22" className="mono focus-ring" style={inputStyle} />
                </Field>
                <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
                  Live mode requires running <code className="mono">sudo ./ndpi-engine/covert_detector {iface} {bpf && `"${bpf}"`}</code> in
                  the lab VM — it streams classified flows to this backend on TCP :9999.
                </div>
              </>
            )}
            <button
              onClick={toggleCapture}
              disabled={!captureActive && !ifaceValid}
              className="mono focus-ring"
              style={btnStyle(captureActive, !captureActive && !ifaceValid)}
            >
              {captureActive ? "Stop capture" : "Start capture"}
            </button>
          </div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Offline PCAP replay</SectionLabel>
          <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5, marginBottom: 14 }}>
            Upload an authorized Ethernet PCAP or PCAPNG capture for offline analysis. Replay is IPv4/IPv6-aware,
            creates directional flows, and sends them through the same detection pipeline as live traffic.
            Files are limited to 25 MiB, 100,000 packets, and 5,000 flows; malformed or unsupported packets are skipped.
            This does not transmit any traffic.
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12 }}>
            <input
              type="file"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
              onChange={(event) => {
                setPcapFile(event.target.files?.[0] || null);
                setPcapReplay(null);
              }}
              disabled={replayingPcap}
              className="mono focus-ring"
              aria-label="Choose a PCAP or PCAPNG file"
            />
            <button
              onClick={replayPcap}
              disabled={!connected || demoMode || !pcapFile || pcapFile.size > 25 * 1024 * 1024 || replayingPcap}
              className="mono focus-ring"
              style={btnStyle(replayingPcap, !connected || demoMode || !pcapFile || pcapFile.size > 25 * 1024 * 1024 || replayingPcap)}
            >
              {replayingPcap ? "Analyzing capture…" : "Replay PCAP"}
            </button>
          </div>
          {pcapFile && (
            <div className="mono" style={{ fontSize: 11, color: pcapFile.size > 25 * 1024 * 1024 ? "var(--signal-red)" : "var(--text-muted)", marginTop: 8 }}>
              {pcapFile.name} · {(pcapFile.size / (1024 * 1024)).toFixed(2)} MiB
              {pcapFile.size > 25 * 1024 * 1024 && " · exceeds 25 MiB limit"}
            </div>
          )}
          {(!connected || demoMode) && (
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
              Connect to the authenticated backend to replay a capture; demo mode does not upload files.
            </div>
          )}
          {pcapReplay && (
            <div role="status" className="mono" style={{ fontSize: 12, color: pcapReplay.error ? "var(--signal-red)" : "var(--signal-cyan)", marginTop: 12 }}>
              {pcapReplay.error
                ? pcapReplay.error
                : `${pcapReplay.filename}: ${pcapReplay.flows_replayed} flows replayed · ${pcapReplay.alerts_raised} alerts · ${pcapReplay.skipped_packets} unsupported/malformed packets skipped`}
            </div>
          )}
        </div>

        <div className="card" style={{ padding: 20 }}>
          <SectionLabel>Lab-only test traffic generator</SectionLabel>
          <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5, marginBottom: 12 }}>
            Generates loopback-only synthetic covert-pattern traffic (timing / DNS / HTTP / ICMP signatures) so you
            can validate the detector against known-bad traffic. Only runs against <code className="mono">127.0.0.1</code> in
            your isolated lab VM — never against a real target.
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--text-secondary)", marginBottom: 12, cursor: "pointer" }}>
            <input type="checkbox" checked={labAck} onChange={(e) => setLabAck(e.target.checked)} />
            I'm running this inside my authorized, isolated lab VM
          </label>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Field label="Technique">
              <select value={technique} onChange={(e) => setTechnique(e.target.value)} disabled={generatorRunning || !labAck} className="mono focus-ring" style={inputStyle}>
                <option value="all">All techniques</option>
                <option value="timing">Timing channel</option>
                <option value="dns">DNS tunnel</option>
                <option value="http">HTTP header channel</option>
                <option value="icmp">ICMP payload channel</option>
              </select>
            </Field>
            <button onClick={toggleGenerator} disabled={!labAck} className="mono focus-ring" style={btnStyle(generatorRunning, !labAck)}>
              {generatorRunning ? "Stop generator" : "Start generator (loopback only)"}
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <SectionLabel>Detection thresholds</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          {Object.entries(thresholds).map(([key, t]) => (
            <div key={key}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontSize: 12.5, color: "var(--text-secondary)", fontWeight: 600 }}>{key}</span>
                <span className="mono" style={{ fontSize: 12.5, color: "var(--signal-cyan)" }}>{t.value}</span>
              </div>
              <input
                type="range" min={t.min} max={t.max} step={t.step} value={t.value}
                onChange={(e) => updateThreshold(key, parseFloat(e.target.value))}
                style={{ width: "100%", accentColor: "var(--signal-cyan)" }}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{t.description}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
          <SectionLabel>Blocklist ({blockedIps.size} active)</SectionLabel>
        </div>
        <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5, marginBottom: 12 }}>
          Advisory blocks raised from Alerts or Flows. CovertScope doesn't sit inline on the network path, so this
          doesn't drop packets itself — it flags any future matching flow immediately, and{" "}
          <code className="mono">GET /api/blocklist</code> is there for a real firewall/edge device to poll and enforce.
        </div>
        {blockedIps.size === 0 ? (
          <div style={{ fontSize: 12.5, color: "var(--text-muted)" }}>No IPs currently blocked.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Array.from(blockedIps.entries()).map(([ip, info]) => (
              <div
                key={ip}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "9px 12px", borderRadius: 8, background: "var(--panel-raised)",
                  border: "1px solid var(--hairline)",
                }}
              >
                <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                  <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "var(--signal-red)" }}>{ip}</span>
                  {info?.reason && (
                    <span style={{ fontSize: 11.5, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {info.reason}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => onUnblock?.(ip)}
                  className="mono focus-ring"
                  style={{
                    fontSize: 11.5, fontWeight: 600, padding: "6px 12px", borderRadius: 7, cursor: "pointer",
                    color: "var(--text-secondary)", background: "var(--panel)", border: "1px solid var(--hairline)",
                    flexShrink: 0, marginLeft: 12,
                  }}
                >
                  Unblock
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card" style={{ padding: 20, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <SectionLabel>Export</SectionLabel>
          <div style={{ fontSize: 12.5, color: "var(--text-muted)" }}>Download the full flow + alert report as JSON.</div>
        </div>
        <button onClick={downloadReport} className="mono focus-ring" style={btnStyle(false)}>
          Export report.json
        </button>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginBottom: 5 }}>{label}</div>
      {children}
    </div>
  );
}

const inputStyle = {
  width: "100%", background: "var(--panel-raised)", border: "1px solid var(--hairline)", borderRadius: 7,
  padding: "8px 10px", color: "var(--text-primary)", fontSize: 12.5, outline: "none",
};

function btnStyle(active, disabled = false) {
  return {
    fontSize: 12.5, fontWeight: 600, padding: "10px 16px", borderRadius: 8,
    cursor: disabled ? "not-allowed" : "pointer",
    color: disabled ? "var(--text-muted)" : active ? "var(--signal-red)" : "var(--bg)",
    background: disabled ? "var(--panel-raised)" : active ? "rgba(239,83,104,0.12)" : "var(--signal-cyan)",
    border: disabled ? "1px solid var(--hairline)" : active ? "1px solid var(--signal-red)" : "none",
    opacity: disabled ? 0.6 : 1,
  };
}
