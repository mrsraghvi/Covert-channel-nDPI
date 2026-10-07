const BENIGN_PROTOCOLS = ["HTTPS", "QUIC", "TLS", "NTP", "SSH", "DNS", "HTTP"];
const COVERT_TYPES = ["TIMING", "DNS", "HTTP", "ICMP"];

let flowCounter = 1000;

function randIp(priv = true) {
  return priv
    ? `192.168.${rnd(0, 5)}.${rnd(2, 254)}`
    : `${rnd(20, 220)}.${rnd(0, 255)}.${rnd(0, 255)}.${rnd(1, 254)}`;
}
function rnd(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
function rndf(a, b) { return Math.random() * (b - a) + a; }
function choice(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

export function genBenignFlow() {
  const id = ++flowCounter;
  const proto = choice(BENIGN_PROTOCOLS);
  const packets = rnd(4, 60);
  const duration_ms = rnd(200, 8000);
  const avgLen = rndf(300, 1400);
  return {
    id, protocol: proto,
    src: `${randIp()}:${rnd(1024, 65000)}`,
    dst: `${randIp(false)}:${proto === "HTTP" ? 80 : 443}`,
    packets, bytes: Math.round(packets * avgLen), duration_ms,
    iat_cv: rndf(0.15, 0.9),
    payload_entropy: rndf(2.5, 6.0),
    anomaly_score: rndf(0.02, 0.25),
    is_covert: false,
    ts: Date.now(),
  };
}

export function genCovertFlow(technique) {
  const id = ++flowCounter;
  technique = technique || choice(COVERT_TYPES);
  const map = {
    TIMING: { protocol: "TLS", entropy: rndf(3, 5), score: rndf(0.65, 0.95) },
    DNS: { protocol: "DNS", entropy: rndf(3.9, 4.6), score: rndf(0.7, 0.97) },
    HTTP: { protocol: "HTTP", entropy: rndf(4.6, 5.4), score: rndf(0.6, 0.9) },
    ICMP: { protocol: "ICMP", entropy: rndf(6.2, 7.6), score: rndf(0.55, 0.88) },
  };
  const m = map[technique];
  const packets = rnd(10, 150);
  return {
    id, protocol: m.protocol,
    src: `${randIp()}:${rnd(1024, 65000)}`,
    dst: `${randIp(false)}:${technique === "DNS" ? 53 : technique === "ICMP" ? 0 : 443}`,
    packets, bytes: rnd(2000, 25000), duration_ms: rnd(500, 12000),
    iat_cv: technique === "TIMING" ? rndf(0.005, 0.03) : rndf(0.2, 0.6),
    payload_entropy: m.entropy,
    anomaly_score: m.score,
    is_covert: true,
    covert_type: technique,
    ts: Date.now(),
  };
}

export function genAlert(flow) {
  const reasons = {
    TIMING: `[TIMING] suspiciously regular IAT: cv=${flow.iat_cv.toFixed(4)} < 0.05`,
    DNS: `[DNS] combined length+entropy signature strongly indicates tunneling`,
    HTTP: `[HTTP] URL entropy ${flow.payload_entropy.toFixed(2)} > 4.8, len > 128`,
    ICMP: `[ICMP] payload entropy ${flow.payload_entropy.toFixed(2)} > 6.0`,
  };
  const recs = {
    TIMING: "Investigate the endpoint for scheduled beaconing; compare IAT against known C2 jitter profiles.",
    DNS: "Likely DNS tunneling — review the queried domain and consider forcing DNS through an inspected resolver.",
    HTTP: "Header-based covert channel suspected — inspect User-Agent/header values for encoded payloads.",
    ICMP: "Oversized/high-entropy ICMP payload suggests exfiltration over ping — capture a pcap sample.",
  };
  const confidence = flow.anomaly_score >= 0.85 ? "CRITICAL" : flow.anomaly_score >= 0.65 ? "HIGH" : flow.anomaly_score >= 0.45 ? "MEDIUM" : "LOW";
  return {
    id: flow.id,
    flow_id: flow.id,
    covert_type: flow.covert_type,
    final_score: flow.anomaly_score,
    confidence,
    reason: reasons[flow.covert_type],
    recommendation: recs[flow.covert_type],
    src_ip: flow.src.split(":")[0],
    dst_ip: flow.dst.split(":")[0],
    ts: flow.ts,
  };
}

export function makeInitialHistory(n = 60) {
  const flows = [];
  const alerts = [];
  for (let i = 0; i < n; i++) {
    const covert = Math.random() < 0.12;
    const f = covert ? genCovertFlow() : genBenignFlow();
    f.ts = Date.now() - (n - i) * 1500;
    flows.push(f);
    if (covert) alerts.push(genAlert(f));
  }
  return { flows, alerts };
}
