export default function Gauge({ value = 0, label, sublabel, size = 140, color = "var(--signal-cyan)" }) {
  const pct = Math.max(0, Math.min(1, value));
  const strokeWidth = 10;
  const r = (size - strokeWidth) / 2;
  const circumference = Math.PI * r; // half circle
  const offset = circumference * (1 - pct);
  const cx = size / 2;
  const cy = size / 2;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width={size} height={size / 2 + 12} viewBox={`0 0 ${size} ${size / 2 + 12}`}>
        <path
          d={`M ${strokeWidth / 2} ${cy} A ${r} ${r} 0 0 1 ${size - strokeWidth / 2} ${cy}`}
          fill="none"
          stroke="var(--hairline)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        <path
          d={`M ${strokeWidth / 2} ${cy} A ${r} ${r} 0 0 1 ${size - strokeWidth / 2} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text x={cx} y={cy - 6} textAnchor="middle" className="mono" fill="var(--text-primary)" fontSize="22" fontWeight="600">
          {(pct * 100).toFixed(0)}%
        </text>
      </svg>
      {label && <div style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>{label}</div>}
      {sublabel && <div className="eyebrow">{sublabel}</div>}
    </div>
  );
}
