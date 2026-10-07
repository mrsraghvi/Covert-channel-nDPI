import { useEffect, useRef } from "react";

/**
 * Renders a scrolling oscilloscope trace driven by `value` (0..1).
 * This is CovertScope's signature visual motif: every page reuses this
 * same waveform language (topbar ticker, per-flow sparkline, entropy
 * trend) to keep the "signal analysis" identity consistent.
 */
export default function Waveform({ value = 0, color = "var(--signal-cyan)", height = 40, width = 220, dense = false }) {
  const canvasRef = useRef(null);
  const historyRef = useRef(new Array(dense ? 60 : 90).fill(0));
  const rafRef = useRef(null);

  useEffect(() => {
    const hist = historyRef.current;
    hist.push(Math.max(0, Math.min(1, value)));
    hist.shift();
  }, [value]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    let phase = 0;
    function draw() {
      ctx.clearRect(0, 0, width, height);
      const hist = historyRef.current;
      const midY = height / 2;

      // faint baseline grid
      ctx.strokeStyle = "rgba(255,255,255,0.05)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, midY);
      ctx.lineTo(width, midY);
      ctx.stroke();

      ctx.beginPath();
      const step = width / (hist.length - 1);
      hist.forEach((v, i) => {
        const jitter = Math.sin(phase + i * 0.6) * 1.5 * v;
        const y = midY - v * (height * 0.42) + jitter;
        const x = i * step;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color.startsWith("var") ? getComputedStyle(document.documentElement).getPropertyValue(color.slice(4, -1)) : color;
      ctx.lineWidth = 1.6;
      ctx.lineJoin = "round";
      ctx.stroke();

      phase += 0.05;
      rafRef.current = requestAnimationFrame(draw);
    }
    draw();
    return () => cancelAnimationFrame(rafRef.current);
  }, [color, width, height]);

  return <canvas ref={canvasRef} style={{ width, height, display: "block" }} />;
}
