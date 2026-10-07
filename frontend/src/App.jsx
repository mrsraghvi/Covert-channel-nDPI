import { Routes, Route } from "react-router-dom";
import { useState, Suspense, lazy } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import ApiKeyGate from "./components/ApiKeyGate";
import Dashboard from "./pages/Dashboard";
import { useLiveData } from "./hooks/useLiveData";

// Lazy-loaded: these aren't needed for first paint (the landing route is
// Dashboard), and Analysis in particular pulls in most of the app's
// recharts usage — splitting it out measurably shrinks the initial bundle
// instead of shipping chart-library code nobody's looking at yet.
const Flows = lazy(() => import("./pages/Flows"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Analysis = lazy(() => import("./pages/Analysis"));
const Control = lazy(() => import("./pages/Control"));
const NotFound = lazy(() => import("./pages/NotFound"));

function RouteFallback() {
  return (
    <div className="mono" style={{ padding: 40, color: "var(--text-muted)", fontSize: 12.5 }}>
      loading…
    </div>
  );
}

export default function App() {
  const {
    connected, demoMode, needsApiKey, retry, useDemoInstead,
    flows, alerts, stats, blockedIps, blockIp, unblockIp,
  } = useLiveData();
  const [manualGate, setManualGate] = useState(false);

  const showGate = needsApiKey || manualGate;

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <Sidebar />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <Topbar
          connected={connected}
          demoMode={demoMode}
          packetsPerSec={stats?.packets_per_sec ?? 0}
          activeAlerts={alerts.filter((a) => a.confidence === "CRITICAL" || a.confidence === "HIGH").length}
          onOpenApiKey={() => setManualGate(true)}
        />
        <main style={{ flex: 1, overflowY: "auto", padding: "24px 28px 60px" }}>
          <Suspense fallback={<RouteFallback />}>
            <Routes>
              <Route path="/" element={<Dashboard flows={flows} alerts={alerts} stats={stats} />} />
              <Route path="/flows" element={<Flows flows={flows} blockedIps={blockedIps} onBlock={blockIp} onUnblock={unblockIp} />} />
              <Route path="/alerts" element={<Alerts alerts={alerts} blockedIps={blockedIps} onBlock={blockIp} onUnblock={unblockIp} />} />
              <Route path="/analysis" element={<Analysis flows={flows} alerts={alerts} stats={stats} />} />
              <Route
                path="/control"
                element={
                  <Control
                    demoMode={demoMode}
                    connected={connected}
                    blockedIps={blockedIps}
                    onUnblock={unblockIp}
                  />
                }
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </main>
      </div>
      {showGate && (
        <ApiKeyGate
          onDismiss={() => {
            setManualGate(false);
            if (needsApiKey) useDemoInstead();
          }}
          onSubmit={() => {
            setManualGate(false);
            retry();
          }}
        />
      )}
    </div>
  );
}
