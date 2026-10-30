import { Routes, Route } from "react-router-dom";
import { useState, Suspense, lazy } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import ApiKeyGate from "./components/ApiKeyGate";
import { useLiveData } from "./hooks/useLiveData";

// Load route pages after the app shell so chart dependencies do not inflate
// the initial bundle, especially for users who navigate away from Dashboard.
const Dashboard = lazy(() => import("./pages/Dashboard"));
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
    flows, alerts, stats, blockedIps, blockIp, unblockIp, acknowledgeAlert,
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
          activeAlerts={alerts.filter((a) => !a.acknowledged && (a.confidence === "CRITICAL" || a.confidence === "HIGH")).length}
          onOpenApiKey={() => setManualGate(true)}
        />
        <main style={{ flex: 1, overflowY: "auto", padding: "24px 28px 60px" }}>
          <Suspense fallback={<RouteFallback />}>
            <Routes>
              <Route path="/" element={<Dashboard flows={flows} alerts={alerts} stats={stats} />} />
              <Route path="/flows" element={<Flows flows={flows} blockedIps={blockedIps} onBlock={blockIp} onUnblock={unblockIp} />} />
              <Route path="/alerts" element={<Alerts alerts={alerts} blockedIps={blockedIps} onBlock={blockIp} onUnblock={unblockIp} onAcknowledge={acknowledgeAlert} />} />
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
