import { useState, useEffect, useRef } from "react";
import { AlertTriangle, Trash2, CheckCircle, Shield, Clock } from "lucide-react";

let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
let listen: ((event: string, cb: (e: { payload: unknown }) => void) => Promise<() => void>) | null = null;

try {
  import("@tauri-apps/api/core").then((m) => {
    invoke = m.invoke;
  });
  import("@tauri-apps/api/event").then((m) => {
    listen = m.listen;
  });
} catch {}

interface SecurityAlert {
  process: string;
  pid: number;
  path: string;
  entropy: number;
  timestamp: string;
  score?: number;
  reasons?: string[];
}

interface ThreatEvent {
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  pid: number;
  process: string;
  file?: string;
  action: string;
  entropy?: number;
  velocity?: number;
  timestamp?: string;
}

export default function AlertsView() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const alertsRef = useRef<SecurityAlert[]>([]);

  const fetchAlerts = async () => {
    if (!invoke) return;
    try {
      const hist = await invoke("get_alert_history") as SecurityAlert[];
      if (hist && hist.length > 0) {
        setAlerts(hist);
        alertsRef.current = hist;
        setIsConnected(true);
      }
    } catch (e) {
      console.error("Failed to fetch alerts:", e);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!listen) return;

    const setupListeners = async () => {
      if (!listen) return;
      const unlisten = await listen("THREAT_DETECTED", (evt) => {
        const threat = evt.payload as ThreatEvent;
        const newAlert: SecurityAlert = {
          process: threat.process,
          pid: threat.pid,
          path: threat.file || "Unknown",
          entropy: threat.entropy || 0,
          timestamp: threat.timestamp || new Date().toISOString(),
          score: getScoreFromLevel(threat.level),
          reasons: [`${threat.action}: ${threat.level}`],
        };
        alertsRef.current = [newAlert, ...alertsRef.current].slice(0, 100);
        setAlerts([...alertsRef.current]);
        setIsConnected(true);
      });

      return () => {
        unlisten();
      };
    };

    const cleanup = setupListeners();
    return () => {
      cleanup.then((fn) => fn?.());
    };
  }, []);

  const clearAlerts = async () => {
    if (!invoke) return;
    try {
      await invoke("clear_alert_history");
      setAlerts([]);
      alertsRef.current = [];
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "#ff7350";
    if (score >= 50) return "#fdc003";
    if (score >= 20) return "#60a5fa";
    return "#3fff8b";
  };

  const getLevelLabel = (score: number) => {
    if (score >= 80) return "CRITICAL";
    if (score >= 50) return "HIGH";
    if (score >= 20) return "MEDIUM";
    return "LOW";
  };

  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter((a) => (a.score || 0) >= 80).length;
  const highCount = alerts.filter((a) => (a.score || 0) >= 50 && (a.score || 0) < 80).length;

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <div className="flex items-center justify-between w-full max-w-7xl mb-6">
        <div className="flex items-center gap-3">
          <h1
            className="text-2xl font-display font-bold tracking-wider flex items-center gap-3"
            style={{ color: criticalCount > 0 ? "#ff7350" : "#e3e3fd" }}
          >
            <AlertTriangle size={24} />
            THREAT ALERT HISTORY
          </h1>
          <div
            className="flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono"
            style={{
              background: isConnected ? "rgba(63,255,139,0.1)" : "rgba(69,70,91,0.3)",
              color: isConnected ? "#3fff8b" : "#60a5fa",
              border: `1px solid ${isConnected ? "rgba(63,255,139,0.3)" : "rgba(96,165,250,0.3)"}`,
            }}
          >
            <span className={`w-2 h-2 rounded-full ${isConnected ? "bg-[#3fff8b]" : "bg-[#60a5fa]"}`} />
            {isConnected ? "LIVE" : "CONNECTING..."}
          </div>
        </div>
        <div className="flex items-center gap-4">
          {criticalCount > 0 && (
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-md animate-pulse"
              style={{ background: "rgba(255,115,80,0.15)", color: "#ff7350" }}
            >
              <Shield size={14} />
              <span className="text-sm font-bold">{criticalCount} CRITICAL</span>
            </div>
          )}
          {highCount > 0 && (
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-md"
              style={{ background: "rgba(253,192,3,0.1)", color: "#fdc003" }}
            >
              <AlertTriangle size={14} />
              <span className="text-sm font-bold">{highCount} HIGH</span>
            </div>
          )}
          <button
            onClick={clearAlerts}
            className="flex items-center gap-2 px-4 py-2 rounded-md hover:bg-tertiary transition-all text-sm tracking-widest uppercase"
            style={{
              background: "rgba(21, 24, 45, 0.4)",
              border: "1px solid rgba(69,70,91,0.3)",
            }}
          >
            <Trash2 size={16} /> Clear Log
          </button>
        </div>
      </div>

      <div
        className="flex-1 overflow-auto border rounded-lg w-full max-w-7xl"
        style={{
          background: "rgba(21, 24, 45, 0.2)",
          borderColor: criticalCount > 0 ? "rgba(255,115,80,0.3)" : "rgba(69,70,91,0.3)",
        }}
      >
        {alerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center opacity-50 text-sm tracking-widest uppercase">
            <Shield size={48} className="mb-4 opacity-30" />
            No Security Events Logged
            <span className="text-xs mt-2 opacity-60">Rakshak is actively monitoring your system</span>
          </div>
        ) : (
          <table className="w-full text-left text-sm table-fixed">
            <thead className="sticky top-0 border-b backdrop-blur-md z-10" style={{ background: "#0b0d1e", borderColor: "rgba(69,70,91,0.3)" }}>
              <tr className="text-on-surface-muted uppercase text-xs tracking-widest">
                <th className="px-6 py-4 w-48">
                  <div className="flex items-center gap-2">
                    <Clock size={12} /> Timestamp
                  </div>
                </th>
                <th className="px-6 py-4 w-40">Process</th>
                <th className="px-6 py-4 w-20">PID</th>
                <th className="px-6 py-4 w-32">Threat Level</th>
                <th className="px-6 py-4 w-48">Detection Rule</th>
                <th className="px-6 py-4">Impacted File</th>
                <th className="px-6 py-4 w-32 text-right">Status</th>
              </tr>
            </thead>
            <tbody>
              {[...alerts].map((al, i) => {
                const score = al.score || 0;
                const scoreColor = getScoreColor(score);
                const levelLabel = getLevelLabel(score);
                const isRecent = Date.now() - new Date(al.timestamp).getTime() < 5000;

                return (
                  <tr
                    key={i}
                    className={`border-b transition-colors ${isRecent ? "animate-pulse" : ""}`}
                    style={{
                      borderColor: "rgba(69,70,91,0.2)",
                      background: score >= 80 ? "rgba(255,115,80,0.05)" : score >= 50 ? "rgba(253,192,3,0.03)" : "transparent",
                    }}
                  >
                    <td className="px-6 py-3 font-mono opacity-80 whitespace-nowrap text-xs">
                      {new Date(al.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 font-bold truncate max-w-[10rem]" style={{ color: scoreColor }}>
                      {al.process}
                    </td>
                    <td className="px-6 py-3 font-mono opacity-80">{al.pid}</td>
                    <td className="px-6 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-bold border uppercase tracking-wider ${
                          score >= 80 ? "animate-pulse" : ""
                        }`}
                        style={{
                          color: scoreColor,
                          borderColor: `${scoreColor}40`,
                          background: `${scoreColor}15`,
                        }}
                      >
                        {levelLabel}
                      </span>
                    </td>
                    <td className="px-6 py-3 whitespace-nowrap">
                      <span
                        className="px-2 py-1 rounded text-xs border uppercase tracking-wider"
                        style={{
                          color: scoreColor,
                          borderColor: `${scoreColor}30`,
                          background: `${scoreColor}10`,
                        }}
                      >
                        Entropy {al.entropy.toFixed(2)}
                      </span>
                      {al.reasons?.map((r, j) => (
                        <div key={j} className="mt-1 text-xs opacity-60">
                          {r}
                        </div>
                      ))}
                    </td>
                    <td className="px-6 py-3 opacity-60 font-mono break-all text-xs max-w-xs">
                      {al.path}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <span
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider"
                        style={{
                          color: score >= 80 ? "#ff7350" : "#3fff8b",
                          border: `1px solid ${score >= 80 ? "rgba(255,115,80,0.3)" : "rgba(63,255,139,0.3)"}`,
                          background: `${score >= 80 ? "rgba(255,115,80,0.1)" : "rgba(63,255,139,0.1)"}`,
                        }}
                      >
                        {score >= 80 ? <Shield size={12} /> : <CheckCircle size={12} />}
                        {score >= 80 ? "Neutralized" : "Detected"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex items-center justify-between mt-4 text-xs opacity-50 font-mono max-w-7xl">
        <span>Total Events: {totalAlerts}</span>
        <span>Connection: {isConnected ? "Active" : "Inactive"}</span>
        <span>Last Update: {new Date().toLocaleTimeString()}</span>
      </div>
    </div>
  );
}

function getScoreFromLevel(level: string): number {
  switch (level) {
    case "CRITICAL":
      return 100;
    case "HIGH":
      return 70;
    case "MEDIUM":
      return 40;
    case "LOW":
      return 20;
    default:
      return 10;
  }
}
