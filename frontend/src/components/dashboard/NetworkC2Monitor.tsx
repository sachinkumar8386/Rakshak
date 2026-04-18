import { useState } from "react";
import { Wifi, Skull, ShieldCheck, RotateCcw } from "lucide-react";

let invoke: any = null;
try {
  import("@tauri-apps/api/core").then((m) => (invoke = m.invoke));
} catch {}

interface C2Result {
  process_name: string;
  pid: number;
  remote_ip: string;
  remote_port: number;
  protocol: string;
  risk_level: string;
  reason: string;
}

interface Props {
  onC2Detected: (detected: boolean) => void;
}

export default function NetworkC2Monitor({ onC2Detected }: Props) {
  const [results, setResults] = useState<C2Result[]>([]);
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState<string | null>(null);

  const runAudit = async () => {
    if (!invoke) return;
    setScanning(true);
    try {
      const res: C2Result[] = await invoke("run_network_audit");
      setResults(res);
      setLastScan(new Date().toLocaleTimeString("en-US", { hour12: false }));
      const hasC2 = res.some((r) => r.risk_level === "SUSPICIOUS_C2_ACTIVITY");
      onC2Detected(hasC2);
    } catch (e) {
      console.error("Audit failed:", e);
    } finally {
      setScanning(false);
    }
  };

  const resetLogs = async () => {
    if (!invoke) return;
    try {
      await invoke("reset_c2_audit");
      setResults([]);
      setLastScan(null);
      onC2Detected(false);
    } catch (e) {
      console.error("Reset failed:", e);
    }
  };

  const killProcess = async (pid: number) => {
    if (!invoke) return;
    try {
      await invoke("kill_process", { pid });
      // Re-run audit after kill
      runAudit();
    } catch (e) {
      console.error("Kill failed:", e);
    }
  };

  const suspiciousCount = results.filter(
    (r) => r.risk_level === "SUSPICIOUS_C2_ACTIVITY"
  ).length;

  return (
    <div
      className="flex flex-col rounded-lg overflow-hidden glass-card"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-surface-ring/50">
        <div className="flex items-center gap-3">
          <Wifi size={18} style={{ color: suspiciousCount > 0 ? "#ff7350" : "#3fff8b" }} />
          <h3 className="text-sm font-bold uppercase tracking-widest text-on-surface">
            Network & C2 Monitor
          </h3>
          {suspiciousCount > 0 && (
            <span
              className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider animate-pulse"
              style={{
                color: "#ff7350",
                background: "rgba(255, 115, 80, 0.15)",
                border: "1px solid rgba(255, 115, 80, 0.3)",
              }}
            >
              {suspiciousCount} C2 BEACON{suspiciousCount > 1 ? "S" : ""} DETECTED
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            id="reset-logs-btn"
            onClick={resetLogs}
            disabled={scanning || results.length === 0}
            className="px-3 py-1.5 rounded-md text-xs font-bold uppercase tracking-widest"
            style={{
              background: "rgba(115, 116, 138, 0.15)",
              color: scanning || results.length === 0 ? "#45465b" : "#a8a9c1",
              border: "1px solid rgba(69, 70, 91, 0.4)",
              cursor: scanning || results.length === 0 ? "not-allowed" : "pointer",
              opacity: scanning || results.length === 0 ? 0.4 : 1,
              transition: "background 0.2s, opacity 0.2s",
            }}
          >
            <span className="flex items-center gap-1.5">
              <RotateCcw size={12} />
              RESET LOGS
            </span>
          </button>
          <button
            id="threat-audit-btn"
            onClick={runAudit}
            disabled={scanning}
            className="px-4 py-1.5 rounded-md text-xs font-bold uppercase tracking-widest"
            style={{
              background: scanning ? "transparent" : "#ff7350",
              color: scanning ? "#ff7350" : "#000",
              border: scanning ? "1px solid #ff7350" : "1px solid transparent",
              cursor: scanning ? "not-allowed" : "pointer",
              opacity: scanning ? 0.7 : 1,
              transition: "background 0.2s, opacity 0.2s",
              /* Prevent blink/flicker on tap */
              WebkitTapHighlightColor: "transparent",
              outline: "none",
            }}
          >
            {scanning ? "SCANNING NETWORK…" : "⚡ THREAT AUDIT"}
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="max-h-72 overflow-y-auto">
        {results.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 opacity-40 text-xs tracking-widest uppercase">
            {lastScan ? (
              <div className="flex items-center gap-2 text-primary">
                <ShieldCheck size={18} /> No active C2 beacons detected
              </div>
            ) : (
              "Run a Threat Audit to scan network connections"
            )}
          </div>
        )}

        {results.length > 0 && (
          <table className="w-full text-left text-xs table-auto">
            <thead className="sticky top-0 z-10 border-b border-surface-ring text-on-surface-muted uppercase tracking-widest" style={{ background: "#0b0d1e" }}>
              <tr>
                <th className="px-4 py-3 whitespace-nowrap">Status</th>
                <th className="px-4 py-3 whitespace-nowrap">Process</th>
                <th className="px-4 py-3 whitespace-nowrap">PID</th>
                <th className="px-4 py-3 whitespace-nowrap">Remote IP</th>
                <th className="px-4 py-3 whitespace-nowrap">Port</th>
                <th className="px-4 py-3">Reason</th>
                <th className="px-4 py-3 whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => {
                const isSus = r.risk_level === "SUSPICIOUS_C2_ACTIVITY";
                return (
                  <tr
                    key={`${r.pid}-${r.remote_ip}-${r.remote_port}-${i}`}
                    className="border-b border-surface-ring/30 transition-colors"
                    style={{
                      background: isSus
                        ? "rgba(255, 115, 80, 0.08)"
                        : "transparent",
                    }}
                  >
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {isSus ? (
                        <span className="flex items-center gap-1 font-bold" style={{ color: "#ff7350" }}>
                          <Skull size={12} /> C2
                        </span>
                      ) : (
                        <span className="opacity-40">OK</span>
                      )}
                    </td>
                    <td
                      className="px-4 py-2.5 font-mono font-bold whitespace-nowrap"
                      style={{ color: isSus ? "#ff7350" : "#e3e3fd" }}
                    >
                      {r.process_name}
                    </td>
                    <td className="px-4 py-2.5 font-mono opacity-70 whitespace-nowrap">{r.pid}</td>
                    <td className="px-4 py-2.5 font-mono opacity-80 whitespace-nowrap">
                      {r.remote_ip}
                    </td>
                    <td className="px-4 py-2.5 font-mono opacity-60 whitespace-nowrap">
                      {r.remote_port}
                    </td>
                    <td className="px-4 py-2.5 opacity-50 text-[10px] break-words max-w-xs">
                      {r.reason}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {isSus && (
                        <button
                          onClick={() => killProcess(r.pid)}
                          className="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider hover:brightness-125"
                          style={{
                            background: "rgba(255, 50, 50, 0.2)",
                            color: "#ff5050",
                            border: "1px solid rgba(255, 50, 50, 0.4)",
                            transition: "filter 0.15s",
                          }}
                        >
                          KILL
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {lastScan && (
        <div className="px-5 py-2 border-t border-surface-ring/30 text-[10px] opacity-30 font-mono">
          Last scan: {lastScan} · {results.length} connections audited
        </div>
      )}
    </div>
  );
}
