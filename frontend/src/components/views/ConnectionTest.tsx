import { useState } from "react";
import { Shield, AlertTriangle, Zap, Activity, CheckCircle } from "lucide-react";

let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;

try {
  import("@tauri-apps/api/core").then((m) => {
    invoke = m.invoke;
  });
} catch {}

interface TestResult {
  command: string;
  status: "pending" | "success" | "error";
  response?: string;
  timestamp: string;
}

export default function ConnectionTest() {
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  const addResult = (command: string, status: "pending" | "success" | "error", response?: string) => {
    setTestResults((prev) => [
      { command, status, response, timestamp: new Date().toLocaleTimeString() },
      ...prev.slice(0, 9),
    ]);
  };

  const testConnection = async () => {
    if (!invoke) {
      addResult("Connection Check", "error", "Tauri API not available (running in browser?)");
      return;
    }

    try {
      addResult("Connection Check", "pending");
      
      await invoke("get_telemetry");
      await invoke("get_alert_history");
      await invoke("get_detection_scores");
      
      setIsConnected(true);
      addResult("Connection Check", "success", "Backend responding correctly");
    } catch (e) {
      setIsConnected(false);
      addResult("Connection Check", "error", String(e));
    }
  };

  const simulateCritical = async () => {
    if (!invoke) return;
    addResult("simulate_critical_threat", "pending");
    try {
      await invoke("simulate_critical_threat");
      addResult("simulate_critical_threat", "success", "CRITICAL threat emitted");
    } catch (e) {
      addResult("simulate_critical_threat", "error", String(e));
    }
  };

  const simulateHigh = async () => {
    if (!invoke) return;
    addResult("simulate_high_threat", "pending");
    try {
      await invoke("simulate_high_threat");
      addResult("simulate_high_threat", "success", "HIGH threat emitted");
    } catch (e) {
      addResult("simulate_high_threat", "error", String(e));
    }
  };

  const simulateMedium = async () => {
    if (!invoke) return;
    addResult("simulate_medium_threat", "pending");
    try {
      await invoke("simulate_medium_threat");
      addResult("simulate_medium_threat", "success", "MEDIUM threat emitted");
    } catch (e) {
      addResult("simulate_medium_threat", "error", String(e));
    }
  };

  const clearResults = () => {
    setTestResults([]);
  };

  const resetDetection = async () => {
    if (!invoke) return;
    addResult("reset_detection_state", "pending");
    try {
      await invoke("reset_detection_state");
      addResult("reset_detection_state", "success", "Detection state reset - ready for new tests");
    } catch (e) {
      addResult("reset_detection_state", "error", String(e));
    }
  };

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <div className="flex items-center justify-between w-full max-w-5xl mb-6">
        <h1 className="text-2xl font-display font-bold tracking-wider flex items-center gap-3" style={{ color: "#60a5fa" }}>
          <Zap size={24} />
          CONNECTION TEST
        </h1>
        <div className="flex items-center gap-4">
          <div
            className="flex items-center gap-2 px-4 py-2 rounded-full text-sm font-mono"
            style={{
              background: isConnected ? "rgba(63,255,139,0.1)" : "rgba(255,115,80,0.1)",
              color: isConnected ? "#3fff8b" : "#ff7350",
              border: `1px solid ${isConnected ? "rgba(63,255,139,0.3)" : "rgba(255,115,80,0.3)"}`,
            }}
          >
            <span className={`w-2 h-2 rounded-full ${isConnected ? "bg-[#3fff8b]" : "bg-[#ff7350]"}`} />
            {isConnected ? "BACKEND CONNECTED" : "NOT CONNECTED"}
          </div>
        </div>
      </div>

      <div className="flex gap-6 flex-1 overflow-hidden">
        <div className="flex flex-col gap-4 w-80">
          <div className="p-4 rounded-lg" style={{ background: "rgba(21, 24, 45, 0.4)", border: "1px solid rgba(69,70,91,0.3)" }}>
            <h2 className="text-sm font-display uppercase tracking-wider mb-3 opacity-70">Test Controls</h2>
            <div className="flex flex-col gap-2">
              <button
                onClick={testConnection}
                className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-display transition-all"
                style={{
                  background: "rgba(63,255,139,0.1)",
                  color: "#3fff8b",
                  border: "1px solid rgba(63,255,139,0.3)",
                }}
              >
                <Activity size={14} /> Test Connection
              </button>
            </div>
          </div>

          <div className="p-4 rounded-lg" style={{ background: "rgba(21, 24, 45, 0.4)", border: "1px solid rgba(69,70,91,0.3)" }}>
            <h2 className="text-sm font-display uppercase tracking-wider mb-3 opacity-70">Simulate Threats</h2>
            <div className="flex flex-col gap-2">
              <button
                onClick={simulateCritical}
                className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-display transition-all hover:scale-[1.02]"
                style={{
                  background: "rgba(255,115,80,0.15)",
                  color: "#ff7350",
                  border: "1px solid rgba(255,115,80,0.3)",
                }}
              >
                <Shield size={14} /> Simulate CRITICAL
              </button>
              <button
                onClick={simulateHigh}
                className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-display transition-all hover:scale-[1.02]"
                style={{
                  background: "rgba(253,192,3,0.1)",
                  color: "#fdc003",
                  border: "1px solid rgba(253,192,3,0.3)",
                }}
              >
                <AlertTriangle size={14} /> Simulate HIGH
              </button>
              <button
                onClick={simulateMedium}
                className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-display transition-all hover:scale-[1.02]"
                style={{
                  background: "rgba(96,165,250,0.1)",
                  color: "#60a5fa",
                  border: "1px solid rgba(96,165,250,0.3)",
                }}
              >
                <Activity size={14} /> Simulate MEDIUM
              </button>
            </div>
          </div>

          <button
            onClick={clearResults}
            className="flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-display opacity-50 hover:opacity-100 transition-all"
          >
            Clear Results
          </button>
          <button
            onClick={resetDetection}
            className="flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-display transition-all"
            style={{
              background: "rgba(168,85,247,0.1)",
              color: "#a855f7",
              border: "1px solid rgba(168,85,247,0.3)",
            }}
          >
            Reset Detection
          </button>
        </div>

        <div className="flex-1 flex flex-col gap-4 overflow-hidden">
          <div className="flex-1 overflow-auto rounded-lg p-4" style={{ background: "rgba(21, 24, 45, 0.3)", border: "1px solid rgba(69,70,91,0.3)" }}>
            <h2 className="text-sm font-display uppercase tracking-wider mb-3 opacity-70">Test Results</h2>
            <div className="flex flex-col gap-2">
              {testResults.map((result, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 p-3 rounded-md"
                  style={{
                    background: result.status === "success" ? "rgba(63,255,139,0.05)" :
                               result.status === "error" ? "rgba(255,115,80,0.05)" :
                               "rgba(96,165,250,0.05)",
                    border: `1px solid ${
                      result.status === "success" ? "rgba(63,255,139,0.2)" :
                      result.status === "error" ? "rgba(255,115,80,0.2)" :
                      "rgba(96,165,250,0.2)"
                    }`,
                  }}
                >
                  {result.status === "success" ? (
                    <CheckCircle size={14} style={{ color: "#3fff8b" }} />
                  ) : result.status === "error" ? (
                    <AlertTriangle size={14} style={{ color: "#ff7350" }} />
                  ) : (
                    <Activity size={14} style={{ color: "#60a5fa" }} className="animate-pulse" />
                  )}
                  <div className="flex-1">
                    <div className="font-mono text-sm" style={{ color: "#e3e3fd" }}>{result.command}</div>
                    {result.response && (
                      <div className="text-xs opacity-60 mt-1">{result.response}</div>
                    )}
                  </div>
                  <span className="text-xs font-mono opacity-50">{result.timestamp}</span>
                </div>
              ))}
              {testResults.length === 0 && (
                <div className="text-center opacity-50 py-8">
                  No tests run yet. Click "Test Connection" to begin.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
