import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, Clock, FileWarning, Flame, CheckCircle2, Wifi, Activity } from "lucide-react";

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

interface LogEntry {
  id: number;
  type: "threat" | "warning" | "info";
  message: string;
  time: string;
  path?: string;
  entropy?: number;
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

let _id = 1;

function typeColor(type: LogEntry["type"]) {
  if (type === "threat") return "#ff7350";
  if (type === "warning") return "#fdc003";
  return "#3fff8b";
}

function typeIcon(type: LogEntry["type"]) {
  if (type === "threat") return <Flame size={12} />;
  if (type === "warning") return <FileWarning size={12} />;
  return <CheckCircle2 size={12} />;
}

function now() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

interface DashboardProps {
  threatActive: boolean;
  onOpenC2: () => void;
  ShieldComponent: React.ReactNode;
  WatcherComponent: React.ReactNode;
}

export default function Dashboard({
  threatActive,
  onOpenC2,
  ShieldComponent,
  WatcherComponent,
}: DashboardProps) {
  const [logs, setLogs] = useState<LogEntry[]>([
    { id: _id++, type: "info", message: "Engine started. Honeypots armed.", time: now() },
    { id: _id++, type: "info", message: "Real-time protection active", time: now() },
    { id: _id++, type: "info", message: "File watcher monitoring...", time: now() },
  ]);
  const [backendConnected, setBackendConnected] = useState(false);
  const threatEventsRef = useRef<ThreatEvent[]>([]);
  const unlistenRef = useRef<(() => void)[]>([]);

  useEffect(() => {
    if (!listen) return;

    const setupListeners = async () => {
      if (!listen) return;

      const unlisten = await listen("THREAT_DETECTED", (evt) => {
        const threat = evt.payload as ThreatEvent;
        threatEventsRef.current = [threat, ...threatEventsRef.current].slice(0, 50);

        const logType = threat.level === "CRITICAL" || threat.level === "HIGH" ? "threat" : "warning";

        setLogs((prev) => [
          ...prev.slice(-40),
          {
            id: _id++,
            type: logType,
            message: `${threat.level}: ${threat.process} - ${threat.action}`,
            time: now(),
            path: threat.file,
            entropy: threat.entropy,
          },
        ]);
      });

      const unlistenKill = await listen("PROCESS_KILLED", () => {
        setLogs((prev) => [
          ...prev.slice(-40),
          { id: _id++, type: "info", message: "Process terminated - threat neutralized", time: now() },
        ]);
      });

      unlistenRef.current = [unlisten, unlistenKill];
      setBackendConnected(true);
    };

    setupListeners();

    return () => {
      unlistenRef.current.forEach((fn) => fn());
    };
  }, []);

  useEffect(() => {
    if (!invoke) return;

    const fetchStatus = async () => {
      if (!invoke) return;
      try {
        await invoke("get_alert_history");
        setBackendConnected(true);
      } catch {}
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (threatActive) {
      setLogs((prev) => [
        ...prev.slice(-40),
        { id: _id++, type: "threat", message: "ALERT: High-entropy write detected!", time: now(), path: "Documents" },
        { id: _id++, type: "threat", message: "PID flagged — checking network beacons", time: now() },
      ]);
    }
  }, [threatActive]);

  return (
    <div className="h-full flex flex-col gap-3 p-5 overflow-hidden">
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-xl font-display font-bold tracking-tight text-on-surface">
            Threat Dashboard
          </h1>
          <p className="text-xs opacity-40 mt-0.5 font-body tracking-wide">
            RAKSHAK INTELLIGENCE PLATFORM · REAL-TIME
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 opacity-50 text-xs font-mono">
            <Clock size={12} />
            <LiveClock />
          </div>
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-display font-semibold select-none"
            style={{
              background: threatActive ? "rgba(255,115,80,0.15)" : backendConnected ? "rgba(63,255,139,0.1)" : "rgba(69,70,91,0.2)",
              color: threatActive ? "#ff7350" : backendConnected ? "#3fff8b" : "#60a5fa",
              outline: "1px solid rgba(69,70,91,0.3)",
            }}
          >
            {backendConnected ? (
              <>
                <Activity size={14} />
                {threatActive ? "THREAT ACTIVE" : "MONITORING"}
              </>
            ) : (
              <>
                <Bell size={14} />
                CONNECTING...
              </>
            )}
            {threatActive && (
              <span className="w-2 h-2 rounded-full bg-tertiary animate-ping" />
            )}
          </div>
          <button
            id="c2-monitor-open-btn"
            onClick={onOpenC2}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-display font-semibold select-none cursor-pointer transition-all"
            style={{
              background: "rgba(69, 70, 91, 0.25)",
              color: "#60a5fa",
              border: "1px solid rgba(96, 165, 250, 0.2)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(96, 165, 250, 0.15)";
              e.currentTarget.style.borderColor = "rgba(96, 165, 250, 0.4)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(69, 70, 91, 0.25)";
              e.currentTarget.style.borderColor = "rgba(96, 165, 250, 0.2)";
            }}
          >
            <Wifi size={12} />
            C2 MONITOR
          </button>
        </div>
      </div>

      <div className="flex gap-3 flex-1 min-h-0">
        <div
          className="flex flex-col shrink-0 rounded-lg p-4 overflow-y-auto glass-card"
          style={{ width: "26%", minWidth: 210 }}
        >
          {WatcherComponent}
        </div>

        <motion.div
          className="flex-1 flex flex-col items-center justify-center rounded-lg p-6 relative overflow-hidden glass-card"
          animate={{
            background: threatActive
              ? "rgba(26, 13, 11, 0.6)"
              : "rgba(15, 18, 37, 0.5)",
          }}
          transition={{ duration: 0.8 }}
        >
          <motion.div
            className="absolute inset-0 pointer-events-none"
            animate={{
              background: threatActive
                ? "radial-gradient(circle at 50% 50%, rgba(255,115,80,0.1) 0%, transparent 65%)"
                : "radial-gradient(circle at 50% 50%, rgba(63,255,139,0.08) 0%, transparent 65%)",
            }}
            transition={{ duration: 0.8 }}
          />
          {ShieldComponent}
        </motion.div>

        <div
          className="flex flex-col rounded-lg p-4 overflow-hidden glass-card"
          style={{ width: "26%", minWidth: 200, maxWidth: 320, flexShrink: 0 }}
        >
          <div className="flex items-center gap-2 mb-3 shrink-0">
            <Bell size={14} className="opacity-50" style={{ color: "#fdc003" }} />
            <h2 className="text-xs uppercase tracking-[0.2em] font-display opacity-60 text-on-surface">
              Activity Log
            </h2>
            {threatEventsRef.current.length > 0 && (
              <span
                className="ml-auto text-xs font-mono px-2 py-0.5 rounded"
                style={{ background: "rgba(255,115,80,0.15)", color: "#ff7350" }}
              >
                {threatEventsRef.current.length}
              </span>
            )}
          </div>
          <div className="flex flex-col gap-1 overflow-y-auto flex-1 pr-1">
            <AnimatePresence initial={false}>
              {[...logs].reverse().map((entry) => (
                <motion.div
                  key={entry.id}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="flex gap-2 p-2.5 rounded text-xs items-start shrink-0"
                  style={{
                    background: entry.type === "threat" ? "rgba(255,115,80,0.08)" : "#21243d",
                  }}
                >
                  <span className="mt-0.5" style={{ color: typeColor(entry.type) }}>
                    {typeIcon(entry.type)}
                  </span>
                  <div className="flex flex-col gap-0.5 min-w-0">
                    <span className="font-mono leading-snug break-words" style={{ color: "#e3e3fd" }}>
                      {entry.message}
                    </span>
                    {entry.path && (
                      <span className="font-mono opacity-50 break-all text-[10px]" style={{ color: "#a8a9c1" }}>
                        {entry.path}
                      </span>
                    )}
                    {entry.entropy !== undefined && (
                      <span className="font-mono opacity-50 text-[10px]" style={{ color: "#fdc003" }}>
                        Entropy: {entry.entropy.toFixed(2)}
                      </span>
                    )}
                    <span className="opacity-30 font-mono text-[10px]">{entry.time}</span>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}

function LiveClock() {
  const [time, setTime] = useState(now());
  useEffect(() => {
    const id = setInterval(() => setTime(now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{time}</span>;
}
