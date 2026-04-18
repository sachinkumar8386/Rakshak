import { useState, useEffect, useCallback, useRef } from "react";

let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
let listen: ((event: string, cb: (e: { payload: unknown }) => void) => Promise<() => void>) | null = null;

try {
  import("@tauri-apps/api/core").then((m) => {
    invoke = m.invoke;
  });
  import("@tauri-apps/api/event").then((m) => {
    listen = m.listen;
  });
} catch {
  console.log("Running outside Tauri environment");
}

export interface SecurityAlert {
  process: string;
  pid: number;
  path: string;
  entropy: number;
  timestamp: string;
  score?: number;
  reasons?: string[];
}

export interface ProcessScore {
  pid: number;
  name: string;
  score: number;
  event_count: number;
  is_ransomware: boolean;
  is_suspicious: boolean;
}

export interface SystemTelemetry {
  cpu_usage: number;
  ram_usage: number;
  disk_io: number;
  network_io: number;
  active_processes: number;
}

export interface ThreatEvent {
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  pid: number;
  process: string;
  file?: string;
  action: string;
  entropy?: number;
  velocity?: number;
  timestamp: string;
}

export function useBackendConnection() {
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [detectionScores, setDetectionScores] = useState<ProcessScore[]>([]);
  const [telemetry, setTelemetry] = useState<SystemTelemetry | null>(null);
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([]);
  const listenersRef = useRef<(() => void)[]>([]);

  const fetchAlerts = useCallback(async () => {
    if (!invoke) return;
    try {
      const hist = await invoke("get_alert_history") as SecurityAlert[];
      if (hist) setAlerts(hist);
    } catch (e) {
      console.error("Failed to fetch alerts:", e);
    }
  }, []);

  const fetchDetectionScores = useCallback(async () => {
    if (!invoke) return;
    try {
      const scores = await invoke("get_detection_scores") as ProcessScore[];
      if (scores) setDetectionScores(scores);
    } catch (e) {
      console.error("Failed to fetch detection scores:", e);
    }
  }, []);

  const fetchTelemetry = useCallback(async () => {
    if (!invoke) return;
    try {
      const tel = await invoke("get_telemetry") as SystemTelemetry;
      if (tel) setTelemetry(tel);
    } catch (e) {
      console.error("Failed to fetch telemetry:", e);
    }
  }, []);

  useEffect(() => {
    if (!listen) return;

    const setupListeners = async () => {
      if (!listen) return;
      const cleanup: (() => void)[] = [];

      const unlistenThreat = await listen("THREAT_DETECTED", (evt) => {
        const threat = evt.payload as ThreatEvent;
        setThreatEvents((prev) => [threat, ...prev].slice(0, 100));
        setAlerts((prev) => {
          const newAlert: SecurityAlert = {
            process: threat.process,
            pid: threat.pid,
            path: threat.file || "Unknown",
            entropy: threat.entropy || 0,
            timestamp: threat.timestamp || new Date().toISOString(),
            score: threat.level === "CRITICAL" ? 100 : threat.level === "HIGH" ? 60 : 30,
            reasons: [`${threat.action}: ${threat.level}`],
          };
          return [newAlert, ...prev].slice(0, 50);
        });
      });
      cleanup.push(unlistenThreat);

      const unlistenKill = await listen("PROCESS_KILLED", (evt) => {
        console.log("Process killed:", evt.payload);
      });
      cleanup.push(unlistenKill);

      listenersRef.current = cleanup;
      setIsConnected(true);
    };

    setupListeners();

    return () => {
      listenersRef.current.forEach((fn) => fn());
    };
  }, []);

  useEffect(() => {
    fetchAlerts();
    fetchDetectionScores();
    fetchTelemetry();

    const alertInterval = setInterval(fetchAlerts, 2000);
    const scoreInterval = setInterval(fetchDetectionScores, 1000);
    const telemetryInterval = setInterval(fetchTelemetry, 1000);

    return () => {
      clearInterval(alertInterval);
      clearInterval(scoreInterval);
      clearInterval(telemetryInterval);
    };
  }, [fetchAlerts, fetchDetectionScores, fetchTelemetry]);

  const clearAlerts = useCallback(async () => {
    if (!invoke) return;
    try {
      await invoke("clear_alert_history");
      setAlerts([]);
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  }, []);

  return {
    isConnected,
    alerts,
    detectionScores,
    telemetry,
    threatEvents,
    clearAlerts,
    fetchAlerts,
  };
}

export function useThreatListener(onThreat: (threat: ThreatEvent) => void) {
  useEffect(() => {
    if (!listen) return;

    let unlisten: (() => void) | null = null;

    listen("THREAT_DETECTED", (evt) => {
      onThreat(evt.payload as ThreatEvent);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
    };
  }, [onThreat]);
}
