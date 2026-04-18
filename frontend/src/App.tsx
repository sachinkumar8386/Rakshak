import { useState, useEffect, useRef } from "react";
import "./App.css";
import Sidebar from "./components/layout/Sidebar";
import Dashboard from "./components/dashboard/Dashboard";
import Shield from "./components/dashboard/Shield";
import SystemWatcher from "./components/dashboard/SystemWatcher";
import ThreatOverlay from "./components/overlay/ThreatOverlay";
import C2MonitorModal from "./components/overlay/C2MonitorModal";
import ParticleNetwork from "./components/background/ParticleNetwork";
import ShieldWave from "./components/background/ShieldWave";

import ShieldStatusView from "./components/views/ShieldStatusView";
import ExpandedWatcher from "./components/views/ExpandedWatcher";
import ConnectionTest from "./components/views/ConnectionTest";

import AlertsView from "./components/views/AlertsView";
import SettingsView from "./components/views/SettingsView";

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

interface AlertPayload {
  pid?: number;
  process?: string;
  path?: string;
  entropy?: number;
  velocity?: number;
  level?: string;
  action?: string;
  timestamp?: string;
  should_popup?: boolean;
}

interface ProcessScore {
  pid: number;
  name: string;
  score: number;
  event_count: number;
  is_ransomware: boolean;
  is_suspicious: boolean;
}

const AudioContextClass = (window as any).AudioContext || (window as any).webkitAudioContext;
const persistentAudioCtx = AudioContextClass ? new AudioContextClass() : null;

const playAlertSound = () => {
  try {
    if (!persistentAudioCtx) return;
    if (persistentAudioCtx.state === "suspended") {
      persistentAudioCtx.resume();
    }
    const oscillator = persistentAudioCtx.createOscillator();
    const gainNode = persistentAudioCtx.createGain();
    oscillator.connect(gainNode);
    gainNode.connect(persistentAudioCtx.destination);
    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(880, persistentAudioCtx.currentTime);
    gainNode.gain.setValueAtTime(0.1, persistentAudioCtx.currentTime);
    oscillator.start();
    oscillator.stop(persistentAudioCtx.currentTime + 0.15);
  } catch (e) {
    console.warn("Audio play failed", e);
  }
};

const playRansomwareBeep = () => {
  try {
    if (!persistentAudioCtx) return;
    if (persistentAudioCtx.state === "suspended") {
      persistentAudioCtx.resume();
    }
    const times = [0, 0.15, 0.3];
    times.forEach((delay) => {
      const osc = persistentAudioCtx.createOscillator();
      const gain = persistentAudioCtx.createGain();
      osc.connect(gain);
      gain.connect(persistentAudioCtx.destination);
      osc.type = "square";
      osc.frequency.setValueAtTime(delay === 0 ? 1000 : 800, persistentAudioCtx.currentTime + delay);
      gain.gain.setValueAtTime(0.3, persistentAudioCtx.currentTime + delay);
      gain.gain.exponentialRampToValueAtTime(0.01, persistentAudioCtx.currentTime + delay + 0.12);
      osc.start(persistentAudioCtx.currentTime + delay);
      osc.stop(persistentAudioCtx.currentTime + delay + 0.12);
    });
  } catch (e) {
    console.warn("Beep sound failed", e);
  }
};

export default function App() {
  const [activeView, setActiveView] = useState("dashboard");
  const [threatActive, setThreatActive] = useState(false);
  const [c2Breach, setC2Breach] = useState(false);
  const [overlayVisible, setOverlayVisible] = useState(false);
  const [alertPayload, setAlertPayload] = useState<AlertPayload | undefined>();
  const [c2ModalVisible, setC2ModalVisible] = useState(false);
  const [detectionScores, setDetectionScores] = useState<ProcessScore[]>([]);

  const unlistenThreatRef = useRef<(() => void) | null>(null);
  const unlistenKillRef = useRef<(() => void) | null>(null);
  const lastKillRef = useRef<{ pid: number; time: number }>({ pid: 0, time: 0 });
  const isBoundRef = useRef(false);

  function resetThreatState() {
    setThreatActive(false);
    setC2Breach(false);
    setAlertPayload(undefined);
  }

  useEffect(() => {
    let cancelled = false;

    const bind = async () => {
      if (!listen || isBoundRef.current) return;

      try {
        console.log("[App] Binding defense event streams...");

        unlistenThreatRef.current = await listen("THREAT_DETECTED", (evt) => {
          if (cancelled) return;
          const payload = evt.payload as AlertPayload;
          const now = Date.now();

          if (payload.pid === lastKillRef.current.pid && now - lastKillRef.current.time < 5000) {
            return;
          }

          const shouldPopup = payload.should_popup !== false;

          if (shouldPopup) {
            playRansomwareBeep();
            setAlertPayload(payload);
            setThreatActive(true);
            setOverlayVisible(true);
          }

          const isCritical = payload.level === "CRITICAL" || payload.entropy && payload.entropy > 7.5;
          if (isCritical) {
            setDetectionScores((prev) =>
              prev.map((s) =>
                s.pid === payload.pid
                  ? { ...s, score: 100, is_ransomware: true }
                  : s
              )
            );
          }
        });

        unlistenKillRef.current = await listen("PROCESS_KILLED", (evt) => {
          if (cancelled) return;
          const payload = evt.payload as { pid: number };
          lastKillRef.current = { pid: payload.pid, time: Date.now() };
          console.log(`[App] Neutralization confirmed. Holding red for 5s...`);
          setTimeout(() => {
            if (!cancelled) resetThreatState();
          }, 5000);
        });

        isBoundRef.current = true;
        console.log("[App] Defense streams successfully bound.");
      } catch (err) {
        console.error("[App] Failed to bind listeners:", err);
      }
    };

    const heartbeat = setInterval(() => {
      if (!isBoundRef.current && listen) {
        bind();
      }
    }, 500);

    bind();

    const fetchScores = async () => {
      if (!invoke) return;
      try {
        const scores = await invoke("get_detection_scores") as ProcessScore[];
        if (scores) setDetectionScores(scores);
      } catch {}
    };
    fetchScores();
    const scoreInterval = setInterval(fetchScores, 1000);

    return () => {
      cancelled = true;
      clearInterval(heartbeat);
      clearInterval(scoreInterval);
      unlistenThreatRef.current?.();
      unlistenKillRef.current?.();
      isBoundRef.current = false;
    };
  }, []);

  function handleC2Detected(detected: boolean) {
    setC2Breach(detected);
    if (detected) {
      setThreatActive(true);
      playAlertSound();
      setAlertPayload({
        pid: 0,
        process: "C2 Beacon Correlation",
        path: "Network → External IP",
        entropy: 0,
        timestamp: new Date().toISOString(),
      });
      setOverlayVisible(true);
    }
  }

  const hasSuspicious = detectionScores.some((s) => s.is_suspicious || s.score > 30);

  return (
    <div
      className="relative flex h-screen w-screen overflow-hidden"
      style={{ background: "#0b0d1e", fontFamily: "Inter, sans-serif" }}
    >
      <ParticleNetwork />
      <ShieldWave threatActive={threatActive} />
      <Sidebar
        activeView={activeView}
        onNavigate={(id) => setActiveView(id)}
        onOpenC2={() => setC2ModalVisible(true)}
        threatActive={threatActive}
      />
      <main className="relative flex-1 overflow-y-auto min-w-0 z-10">
        {activeView === "dashboard" && (
          <Dashboard
            threatActive={threatActive}
            onOpenC2={() => setC2ModalVisible(true)}
            ShieldComponent={
              <Shield
                threatActive={threatActive}
                warningActive={hasSuspicious}
                c2Breach={c2Breach}
              />
            }
            WatcherComponent={<SystemWatcher threatActive={threatActive} />}
          />
        )}
        {activeView === "shield" && <ShieldStatusView />}
        {activeView === "watcher" && <ExpandedWatcher />}
        {activeView === "alerts" && <AlertsView />}
        {activeView === "test" && <ConnectionTest />}
        {activeView === "settings" && <SettingsView />}
      </main>
      <C2MonitorModal
        visible={c2ModalVisible}
        onClose={() => setC2ModalVisible(false)}
        onC2Detected={handleC2Detected}
      />
      <ThreatOverlay
        visible={overlayVisible}
        onDismiss={() => setOverlayVisible(false)}
        payload={alertPayload}
      />
    </div>
  );
}
