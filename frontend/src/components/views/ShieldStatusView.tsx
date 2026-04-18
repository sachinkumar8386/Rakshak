import { useState, useEffect } from "react";

let invoke: any = null;
try {
  import("@tauri-apps/api/core").then((m) => (invoke = m.invoke));
} catch {}

interface Settings {
  engine_enabled: boolean;
  honeypots_enabled: boolean;
  watchdog_enabled: boolean;
}

export default function ShieldStatusView() {
  const [settings, setSettings] = useState<Settings>({
    engine_enabled: true,
    honeypots_enabled: true,
    watchdog_enabled: true,
  });

  useEffect(() => {
    if (invoke) {
      invoke("get_settings").then((s: any) => setSettings(s));
    }
  }, []);

  const toggle = async (key: keyof Settings, layerName: string) => {
    const newVal = !settings[key];
    setSettings((prev) => ({ ...prev, [key]: newVal }));
    if (invoke) {
      await invoke("toggle_layer", { layer: layerName, enabled: newVal });
    }
  };

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <h1 className="text-2xl font-display font-bold tracking-wider mb-8 flex items-center gap-3">
        <span className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_#3fff8b]"></span>
        SHIELD STATUS
      </h1>
      
      <div className="flex flex-col gap-4 max-w-3xl">
        <LayerCard 
          title="Entropy Engine" 
          desc="Real-time Shannon entropy baseline analysis and heuristic chunking."
          active={settings.engine_enabled}
          onToggle={() => toggle("engine_enabled", "engine")}
        />
        <LayerCard 
          title="Honeypots" 
          desc="Decoy documents across file system to instantly trap ransomware IO."
          active={settings.honeypots_enabled}
          onToggle={() => toggle("honeypots_enabled", "honeypots")}
        />
        <LayerCard 
          title="Watchdog Limits" 
          desc="Hard OS process limits targeting aggressive unbounded CPU spikes."
          active={settings.watchdog_enabled}
          onToggle={() => toggle("watchdog_enabled", "watchdog")}
        />
      </div>
    </div>
  );
}

function LayerCard({ title, desc, active, onToggle }: { title: string, desc: string, active: boolean, onToggle: () => void }) {
  return (
    <div className="flex items-center justify-between p-5 rounded-lg border border-surface-ring group transition-all" style={{ background: "rgba(21, 24, 45, 0.4)" }}>
      <div>
        <h3 className="text-lg font-bold" style={{ color: active ? "#3fff8b" : "#a8a9c1" }}>{title}</h3>
        <p className="text-sm text-on-surface-muted mt-1">{desc}</p>
      </div>
      <div>
        <button 
          onClick={onToggle}
          className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer outline-none"
          style={{ background: active ? "#3fff8b" : "#45465b" }}
        >
          <span className={`inline-block h-4 w-4 transform rounded-full bg-black transition-transform ${active ? 'translate-x-6' : 'translate-x-1'}`} />
        </button>
      </div>
    </div>
  );
}
