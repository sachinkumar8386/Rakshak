import { useState, useEffect } from "react";
import { Settings as SettingsIcon, Save } from "lucide-react";

let invoke: any = null;
try {
  import("@tauri-apps/api/core").then((m) => (invoke = m.invoke));
} catch {}

export default function SettingsView() {
  const [settings, setSettings] = useState<any>({ whitelist: "", auto_snapshot: false });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (invoke) {
      invoke("get_settings").then((s: any) => setSettings(s));
    }
  }, []);

  const saveSettings = async () => {
    if (!invoke) return;
    setSaving(true);
    // Note: rust endpoint is update_settings(new_settings: AppSettings)
    // By tauri standard, rust camelCases parameter to `newSettings` map JSON wrapper or raw depending on signature
    // Since rust takes `new_settings`, the payload usually needs matching key: `newSettings`
    await invoke("update_settings", { newSettings: settings });
    setTimeout(() => setSaving(false), 800);
  };

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <h1 className="text-2xl font-display font-bold tracking-wider flex items-center gap-3 opacity-80 mb-8">
        <SettingsIcon size={24} />
        GLOBAL SETTINGS
      </h1>

      <div className="max-w-2xl flex flex-col gap-6">
        <div className="p-6 rounded-lg border border-surface-ring" style={{ background: "rgba(21, 24, 45, 0.4)" }}>
            <h3 className="text-lg font-bold mb-2">Process Whitelist</h3>
            <p className="text-sm text-on-surface-muted mb-4 tracking-wide">Enter exact process names separated by commas (e.g. chrome.exe, code.exe) that will bypass heuristic detection rules.</p>
            <textarea 
                value={settings?.whitelist || ""}
                onChange={e => setSettings({...settings, whitelist: e.target.value})}
                className="w-full h-24 bg-[#0b0d1e] border border-surface-ring rounded-md p-4 text-sm font-mono focus:border-primary outline-none transition-colors"
            />
        </div>

        <div className="p-6 rounded-lg border border-surface-ring flex items-center justify-between" style={{ background: "rgba(21, 24, 45, 0.4)" }}>
            <div>
                <h3 className="text-lg font-bold mb-1">Auto-Snapshot</h3>
                <p className="text-sm text-on-surface-muted tracking-wide">Automatically create a Volume Shadow Copy (VSS) when a threat is identified and before process termination.</p>
            </div>
            <button 
              onClick={() => setSettings({...settings, auto_snapshot: !settings.auto_snapshot})}
              className="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer outline-none"
              style={{ background: settings?.auto_snapshot ? "#3fff8b" : "#45465b" }}
            >
              <span className={`inline-block h-4 w-4 transform rounded-full bg-black transition-transform ${settings?.auto_snapshot ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
        </div>

        <button 
            onClick={saveSettings}
            disabled={saving}
            className="self-start mt-4 px-8 py-3 rounded-lg font-bold transition-all text-sm tracking-widest uppercase flex items-center gap-2"
            style={{
                background: saving ? "transparent" : "#3fff8b",
                border: saving ? "1px solid #3fff8b" : "1px solid transparent",
                color: saving ? "#3fff8b" : "#000",
            }}
        >
            <Save size={18} />
            {saving ? "SAVED!" : "SAVE SETTINGS"}
        </button>
      </div>

    </div>
  );
}
