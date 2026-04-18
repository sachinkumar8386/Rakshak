import { useState } from "react";
import { FolderSearch, AlertTriangle, ShieldCheck, FolderOpen } from "lucide-react";

let invoke: any = null;
try {
  import("@tauri-apps/api/core").then((m) => (invoke = m.invoke));
} catch {}

let openDialog: any = null;
try {
  import("@tauri-apps/plugin-dialog").then((m) => (openDialog = m.open));
} catch {}

interface ScanResult {
  path: string;
  entropy: number;
  is_suspicious: boolean;
}

export default function FileScanner() {
  const [path, setPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[] | null>(null);

  const browseFolder = async () => {
    if (!openDialog) return;
    try {
      const selected = await openDialog({
        directory: true,
        multiple: false,
        title: "Select folder to scan",
      });
      if (selected && typeof selected === "string") {
        setPath(selected);
      }
    } catch (e) {
      console.warn("Dialog cancelled or failed:", e);
    }
  };

  const startScan = async () => {
    if (!path || !invoke) return;
    setScanning(true);
    setResults(null);
    try {
      const res: ScanResult[] = await invoke("scan_directory", { path });
      setResults(res);
    } catch (e) {
      console.error(e);
      alert("Scan failed: " + e);
    } finally {
      setScanning(false);
    }
  };

  const suspiciousCount = results?.filter((r) => r.is_suspicious).length ?? 0;
  const safeCount = results ? results.length - suspiciousCount : 0;

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <h1 className="text-2xl font-display font-bold tracking-wider mb-8 flex items-center gap-3">
        <FolderSearch size={24} className="text-primary" />
        ON-DEMAND SCAN
      </h1>

      <div className="flex gap-3 mb-6 shrink-0">
        <input 
          type="text" 
          placeholder="C:\Users\Username\Documents"
          className="flex-1 border border-surface-ring rounded-lg px-4 py-2.5 text-sm outline-none focus:border-primary transition-colors"
          style={{ background: "rgba(21, 24, 45, 0.4)" }}
          value={path}
          onChange={e => setPath(e.target.value)}
        />
        <button 
          onClick={browseFolder}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold uppercase tracking-wider transition-all cursor-pointer"
          style={{
            background: "rgba(69, 70, 91, 0.35)",
            color: "#a8a9c1",
            border: "1px solid rgba(69, 70, 91, 0.5)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "rgba(96, 165, 250, 0.15)";
            e.currentTarget.style.color = "#60a5fa";
            e.currentTarget.style.borderColor = "rgba(96, 165, 250, 0.4)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "rgba(69, 70, 91, 0.35)";
            e.currentTarget.style.color = "#a8a9c1";
            e.currentTarget.style.borderColor = "rgba(69, 70, 91, 0.5)";
          }}
        >
          <FolderOpen size={16} />
          Browse
        </button>
        <button 
          onClick={startScan}
          disabled={scanning || !path}
          className="bg-primary text-black px-6 py-2.5 rounded-lg font-bold hover:brightness-110 active:scale-95 transition-all disabled:opacity-50 disabled:active:scale-100 uppercase tracking-widest text-sm"
        >
          {scanning ? "Scanning..." : "Scan"}
        </button>
      </div>

      {/* Stats bar */}
      {results && results.length > 0 && (
        <div className="flex items-center gap-4 mb-4 shrink-0">
          <span className="text-xs font-mono uppercase tracking-wider opacity-60">
            {results.length} files scanned
          </span>
          <span className="text-xs font-bold uppercase tracking-wider" style={{ color: "#3fff8b" }}>
            {safeCount} Safe
          </span>
          {suspiciousCount > 0 && (
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: "#ff7350" }}>
              {suspiciousCount} Suspicious
            </span>
          )}
        </div>
      )}

      <div className="flex-1 overflow-auto border border-surface-ring rounded-lg" style={{ background: "rgba(21, 24, 45, 0.2)" }}>
        {results === null && !scanning && (
          <div className="h-full flex flex-col items-center justify-center opacity-30 text-sm tracking-widest uppercase gap-3">
            <FolderSearch size={40} className="opacity-40" />
            Select a folder and hit Scan
          </div>
        )}
        
        {scanning && (
          <div className="h-full flex flex-col items-center justify-center opacity-80 text-sm tracking-widest uppercase animate-pulse text-primary gap-3">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            Analyzing Entropy Signatures...
          </div>
        )}

        {results && results.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-sm tracking-widest uppercase text-primary opacity-50">
            <ShieldCheck size={48} className="mb-4 opacity-50" />
            No threats detected
          </div>
        )}

        {results && results.length > 0 && (
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 border-b border-surface-ring text-on-surface-muted uppercase text-xs tracking-widest backdrop-blur-md bg-[#0b0d1e]/80 z-10">
              <tr>
                <th className="px-6 py-4">Threat Level</th>
                <th className="px-6 py-4">Entropy</th>
                <th className="px-6 py-4 w-full">File Path</th>
              </tr>
            </thead>
            <tbody>
              {results.map((res, i) => (
                <tr key={i} className="border-b border-surface-ring/50 hover:bg-surface-ring/20 transition-colors">
                  <td className="px-6 py-3">
                    {res.is_suspicious ? (
                      <span className="text-tertiary flex items-center gap-2 font-bold"><AlertTriangle size={14}/> HIGH</span>
                    ) : (
                      <span className="text-primary flex items-center gap-2">SAFE</span>
                    )}
                  </td>
                  <td className="px-6 py-3 font-mono opacity-80">{res.entropy.toFixed(3)}</td>
                  <td className="px-6 py-3 opacity-60 font-mono break-all text-xs">{res.path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
