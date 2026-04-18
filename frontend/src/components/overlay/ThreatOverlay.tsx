import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  X,
  Wifi,
  HardDrive,
  Terminal,
  Zap,
} from "lucide-react";

interface ThreatOverlayProps {
  visible: boolean;
  onDismiss: () => void;
  payload?: {
    pid?: number;
    process?: string;
    path?: string;
    entropy?: number;
    timestamp?: string;
  };
}

const STATIC_LINES = [
  "Monitoring kernel-level syscalls...",
  "Shadow copy deletion attempt blocked",
  "Honeypot access at C:/rakshak/.trap/decoy_01.docx",
  "Entropy spike: 7.94 bits/byte at AppData\\Local",
  "ISOLATING: PID 4821 — suspicious_proc.exe",
];

function GlitchText({ children }: { children: string }) {
  const [glitch, setGlitch] = useState(false);
  useEffect(() => {
    const id = setInterval(() => {
      setGlitch(true);
      setTimeout(() => setGlitch(false), 80);
    }, 2400 + Math.random() * 2000);
    return () => clearInterval(id);
  }, []);
  return (
    <motion.span
      style={{
        display: "inline-block",
        filter: glitch ? "blur(0.5px) brightness(1.8)" : "none",
        transform: glitch ? `skewX(${(Math.random() - 0.5) * 8}deg)` : "none",
        transition: "filter 0.05s, transform 0.05s",
      }}
    >
      {children}
    </motion.span>
  );
}

export default function ThreatOverlay({ visible, onDismiss, payload }: ThreatOverlayProps) {
  const [logLines, setLogLines] = useState<string[]>([]);
  const now = payload?.timestamp ?? new Date().toISOString();

  // Feed log lines progressively when overlay opens
  useEffect(() => {
    if (!visible) {
      setLogLines([]);
      return;
    }
    let i = 0;
    const id = setInterval(() => {
      if (i < STATIC_LINES.length) {
        setLogLines((prev) => [...prev, STATIC_LINES[i]]);
        i++;
      } else {
        clearInterval(id);
      }
    }, 420);
    return () => clearInterval(id);
  }, [visible]);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          key="threat-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-6"
          style={{
            backdropFilter: "blur(20px) saturate(0.7)",
            WebkitBackdropFilter: "blur(20px) saturate(0.7)",
            background: "rgba(11,13,30,0.85)",
          }}
        >
          {/* Animated scan line */}
          <motion.div
            className="absolute left-0 right-0 h-px pointer-events-none"
            style={{ background: "rgba(255,115,80,0.3)" }}
            animate={{ top: ["0%", "100%"] }}
            transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          />

          {/* Main card */}
          <motion.div
            initial={{ scale: 0.88, y: 24, opacity: 0 }}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.92, y: 12, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
            className="relative flex flex-col gap-6 w-full max-w-xl p-8 rounded-lg overflow-hidden"
            style={{
              background: "rgba(21,24,45,0.92)",
              boxShadow:
                "0 0 0 1px rgba(255,115,80,0.25), 0 0 80px rgba(255,115,80,0.18), 0 32px 64px rgba(0,0,0,0.6)",
            }}
          >
            {/* Red top accent strip */}
            <div
              className="absolute top-0 left-0 right-0 h-0.5"
              style={{
                background: "linear-gradient(90deg, transparent, #ff7350, #fc3c00, #ff7350, transparent)",
              }}
            />

            {/* Header */}
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-4">
                <motion.div
                  className="p-3 rounded-md shrink-0"
                  animate={{
                    boxShadow: [
                      "0 0 12px rgba(255,115,80,0.4)",
                      "0 0 28px rgba(255,115,80,0.7)",
                      "0 0 12px rgba(255,115,80,0.4)",
                    ],
                  }}
                  transition={{ duration: 1.2, repeat: Infinity }}
                  style={{ background: "rgba(255,115,80,0.15)" }}
                >
                  <ShieldAlert size={28} color="#ff7350" />
                </motion.div>
                <div>
                  <p
                    className="text-xs tracking-[0.3em] uppercase font-display mb-1 font-bold"
                    style={{ color: "#ff7350" }}
                  >
                    Security Alert
                  </p>
                  <h2 className="text-2xl font-display font-bold text-on-surface tracking-tight">
                    <GlitchText>Ransomware Detected</GlitchText>
                  </h2>
                </div>
              </div>
              <button
                onClick={onDismiss}
                className="opacity-40 hover:opacity-100 transition-opacity mt-1 shrink-0 cursor-pointer"
                style={{ color: "#e3e3fd" }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Threat details grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { icon: <Terminal size={14} />, label: "Process", value: payload?.process ?? "suspicious_proc.exe" },
                { icon: <Zap size={14} />, label: "Entropy", value: payload?.entropy != null ? `${payload.entropy.toFixed(2)} bits/byte` : "7.94" },
                { icon: <HardDrive size={14} />, label: "PID", value: payload?.pid ?? "4821" },
                { icon: <Wifi size={14} />, label: "Timestamp", value: now.replace("T", " ").slice(0, 19) },
              ].map((item) => (
                <div
                  key={item.label}
                  className="flex flex-col gap-1.5 p-3 rounded-md border border-surface-ring/10"
                  style={{ background: "#1c1f38" }}
                >
                  <div
                    className="flex items-center gap-1.5 text-xs uppercase tracking-widest opacity-50"
                    style={{ color: "#a8a9c1" }}
                  >
                    {item.icon}
                    {item.label}
                  </div>
                  <span
                    className="text-sm font-mono break-all font-bold"
                    style={{ color: "#e3e3fd" }}
                  >
                    {item.value}
                  </span>
                </div>
              ))}
            </div>

            {/* Live log feed */}
            <div
              className="p-3 rounded-md font-mono text-xs flex flex-col gap-1.5 overflow-hidden"
              style={{ background: "#0b0d1e", minHeight: 100 }}
            >
              <AnimatePresence initial={false}>
                {logLines.map((line, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.25 }}
                    className="flex items-start gap-2 leading-relaxed"
                  >
                    <span style={{ color: "#ff7350" }}>❯</span>
                    <span style={{ color: "#a8a9c1" }}>{line}</span>
                  </motion.div>
                ))}
              </AnimatePresence>
              {logLines.length < STATIC_LINES.length && (
                <motion.span
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 0.7, repeat: Infinity }}
                  style={{ color: "#ff7350" }}
                >
                  █
                </motion.span>
              )}
            </div>

            {/* Action area — process was auto-killed by the backend */}
            <div className="flex flex-col gap-3">
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.5 }}
                className="py-3 rounded-md text-sm font-display font-bold flex items-center justify-center gap-2 uppercase tracking-widest"
                style={{
                  background: "rgba(63,255,139,0.12)",
                  color: "#3fff8b",
                  border: "1px solid rgba(63,255,139,0.25)",
                }}
              >
                <ShieldAlert size={16} />
                THREAT NEUTRALIZED — Process auto-killed
              </motion.div>
              <button
                onClick={onDismiss}
                className="w-full py-3 rounded-md text-sm font-display font-medium transition-all duration-200 cursor-pointer"
                style={{
                  background: "rgba(69,70,91,0.25)",
                  color: "#a8a9c1",
                  border: "1px solid rgba(69,70,91,0.4)",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(69,70,91,0.35)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "rgba(69,70,91,0.25)")}
              >
                Dismiss
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
