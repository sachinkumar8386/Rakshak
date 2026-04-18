import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, ShieldAlert, ShieldOff, Zap, Clock } from "lucide-react";

interface ShieldProps {
  threatActive: boolean;
  warningActive: boolean;
  c2Breach?: boolean;
}

// Pulsing ring component
function PulseRing({
  color,
  delay,
  size,
}: {
  color: string;
  delay: number;
  size: number;
}) {
  return (
    <motion.div
      className="absolute rounded-full pointer-events-none"
      style={{
        width: size,
        height: size,
        border: `1px solid ${color}`,
        top: "50%",
        left: "50%",
        x: "-50%",
        y: "-50%",
      }}
      animate={{ scale: [1, 1.6], opacity: [0.4, 0] }}
      transition={{ duration: 2.5, repeat: Infinity, delay, ease: "easeOut" }}
    />
  );
}

export default function Shield({ threatActive, warningActive, c2Breach }: ShieldProps) {
  const primary = "#3fff8b";
  const tertiary = "#ff7350";
  const secondary = "#fdc003";
  const c2Red = "#ff2020";

  const isAlert = threatActive || c2Breach;
  const color = c2Breach ? c2Red : threatActive ? tertiary : warningActive ? secondary : primary;
  const glowColor = c2Breach
    ? "rgba(255,32,32,0.35)"
    : threatActive
    ? "rgba(255,115,80,0.3)"
    : warningActive
    ? "rgba(253,192,3,0.25)"
    : "rgba(63,255,139,0.25)";

  const label = c2Breach
    ? "C2 BREACH DETECTED"
    : threatActive
    ? "THREAT DETECTED"
    : warningActive
    ? "CAUTION — ANOMALY"
    : "SYSTEM SECURE";

  const Icon = isAlert ? ShieldAlert : warningActive ? ShieldOff : ShieldCheck;

  return (
    <div className="flex flex-col items-center gap-6 select-none">
      {/* Status label */}
      <motion.div
        animate={{ color }}
        transition={{ duration: 0.6 }}
        className="text-xs tracking-[0.25em] uppercase font-display font-semibold flex items-center gap-2"
      >
        <motion.div
          className="w-2 h-2 rounded-full"
          animate={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
          style={{ animation: "none" }}
          transition={{ duration: 0.6 }}
        />
        <motion.span animate={{ opacity: [0.7, 1, 0.7] }} transition={{ duration: 2, repeat: Infinity }}>
          {label}
        </motion.span>
      </motion.div>

      {/* Shield with rings */}
      <div className="relative flex items-center justify-center" style={{ width: 220, height: 220 }}>
        {/* Pulse rings */}
        <AnimatePresence>
          {!isAlert && (
            <>
              <PulseRing color={color} delay={0} size={160} />
              <PulseRing color={color} delay={0.8} size={200} />
            </>
          )}
          {isAlert && (
            <>
              <motion.div
                key="threat-ring-1"
                className="absolute rounded-full"
                style={{ width: 160, height: 160, top: "50%", left: "50%", x: "-50%", y: "-50%" }}
                animate={{ scale: [1, 1.5], opacity: [0.6, 0] }}
                transition={{ duration: 1, repeat: Infinity, ease: "easeOut", delay: 0 }}
              >
                <div className="w-full h-full rounded-full" style={{ border: `1px solid ${tertiary}` }} />
              </motion.div>
              <motion.div
                key="threat-ring-2"
                className="absolute rounded-full"
                style={{ width: 190, height: 190, top: "50%", left: "50%", x: "-50%", y: "-50%" }}
                animate={{ scale: [1, 1.5], opacity: [0.4, 0] }}
                transition={{ duration: 1, repeat: Infinity, ease: "easeOut", delay: 0.3 }}
              >
                <div className="w-full h-full rounded-full" style={{ border: `1px solid ${tertiary}` }} />
              </motion.div>
            </>
          )}
        </AnimatePresence>

        {/* Main shield circle */}
        <motion.div
          className="relative flex items-center justify-center rounded-full z-10"
          style={{ width: 140, height: 140 }}
          animate={{
            background: `radial-gradient(circle at 40% 35%, ${color}22, ${color}08 60%, #15182d 100%)`,
            boxShadow: `0 0 40px ${glowColor}, inset 0 0 24px ${glowColor}`,
          }}
          transition={{ duration: 0.6 }}
        >
          {/* Inner ring */}
          <motion.div
            className="absolute inset-3 rounded-full"
            animate={{
              boxShadow: `inset 0 0 0 1px ${color}33`,
            }}
            transition={{ duration: 0.6 }}
          />
          {/* Icon */}
          <motion.div
            animate={{ color, filter: `drop-shadow(0 0 8px ${color})` }}
            transition={{ duration: 0.5 }}
          >
            <AnimatePresence mode="wait">
              <motion.div
                key={label}
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.6, opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <Icon size={56} strokeWidth={1.5} />
              </motion.div>
            </AnimatePresence>
          </motion.div>
        </motion.div>
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-8 mt-2">
        <div className="flex flex-col items-center gap-1">
          <span className="text-xs uppercase tracking-widest text-outline font-display">Protected Files</span>
          <span className="text-2xl font-bold font-display" style={{ color: primary }}>
            2,481
          </span>
        </div>
        <div className="w-px h-10" style={{ background: "rgba(69,70,91,0.4)" }} />
        <div className="flex flex-col items-center gap-1">
          <span className="text-xs uppercase tracking-widest text-outline font-display">Honeypots</span>
          <span className="text-2xl font-bold font-display" style={{ color: secondary }}>
            12
          </span>
        </div>
        <div className="w-px h-10" style={{ background: "rgba(69,70,91,0.4)" }} />
        <div className="flex flex-col items-center gap-1">
          <span className="text-xs uppercase tracking-widest text-outline font-display">Uptime</span>
          <span
            className="text-2xl font-bold font-display flex items-center gap-1"
            style={{ color: "#e3e3fd" }}
          >
            <Clock size={16} className="opacity-50" />
            99.8%
          </span>
        </div>
      </div>

      {/* Threat Scrape bar */}
      <div className="w-full max-w-xs mt-2">
        <div className="flex justify-between text-xs uppercase tracking-widest text-outline mb-2">
          <span>Integrity</span>
          <motion.span animate={{ color }} transition={{ duration: 0.5 }}>
            {threatActive ? "COMPROMISED" : "SECURE"}
          </motion.span>
        </div>
        <div
          className="w-full h-1.5 rounded-full overflow-hidden"
          style={{ background: "#000" }}
        >
          <motion.div
            className="h-full rounded-full"
            animate={{
              width: threatActive ? "78%" : "100%",
              background: threatActive
                ? "linear-gradient(90deg, #3fff8b, #fdc003, #ff7350)"
                : "linear-gradient(90deg, #3fff8b, #13ea79)",
            }}
            transition={{ duration: 1, ease: "easeInOut" }}
          />
        </div>
      </div>

      {/* Telemetry tag */}
      <div className="flex items-center gap-2 opacity-40 text-xs font-mono">
        <Zap size={12} />
        <span>ENTROPY MONITOR ACTIVE · v2.4.1</span>
      </div>
    </div>
  );
}
