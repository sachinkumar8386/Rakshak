import { useEffect, useState, useCallback } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  YAxis,
} from "recharts";
import { Activity, Cpu, HardDrive, Wifi, Shield, AlertTriangle } from "lucide-react";

let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
try {
  import("@tauri-apps/api/core").then((m) => {
    invoke = m.invoke;
  });
} catch {}

interface DataPoint {
  t: number;
  value: number;
}

interface SystemTelemetry {
  cpu_usage: number;
  ram_usage: number;
  disk_io: number;
  network_io: number;
  active_processes: number;
}

interface ProcessScore {
  pid: number;
  name: string;
  score: number;
  event_count: number;
  is_ransomware: boolean;
  is_suspicious: boolean;
}

function useRealTimeData(getValue: () => number, tickMs = 1000, maxPoints = 30) {
  const [data, setData] = useState<DataPoint[]>(() =>
    Array.from({ length: maxPoints }, (_, i) => ({
      t: Date.now() - (maxPoints - i) * tickMs,
      value: getValue(),
    }))
  );

  useEffect(() => {
    const id = setInterval(() => {
      setData((prev) => {
        const next: DataPoint = { t: Date.now(), value: getValue() };
        return [...prev.slice(1), next];
      });
    }, tickMs);
    return () => clearInterval(id);
  }, [tickMs, getValue]);

  return data;
}

function useBackendTelemetry() {
  const [telemetry, setTelemetry] = useState<SystemTelemetry>({
    cpu_usage: 0,
    ram_usage: 0,
    disk_io: 0,
    network_io: 0,
    active_processes: 0,
  });

  useEffect(() => {
    const fetchTelemetry = async () => {
      if (!invoke) return;
      try {
        const tel = await invoke("get_telemetry") as SystemTelemetry;
        if (tel) setTelemetry(tel);
      } catch {}
    };

    fetchTelemetry();
    const id = setInterval(fetchTelemetry, 1000);
    return () => clearInterval(id);
  }, []);

  return telemetry;
}

function useDetectionScores() {
  const [scores, setScores] = useState<ProcessScore[]>([]);

  useEffect(() => {
    const fetchScores = async () => {
      if (!invoke) return;
      try {
        const result = await invoke("get_detection_scores") as ProcessScore[];
        if (result) setScores(result);
      } catch {}
    };

    fetchScores();
    const id = setInterval(fetchScores, 1000);
    return () => clearInterval(id);
  }, []);

  return scores;
}

interface WatcherChartProps {
  label: string;
  icon: React.ReactNode;
  data: DataPoint[];
  color: string;
  unit: string;
  alertThreshold?: number;
  threatActive: boolean;
  currentValue?: number;
}

function WatcherChart({ label, icon, data, color, unit, alertThreshold = 80, threatActive, currentValue }: WatcherChartProps) {
  const latest = currentValue ?? data[data.length - 1]?.value ?? 0;
  const isHigh = latest > alertThreshold;
  const activeColor = isHigh ? "#ff7350" : color;

  return (
    <div
      className="flex flex-col gap-3 p-4 rounded-md"
      style={{
        background: "rgba(33, 36, 61, 0.7)",
        boxShadow: isHigh || threatActive ? "0 0 20px rgba(255,115,80,0.12)" : "none",
      }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2" style={{ color: activeColor }}>
          <span className="opacity-80">{icon}</span>
          <span className="text-xs font-display uppercase tracking-widest text-on-surface opacity-70">
            {label}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isHigh && (
            <span
              className="text-xs font-mono px-2 py-0.5 rounded animate-pulse"
              style={{ background: "rgba(255,115,80,0.15)", color: "#ff7350" }}
            >
              HIGH
            </span>
          )}
          <span
            className="text-lg font-display font-bold tabular-nums"
            style={{ color: activeColor }}
          >
            {latest.toFixed(1)}
            <span className="text-xs font-body opacity-50 ml-1">{unit}</span>
          </span>
        </div>
      </div>

      <div style={{ height: 72 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id={`line-${label}`} x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor={color} stopOpacity={0.4} />
                <stop offset="100%" stopColor={activeColor} stopOpacity={1} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="4 4"
              stroke="rgba(69,70,91,0.3)"
              vertical={false}
            />
            <YAxis domain={[0, 100]} hide />
            <Tooltip
              contentStyle={{
                background: "#15182d",
                border: `1px solid ${activeColor}33`,
                borderRadius: 6,
                color: "#e3e3fd",
                fontSize: 12,
                fontFamily: "Inter",
              }}
              formatter={(val) => [`${(val as number).toFixed(1)} ${unit}`, label]}
              labelFormatter={() => ""}
            />
            {alertThreshold && (
              <ReferenceLine
                y={alertThreshold}
                stroke="#ff7350"
                strokeDasharray="3 3"
                strokeOpacity={0.4}
              />
            )}
            <Line
              type="monotone"
              dataKey="value"
              stroke={`url(#line-${label})`}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, fill: activeColor, stroke: "none" }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

interface ThreatLevelIndicatorProps {
  scores: ProcessScore[];
}

function ThreatLevelIndicator({ scores }: ThreatLevelIndicatorProps) {
  const maxScore = Math.max(...scores.map((s) => s.score), 0);
  const suspiciousCount = scores.filter((s) => s.is_suspicious).length;
  const ransomwareCount = scores.filter((s) => s.is_ransomware).length;

  const getLevel = () => {
    if (ransomwareCount > 0) return { color: "#ff7350", label: "CRITICAL", icon: <Shield size={14} /> };
    if (suspiciousCount > 0 || maxScore > 60) return { color: "#fdc003", label: "HIGH", icon: <AlertTriangle size={14} /> };
    if (maxScore > 30) return { color: "#60a5fa", label: "MEDIUM", icon: <Activity size={14} /> };
    return { color: "#3fff8b", label: "SAFE", icon: <Shield size={14} /> };
  };

  const level = getLevel();

  return (
    <div
      className="flex items-center gap-2 p-3 rounded-md"
      style={{
        background: `rgba(${level.color === "#ff7350" ? "255,115,80" : level.color === "#fdc003" ? "253,192,3" : level.color === "#60a5fa" ? "96,165,250" : "63,255,139"}, 0.1)`,
        border: `1px solid ${level.color}40`,
      }}
    >
      <span style={{ color: level.color }}>{level.icon}</span>
      <span className="text-xs font-display uppercase tracking-wider" style={{ color: level.color }}>
        {level.label}
      </span>
      {suspiciousCount > 0 && (
        <span className="text-xs font-mono opacity-70" style={{ color: level.color }}>
          ({suspiciousCount} suspicious)
        </span>
      )}
    </div>
  );
}

interface ProcessMonitorProps {
  scores: ProcessScore[];
}

function ProcessMonitor({ scores }: ProcessMonitorProps) {
  const topProcesses = scores
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  if (topProcesses.length === 0) return null;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 mb-1">
        <Activity size={14} className="opacity-60" style={{ color: "#60a5fa" }} />
        <span className="text-xs font-display uppercase tracking-widest text-on-surface opacity-60">
          Monitored Processes
        </span>
      </div>
      {topProcesses.map((proc) => (
        <div
          key={proc.pid}
          className="flex items-center justify-between p-2 rounded text-xs"
          style={{
            background: proc.is_ransomware
              ? "rgba(255,115,80,0.15)"
              : proc.is_suspicious
              ? "rgba(253,192,3,0.1)"
              : "rgba(33,36,61,0.5)",
            border: proc.is_ransomware
              ? "1px solid rgba(255,115,80,0.3)"
              : proc.is_suspicious
              ? "1px solid rgba(253,192,3,0.2)"
              : "1px solid rgba(69,70,91,0.3)",
          }}
        >
          <span className="font-mono truncate max-w-[100px]" style={{ color: "#e3e3fd" }}>
            {proc.name}
          </span>
          <span className="font-mono opacity-60">PID {proc.pid}</span>
          <span
            className="font-bold tabular-nums"
            style={{
              color: proc.is_ransomware ? "#ff7350" : proc.is_suspicious ? "#fdc003" : "#60a5fa",
            }}
          >
            {proc.score}
          </span>
        </div>
      ))}
    </div>
  );
}

interface SystemWatcherProps {
  threatActive: boolean;
}

export default function SystemWatcher({ threatActive }: SystemWatcherProps) {
  const telemetry = useBackendTelemetry();
  const scores = useDetectionScores();

  const getCpuValue = useCallback(() => telemetry.cpu_usage || 35, [telemetry.cpu_usage]);
  const getRamValue = useCallback(() => telemetry.ram_usage || 55, [telemetry.ram_usage]);
  const getDiskValue = useCallback(() => telemetry.disk_io || 20, [telemetry.disk_io]);
  const getNetValue = useCallback(() => telemetry.network_io || 15, [telemetry.network_io]);

  const cpuData = useRealTimeData(getCpuValue, 1000);
  const ramData = useRealTimeData(getRamValue, 1200);
  const diskData = useRealTimeData(getDiskValue, 1500);
  const netData = useRealTimeData(getNetValue, 800);

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Activity size={14} className="opacity-60" style={{ color: "#3fff8b" }} />
          <h2 className="text-xs uppercase tracking-[0.2em] font-display opacity-60 text-on-surface">
            System Watcher
          </h2>
        </div>
        <ThreatLevelIndicator scores={scores} />
      </div>

      <div className="grid grid-cols-1 gap-3 flex-1">
        <WatcherChart
          label="CPU Usage"
          icon={<Cpu size={14} />}
          data={cpuData}
          color="#3fff8b"
          unit="%"
          currentValue={telemetry.cpu_usage}
          threatActive={threatActive}
        />
        <WatcherChart
          label="RAM Usage"
          icon={<Activity size={14} />}
          data={ramData}
          color="#fdc003"
          alertThreshold={85}
          unit="%"
          currentValue={telemetry.ram_usage}
          threatActive={threatActive}
        />
        <WatcherChart
          label="Disk I/O"
          icon={<HardDrive size={14} />}
          data={diskData}
          color="#3fff8b"
          unit="MB/s"
          alertThreshold={75}
          currentValue={telemetry.disk_io}
          threatActive={threatActive}
        />
        <WatcherChart
          label="Net Activity"
          icon={<Wifi size={14} />}
          data={netData}
          color="#a78bfa"
          unit="Mb/s"
          alertThreshold={70}
          currentValue={telemetry.network_io}
          threatActive={threatActive}
        />
      </div>

      <ProcessMonitor scores={scores} />
    </div>
  );
}
