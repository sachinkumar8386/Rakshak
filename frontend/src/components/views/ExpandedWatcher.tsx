import { useState, useEffect } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

let invoke: any = null;
try {
  import("@tauri-apps/api/core").then((m) => (invoke = m.invoke));
} catch {}

interface DataPoint {
  time: string;
  cpu: number;
  disk: number;
}

export default function ExpandedWatcher() {
  const [data, setData] = useState<DataPoint[]>([]);

  useEffect(() => {
    let unmounted = false;
    // Initial populate empty data so chart renders initially
    const initData: DataPoint[] = Array.from({ length: 60 }).map((_, i) => ({
      time: `-${60 - i}s`,
      cpu: 0,
      disk: 0
    }));
    setData(initData);

    const interval = setInterval(async () => {
      if (!invoke || unmounted) return;
      try {
        const tel: any = await invoke("get_telemetry");
        
        setData(prev => {
          const now = new Date();
          const p = { 
            time: now.getSeconds().toString() + "s", 
            cpu: Math.round(tel.cpu), 
            disk: Number((tel.disk_write / 1024 / 1024).toFixed(2)) // Convert bytes to MB/s
          };
          const nd = [...prev, p];
          if (nd.length > 60) nd.shift();
          return nd;
        });
      } catch (e) {
        console.error(e);
      }
    }, 1000);

    return () => {
      unmounted = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="p-8 h-full flex flex-col text-on-surface">
      <h1 className="text-2xl font-display font-bold tracking-wider mb-8 flex items-center gap-3">
        <span className="w-2 h-2 rounded-full bg-blue-400 shadow-[0_0_8px_#60a5fa]"></span>
        SYSTEM WATCHER
      </h1>
      
      <div className="flex-1 grid grid-cols-1 gap-6 min-h-0" style={{ gridTemplateRows: "1fr 1fr" }}>
        <ChartCard title="Global CPU Usage" data={data} dataKey="cpu" color="#3fff8b" unit="%" />
        <ChartCard title="Disk Write (System)" data={data} dataKey="disk" color="#60a5fa" unit=" MB/s" />
      </div>
    </div>
  );
}

function ChartCard({ title, data, dataKey, color, unit }: any) {
  return (
    <div className="flex flex-col p-5 rounded-lg border border-surface-ring" style={{ background: "rgba(21, 24, 45, 0.4)" }}>
      <h3 className="text-sm font-bold text-on-surface-muted uppercase tracking-widest mb-4">{title}</h3>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={color} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#252843" vertical={false} />
            <XAxis dataKey="time" hide />
            <YAxis stroke="#45465b" fontSize={11} tickFormatter={(val) => `${val}${unit}`} width={55} />
            <Tooltip 
              contentStyle={{ background: "#0b0d1e", border: "1px solid #21243d", borderRadius: "8px" }}
              itemStyle={{ color: "#fff" }}
              formatter={((val: any) => [`${val}${unit}`, title]) as any}
              labelStyle={{ display: "none" }}
            />
            <Area type="monotone" dataKey={dataKey} stroke={color} fill={`url(#grad-${dataKey})`} strokeWidth={2} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
