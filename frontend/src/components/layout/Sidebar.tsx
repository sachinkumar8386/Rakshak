import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  ShieldCheck,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Zap,
} from "lucide-react";

interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  alert?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={20} /> },
  { id: "shield", label: "Shield Status", icon: <ShieldCheck size={20} /> },
  { id: "watcher", label: "System Watcher", icon: <Activity size={20} /> },
  { id: "alerts", label: "Alerts", icon: <AlertTriangle size={20} />, alert: true },
  { id: "test", label: "Connection Test", icon: <Zap size={20} /> },
  { id: "settings", label: "Settings", icon: <Settings size={20} /> },
];

interface SidebarProps {
  activeView: string;
  onNavigate: (id: string) => void;
  onOpenC2: () => void;
  threatActive: boolean;
}

export default function Sidebar({ activeView, onNavigate, onOpenC2, threatActive }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <motion.aside
      animate={{ width: collapsed ? 48 : 170 }}
      transition={{ duration: 0.3, ease: "easeInOut" }}
      className="relative flex flex-col h-full shrink-0 overflow-hidden z-10"
      style={{
        background: "rgba(21, 24, 45, 0.85)",
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
        borderRight: "1px solid rgba(69, 70, 91, 0.25)",
      }}
    >
      {/* Logo / Brand — perfectly centered container when collapsed */}
      <div className={`flex items-center h-14 shrink-0 overflow-hidden ${collapsed ? 'justify-center' : 'px-4 gap-3'}`}>
        <motion.div
          className="w-7 h-7 rounded-md flex items-center justify-center shrink-0"
          animate={{
            boxShadow: threatActive
              ? "0 0 16px 4px rgba(255,115,80,0.5)"
              : "0 0 12px 2px rgba(63,255,139,0.4)",
            background: threatActive
              ? "linear-gradient(135deg, #ff7350, #fc3c00)"
              : "linear-gradient(135deg, #3fff8b, #13ea79)",
          }}
          transition={{ duration: 0.6 }}
        >
          <ShieldCheck size={16} color="#0b0d1e" strokeWidth={2.5} />
        </motion.div>
        <AnimatePresence>
          {!collapsed && (
            <motion.span
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
              className="font-display font-bold text-sm tracking-widest text-on-surface whitespace-nowrap"
            >
              RAKSHAK
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      <div className="h-px mx-3" style={{ background: "rgba(69,70,91,0.4)" }} />

      {/* Nav Items */}
      <nav className={`flex flex-col gap-1 mt-3 flex-1 ${collapsed ? 'px-1' : 'px-2'}`}>
        {NAV_ITEMS.map((item) => {
          const isActive = activeView === item.id;
          return (
            <motion.button
              key={item.id}
              onClick={() => item.id === "c2monitor" ? onOpenC2() : onNavigate(item.id)}
              whileHover={{ x: collapsed ? 0 : 2 }}
              whileTap={{ scale: 0.97 }}
              className={`relative flex items-center gap-3 py-2 rounded-md cursor-pointer w-full transition-colors duration-200 ${collapsed ? 'justify-center px-0' : 'px-3 text-left'}`}
              style={{
                background: isActive ? "#21243d" : "transparent",
                color: isActive ? "#3fff8b" : "#a8a9c1",
              }}
            >
              {isActive && (
                <motion.div
                  layoutId="active-pill"
                  className="absolute inset-0 rounded-md"
                  style={{
                    background: "rgba(63,255,139,0.06)",
                    boxShadow: "inset 0 0 0 1px rgba(63,255,139,0.12)",
                  }}
                />
              )}
              <span className="relative shrink-0">
                {item.icon}
                {item.alert && threatActive && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-tertiary animate-pulse" />
                )}
              </span>
              <AnimatePresence>
                {!collapsed && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="relative text-sm font-medium whitespace-nowrap"
                    style={{ fontFamily: "Inter, sans-serif" }}
                  >
                    {item.label}
                  </motion.span>
                )}
              </AnimatePresence>
            </motion.button>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed((c) => !c)}
        className="flex items-center justify-center h-10 w-full mb-3 opacity-40 hover:opacity-100 transition-opacity text-on-surface"
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </motion.aside>
  );
}
