import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
import NetworkC2Monitor from "../dashboard/NetworkC2Monitor";

interface C2MonitorModalProps {
  visible: boolean;
  onClose: () => void;
  onC2Detected: (detected: boolean) => void;
}

export default function C2MonitorModal({
  visible,
  onClose,
  onC2Detected,
}: C2MonitorModalProps) {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          className="fixed inset-0 z-50 flex items-center justify-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.25 }}
        >
          {/* Backdrop */}
          <motion.div
            className="absolute inset-0"
            style={{
              background: "rgba(5, 7, 18, 0.6)",
              backdropFilter: "blur(12px)",
              WebkitBackdropFilter: "blur(12px)",
            }}
            onClick={onClose}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />

          {/* Modal panel */}
          <motion.div
            className="relative w-[90vw] max-w-5xl max-h-[80vh] overflow-y-auto rounded-xl"
            style={{
              background: "rgba(15, 18, 37, 0.92)",
              backdropFilter: "blur(24px)",
              WebkitBackdropFilter: "blur(24px)",
              border: "1px solid rgba(69, 70, 91, 0.4)",
              boxShadow:
                "0 0 60px rgba(0, 230, 118, 0.06), 0 24px 48px rgba(0, 0, 0, 0.5)",
            }}
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Close button — positioned outside the scrollable body */}
            <button
              id="c2-modal-close-btn"
              onClick={onClose}
              className="absolute top-3 right-3 z-20 flex items-center justify-center w-8 h-8 rounded-full transition-colors"
              style={{
                background: "rgba(69, 70, 91, 0.5)",
                color: "#a8a9c1",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(255, 115, 80, 0.3)";
                e.currentTarget.style.color = "#ff7350";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(69, 70, 91, 0.5)";
                e.currentTarget.style.color = "#a8a9c1";
              }}
            >
              <X size={14} strokeWidth={3} />
            </button>

            {/* Body — significant top padding to avoid close button overlap with header buttons */}
            <div className="pt-12 pr-2">
              <NetworkC2Monitor onC2Detected={onC2Detected} />
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
