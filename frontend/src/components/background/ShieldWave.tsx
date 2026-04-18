/**
 * ShieldWave — CSS-animated radial gradient that pulses from center outward.
 * Sits behind all dashboard cards (z-0) with pointer-events: none.
 * Color shifts from green to red when a threat is active.
 */

interface ShieldWaveProps {
  threatActive: boolean;
}

export default function ShieldWave({ threatActive }: ShieldWaveProps) {
  const color = threatActive
    ? "rgba(255, 115, 80, 0.07)"
    : "rgba(0, 230, 118, 0.05)";
  const colorOuter = threatActive
    ? "rgba(255, 60, 0, 0.02)"
    : "rgba(0, 230, 118, 0.01)";

  return (
    <div
      className="fixed inset-0 z-0 shield-wave-container"
      style={{ pointerEvents: "none" }}
      aria-hidden="true"
    >
      {/* Wave ring 1 */}
      <div
        className="shield-wave shield-wave-1"
        style={{
          background: `radial-gradient(circle, ${color} 0%, ${colorOuter} 40%, transparent 70%)`,
        }}
      />
      {/* Wave ring 2 (delayed) */}
      <div
        className="shield-wave shield-wave-2"
        style={{
          background: `radial-gradient(circle, ${color} 0%, ${colorOuter} 35%, transparent 65%)`,
        }}
      />
      {/* Wave ring 3 (delayed) */}
      <div
        className="shield-wave shield-wave-3"
        style={{
          background: `radial-gradient(circle, transparent 0%, ${colorOuter} 30%, transparent 60%)`,
        }}
      />
    </div>
  );
}
