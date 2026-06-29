import React from 'react';

export const RadarBackground: React.FC = () => {
  return (
    <div className="fixed inset-0 pointer-events-none select-none z-0 overflow-hidden bg-[var(--bg-base)]">
      <svg 
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] h-[95vw] max-w-[850px] max-h-[850px] opacity-[0.035] text-[var(--accent-amber)]"
        viewBox="0 0 200 200" 
        fill="none" 
        stroke="currentColor" 
        strokeWidth="0.3"
      >
        {/* Concentric Grid Rings */}
        <circle cx="100" cy="100" r="90" strokeDasharray="1 3" />
        <circle cx="100" cy="100" r="70" />
        <circle cx="100" cy="100" r="50" strokeDasharray="1 3" />
        <circle cx="100" cy="100" r="30" />
        <circle cx="100" cy="100" r="10" strokeDasharray="1 3" />

        {/* Crosshair lines */}
        <line x1="100" y1="5" x2="100" y2="195" strokeDasharray="2 2" />
        <line x1="5" y1="100" x2="195" y2="100" strokeDasharray="2 2" />

        {/* Angle indicators / ticks */}
        <line x1="100" y1="100" x2="163.64" y2="36.36" strokeDasharray="1 4" />
        <line x1="100" y1="100" x2="36.36" y2="163.64" strokeDasharray="1 4" />
        <line x1="100" y1="100" x2="163.64" y2="163.64" strokeDasharray="1 4" />
        <line x1="100" y1="100" x2="36.36" y2="36.36" strokeDasharray="1 4" />

        {/* Sweep Hand with rotating animation */}
        <g className="origin-[100px_100px] animate-[radar-sweep_12s_linear_infinite] motion-reduce:animate-none">
          {/* Gradient Sweep sector */}
          <path 
            d="M 100 100 L 100 10 A 90 90 0 0 1 190 100 Z" 
            fill="url(#radar-grad)" 
            stroke="none" 
            className="motion-reduce:hidden"
          />
          {/* Sweep leading edge line */}
          <line x1="100" y1="100" x2="100" y2="10" stroke="currentColor" strokeWidth="0.8" />
        </g>

        <defs>
          <radialGradient id="radar-grad" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.4" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </radialGradient>
        </defs>
      </svg>
      {/* CSS for custom keyframe animation */}
      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes radar-sweep {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}} />
    </div>
  );
};
export default RadarBackground;
