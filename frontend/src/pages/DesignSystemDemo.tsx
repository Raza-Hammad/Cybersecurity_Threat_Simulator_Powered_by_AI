import React, { useState } from 'react';
import RadarBackground from '../components/ui/RadarBackground';
import GlowPanel from '../components/ui/GlowPanel';
import GlowButton from '../components/ui/GlowButton';
import StatusBadge from '../components/ui/StatusBadge';
import { Shield, Settings, Info, RefreshCw, Terminal } from 'lucide-react';

export const DesignSystemDemo: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [inputValue, setInputValue] = useState('10');

  const handleSimulate = () => {
    setLoading(true);
    setTimeout(() => setLoading(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)] font-sans relative overflow-hidden flex flex-col items-center justify-center p-8 select-none">
      {/* Signature Rotating Radar Background Sweep */}
      <RadarBackground />

      {/* Main Console HUD container */}
      <div className="relative z-10 w-full max-w-4xl space-y-8">
        
        {/* Header HUD panel */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[var(--border-subtle)] pb-6">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight font-display text-white uppercase flex items-center gap-3">
              <Shield className="w-8 h-8 text-[var(--accent-amber)] animate-pulse" />
              SOC Command Center
            </h1>
            <p className="text-[var(--text-secondary)] text-xs mt-1">
              Design System Token Foundation & Reusable HUD Component Specs
            </p>
          </div>
          <div className="flex gap-2">
            <StatusBadge status="Secure" />
            <StatusBadge status="Connected" />
          </div>
        </div>

        {/* 2-Column HUD Layout Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* Column 1: Typography and Badges Specs (Span 1) */}
          <div className="md:col-span-1 space-y-6">
            
            <GlowPanel>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-[var(--border-subtle)] pb-2 flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-[var(--accent-amber)]" />
                Severity Badges
              </h3>
              <div className="flex flex-wrap gap-3">
                <StatusBadge status="Critical" />
                <StatusBadge status="High" />
                <StatusBadge status="Medium" />
                <StatusBadge status="Low" />
                <StatusBadge status="Info" />
                <StatusBadge status="Secure" />
                <StatusBadge status="Active" />
              </div>
            </GlowPanel>

            <GlowPanel>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-[var(--border-subtle)] pb-2 flex items-center gap-2">
                <Settings className="w-3.5 h-3.5 text-[var(--accent-amber)]" />
                Control Readout
              </h3>
              <div className="space-y-4">
                <div>
                  <label className="text-[var(--text-secondary)] text-[10px] uppercase font-semibold block mb-1.5">
                    Simulation Packet Rate (pkts/sec)
                  </label>
                  <input
                    type="number"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    className="w-full bg-[var(--bg-base)] border border-[var(--border-subtle)] focus:border-[var(--accent-amber)] rounded-[var(--radius-sm)] py-2 px-3 text-xs text-white font-mono outline-none transition-all"
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <GlowButton variant="primary" className="flex-1" onClick={handleSimulate} disabled={loading}>
                    {loading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Processing...
                      </>
                    ) : (
                      'Simulate'
                    )}
                  </GlowButton>
                </div>
              </div>
            </GlowPanel>

          </div>

          {/* Column 2: Typography, Grid, and Button Specs (Span 2) */}
          <div className="md:col-span-2 space-y-6">
            
            <GlowPanel>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-[var(--border-subtle)] pb-2 flex items-center gap-2">
                <Shield className="w-3.5 h-3.5 text-[var(--accent-amber)]" />
                Command Typography Spec
              </h3>
              <div className="space-y-4">
                <div>
                  <span className="text-[10px] text-[var(--text-secondary)] uppercase block mb-1">Header font (Space Grotesk)</span>
                  <h2 className="text-xl font-bold text-white uppercase tracking-wide">
                    GEOMETRIC DISPLAY SUBHEADING
                  </h2>
                </div>
                <div>
                  <span className="text-[10px] text-[var(--text-secondary)] uppercase block mb-1">Body UI font (Inter)</span>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                    This is paragraph body text styled in Inter. It is clean and readable, keeping contrast fully compliant with WCAG AA standards.
                  </p>
                </div>
                <div>
                  <span className="text-[10px] text-[var(--text-secondary)] uppercase block mb-1">Telemetry readouts font (JetBrains Mono)</span>
                  <div className="bg-[var(--bg-base)] p-3 rounded-[var(--radius-sm)] border border-[var(--border-subtle)] text-[11px] font-mono text-emerald-400 leading-normal">
                    <p>SYSTEM_VERDICT: DDoS_ATTACK_DETECTED</p>
                    <p>CONFIDENCE:     99.9824% (TIER_1_SCREENER)</p>
                    <p>TIMESTAMP:      2026-06-29 05:54:12 UTC</p>
                    <p>FLOW_BANDWIDTH: 148,252.12 pkts/sec</p>
                  </div>
                </div>
              </div>
            </GlowPanel>

            <GlowPanel>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-[var(--border-subtle)] pb-2 flex items-center gap-2">
                <Info className="w-3.5 h-3.5 text-[var(--accent-amber)]" />
                HUD Action Buttons
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <span className="text-[9px] text-[var(--text-secondary)] uppercase block text-center">Primary Action</span>
                  <GlowButton variant="primary" className="w-full">
                    Accept Threat
                  </GlowButton>
                </div>
                <div className="space-y-2">
                  <span className="text-[9px] text-[var(--text-secondary)] uppercase block text-center">Secondary Outline</span>
                  <GlowButton variant="secondary" className="w-full">
                    Acknowledge
                  </GlowButton>
                </div>
                <div className="space-y-2">
                  <span className="text-[9px] text-[var(--text-secondary)] uppercase block text-center">Ghost Option</span>
                  <GlowButton variant="ghost" className="w-full">
                    Dismiss
                  </GlowButton>
                </div>
              </div>
            </GlowPanel>

          </div>

        </div>

        {/* Footer Panel */}
        <div className="text-center py-4 border-t border-[var(--border-subtle)]">
          <span className="text-[9px] text-[var(--text-muted)] font-mono uppercase tracking-wider">
            ThreatSim AI SOC Console Platform • Version 0.1.0 • Protected Session
          </span>
        </div>

      </div>
    </div>
  );
};
export default DesignSystemDemo;
