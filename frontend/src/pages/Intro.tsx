import React, { useState, useEffect } from 'react';
import GlowButton from '../components/ui/GlowButton';
import { Shield, Sparkles } from 'lucide-react';

interface IntroProps {
  onComplete: () => void;
}

export const Intro: React.FC<IntroProps> = ({ onComplete }) => {
  const [step, setStep] = useState(0);

  // Auto-skip if prefers-reduced-motion is active
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mediaQuery.matches) {
      onComplete();
    }
  }, [onComplete]);

  useEffect(() => {
    // Phase timeline offsets (natural 10-12s pacing)
    const t1 = setTimeout(() => setStep(1), 2200);   // 2.2s: Red threat blips appear + first caption
    const t2 = setTimeout(() => setStep(2), 4800);   // 4.8s: Sweep speeds up, locks target 1
    const t3 = setTimeout(() => setStep(3), 7400);   // 7.4s: Locks targets 2 & 3 + second caption
    const t4 = setTimeout(() => setStep(4), 10000);  // 10s: Sweep settles, logo + button fade in

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, []);

  return (
    <div className="fixed inset-0 bg-[#0A0E1A] text-[#F3F4F6] font-sans flex flex-col items-center justify-center overflow-hidden z-50">
      
      {/* Top Right Skip Link */}
      <button 
        onClick={onComplete}
        className="absolute top-6 right-6 text-xs uppercase tracking-wider text-[#9CA3AF] hover:text-white transition-colors cursor-pointer select-none font-mono flex items-center gap-1.5 z-50 border border-transparent hover:border-current/15 px-2.5 py-1 rounded"
      >
        <span>Skip Sequence</span>
        <span className="text-[10px]">»</span>
      </button>

      {/* Center Instrument Panel Radar Container */}
      <div className="relative flex flex-col items-center justify-center w-full max-w-lg px-6">
        
        {/* SVG Radar Graphic Grid */}
        <div className="relative w-full aspect-square max-w-[340px] flex items-center justify-center mb-10">
          <svg 
            viewBox="0 0 200 200" 
            className="w-full h-full text-[var(--accent-amber)] opacity-80"
            fill="none" 
            stroke="currentColor" 
            strokeWidth="0.25"
          >
            {/* Radar concentric circular scale */}
            <circle cx="100" cy="100" r="90" strokeDasharray="1 3" opacity="0.2" />
            <circle cx="100" cy="100" r="70" opacity="0.3" />
            <circle cx="100" cy="100" r="50" strokeDasharray="1 3" opacity="0.3" />
            <circle cx="100" cy="100" r="30" opacity="0.4" />
            <circle cx="100" cy="100" r="10" strokeDasharray="1 3" opacity="0.4" />

            {/* Angular axes */}
            <line x1="10" y1="100" x2="190" y2="100" strokeDasharray="2 3" opacity="0.25" />
            <line x1="100" y1="10" x2="100" y2="190" strokeDasharray="2 3" opacity="0.25" />

            {/* Sweep arm sector (speed varies based on phase step) */}
            <g className={`origin-[100px_100px] ${
              step === 2 || step === 3
                ? 'animate-[intro-sweep-fast_3s_linear_infinite]' 
                : 'animate-[intro-sweep-slow_7s_linear_infinite]'
            }`}>
              {/* Soft sector fill */}
              <path 
                d="M 100 100 L 100 10 A 90 90 0 0 1 180 60 Z" 
                fill="url(#intro-grad)" 
                stroke="none"
              />
              <line x1="100" y1="100" x2="100" y2="10" stroke="currentColor" strokeWidth="0.5" opacity="0.9" />
            </g>

            {/* Target Threat Blips */}
            
            {/* Blip Alpha: (65, 75) - Neutralized in Step 2 */}
            {step >= 1 && (
              <g className="transition-all duration-700">
                <circle 
                  cx="65" 
                  cy="75" 
                  r="2" 
                  fill={step >= 2 ? 'var(--color-calm)' : 'var(--color-critical)'} 
                  className="transition-colors duration-500"
                />
                {step === 1 && (
                  <circle cx="65" cy="75" r="4.5" stroke="var(--color-critical)" strokeWidth="0.3" fill="none" className="animate-ping" />
                )}
                {step === 2 && (
                  <>
                    <circle cx="65" cy="75" r="6" stroke="var(--color-calm)" strokeWidth="0.3" strokeDasharray="1 1" fill="none" className="animate-spin" style={{ animationDuration: '3s' }} />
                    <circle cx="65" cy="75" r="9" stroke="var(--color-calm)" strokeWidth="0.2" fill="none" className="animate-ping" />
                  </>
                )}
              </g>
            )}

            {/* Blip Beta: (135, 125) - Neutralized in Step 3 */}
            {step >= 1 && (
              <g className="transition-all duration-700">
                <circle 
                  cx="135" 
                  cy="125" 
                  r="2" 
                  fill={step >= 3 ? 'var(--color-calm)' : 'var(--color-critical)'} 
                  className="transition-colors duration-500"
                />
                {step === 1 && (
                  <circle cx="135" cy="125" r="4.5" stroke="var(--color-critical)" strokeWidth="0.3" fill="none" className="animate-ping" />
                )}
                {step === 3 && (
                  <>
                    <circle cx="135" cy="125" r="6" stroke="var(--color-calm)" strokeWidth="0.3" strokeDasharray="1 1" fill="none" className="animate-spin" style={{ animationDuration: '3s' }} />
                    <circle cx="135" cy="125" r="9" stroke="var(--color-calm)" strokeWidth="0.2" fill="none" className="animate-ping" />
                  </>
                )}
              </g>
            )}

            {/* Blip Gamma: (115, 55) - Neutralized in Step 3 */}
            {step >= 1 && (
              <g className="transition-all duration-700">
                <circle 
                  cx="115" 
                  cy="55" 
                  r="2" 
                  fill={step >= 3 ? 'var(--color-calm)' : 'var(--color-critical)'} 
                  className="transition-colors duration-500"
                />
                {step === 1 && (
                  <circle cx="115" cy="55" r="4.5" stroke="var(--color-critical)" strokeWidth="0.3" fill="none" className="animate-ping" />
                )}
                {step === 3 && (
                  <>
                    <circle cx="115" cy="55" r="6" stroke="var(--color-calm)" strokeWidth="0.3" strokeDasharray="1 1" fill="none" className="animate-spin" style={{ animationDuration: '3s' }} />
                    <circle cx="115" cy="55" r="9" stroke="var(--color-calm)" strokeWidth="0.2" fill="none" className="animate-ping" />
                  </>
                )}
              </g>
            )}

            <defs>
              <radialGradient id="intro-grad" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
                <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
              </radialGradient>
            </defs>
          </svg>

          {/* Sweeper animations custom CSS */}
          <style dangerouslySetInnerHTML={{ __html: `
            @keyframes intro-sweep-slow {
              from { transform: rotate(0deg); }
              to { transform: rotate(360deg); }
            }
            @keyframes intro-sweep-fast {
              from { transform: rotate(0deg); }
              to { transform: rotate(360deg); }
            }
          `}} />
        </div>

        {/* Narrative HUD captions */}
        <div className="h-16 flex items-center justify-center text-center px-4 w-full select-none">
          {step === 1 && (
            <p className="text-sm font-semibold tracking-wider text-[#F97316] uppercase animate-pulse leading-relaxed">
              Threats don't announce themselves.
            </p>
          )}
          {(step === 2 || step === 3) && (
            <p className="text-sm font-semibold tracking-wider text-[var(--accent-amber)] uppercase animate-pulse leading-relaxed">
              Our AI doesn't just scan.<br/>
              <span className="text-xs text-[#9CA3AF] tracking-normal font-normal normal-case">
                It detects, explains, and responds.
              </span>
            </p>
          )}
        </div>

        {/* Cinematic Title & Interactive Button Fading In */}
        <div className={`mt-6 w-full flex flex-col items-center gap-6 transition-all duration-1000 transform ${
          step >= 4 ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6 pointer-events-none'
        }`}>
          <div className="text-center space-y-1">
            <h2 className="text-3xl font-extrabold tracking-tight font-display text-white uppercase flex items-center justify-center gap-2">
              <Shield className="w-7 h-7 text-[var(--accent-amber)]" />
              ThreatSim AI
            </h2>
            <p className="text-[10px] uppercase tracking-widest text-[#9CA3AF] font-semibold">
              Advanced Multi-Tier Cascade SOC Portal
            </p>
          </div>
          <GlowButton 
            variant="primary" 
            onClick={onComplete}
            className="px-8 py-3 text-xs tracking-wider"
          >
            <span>Enter Command Center</span>
            <Sparkles className="w-3.5 h-3.5" />
          </GlowButton>
        </div>

      </div>
    </div>
  );
};
export default Intro;
