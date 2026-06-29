import React from 'react';

interface GlowPanelProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const GlowPanel: React.FC<GlowPanelProps> = ({ children, className = '', ...props }) => {
  return (
    <div 
      className={`relative bg-[var(--bg-panel)] border border-[var(--border-subtle)] rounded-[var(--radius-md)] p-5 shadow-lg transition-all hover:border-[var(--border-glow-hover)] ${className}`}
      {...props}
    >
      {/* HUD corner targeting brackets */}
      <span className="absolute top-[-1px] left-[-1px] w-2.5 h-2.5 border-t-2 border-l-2 border-[var(--accent-amber)] rounded-tl-[var(--radius-sm)] pointer-events-none" />
      <span className="absolute top-[-1px] right-[-1px] w-2.5 h-2.5 border-t-2 border-r-2 border-[var(--accent-amber)] rounded-tr-[var(--radius-sm)] pointer-events-none" />
      <span className="absolute bottom-[-1px] left-[-1px] w-2.5 h-2.5 border-b-2 border-l-2 border-[var(--accent-amber)] rounded-bl-[var(--radius-sm)] pointer-events-none" />
      <span className="absolute bottom-[-1px] right-[-1px] w-2.5 h-2.5 border-b-2 border-r-2 border-[var(--accent-amber)] rounded-br-[var(--radius-sm)] pointer-events-none" />
      
      {children}
    </div>
  );
};
export default GlowPanel;
