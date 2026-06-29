import React from 'react';

interface GlowButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost';
  children: React.ReactNode;
}

export const GlowButton: React.FC<GlowButtonProps> = ({ 
  variant = 'primary', 
  children, 
  className = '', 
  ...props 
}) => {
  let styleClasses = '';
  
  if (variant === 'primary') {
    styleClasses = 'bg-[var(--accent-amber)] hover:bg-[var(--accent-amber-hover)] text-slate-950 font-bold shadow-[0_0_10px_rgba(245,166,35,0.25)] hover:shadow-[0_0_18px_rgba(245,166,35,0.5)] border border-transparent';
  } else if (variant === 'secondary') {
    styleClasses = 'bg-transparent border border-[var(--accent-amber)] text-[var(--accent-amber)] hover:bg-[var(--accent-amber-glow)] font-bold';
  } else {
    styleClasses = 'bg-transparent border border-transparent text-slate-300 hover:text-white hover:bg-slate-800/40 font-semibold';
  }

  return (
    <button
      className={`px-4 py-2 text-xs uppercase tracking-wider rounded-[var(--radius-sm)] transition-all outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-amber)] disabled:opacity-40 disabled:pointer-events-none cursor-pointer flex items-center justify-center gap-1.5 ${styleClasses} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};
export default GlowButton;
