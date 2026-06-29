import React from 'react';

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  const statusUpper = status.toUpperCase();
  
  let badgeStyle = {
    color: 'var(--text-secondary)',
    bg: 'rgba(148, 163, 184, 0.08)',
    dot: 'bg-slate-400'
  };

  if (statusUpper === 'CRITICAL') {
    badgeStyle = {
      color: 'var(--color-critical)',
      bg: 'rgba(239, 68, 68, 0.12)',
      dot: 'bg-red-500 animate-pulse'
    };
  } else if (statusUpper === 'HIGH') {
    badgeStyle = {
      color: 'var(--color-high)',
      bg: 'rgba(249, 115, 22, 0.12)',
      dot: 'bg-orange-500 animate-pulse'
    };
  } else if (statusUpper === 'MEDIUM') {
    badgeStyle = {
      color: 'var(--color-medium)',
      bg: 'rgba(245, 166, 35, 0.12)',
      dot: 'bg-amber-500'
    };
  } else if (statusUpper === 'LOW' || statusUpper === 'INFO') {
    badgeStyle = {
      color: 'var(--color-low)',
      bg: 'rgba(100, 116, 139, 0.12)',
      dot: 'bg-slate-500'
    };
  } else if (statusUpper === 'SECURE' || statusUpper === 'CONNECTED' || statusUpper === 'SUCCESS' || statusUpper === 'OK' || statusUpper === 'ACTIVE') {
    badgeStyle = {
      color: 'var(--color-calm)',
      bg: 'rgba(45, 212, 191, 0.12)',
      dot: 'bg-teal-400 animate-pulse'
    };
  }

  return (
    <span 
      style={{ color: badgeStyle.color, backgroundColor: badgeStyle.bg }}
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-bold font-mono uppercase tracking-wider rounded-full border border-current/10 ${className}`}
    >
      <span className={`w-1 h-1 rounded-full ${badgeStyle.dot}`} />
      {status}
    </span>
  );
};
export default StatusBadge;
