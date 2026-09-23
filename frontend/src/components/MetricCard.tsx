import type { ReactNode } from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon?: ReactNode;
}

export const MetricCard = ({ label, value, sub, icon }: MetricCardProps) => (
  <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4 hover:border-slate-500 transition-colors">
    <div className="flex items-start justify-between gap-3">
      <div>
        <div className="text-[11px] uppercase tracking-widest text-slate-400 font-medium">{label}</div>
        <div className="text-2xl font-extrabold text-slate-100 mt-1 leading-none">{value}</div>
        {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
      </div>
      {icon && <div className="text-slate-500">{icon}</div>}
    </div>
  </div>
);