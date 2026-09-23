import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, AlertCircle } from 'lucide-react';
import type { SeverityLevel } from '../types/api';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md';
}

const config: Record<string, { icon: React.ComponentType<{ size?: number }>, label: string, bg: string, text: string, border: string }> = {
  critical: { icon: ShieldAlert, label: 'Critical', bg: 'bg-red-950', text: 'text-red-300', border: 'border-red-700' },
  high: { icon: AlertTriangle, label: 'High', bg: 'bg-amber-950', text: 'text-amber-300', border: 'border-amber-700' },
  medium: { icon: AlertCircle, label: 'Medium', bg: 'bg-yellow-950', text: 'text-yellow-300', border: 'border-yellow-700' },
  low: { icon: Shield, label: 'Low', bg: 'bg-emerald-950', text: 'text-emerald-300', border: 'border-emerald-700' },
  info: { icon: ShieldCheck, label: 'Info', bg: 'bg-slate-800', text: 'text-slate-300', border: 'border-slate-700' },
};

export const SeverityBadge = ({ severity, size = 'md' }: SeverityBadgeProps) => {
  const s = String(severity).toLowerCase();
  const cfg = config[s] || config.info;
  const Icon = cfg.icon;
  const px = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded border font-semibold tracking-wide ${cfg.bg} ${cfg.text} ${cfg.border} ${px}`}>
      <Icon size={size === 'sm' ? 10 : 12} />
      <span className="uppercase">{cfg.label}</span>
    </span>
  );
};
