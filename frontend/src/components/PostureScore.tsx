interface PostureScoreProps {
  score: number | null;
  status: string;
  size?: 'md' | 'lg';
}

const tone = (score: number | null) =>
  score === null ? ['text-slate-400', 'text-slate-300', '#64748b']
    : score >= 75 ? ['text-emerald-400', 'text-emerald-300', '#34d399']
    : score >= 60 ? ['text-amber-400', 'text-amber-300', '#fbbf24']
    : score >= 40 ? ['text-orange-400', 'text-orange-300', '#fb923c']
    : ['text-red-400', 'text-red-300', '#f87171'];

/** Score ring. ``score === null`` means insufficient evidence (never drawn as 0 or 100). */
export const PostureScore = ({ score, status, size = 'lg' }: PostureScoreProps) => {
  const [scoreColor, statusColor, stroke] = tone(score);
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score));
  return (
    <div className="flex flex-col items-center" aria-label={`Security posture ${score === null ? 'not assessable' : `${Math.round(pct)} of 100`}, ${status}`}>
      <div className={`relative ${size === 'lg' ? 'w-28 h-28' : 'w-20 h-20'}`}>
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100" aria-hidden="true">
          <circle cx="50" cy="50" r="42" fill="none" stroke="#1a2332" strokeWidth="8" />
          {score !== null && (
            <circle cx="50" cy="50" r="42" fill="none" stroke={stroke} strokeWidth="8" strokeLinecap="round"
              strokeDasharray={`${pct * 2.64} 264`} />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`${size === 'lg' ? 'text-3xl' : 'text-xl'} font-extrabold ${scoreColor}`}>
            {score === null ? 'N/A' : Math.round(pct)}
          </span>
          {score !== null && (
            <span className={`${size === 'lg' ? 'text-[10px]' : 'text-[8px]'} uppercase tracking-wider font-bold text-slate-400`}>of 100</span>
          )}
        </div>
      </div>
      <div className={`mt-2 text-center ${statusColor} font-bold tracking-wide ${size === 'lg' ? 'text-sm' : 'text-xs'}`}>
        {score === null ? 'INSUFFICIENT EVIDENCE' : status.toUpperCase()}
      </div>
    </div>
  );
};
