interface PostureScoreProps {
  score: number;
  status: string;
  size?: 'md' | 'lg';
}

export const PostureScore = ({ score, status, size = 'lg' }: PostureScoreProps) => {
  const scoreColor = score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : score >= 40 ? 'text-orange-400' : 'text-red-400';
  const statusColor = score >= 80 ? 'text-emerald-300' : score >= 60 ? 'text-amber-300' : score >= 40 ? 'text-orange-300' : 'text-red-300';

  return (
    <div className="flex flex-col items-center">
      <div className={`relative ${size === 'lg' ? 'w-28 h-28' : 'w-20 h-20'}`}>
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="42" fill="none" stroke="#1a2332" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="42"
            fill="none"
            stroke={score >= 80 ? '#34d399' : score >= 60 ? '#fbbf24' : score >= 40 ? '#fb923c' : '#f87171'}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${score * 2.64} 264`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`${size === 'lg' ? 'text-3xl font-extrabold' : 'text-xl font-extrabold'} ${scoreColor}`}>{score}</span>
          <span className={`${size === 'lg' ? 'text-[10px]' : 'text-[8px]'} uppercase tracking-wider font-bold text-slate-400`}>of 100</span>
        </div>
      </div>
      <div className={`mt-2 text-center ${statusColor} font-bold tracking-wide ${size === 'lg' ? 'text-sm' : 'text-xs'}`}>{status.toUpperCase()}</div>
    </div>
  );
};
