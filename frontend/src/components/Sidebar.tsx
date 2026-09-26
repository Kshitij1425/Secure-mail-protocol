import { LayoutDashboard, FileSearch, ShieldAlert, Activity, Receipt, UploadCloud } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

const nav = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Findings', to: '/findings', icon: ShieldAlert },
  { label: 'Sessions', to: '/sessions', icon: Activity },
  { label: 'Certificates', to: '/certificates', icon: Receipt },
  { label: 'Anomalies', to: '/anomalies', icon: FileSearch },
  { label: 'Upload', to: '/upload', icon: UploadCloud },
];

export const Sidebar = () => {
  const { pathname } = useLocation();
  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col shrink-0">
      <div className="p-5 border-b border-slate-800 flex items-center gap-3">
        <ShieldAlert className="text-amber-400" size={28} />
        <div>
          <h1 className="font-extrabold text-slate-100 text-sm tracking-tight leading-none">SecureMailScope</h1>
          <span className="text-[10px] text-slate-500 tracking-widest uppercase font-medium">Forensic Dashboard</span>
        </div>
      </div>
      <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
        {nav.map(({ label, to, icon: Icon }) => (
          <Link
            key={to}
            to={to}
            className={`flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
              pathname === to ? 'bg-slate-800 text-amber-300' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Icon size={18} />
            <span>{label}</span>
          </Link>
        ))}
      </nav>
      <div className="p-4 border-t border-slate-800 text-[10px] text-slate-600">        SecureMailScope Security Dashboard
      </div>
    </aside>
  );
};
