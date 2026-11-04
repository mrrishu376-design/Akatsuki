import React from 'react';
import { ForensicCase } from '../types/forensic';

interface SidebarProps {
  currentView: 'dashboard' | 'workspace' | 'comparison' | 'threatintel';
  onSelectView: (view: 'dashboard' | 'workspace' | 'comparison' | 'threatintel') => void;
  cases: ForensicCase[];
  activeCaseIndex: number;
  onSelectCase: (index: number) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  cases,
  activeCaseIndex,
  onSelectCase,
}) => {
  return (
    <aside className="w-full lg:w-64 bg-slate-900/90 border-r border-slate-800 flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-6">
        {/* Navigation Menu */}
        <div className="space-y-1">
          <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2 font-mono">
            Investigation Module
          </div>

          <button
            onClick={() => onSelectView('dashboard')}
            className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              currentView === 'dashboard'
                ? 'bg-rose-600/10 text-rose-400 border border-rose-500/20'
                : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
            }`}
          >
            <i className="fa-solid fa-chart-pie w-5 text-center"></i>
            <span>Dashboard Overview</span>
          </button>

          <button
            onClick={() => onSelectView('workspace')}
            className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              currentView === 'workspace'
                ? 'bg-rose-600/10 text-rose-400 border border-rose-500/20'
                : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
            }`}
          >
            <i className="fa-solid fa-microscope w-5 text-center"></i>
            <span>APK Analysis Workspace</span>
          </button>

          <button
            onClick={() => onSelectView('comparison')}
            className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              currentView === 'comparison'
                ? 'bg-rose-600/10 text-rose-400 border border-rose-500/20'
                : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
            }`}
          >
            <i className="fa-solid fa-code-compare w-5 text-center"></i>
            <span>Side-by-Side Compare</span>
          </button>

          <button
            onClick={() => onSelectView('threatintel')}
            className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              currentView === 'threatintel'
                ? 'bg-rose-600/10 text-rose-400 border border-rose-500/20'
                : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
            }`}
          >
            <i className="fa-solid fa-globe w-5 text-center"></i>
            <span>Global IOC Database</span>
          </button>
        </div>

        {/* Active Cases Quick List */}
        <div className="space-y-2">
          <div className="flex items-center justify-between px-3">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
              Forensic Evidence
            </span>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-1.5 py-0.5 rounded border border-emerald-800/50">
              {cases.length} Cases
            </span>
          </div>

          <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
            {cases.map((c, idx) => {
              const isCrit = c.riskScore > 80;
              const isSelected = activeCaseIndex === idx;
              const badgeColor = isCrit
                ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                : 'bg-amber-500/20 text-amber-400 border-amber-500/30';

              return (
                <div
                  key={`sidebar-case-${c.id ?? idx}-${idx}`}
                  onClick={() => {
                    onSelectCase(idx);
                    onSelectView('workspace');
                  }}
                  className={`p-2.5 rounded-xl border cursor-pointer transition flex items-center justify-between group ${
                    isSelected
                      ? 'bg-slate-800/90 border-rose-500/40 shadow-sm'
                      : 'bg-slate-950/60 hover:bg-slate-800/80 border-slate-800/80'
                  }`}
                >
                  <div className="truncate pr-2">
                    <div className="text-xs font-medium text-slate-200 group-hover:text-white truncate">
                      {c.filename}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 truncate">{c.pkg}</div>
                  </div>
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${badgeColor} shrink-0`}>
                    {c.riskScore}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom System Status */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-900/50">
        <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800 space-y-2 text-xs">
          <div className="flex justify-between text-slate-400">
            <span>Database:</span>
            <span className="font-mono text-slate-200">IOC-v2026.4</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>YARA Rules:</span>
            <span className="font-mono text-emerald-400">1,420 Active</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Encryption:</span>
            <span className="font-mono text-slate-200">AES-256 (FIPS)</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
