import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { isSupabaseConfigured } from '../services/supabaseClient';

interface HeaderProps {
  onOpenUpload: () => void;
  onOpenAuth: () => void;
  onOpenPrivacy: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenUpload,
  onOpenAuth,
  onOpenPrivacy,
}) => {
  const { user, logout } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const isSupabaseConnected = isSupabaseConfigured();

  const getInitials = (email: string) => {
    const parts = email.split('@')[0].split('.');
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return email.substring(0, 2).toUpperCase();
  };

  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40 px-4 lg:px-8 py-3 flex items-center justify-between">
      {/* Brand & Badge */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 to-amber-500 flex items-center justify-center shadow-lg shadow-rose-900/30 shrink-0">
          <i className="fa-solid fa-shield-virus text-white text-lg"></i>
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-bold text-lg tracking-wide bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              AppIntel Pro
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
              LE-SOC v4.2
            </span>
          </div>
          <p className="text-xs text-slate-400 hidden sm:block">
            Advanced Android Malware &amp; Digital Forensics Workstation
          </p>
        </div>
      </div>

      {/* Cluster Status, Actions & Profile */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* Database Status Indicator (Read-only status badge, no clickable modal or credential disclosure) */}
        <div
          title={isSupabaseConnected ? 'Connected to Remote Supabase PostgreSQL Cluster' : 'Local Forensics Storage Active'}
          className="flex items-center space-x-2 bg-slate-800/60 px-3 py-1.5 rounded-lg border border-slate-700/60 text-xs font-mono text-slate-300 select-none"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isSupabaseConnected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-500'
            }`}
          ></span>
          <span className="hidden md:inline">
            DB:{' '}
            <strong className={isSupabaseConnected ? 'text-emerald-400' : 'text-slate-400'}>
              {isSupabaseConnected ? 'POSTGRESQL SYNC' : 'LOCAL ENGINE'}
            </strong>
          </span>
          <span className="md:hidden">
            <i className={`fa-solid fa-database ${isSupabaseConnected ? 'text-emerald-400' : 'text-slate-400'}`}></i>
          </span>
        </div>

        {/* Sandbox Status */}
        <div className="hidden lg:flex items-center space-x-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700/60 text-xs font-mono text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>
            Sandbox: <strong className="text-emerald-400">ONLINE (12 active)</strong>
          </span>
        </div>

        {/* Upload Button */}
        <button
          onClick={onOpenUpload}
          className="bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-medium text-xs px-3.5 sm:px-4 py-2 rounded-lg shadow-md shadow-rose-900/40 flex items-center space-x-2 transition transform active:scale-95"
        >
          <i className="fa-solid fa-cloud-arrow-up"></i>
          <span className="hidden sm:inline">Ingest &amp; Analyze APK</span>
          <span className="sm:hidden">Ingest</span>
        </button>

        {/* Privacy Policy Trigger */}
        <button
          onClick={onOpenPrivacy}
          title="Privacy & Data Retention Policy"
          className="text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-800 p-2 rounded-lg border border-slate-700/60 text-xs transition hidden sm:flex items-center space-x-1"
        >
          <i className="fa-solid fa-shield-halved text-emerald-400"></i>
          <span className="text-[11px]">Privacy</span>
        </button>

        <div className="h-6 w-px bg-slate-800 hidden sm:block"></div>

        {/* User Account / Profile */}
        {user ? (
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center space-x-3 text-left focus:outline-none group"
            >
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-slate-200 group-hover:text-white truncate max-w-[150px]">
                  {user.email}
                </div>
                <div className="text-[10px] text-slate-400 font-mono">Cyber Division - CyberSec HQ</div>
              </div>
              <div className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 group-hover:border-rose-500/50 flex items-center justify-center text-slate-300 font-semibold text-xs transition">
                {getInitials(user.email)}
              </div>
            </button>

            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-2 z-50 text-xs font-mono">
                <div className="p-2 border-b border-slate-800 text-slate-400">
                  <div className="text-[10px] uppercase text-slate-500">Authenticated Session</div>
                  <div className="text-slate-200 truncate mt-0.5">{user.email}</div>
                  <div className="text-[10px] text-emerald-400 mt-1">Status: Active Forensic Officer</div>
                </div>
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    onOpenPrivacy();
                  }}
                  className="w-full text-left px-3 py-2 text-slate-300 hover:bg-slate-800 hover:text-white rounded-lg flex items-center space-x-2 transition"
                >
                  <i className="fa-solid fa-user-shield text-slate-400 w-4"></i>
                  <span>Privacy Disclosures</span>
                </button>
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    logout();
                  }}
                  className="w-full text-left px-3 py-2 text-rose-400 hover:bg-rose-500/10 rounded-lg flex items-center space-x-2 transition mt-1"
                >
                  <i className="fa-solid fa-arrow-right-from-bracket w-4"></i>
                  <span>End Session (Logout)</span>
                </button>
              </div>
            )}
          </div>
        ) : (
          <button
            onClick={onOpenAuth}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium px-3 py-2 rounded-lg flex items-center space-x-2 transition"
          >
            <i className="fa-solid fa-right-to-bracket text-rose-400"></i>
            <span>Email Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
};
