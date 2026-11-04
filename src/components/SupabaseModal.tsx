import React, { useState } from 'react';
import { getSupabaseConfig, setSupabaseOverride } from '../services/supabaseClient';

interface SupabaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (title: string, desc: string, type?: 'success' | 'info' | 'warning' | 'error') => void;
}

export const SupabaseModal: React.FC<SupabaseModalProps> = ({ isOpen, onClose, onShowToast }) => {
  const config = getSupabaseConfig();
  const [url, setUrl] = useState(config.url || '');
  const [anonKey, setAnonKey] = useState('');
  const [activeTab, setActiveTab] = useState<'status' | 'setup' | 'vercel'>('status');

  if (!isOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.startsWith('https://') || !url.includes('.supabase.co')) {
      onShowToast('Invalid URL', 'Please enter a valid Supabase Project URL (https://xyz.supabase.co)', 'error');
      return;
    }
    if (anonKey.length < 20) {
      onShowToast('Invalid Key', 'Please enter a valid Supabase Anon Public Key', 'error');
      return;
    }

    setSupabaseOverride(url, anonKey);
    onShowToast('Configured', 'Supabase credentials saved. Reloading...', 'success');
  };

  const handleReset = () => {
    setSupabaseOverride('', '');
    onShowToast('Reset', 'Supabase credentials cleared, reverting to local mode.', 'info');
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl p-6 space-y-5 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white">
          <i className="fa-solid fa-xmark text-lg"></i>
        </button>

        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center justify-center text-xl shrink-0">
            <i className="fa-solid fa-database"></i>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-base font-bold text-white">Supabase Cloud Database Connection</h3>
              {config.isConfigured ? (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold">
                  CONNECTED
                </span>
              ) : (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 font-bold">
                  LOCAL PERSISTENCE MODE
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              PostgreSQL storage with Row Level Security (RLS) &amp; Email Authentication
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 space-x-4 text-xs font-mono">
          <button
            onClick={() => setActiveTab('status')}
            className={`pb-2 border-b-2 transition ${
              activeTab === 'status'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Connection Status
          </button>
          <button
            onClick={() => setActiveTab('setup')}
            className={`pb-2 border-b-2 transition ${
              activeTab === 'setup'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Supabase Setup (3 Steps)
          </button>
          <button
            onClick={() => setActiveTab('vercel')}
            className={`pb-2 border-b-2 transition ${
              activeTab === 'vercel'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            GitHub &amp; Vercel Deploy Guide
          </button>
        </div>

        {/* Tab 1: Connection Status & Instant Test */}
        {activeTab === 'status' && (
          <div className="space-y-4 text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Database Engine:</span>
                <span className="text-white">Supabase PostgreSQL 15+</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <span className={config.isConfigured ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                  {config.isConfigured ? 'Connected & Verified' : 'Local Fallback (Active)'}
                </span>
              </div>
              {config.isConfigured && (
                <>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Project Endpoint:</span>
                    <span className="text-slate-300 truncate max-w-[280px]">{config.url}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Key Source:</span>
                    <span className="text-slate-300 uppercase">{config.source}</span>
                  </div>
                </>
              )}
            </div>

            <form onSubmit={handleSave} className="space-y-3 pt-2">
              <div className="text-xs font-semibold text-white">
                Configure / Override Supabase Credentials:
              </div>
              <div>
                <label className="text-[11px] text-slate-400 block mb-1 font-mono">VITE_SUPABASE_URL</label>
                <input
                  type="url"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-project-id.supabase.co"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1 font-mono">VITE_SUPABASE_ANON_KEY</label>
                <input
                  type="password"
                  required
                  value={anonKey}
                  onChange={(e) => setAnonKey(e.target.value)}
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-between items-center pt-2">
                {config.isConfigured ? (
                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-rose-400 hover:text-rose-300 text-xs font-mono"
                  >
                    Clear Credentials
                  </button>
                ) : (
                  <div></div>
                )}

                <button
                  type="submit"
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-4 py-2 rounded-xl transition shadow-lg shadow-emerald-900/40"
                >
                  Save &amp; Connect Live
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 2: Supabase Setup Steps */}
        {activeTab === 'setup' && (
          <div className="space-y-4 text-xs text-slate-300">
            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="font-bold text-white flex items-center">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[11px] mr-2">1</span>
                Create Free Supabase Project
              </div>
              <p className="text-slate-400 leading-relaxed">
                Go to <a href="https://supabase.com" target="_blank" rel="noreferrer" className="text-emerald-400 underline">supabase.com</a>, log in, and click <strong>"New project"</strong>. Select any preferred cloud region and give it a database password.
              </p>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="font-bold text-white flex items-center">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[11px] mr-2">2</span>
                Run SQL Schema in Supabase SQL Editor
              </div>
              <p className="text-slate-400 leading-relaxed">
                In your Supabase project dashboard, click on <strong>SQL Editor</strong> in the left sidebar. Copy the entire contents of <code className="text-rose-400 font-mono">/supabase_schema.sql</code> and click <strong>"Run"</strong>. This automatically provisions all 8 forensic tables and sets up Row Level Security (RLS) policies.
              </p>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="font-bold text-white flex items-center">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-[11px] mr-2">3</span>
                Copy Project URL &amp; Anon Key
              </div>
              <p className="text-slate-400 leading-relaxed">
                Go to <strong>Project Settings → API</strong>. Copy the <strong>Project URL</strong> and <strong>Project API key (anon / public)</strong>.
              </p>
            </div>
          </div>
        )}

        {/* Tab 3: Vercel & GitHub Deploy */}
        {activeTab === 'vercel' && (
          <div className="space-y-4 text-xs text-slate-300 font-mono">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <div className="text-emerald-400 font-bold font-sans flex items-center">
                <i className="fa-brands fa-github text-white mr-2 text-sm"></i> 1. Push to GitHub
              </div>
              <p className="text-slate-400 font-sans text-xs">
                Initialize git in your workspace and push all code:
              </p>
              <pre className="bg-slate-900 p-2.5 rounded-lg text-slate-200 text-[11px] overflow-x-auto">
{`git init
git add .
git commit -m "feat: AppIntel Pro malware analysis platform with Supabase"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/appintel-pro.git
git push -u origin main`}
              </pre>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <div className="text-rose-400 font-bold font-sans flex items-center">
                <i className="fa-solid fa-cloud-arrow-up text-rose-400 mr-2 text-sm"></i> 2. Deploy on Vercel
              </div>
              <p className="text-slate-400 font-sans text-xs">
                In <a href="https://vercel.com" target="_blank" rel="noreferrer" className="text-rose-400 underline">vercel.com</a>, import your GitHub repo and configure the following <strong>Environment Variables</strong>:
              </p>
              <div className="space-y-1.5 bg-slate-900 p-2.5 rounded-lg text-slate-200 text-[11px]">
                <div><span className="text-emerald-400">VITE_SUPABASE_URL</span> = https://your-project.supabase.co</div>
                <div><span className="text-emerald-400">VITE_SUPABASE_ANON_KEY</span> = eyJhbGciOi...</div>
              </div>
              <p className="text-slate-400 font-sans text-xs">
                Click <strong>"Deploy"</strong>. Vercel will automatically build the project via <code className="text-white">npm run build</code> and serve it with single-page routing configured in <code className="text-rose-400">vercel.json</code>.
              </p>
            </div>
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs px-4 py-2 rounded-xl transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
