import React from 'react';

export interface ToastMessage {
  title: string;
  desc: string;
  type?: 'success' | 'info' | 'warning' | 'error';
}

interface ToastProps {
  toast: ToastMessage | null;
  onClose: () => void;
}

export const Toast: React.FC<ToastProps> = ({ toast, onClose }) => {
  if (!toast) return null;

  const isError = toast.type === 'error';
  const isWarning = toast.type === 'warning';
  const isInfo = toast.type === 'info';

  const iconBg = isError
    ? 'bg-rose-500/20 text-rose-400'
    : isWarning
    ? 'bg-amber-500/20 text-amber-400'
    : isInfo
    ? 'bg-blue-500/20 text-blue-400'
    : 'bg-emerald-500/20 text-emerald-400';

  return (
    <div className="fixed bottom-6 right-6 bg-slate-900 border border-slate-700 text-white px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-3 z-50 animate-slide-up">
      <div className={`w-8 h-8 rounded-lg ${iconBg} flex items-center justify-center shrink-0`}>
        {isError ? (
          <i className="fa-solid fa-triangle-exclamation"></i>
        ) : isWarning ? (
          <i className="fa-solid fa-circle-exclamation"></i>
        ) : isInfo ? (
          <i className="fa-solid fa-circle-info"></i>
        ) : (
          <i className="fa-solid fa-check"></i>
        )}
      </div>
      <div>
        <div className="text-xs font-bold text-white">{toast.title}</div>
        <div className="text-[11px] text-slate-400">{toast.desc}</div>
      </div>
      <button onClick={onClose} className="ml-3 text-slate-500 hover:text-white text-xs">
        <i className="fa-solid fa-xmark"></i>
      </button>
    </div>
  );
};
