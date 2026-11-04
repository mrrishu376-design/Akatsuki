import React from 'react';

interface PrivacyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PrivacyModal: React.FC<PrivacyModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl p-6 space-y-5 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white">
          <i className="fa-solid fa-xmark text-lg"></i>
        </button>

        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center justify-center text-lg">
            <i className="fa-solid fa-user-shield"></i>
          </div>
          <div>
            <h3 className="text-base font-bold text-white">AppIntel Pro Privacy & Data Retention Policy</h3>
            <p className="text-xs text-slate-400">Strict Law Enforcement and Privacy-First Protocol</p>
          </div>
        </div>

        <div className="space-y-4 text-xs text-slate-300 leading-relaxed border-t border-slate-800 pt-4">
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-emerald-400 font-bold flex items-center">
              <i className="fa-solid fa-circle-check mr-2"></i> Zero Unnecessary PII Collection
            </div>
            <p className="text-slate-400">
              AppIntel Pro strictly collects only your email address for account session token verification. We never collect or request:
              your full name, phone number, address, date of birth, gender, organization, photos, or government IDs.
            </p>
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-rose-400 font-bold flex items-center">
              <i className="fa-solid fa-hard-drive mr-2"></i> Ephemeral APK Storage & Sandboxing
            </div>
            <p className="text-slate-400">
              Uploaded Android application packages (APKs) are decompiled and inspected in isolated, disposable memory structures.
              Binary files are <strong>not stored permanently</strong> by default. Decompiled files and sandbox emulator snapshots
              are scheduled for automated eradication following case summary generation.
            </p>
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-amber-400 font-bold flex items-center">
              <i className="fa-solid fa-shield-halved mr-2"></i> Infrastructure & Security Logging
            </div>
            <p className="text-slate-400">
              Network infrastructure providers log only standard HTTP IP connection metadata and TLS parameters necessary to defend
              against Distributed Denial of Service (DDoS) and unauthorized API flooding. We employ zero advertising trackers, zero third-party
              marketing beacons, and zero cross-site behavioral telemetry.
            </p>
          </div>

          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-slate-200 font-bold flex items-center">
              <i className="fa-solid fa-scale-balanced mr-2"></i> Evidentiary & Court Submission Disclaimer
            </div>
            <p className="text-slate-400">
              Cryptographic hashes (SHA-256 and MD5) provide chain-of-custody verification for forensic artifacts. Automated forensic
              reports are intended to assist cybersecurity investigators and malware analysts. Legal admissibility remains subject
              to jurisdictional standards and local statutory requirements.
            </p>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs px-5 py-2.5 rounded-xl transition shadow-lg shadow-rose-900/40"
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
};
