import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const { loginWithEmail, verifyOtp } = useAuth();
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [step, setStep] = useState<'email' | 'otp'>('email');
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [suggestedCode, setSuggestedCode] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleRequestToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setLoading(true);

    try {
      const res = await loginWithEmail(email);
      if (res.success) {
        setStep('otp');
        if (res.otpCode) {
          setSuggestedCode(res.otpCode);
        }
      } else {
        setErrorMessage(res.message);
      }
    } catch {
      setErrorMessage('Failed to send authentication token. Please check the email format.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setLoading(true);

    try {
      const res = await verifyOtp(email, otpCode);
      if (res.success) {
        onSuccess?.();
        onClose();
      } else {
        setErrorMessage(res.message);
      }
    } catch {
      setErrorMessage('Verification failed. Please retry.');
    } finally {
      setLoading(false);
    }
  };

  const fillTestCode = () => {
    if (suggestedCode) {
      setOtpCode(suggestedCode);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-5 shadow-2xl relative">
        <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white">
          <i className="fa-solid fa-xmark text-lg"></i>
        </button>

        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 to-amber-500 flex items-center justify-center shadow-lg shadow-rose-900/30">
            <i className="fa-solid fa-shield-halved text-white text-lg"></i>
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Investigator Authentication</h3>
            <p className="text-xs text-slate-400">Email-Only Secure Access Protocol</p>
          </div>
        </div>

        {/* Privacy Callout */}
        <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-start space-x-2.5 text-xs text-slate-400">
          <i className="fa-solid fa-lock text-emerald-400 mt-0.5"></i>
          <div>
            <strong className="text-slate-200">Zero-PII Assurance:</strong> We only collect your email address for session verification. No name, phone, or personal data collected.
          </div>
        </div>

        {errorMessage && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-xs flex items-center space-x-2">
            <i className="fa-solid fa-triangle-exclamation"></i>
            <span>{errorMessage}</span>
          </div>
        )}

        {step === 'email' ? (
          <form onSubmit={handleRequestToken} className="space-y-4">
            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1">
                Authorized Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 text-xs">
                  <i className="fa-solid fa-envelope"></i>
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="investigator@agency.gov or analyst@corp.com"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-medium text-xs py-2.5 rounded-xl shadow-lg shadow-rose-900/40 transition flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin"></i>
                  <span>Generating One-Time Token...</span>
                </>
              ) : (
                <>
                  <i className="fa-solid fa-key"></i>
                  <span>Dispatch Verification Code</span>
                </>
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-1">
                <label className="text-xs text-slate-300 font-medium">
                  Enter 6-Digit Code
                </label>
                <button
                  type="button"
                  onClick={() => setStep('email')}
                  className="text-[11px] text-rose-400 hover:underline font-mono"
                >
                  Change Email
                </button>
              </div>
              <input
                type="text"
                required
                maxLength={6}
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
                placeholder="6-digit token (e.g. 804804)"
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2.5 text-center font-mono text-base tracking-widest text-emerald-400 focus:outline-none focus:border-rose-500"
              />
            </div>

            {suggestedCode && (
              <div className="bg-emerald-950/40 border border-emerald-800/60 p-3 rounded-xl flex items-center justify-between text-xs">
                <div className="text-emerald-300">
                  <span className="text-[10px] uppercase font-mono block text-emerald-500 font-semibold">Security Token:</span>
                  <strong className="font-mono text-sm tracking-wider">{suggestedCode}</strong>
                </div>
                <button
                  type="button"
                  onClick={fillTestCode}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-mono px-2.5 py-1 rounded-lg transition"
                >
                  Auto-Fill
                </button>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white font-medium text-xs py-2.5 rounded-xl shadow-lg shadow-emerald-900/40 transition flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin"></i>
                  <span>Verifying Token...</span>
                </>
              ) : (
                <>
                  <i className="fa-solid fa-check"></i>
                  <span>Confirm & Enter Workstation</span>
                </>
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
