import React, { useRef, useState } from 'react';
import { analyzeApkFile } from '../services/apkAnalyzer';
import { ForensicCase } from '../types/forensic';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalysisComplete: (newCase: ForensicCase) => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onAnalysisComplete }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [stepText, setStepText] = useState('Initializing analysis pipeline...');
  const [percent, setPercent] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processSelectedFile(e.target.files[0]);
    }
  };

  const processSelectedFile = (file: File) => {
    setErrorMsg('');
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'apk' && ext !== 'zip') {
      setErrorMsg('Invalid file extension. Please select an Android .apk package or .zip archive.');
      return;
    }

    // 250MB limit check
    const maxBytes = 250 * 1024 * 1024;
    if (file.size > maxBytes) {
      setErrorMsg('File exceeds the 250 MB size limit configured for this workstation.');
      return;
    }

    setSelectedFile(file);
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;
    setIsAnalyzing(true);
    setErrorMsg('');
    setPercent(5);
    setStepText('Reading APK binary stream...');

    try {
      const result = await analyzeApkFile(selectedFile, (step, pct) => {
        setStepText(step);
        setPercent(pct);
      });

      setTimeout(() => {
        setIsAnalyzing(false);
        setSelectedFile(null);
        setPercent(0);
        onAnalysisComplete(result);
        onClose();
      }, 500);
    } catch (err: unknown) {
      setIsAnalyzing(false);
      const message = err instanceof Error ? err.message : 'Analysis failed due to malformed APK structure.';
      setErrorMsg(message);
    }
  };

  const handleCancel = () => {
    setIsAnalyzing(false);
    setSelectedFile(null);
    setPercent(0);
    setErrorMsg('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-xl p-6 space-y-6 shadow-2xl relative">
        <button
          onClick={handleCancel}
          disabled={isAnalyzing}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <i className="fa-solid fa-xmark text-lg"></i>
        </button>

        <div>
          <h3 className="text-lg font-bold text-white flex items-center">
            <i className="fa-solid fa-cloud-arrow-up text-rose-500 mr-2"></i> Ingest & Analyze New APK
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Upload an APK package for automated decompilation, manifest auditing, YARA correlation, and behavioral emulation.
          </p>
        </div>

        {errorMsg && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-xs flex items-start space-x-2">
            <i className="fa-solid fa-circle-exclamation mt-0.5"></i>
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Drag & Drop Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isAnalyzing && fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-8 text-center space-y-3 bg-slate-950/50 cursor-pointer transition ${
            isDragging
              ? 'border-rose-500 bg-rose-950/20'
              : selectedFile
              ? 'border-emerald-500/80 bg-emerald-950/10'
              : 'border-slate-700 hover:border-rose-500/80'
          }`}
        >
          <div
            className={`w-12 h-12 rounded-full flex items-center justify-center mx-auto text-xl border ${
              selectedFile
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
            }`}
          >
            <i className={selectedFile ? 'fa-solid fa-file-shield' : 'fa-solid fa-file-arrow-up'}></i>
          </div>

          <div>
            {selectedFile ? (
              <div className="space-y-1">
                <span className="text-sm font-bold text-white font-mono">{selectedFile.name}</span>
                <div className="text-xs text-emerald-400 font-mono">
                  {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for Ingestion
                </div>
              </div>
            ) : (
              <div>
                <span className="text-sm font-semibold text-white">Drag & Drop APK file here</span>, or{' '}
                <span className="text-rose-400 underline">browse files</span>
              </div>
            )}
          </div>

          <p className="text-[11px] text-slate-500 font-mono">Supports Android APK packages up to 250MB</p>
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk,.zip"
            className="hidden"
            onChange={handleFileChange}
          />
        </div>

        {/* Real Progress Box */}
        {isAnalyzing && (
          <div className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs">
            <div className="flex justify-between text-slate-300">
              <span className="truncate pr-2">{stepText}</span>
              <span className="text-rose-400 font-bold shrink-0">{percent}%</span>
            </div>
            <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
              <div
                className="bg-rose-600 h-full transition-all duration-300"
                style={{ width: `${percent}%` }}
              ></div>
            </div>
          </div>
        )}

        <div className="flex justify-between items-center pt-2">
          <div className="text-[11px] text-slate-500 flex items-center">
            <i className="fa-solid fa-shield-halved mr-1.5 text-slate-400"></i>
            <span>Ephemeral isolated sandbox processing</span>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={handleCancel}
              disabled={isAnalyzing}
              className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium px-4 py-2.5 rounded-lg transition"
            >
              Cancel
            </button>
            <button
              onClick={handleStartAnalysis}
              disabled={!selectedFile || isAnalyzing}
              className="bg-rose-600 hover:bg-rose-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium px-5 py-2.5 rounded-lg shadow-lg shadow-rose-900/40 transition flex items-center space-x-2"
            >
              {isAnalyzing ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin"></i>
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <i className="fa-solid fa-play"></i>
                  <span>Start Analysis Pipeline</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
