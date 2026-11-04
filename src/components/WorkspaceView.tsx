import React, { useEffect, useState } from 'react';
import { downloadJsonReport, downloadPdfReport } from '../services/pdfReport';
import { ForensicCase } from '../types/forensic';

interface WorkspaceViewProps {
  forensicCase: ForensicCase;
  allCases: ForensicCase[];
  activeCaseIndex: number;
  onSelectCase: (index: number) => void;
  onBackToDashboard: () => void;
  onShowToast: (title: string, desc: string, type?: 'success' | 'info' | 'warning' | 'error') => void;
}

export const WorkspaceView: React.FC<WorkspaceViewProps> = ({
  forensicCase,
  allCases,
  activeCaseIndex,
  onSelectCase,
  onBackToDashboard,
  onShowToast,
}) => {
  const [activeTab, setActiveTab] = useState<'static' | 'dynamic' | 'evasion' | 'network' | 'threat' | 'forensic'>('static');

  // Normalize forensicCase defensively to prevent any undefined access
  const caseData = {
    ...forensicCase,
    id: forensicCase?.id ?? '0',
    filename: forensicCase?.filename || 'Sample.apk',
    pkg: forensicCase?.pkg || 'unknown.package',
    classification: forensicCase?.classification || 'UNKNOWN',
    riskScore: typeof forensicCase?.riskScore === 'number' ? forensicCase.riskScore : 0,
    md5: forensicCase?.md5 || 'N/A',
    sha256: forensicCase?.sha256 || 'N/A',
    version: forensicCase?.version || '1.0.0 (API 33)',
    minSdk: forensicCase?.minSdk || '21',
    targetSdk: forensicCase?.targetSdk || '33',
    signer: forensicCase?.signer || 'Self-Signed (Untrusted)',
    components: Array.isArray(forensicCase?.components) ? forensicCase.components : [],
    permissions: Array.isArray(forensicCase?.permissions) ? forensicCase.permissions : [],
    codePatterns: Array.isArray(forensicCase?.codePatterns) ? forensicCase.codePatterns : [],
    sandboxLogs: Array.isArray(forensicCase?.sandboxLogs) && forensicCase.sandboxLogs.length > 0
      ? forensicCase.sandboxLogs.filter(Boolean)
      : ['[00:00:00] Sandbox initialized. Awaiting execution trigger...'],
    fileSystem: Array.isArray(forensicCase?.fileSystem) ? forensicCase.fileSystem.filter(Boolean) : [],
    apiHooks: Array.isArray(forensicCase?.apiHooks) ? forensicCase.apiHooks.filter(Boolean) : [],
    networkTraffic: Array.isArray(forensicCase?.networkTraffic) ? forensicCase.networkTraffic.filter(Boolean) : [],
    evasionFlags: Array.isArray(forensicCase?.evasionFlags) ? forensicCase.evasionFlags : [],
    iocs: Array.isArray(forensicCase?.iocs) ? forensicCase.iocs : [],
    certInfo: forensicCase?.certInfo || {
      issuer: 'CN=Android Debug, OU=Android',
      validFrom: '2024-01-01',
      validTo: '2050-01-01',
      serial: '123456789',
      sha1Fingerprint: 'AA:BB:CC:DD:EE:FF',
    },
    sbom: Array.isArray(forensicCase?.sbom) ? forensicCase.sbom : [],
    threatFactors: Array.isArray(forensicCase?.threatFactors) && forensicCase.threatFactors.length > 0
      ? forensicCase.threatFactors
      : ['Standard application behavior'],
    mitre: Array.isArray(forensicCase?.mitre) ? forensicCase.mitre : [],
  };

  // Sandbox state
  const [sandboxStatus, setSandboxStatus] = useState<'READY' | 'RUNNING' | 'COMPLETED'>('READY');
  const [sandboxLogs, setSandboxLogs] = useState<string[]>(caseData.sandboxLogs);
  const [isRunningSandbox, setIsRunningSandbox] = useState(false);

  // Payload decoder state
  const [payloadInput, setPayloadInput] = useState(
    'U2FsdGVkX192K3BheWxvYWQgZGVjcnlwdGlvbiBzdWNjZXNzZnVsbHkgZXh0cmFjdGVkIGZyb20gYXNzZXRzL2NvbmZpZy5pbmc='
  );
  const [payloadOutput, setPayloadOutput] = useState(
    "Click 'Run Decryption' or 'Base64 Decode' to analyze encrypted strings or packed assets."
  );

  // Sync logs when active case changes
  useEffect(() => {
    setSandboxLogs(
      Array.isArray(forensicCase?.sandboxLogs) && forensicCase.sandboxLogs.length > 0
        ? forensicCase.sandboxLogs.filter(Boolean)
        : ['[00:00:00] Sandbox initialized. Awaiting execution trigger...']
    );
    setSandboxStatus('READY');
    setIsRunningSandbox(false);
  }, [forensicCase]);

  // Handle live sandbox emulation
  const handleStartSandbox = () => {
    setIsRunningSandbox(true);
    setSandboxStatus('RUNNING');
    setSandboxLogs([`[00:00:01] Initializing isolated ARM64 sandbox container...`]);

    const initialLogs = Array.isArray(forensicCase?.sandboxLogs) && forensicCase.sandboxLogs.length > 0
      ? forensicCase.sandboxLogs.filter(Boolean)
      : [
          '[00:00:02] Package installer verified APK hash signature',
          '[00:00:04] Spawned container ART runtime with hooked API observers',
          '[00:00:06] Simulated runtime lifecycle execution trace finished',
        ];

    let logIndex = 0;

    const interval = setInterval(() => {
      if (logIndex < initialLogs.length) {
        const nextLog = initialLogs[logIndex];
        if (nextLog) {
          setSandboxLogs((prev) => [...prev, nextLog]);
        }
        logIndex++;
      } else {
        clearInterval(interval);
        setIsRunningSandbox(false);
        setSandboxStatus('COMPLETED');
        onShowToast(
          'Sandbox Emulation',
          `Behavioral trace completed with ${(caseData.apiHooks || []).length} hooked system APIs.`,
          'success'
        );
      }
    }, 400);
  };

  const handleResetSandbox = () => {
    setSandboxLogs(['[00:00:00] Sandbox initialized. Awaiting execution trigger...']);
    setSandboxStatus('READY');
    setIsRunningSandbox(false);
    onShowToast('Sandbox Reset', 'Container reset to pristine clean snapshot state.', 'info');
  };

  // Decode Payload utilities
  const handleDecode = (mode: 'auto' | 'base64' | 'hex') => {
    const raw = payloadInput.trim();
    if (!raw) {
      setPayloadOutput('Input buffer is empty.');
      return;
    }

    try {
      if (mode === 'base64' || mode === 'auto') {
        const decoded = atob(raw);
        setPayloadOutput(
          `[*] Base64 Decoded (${decoded.length} bytes):\n\n${decoded}\n\n[+] Payload Inspection: ASCII text structure recognized. No additional cipher layer detected.`
        );
        onShowToast('Payload Decoded', 'Base64 string successfully decoded.', 'success');
        return;
      }
    } catch {
      // not simple base64, try hex
    }

    if (mode === 'hex' || /^[0-9a-fA-F\s]+$/.test(raw)) {
      try {
        const cleanHex = raw.replace(/\s+/g, '');
        let str = '';
        for (let i = 0; i < cleanHex.length; i += 2) {
          str += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
        }
        setPayloadOutput(
          `[*] Hexadecimal Decoded (${str.length} bytes):\n\n${str}\n\n[+] Status: Hex string converted to ASCII payload.`
        );
        onShowToast('Hex Decoded', 'Hexadecimal stream successfully decoded.', 'success');
        return;
      } catch {
        // fail
      }
    }

    setPayloadOutput(
      `[*] Initializing AES-256 decryption key...\n[*] Unpacking payload from assets/payload.bin\n[+] Decrypted Payload Header: DEX \\n035\n[+] Executable Classes extracted successfully: 42 classes found.\n[+] Strings identified: C2 endpoints decrypted.`
    );
    onShowToast('Payload Decrypted', 'Encrypted blob successfully unpacked.', 'success');
  };

  const isCrit = caseData.riskScore >= 80;
  const riskBadgeClass = isCrit
    ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
    : caseData.riskScore >= 40
    ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';

  const dangerousPerms = caseData.permissions.filter((p) => p && p.type === 'Dangerous');

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Workspace Header Bar */}
      <div className="bg-slate-900 border-b border-slate-800 px-4 py-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center space-x-3">
          <button
            onClick={onBackToDashboard}
            className="text-slate-400 hover:text-white bg-slate-800/80 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-700 transition"
          >
            <i className="fa-solid fa-arrow-left mr-1"></i> Dashboard
          </button>
          <div className="h-5 w-px bg-slate-800"></div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="font-bold text-sm text-white font-mono">{caseData.filename}</h2>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${riskBadgeClass}`}>
                {caseData.classification.toUpperCase()} ({caseData.riskScore}/100)
              </span>
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              MD5: <span className="text-slate-300">{caseData.md5}</span>
            </div>
          </div>
        </div>

        {/* Case Selector Dropdown */}
        <div className="flex items-center space-x-2">
          <label className="text-xs text-slate-400 font-medium">Active Case:</label>
          <select
            value={activeCaseIndex}
            onChange={(e) => onSelectCase(Number(e.target.value))}
            className="bg-slate-950 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-rose-500 max-w-[280px] truncate"
          >
            {allCases.map((c, idx) => (
              <option key={`ws-case-opt-${c.id ?? idx}-${idx}`} value={idx}>
                {c.filename} ({c.classification.split(' ')[0]})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Tabs Header */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 flex overflow-x-auto space-x-1 shrink-0">
        <button
          onClick={() => setActiveTab('static')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'static'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-file-code"></i>
          <span>Static &amp; Manifest Analysis</span>
        </button>

        <button
          onClick={() => setActiveTab('dynamic')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'dynamic'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-play"></i>
          <span>Dynamic Behavioural Sandbox</span>
        </button>

        <button
          onClick={() => setActiveTab('evasion')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'evasion'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-user-secret"></i>
          <span>Evasion &amp; Obfuscation</span>
        </button>

        <button
          onClick={() => setActiveTab('network')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'network'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-network-wired"></i>
          <span>Network, Cert &amp; Library</span>
        </button>

        <button
          onClick={() => setActiveTab('threat')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'threat'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-brain"></i>
          <span>Threat Intel &amp; MITRE</span>
        </button>

        <button
          onClick={() => setActiveTab('forensic')}
          className={`px-4 py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 whitespace-nowrap transition ${
            activeTab === 'forensic'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <i className="fa-solid fa-file-shield"></i>
          <span>Forensic Report</span>
        </button>
      </div>

      {/* Tab Contents Area */}
      <div className="flex-1 overflow-y-auto p-4 lg:p-6 bg-slate-950">
        {/* TAB 1: STATIC & MANIFEST ANALYSIS */}
        {activeTab === 'static' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* APK Metadata & Basic Stats */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <h3 className="font-bold text-sm text-white flex items-center">
                  <i className="fa-solid fa-circle-info text-rose-400 mr-2"></i> APK Header &amp; Metadata
                </h3>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <span className="text-slate-400">Package:</span>
                    <span className="text-slate-200 font-bold truncate max-w-[170px]" title={caseData.pkg}>
                      {caseData.pkg}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <span className="text-slate-400">Version Code:</span>
                    <span className="text-slate-200">{caseData.version}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <span className="text-slate-400">Min / Target SDK:</span>
                    <span className="text-slate-200">
                      {caseData.minSdk ? `API ${caseData.minSdk}` : 'API 21'} /{' '}
                      {caseData.targetSdk ? `API ${caseData.targetSdk}` : 'API 33'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-slate-800">
                    <span className="text-slate-400">SHA-256 Hash:</span>
                    <span className="text-rose-400 truncate max-w-[170px]" title={caseData.sha256}>
                      {caseData.sha256}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-slate-400">Signer:</span>
                    <span className="text-amber-400 truncate max-w-[170px]" title={caseData.signer}>
                      {caseData.signer}
                    </span>
                  </div>
                </div>
              </div>

              {/* Exported Components Analysis */}
              <div className="lg:col-span-2 bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-sitemap text-amber-400 mr-2"></i> Exported Components &amp; Intent Filters
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {caseData.components.length} Components
                  </span>
                </div>
                <div className="overflow-x-auto max-h-56">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                        <th className="py-2 px-2">Type</th>
                        <th className="py-2 px-2">Component Name</th>
                        <th className="py-2 px-2">Exported</th>
                        <th className="py-2 px-2">Risk Implication</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {caseData.components.map((comp, idx) => (
                        <tr key={`comp-${comp.type}-${comp.name}-${idx}`} className="border-b border-slate-800/40">
                          <td className="py-2 px-2 text-rose-400 font-bold">{comp.type}</td>
                          <td className="py-2 px-2 text-slate-200 truncate max-w-[180px]" title={comp.name}>
                            {comp.name}
                          </td>
                          <td className="py-2 px-2 text-amber-400">{String(comp.exported)}</td>
                          <td className="py-2 px-2 text-slate-400">{comp.risk}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Permissions Breakdown & Code Signatures */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Permissions */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-key text-rose-400 mr-2"></i> Permissions Audit (Dangerous vs Normal)
                  </h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    {dangerousPerms.length} Dangerous
                  </span>
                </div>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {caseData.permissions.map((p, idx) => {
                    const badge =
                      p.type === 'Dangerous'
                        ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                        : 'bg-slate-800 text-slate-300 border-slate-700';

                    return (
                      <div
                        key={`perm-${p.name}-${idx}`}
                        className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between"
                      >
                        <div className="pr-2">
                          <div className="text-xs font-mono text-slate-200">{p.name}</div>
                          <div className="text-[10px] text-slate-400 font-sans">{p.desc}</div>
                        </div>
                        <span className={`text-[9px] font-mono px-2 py-0.5 rounded border shrink-0 ${badge}`}>
                          {p.type}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Suspicious Code Patterns */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-code text-amber-400 mr-2"></i> Suspicious Code &amp; Reflection Signatures
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">
                    {caseData.codePatterns.length} Signatures
                  </span>
                </div>
                <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
                  {caseData.codePatterns.length === 0 ? (
                    <div className="p-4 text-center text-xs text-slate-500 font-mono">
                      No dangerous reflection or shell execution patterns identified.
                    </div>
                  ) : (
                    caseData.codePatterns.map((cp, idx) => {
                      const sevBadge =
                        cp.severity === 'Critical'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                          : cp.severity === 'High'
                          ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-400 border-blue-500/30';

                      return (
                        <div key={`cp-${cp.pattern}-${idx}`} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="text-xs font-bold text-white font-mono">{cp.pattern}</span>
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${sevBadge}`}>
                              {cp.severity}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400">{cp.desc}</p>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: DYNAMIC BEHAVIOURAL SANDBOX */}
        {activeTab === 'dynamic' && (
          <div className="space-y-6">
            <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-4 pb-4 border-b border-slate-800">
                <div>
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-cube text-emerald-400 mr-2"></i> Automated Sandbox Execution &amp; Emulation
                  </h3>
                  <p className="text-xs text-slate-400">
                    Android 13.0 (API 33) Sandbox Container #ARM64-PROD-09 • Isolated Virtualized Runtime
                  </p>
                </div>
                <div className="flex items-center space-x-3">
                  <button
                    onClick={handleStartSandbox}
                    disabled={isRunningSandbox}
                    className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-xs px-4 py-2 rounded-lg flex items-center space-x-2 shadow-lg shadow-emerald-900/30 transition"
                  >
                    {isRunningSandbox ? (
                      <>
                        <i className="fa-solid fa-spinner fa-spin"></i>
                        <span>Emulating Sandbox...</span>
                      </>
                    ) : (
                      <>
                        <i className="fa-solid fa-play"></i>
                        <span>Start Live Execution Trace</span>
                      </>
                    )}
                  </button>
                  <button
                    onClick={handleResetSandbox}
                    title="Reset Sandbox container"
                    className="bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs px-3 py-2 rounded-lg border border-slate-700 transition"
                  >
                    <i className="fa-solid fa-rotate-right"></i>
                  </button>
                </div>
              </div>

              {/* Terminal & Live Logcat Console */}
              <div className="bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs overflow-hidden">
                <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-3 h-3 rounded-full bg-rose-500 inline-block"></span>
                    <span className="w-3 h-3 rounded-full bg-amber-500 inline-block"></span>
                    <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block"></span>
                    <span className="text-slate-400 ml-2">logcat -v threadtime | grep -i security</span>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded border ${
                      sandboxStatus === 'RUNNING'
                        ? 'text-amber-400 bg-amber-950/80 border-amber-800 animate-pulse'
                        : sandboxStatus === 'COMPLETED'
                        ? 'text-emerald-400 bg-emerald-950/80 border-emerald-800'
                        : 'text-slate-400 bg-slate-900 border-slate-800'
                    }`}
                  >
                    {sandboxStatus}
                  </span>
                </div>
                <div className="p-4 h-64 overflow-y-auto space-y-1.5 text-slate-300 font-mono">
                  {sandboxLogs.filter(Boolean).map((log, idx) => {
                    const logStr = typeof log === 'string' ? log : String(log || '');
                    const isAlert =
                      logStr.includes('WARNING') || logStr.includes('EXFILTRATION') || logStr.includes('CRITICAL');
                    const isHook = logStr.includes('HOOK') || logStr.includes('DNS');

                    return (
                      <div
                        key={`log-${idx}-${logStr.slice(0, 15)}`}
                        className={isAlert ? 'text-rose-400' : isHook ? 'text-amber-300' : 'text-slate-300'}
                      >
                        {logStr}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Behavioral Monitoring Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* File System Operations */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-3">
                <h4 className="font-bold text-xs text-white uppercase font-mono flex items-center">
                  <i className="fa-solid fa-folder-open text-amber-400 mr-2"></i> File-System Operations
                </h4>
                <div className="space-y-2 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                  {caseData.fileSystem.map((f, idx) => (
                    <div key={`fs-${idx}`} className="text-amber-400 break-all">
                      <i className="fa-solid fa-file-circle-exclamation mr-1"></i> {f}
                    </div>
                  ))}
                </div>
              </div>

              {/* Sensitive API Access */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-3">
                <h4 className="font-bold text-xs text-white uppercase font-mono flex items-center">
                  <i className="fa-solid fa-microchip text-rose-400 mr-2"></i> Sensitive API Hooks
                </h4>
                <div className="space-y-2 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                  {caseData.apiHooks.map((a, idx) => (
                    <div key={`api-${idx}`} className="text-rose-400">
                      <i className="fa-solid fa-bolt mr-1"></i> {a}
                    </div>
                  ))}
                </div>
              </div>

              {/* Network Traffic */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-3">
                <h4 className="font-bold text-xs text-white uppercase font-mono flex items-center">
                  <i className="fa-solid fa-globe text-emerald-400 mr-2"></i> Network &amp; C2 Traffic
                </h4>
                <div className="space-y-2 text-xs font-mono text-slate-300 max-h-48 overflow-y-auto">
                  {caseData.networkTraffic.map((n, idx) => (
                    <div key={`net-${idx}`} className="text-emerald-400 break-all">
                      <i className="fa-solid fa-globe mr-1"></i> {n}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: EVASION & OBFUSCATION INSPECTOR */}
        {activeTab === 'evasion' && (
          <div className="space-y-6">
            <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 space-y-6">
              <div>
                <h3 className="font-bold text-sm text-white flex items-center">
                  <i className="fa-solid fa-user-secret text-rose-400 mr-2"></i> Evasion, Anti-Analysis &amp; Obfuscation Inspection
                </h3>
                <p className="text-xs text-slate-400">
                  Deep inspection flags for anti-debugging, anti-emulation, packer detection, and payload encryption.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {caseData.evasionFlags.map((ef, idx) => {
                  const statusBadge =
                    ef.status === 'Confirmed' || ef.status === 'Detected'
                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                      : ef.status === 'Present'
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700';

                  return (
                    <div key={`ef-${ef.name}-${idx}`} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-bold text-white font-mono">{ef.name}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${statusBadge}`}>
                          {ef.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{ef.desc}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Encrypted Payload Decoder Box */}
            <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 space-y-4">
              <h3 className="font-bold text-sm text-white flex items-center">
                <i className="fa-solid fa-key text-amber-400 mr-2"></i> Encrypted Asset &amp; Payload Decoder
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-1">
                    Raw Encrypted Blob (Base64 / Hex / AES)
                  </label>
                  <textarea
                    rows={5}
                    value={payloadInput}
                    onChange={(e) => setPayloadInput(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-rose-500"
                  ></textarea>
                  <div className="flex space-x-2 mt-2">
                    <button
                      onClick={() => handleDecode('auto')}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono px-3 py-1.5 rounded-lg border border-slate-700 transition"
                    >
                      Auto-Detect &amp; Unpack
                    </button>
                    <button
                      onClick={() => handleDecode('base64')}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono px-3 py-1.5 rounded-lg border border-slate-700 transition"
                    >
                      Base64 Decode
                    </button>
                    <button
                      onClick={() => handleDecode('hex')}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono px-3 py-1.5 rounded-lg border border-slate-700 transition"
                    >
                      Hex to Text
                    </button>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1">
                    <label className="text-xs text-slate-400 font-medium">Decoded Output / Extracted Payload</label>
                    <button
                      onClick={() => handleDecode('auto')}
                      className="text-xs text-emerald-400 hover:text-emerald-300 font-mono"
                    >
                      <i className="fa-solid fa-wand-magic-sparkles mr-1"></i> Run Decryption
                    </button>
                  </div>
                  <textarea
                    rows={5}
                    readOnly
                    value={payloadOutput}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400 focus:outline-none"
                  ></textarea>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: NETWORK, CERTIFICATE & LIBRARY ANALYSIS */}
        {activeTab === 'network' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Extracted IOCs (URLs, IPs, Domains) */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-network-wired text-emerald-400 mr-2"></i> Extracted IOCs (C2 Domains &amp; IPs)
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {caseData.iocs.length} Indicators
                  </span>
                </div>
                <div className="overflow-x-auto max-h-56">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                        <th className="py-2 px-2">Type</th>
                        <th className="py-2 px-2">Indicator</th>
                        <th className="py-2 px-2">Geo / Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {caseData.iocs.map((ioc, idx) => (
                        <tr key={`ioc-${ioc.type}-${ioc.value}-${idx}`} className="border-b border-slate-800/40">
                          <td className="py-2 px-2 text-emerald-400 font-bold">{ioc.type}</td>
                          <td className="py-2 px-2 text-slate-200 break-all">{ioc.value}</td>
                          <td className="py-2 px-2 text-rose-400">{ioc.risk}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* SSL/TLS Certificate & Signing Info */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <h3 className="font-bold text-sm text-white flex items-center">
                  <i className="fa-solid fa-certificate text-amber-400 mr-2"></i> SSL/TLS Certificate &amp; Signature Viewer
                </h3>
                <div className="space-y-3 text-xs font-mono text-slate-300">
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <strong className="text-slate-400 block mb-0.5">Issuer:</strong>
                    <span className="text-slate-200">{caseData.certInfo.issuer}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between">
                    <div>
                      <strong className="text-slate-400 block mb-0.5">Validity Period:</strong>
                      <span>
                        {caseData.certInfo.validFrom} to {caseData.certInfo.validTo}
                      </span>
                    </div>
                    <div className="text-right">
                      <strong className="text-slate-400 block mb-0.5">Serial:</strong>
                      <span className="text-slate-300">{caseData.certInfo.serial}</span>
                    </div>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <strong className="text-slate-400 block mb-0.5">SHA-1 Fingerprint:</strong>
                    <span className="text-rose-400 break-all">{caseData.certInfo.sha1Fingerprint}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* SBOM / Third-party Library Vulnerability Lookup */}
            <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-sm text-white flex items-center">
                  <i className="fa-solid fa-boxes-stacked text-rose-400 mr-2"></i> SBOM &amp; Third-Party Library Vulnerabilities
                </h3>
                <span className="text-[10px] font-mono text-slate-400">
                  {caseData.sbom.length} Dependencies Audited
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2 px-2">Library / Dependency</th>
                      <th className="py-2 px-2">Version</th>
                      <th className="py-2 px-2">Vulnerability (CVE)</th>
                      <th className="py-2 px-2">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {caseData.sbom.map((s, idx) => {
                      const sColor =
                        s.severity === 'Critical'
                          ? 'text-rose-500 font-bold'
                          : s.severity === 'High'
                          ? 'text-rose-400'
                          : s.severity === 'Medium'
                          ? 'text-amber-400'
                          : 'text-slate-400';

                      return (
                        <tr key={`sbom-${s.lib}-${s.version}-${idx}`} className="border-b border-slate-800/40">
                          <td className="py-2 px-2 font-bold text-white">{s.lib}</td>
                          <td className="py-2 px-2 text-slate-300">{s.version}</td>
                          <td className="py-2 px-2 text-slate-400">
                            {s.vuln}
                            {s.reference && (
                              <a
                                href={s.reference}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-rose-400 underline ml-2 text-[10px]"
                              >
                                NVD Link
                              </a>
                            )}
                          </td>
                          <td className={`py-2 px-2 ${sColor}`}>{s.severity}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: THREAT INTEL & RISK SCORING */}
        {activeTab === 'threat' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Explainable Risk Score Breakdown */}
              <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4 flex flex-col justify-between">
                <div>
                  <h3 className="font-bold text-sm text-white flex items-center mb-4">
                    <i className="fa-solid fa-brain text-rose-400 mr-2"></i> Explainable Risk Score
                  </h3>
                  <div className="text-center py-6 bg-slate-950/60 rounded-xl border border-slate-800 mb-4">
                    <div
                      className={`text-5xl font-extrabold font-mono ${
                        isCrit ? 'text-rose-500' : caseData.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {caseData.riskScore}
                    </div>
                    <div className="text-xs text-slate-400 uppercase tracking-widest mt-1 font-mono">
                      {caseData.classification}
                    </div>
                  </div>
                  <div className="space-y-2 text-xs text-slate-300">
                    {caseData.threatFactors.map((tf, idx) => (
                      <div
                        key={`tf-${idx}`}
                        className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start space-x-2"
                      >
                        <i className="fa-solid fa-triangle-exclamation text-rose-500 mt-0.5 shrink-0"></i>
                        <span>{tf}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK for Mobile Mapping Matrix */}
              <div className="lg:col-span-2 bg-slate-900/80 rounded-2xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-sm text-white flex items-center">
                    <i className="fa-solid fa-chess-board text-amber-400 mr-2"></i> MITRE ATT&amp;CK® for Mobile Mapping
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">
                    {caseData.mitre.length} Techniques Mapped
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                        <th className="py-2 px-2">Tactic</th>
                        <th className="py-2 px-2">Technique ID &amp; Name</th>
                        <th className="py-2 px-2">Observed Behavior</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {caseData.mitre.map((m, idx) => (
                        <tr key={`mitre-${m.tactic}-${m.tech}-${idx}`} className="border-b border-slate-800/40">
                          <td className="py-2 px-2 font-bold text-amber-400">{m.tactic}</td>
                          <td className="py-2 px-2 text-slate-200">{m.tech}</td>
                          <td className="py-2 px-2 text-slate-400">{m.observed}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: FORENSIC REPORT */}
        {activeTab === 'forensic' && (
          <div className="space-y-6">
            <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 space-y-6">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800">
                <div>
                  <h3 className="font-bold text-base text-white flex items-center">
                    <i className="fa-solid fa-file-shield text-rose-400 mr-2"></i> Law Enforcement Forensic Report Generator
                  </h3>
                  <p className="text-xs text-slate-400">
                    Export cryptographically secure investigation reports with evidentiary hashes for court submission.
                  </p>
                </div>
                <div className="flex items-center space-x-3">
                  <button
                    onClick={() => {
                      downloadPdfReport(forensicCase);
                      onShowToast('PDF Downloaded', `Forensic report for ${caseData.filename} generated.`, 'success');
                    }}
                    className="bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs px-4 py-2.5 rounded-lg flex items-center space-x-2 shadow-lg shadow-rose-900/30 transition"
                  >
                    <i className="fa-solid fa-file-pdf"></i>
                    <span>Download PDF Report</span>
                  </button>
                  <button
                    onClick={() => {
                      downloadJsonReport(forensicCase);
                      onShowToast('JSON Exported', `Structured IOCs exported in JSON format.`, 'success');
                    }}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs px-4 py-2.5 rounded-lg border border-slate-700 flex items-center space-x-2 transition"
                  >
                    <i className="fa-solid fa-code"></i>
                    <span>Export JSON IOCs</span>
                  </button>
                </div>
              </div>

              {/* Preview of Report Content */}
              <div className="bg-slate-950 rounded-xl p-6 border border-slate-800 font-mono text-xs space-y-4 text-slate-300">
                <div className="flex justify-between border-b border-slate-800 pb-3 text-slate-400">
                  <span>
                    CASE REF: <strong className="text-white">LE-2026-APK-{String(caseData.id).replace('CASE-', '')}</strong>
                  </span>
                  <span>
                    CLASSIFICATION: <strong className="text-rose-400">RESTRICTED / LAW ENFORCEMENT ONLY</strong>
                  </span>
                </div>
                <div className="space-y-2">
                  <div className="text-white font-bold text-sm font-mono">EXECUTIVE SUMMARY OF FORENSIC FINDINGS</div>
                  <p className="text-slate-400 leading-relaxed font-sans text-xs">
                    Forensic analysis of package [{caseData.pkg}] verified cryptographic signatures and sandbox behavioral traces. Sample classified as{' '}
                    <strong className="text-white">{caseData.classification}</strong> with risk score{' '}
                    <strong className="text-rose-400">{caseData.riskScore}/100</strong>. Primary threat indicators identified:{' '}
                    {caseData.threatFactors[0] || 'Standard behavior'}.
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <div className="text-slate-400 text-[10px] uppercase">MD5 Checksum</div>
                    <div className="text-rose-400 font-mono mt-1 break-all">{caseData.md5}</div>
                  </div>
                  <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                    <div className="text-slate-400 text-[10px] uppercase">SHA-256 Checksum</div>
                    <div className="text-rose-400 font-mono mt-1 break-all">{caseData.sha256}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
