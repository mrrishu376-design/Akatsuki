import React, { useMemo, useState } from 'react';
import { ForensicCase } from '../types/forensic';

interface ComparisonViewProps {
  cases: ForensicCase[];
  onShowToast: (title: string, desc: string, type?: 'success' | 'info' | 'warning' | 'error') => void;
}

export const ComparisonView: React.FC<ComparisonViewProps> = ({ cases, onShowToast }) => {
  const [indexA, setIndexA] = useState<number>(0);
  const [indexB, setIndexB] = useState<number>(Math.min(1, cases.length - 1));

  const caseA = cases[indexA] || cases[0];
  const caseB = cases[indexB] || cases[1] || cases[0];

  // Compute detailed diffs
  const diffAnalysis = useMemo(() => {
    if (!caseA || !caseB) return null;

    const permsA = new Set(caseA.permissions.map((p) => p.name));
    const permsB = new Set(caseB.permissions.map((p) => p.name));

    const onlyInA = caseA.permissions.filter((p) => !permsB.has(p.name));
    const onlyInB = caseB.permissions.filter((p) => !permsA.has(p.name));
    const sharedPerms = caseA.permissions.filter((p) => permsB.has(p.name));

    const scoreDiff = caseA.riskScore - caseB.riskScore;

    return {
      onlyInA,
      onlyInB,
      sharedPerms,
      scoreDiff,
    };
  }, [caseA, caseB]);

  const handleExportComparison = () => {
    const report = {
      title: 'AppIntel Pro Side-by-Side APK Forensic Comparison Report',
      timestamp: new Date().toISOString(),
      sampleA: {
        filename: caseA.filename,
        pkg: caseA.pkg,
        riskScore: caseA.riskScore,
        classification: caseA.classification,
        md5: caseA.md5,
        sha256: caseA.sha256,
        permissionsCount: caseA.permissions.length,
        iocsCount: caseA.iocs.length,
      },
      sampleB: {
        filename: caseB.filename,
        pkg: caseB.pkg,
        riskScore: caseB.riskScore,
        classification: caseB.classification,
        md5: caseB.md5,
        sha256: caseB.sha256,
        permissionsCount: caseB.permissions.length,
        iocsCount: caseB.iocs.length,
      },
      differences: {
        scoreDifference: diffAnalysis?.scoreDiff,
        permissionsOnlyInA: diffAnalysis?.onlyInA.map((p) => p.name),
        permissionsOnlyInB: diffAnalysis?.onlyInB.map((p) => p.name),
      },
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `comparison_${caseA.filename}_vs_${caseB.filename}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    onShowToast('Comparison Exported', 'Side-by-side forensic comparison report exported.', 'success');
  };

  return (
    <div className="flex-1 overflow-y-auto p-4 lg:p-8 space-y-6">
      <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center">
              <i className="fa-solid fa-code-compare text-rose-400 mr-2"></i> Side-by-Side APK Forensic Comparison
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Compare permissions, exported components, threat scores, and IOC profiles between two forensic samples.
            </p>
          </div>

          <button
            onClick={handleExportComparison}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium px-4 py-2 rounded-xl flex items-center space-x-2 transition"
          >
            <i className="fa-solid fa-file-export text-rose-400"></i>
            <span>Export Comparison JSON</span>
          </button>
        </div>

        {/* Selectors & Profile Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Sample A */}
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-5 space-y-4">
            <div className="flex justify-between items-center">
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                SELECT SAMPLE A:
              </label>
              <select
                value={indexA}
                onChange={(e) => setIndexA(Number(e.target.value))}
                className="bg-slate-900 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-rose-500 max-w-[240px] truncate"
              >
                {cases.map((c, idx) => (
                  <option key={`comp-opt-a-${c.id ?? idx}-${idx}`} value={idx}>
                    {c.filename}
                  </option>
                ))}
              </select>
            </div>

            {caseA && (
              <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
                <div className="text-white font-bold text-sm truncate">{caseA.filename}</div>
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Risk Score:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded text-[10px] border ${
                      caseA.riskScore >= 80
                        ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                    }`}
                  >
                    {caseA.riskScore}/100 ({caseA.classification})
                  </span>
                </div>
                <div className="text-slate-400 truncate">
                  Package: <span className="text-slate-200">{caseA.pkg}</span>
                </div>
                <div className="text-slate-400">
                  Permissions: <span className="text-slate-200">{(caseA.permissions || []).length} total</span> (
                  <span className="text-rose-400">
                    {(caseA.permissions || []).filter((p) => p.type === 'Dangerous').length} Dangerous
                  </span>
                  )
                </div>
                <div className="text-slate-400">
                  Exported Components: <span className="text-slate-200">{(caseA.components || []).length} recorded</span>
                </div>
                <div className="text-slate-400">
                  IOCs: <span className="text-slate-200">{(caseA.iocs || []).length} extracted</span>
                </div>
                <div className="text-slate-400 text-[10px] truncate pt-1 border-t border-slate-800">
                  MD5: <span className="text-slate-300">{caseA.md5}</span>
                </div>
              </div>
            )}
          </div>

          {/* Sample B */}
          <div className="bg-slate-950 rounded-xl border border-slate-800 p-5 space-y-4">
            <div className="flex justify-between items-center">
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                SELECT SAMPLE B:
              </label>
              <select
                value={indexB}
                onChange={(e) => setIndexB(Number(e.target.value))}
                className="bg-slate-900 border border-slate-700 text-xs px-3 py-1.5 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-rose-500 max-w-[240px] truncate"
              >
                {cases.map((c, idx) => (
                  <option key={`comp-opt-b-${c.id ?? idx}-${idx}`} value={idx}>
                    {c.filename}
                  </option>
                ))}
              </select>
            </div>

            {caseB && (
              <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
                <div className="text-white font-bold text-sm truncate">{caseB.filename}</div>
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Risk Score:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded text-[10px] border ${
                      caseB.riskScore >= 80
                        ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                        : caseB.riskScore >= 40
                        ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                    }`}
                  >
                    {caseB.riskScore}/100 ({caseB.classification})
                  </span>
                </div>
                <div className="text-slate-400 truncate">
                  Package: <span className="text-slate-200">{caseB.pkg}</span>
                </div>
                <div className="text-slate-400">
                  Permissions: <span className="text-slate-200">{caseB.permissions.length} total</span> (
                  <span className="text-rose-400">
                    {caseB.permissions.filter((p) => p.type === 'Dangerous').length} Dangerous
                  </span>
                  )
                </div>
                <div className="text-slate-400">
                  Exported Components: <span className="text-slate-200">{caseB.components.length} recorded</span>
                </div>
                <div className="text-slate-400">
                  IOCs: <span className="text-slate-200">{caseB.iocs.length} extracted</span>
                </div>
                <div className="text-slate-400 text-[10px] truncate pt-1 border-t border-slate-800">
                  MD5: <span className="text-slate-300">{caseB.md5}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Detailed Differential Analysis */}
        {diffAnalysis && (
          <div className="space-y-4">
            <h3 className="font-bold text-sm text-white flex items-center">
              <i className="fa-solid fa-list-check text-emerald-400 mr-2"></i> Comparative Differential Breakdown
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Only in A */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs font-mono text-slate-300 border-b border-slate-800 pb-2">
                  <span>Unique Permissions in Sample A:</span>
                  <span className="text-rose-400 font-bold">{diffAnalysis.onlyInA.length} unique</span>
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto text-xs font-mono">
                  {diffAnalysis.onlyInA.length === 0 ? (
                    <div className="text-slate-500">None (Sample A has no unique permissions).</div>
                  ) : (
                    diffAnalysis.onlyInA.map((p, idx) => (
                      <div key={idx} className="p-1.5 rounded bg-slate-900 text-rose-300 flex justify-between">
                        <span className="truncate">{p.name}</span>
                        <span className="text-[10px] text-slate-400">{p.type}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Only in B */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs font-mono text-slate-300 border-b border-slate-800 pb-2">
                  <span>Unique Permissions in Sample B:</span>
                  <span className="text-amber-400 font-bold">{diffAnalysis.onlyInB.length} unique</span>
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto text-xs font-mono">
                  {diffAnalysis.onlyInB.length === 0 ? (
                    <div className="text-slate-500">None (Sample B has no unique permissions).</div>
                  ) : (
                    diffAnalysis.onlyInB.map((p, idx) => (
                      <div key={idx} className="p-1.5 rounded bg-slate-900 text-amber-300 flex justify-between">
                        <span className="truncate">{p.name}</span>
                        <span className="text-[10px] text-slate-400">{p.type}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
