import React, { useMemo, useState } from 'react';
import { GlobalIocItem } from '../types/forensic';

interface ThreatIntelViewProps {
  iocs: GlobalIocItem[];
  onAddIoc: (ioc: GlobalIocItem) => void;
  onShowToast: (title: string, desc: string, type?: 'success' | 'info' | 'warning' | 'error') => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({ iocs, onAddIoc, onShowToast }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [showAddModal, setShowAddModal] = useState(false);

  // New IOC state
  const [newType, setNewType] = useState<GlobalIocItem['type']>('Domain');
  const [newVal, setNewVal] = useState('');
  const [newMalware, setNewMalware] = useState('');
  const [newConfidence, setNewConfidence] = useState('95%');
  const [newSource, setNewSource] = useState('AppIntel Field Unit');

  const filteredIocs = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return iocs.filter((item) => {
      const matchesSearch =
        (item.val || '').toLowerCase().includes(q) ||
        (item.malware || '').toLowerCase().includes(q) ||
        (item.source ? item.source.toLowerCase().includes(q) : false);

      const matchesType = typeFilter === 'ALL' || Boolean(item.type && item.type.includes(typeFilter));

      return matchesSearch && matchesType;
    });
  }, [iocs, searchQuery, typeFilter]);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    onShowToast('Copied to Clipboard', `Indicator ${val} copied.`, 'info');
  };

  const handleExportFeed = (format: 'json' | 'csv') => {
    if (format === 'json') {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredIocs, null, 2));
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = `appintel_global_iocs_${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } else {
      let csv = 'Type,Indicator,Associated Malware,Confidence,Source,Status\n';
      filteredIocs.forEach((i) => {
        csv += `"${i.type}","${i.val}","${i.malware}","${i.conf}","${i.source || ''}","${i.status || 'Verified'}"\n`;
      });
      const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = `appintel_global_iocs_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    onShowToast('Feed Exported', `Global IOC feed exported as ${format.toUpperCase()}.`, 'success');
  };

  const handleCreateIoc = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal.trim() || !newMalware.trim()) return;

    onAddIoc({
      type: newType,
      val: newVal.trim(),
      malware: newMalware.trim(),
      conf: newConfidence,
      source: newSource.trim(),
      firstSeen: new Date().toISOString().slice(0, 10),
      status: 'Active Investigation',
    });

    setNewVal('');
    setNewMalware('');
    setShowAddModal(false);
    onShowToast('IOC Registered', `New threat indicator registered successfully.`, 'success');
  };

  return (
    <div className="flex-1 overflow-y-auto p-4 lg:p-8 space-y-6">
      <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center">
              <i className="fa-solid fa-globe text-emerald-400 mr-2"></i> Global Threat Intelligence &amp; IOC Feed
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Correlated Indicators of Compromise from international law enforcement feeds and verified sandbox traces.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setShowAddModal(true)}
              className="bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs px-3.5 py-2 rounded-xl flex items-center space-x-1.5 transition shadow-lg shadow-rose-900/40"
            >
              <i className="fa-solid fa-plus"></i>
              <span>Register IOC</span>
            </button>
            <button
              onClick={() => handleExportFeed('csv')}
              className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium px-3.5 py-2 rounded-xl flex items-center space-x-1.5 transition"
            >
              <i className="fa-solid fa-download text-emerald-400"></i>
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Search & Filter Toolbar */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          {/* Type Filter Pills */}
          <div className="flex flex-wrap gap-1.5 text-xs font-mono">
            {['ALL', 'Domain', 'IP Address', 'File Hash', 'URL'].map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-3 py-1.5 rounded-lg border transition ${
                  typeFilter === t
                    ? 'bg-emerald-600/20 text-emerald-400 border-emerald-500/40 font-bold'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-72">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 text-xs">
              <i className="fa-solid fa-magnifying-glass"></i>
            </div>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IOC hash, IP, domain..."
              className="w-full bg-slate-950 border border-slate-700 text-xs pl-9 pr-3 py-2 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-mono"
            />
          </div>
        </div>

        {/* IOC Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-3 px-3">Indicator Type</th>
                <th className="py-3 px-3">Value</th>
                <th className="py-3 px-3">Associated Malware</th>
                <th className="py-3 px-3">Confidence</th>
                <th className="py-3 px-3">Source</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredIocs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No threat indicators match the current search filter.
                  </td>
                </tr>
              ) : (
                filteredIocs.map((ioc, idx) => (
                  <tr key={`global-ioc-${ioc.id || ioc.val}-${idx}`} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-3 font-bold text-emerald-400">{ioc.type}</td>
                    <td className="py-3 px-3 text-slate-200 break-all">{ioc.val}</td>
                    <td className="py-3 px-3 text-rose-400">{ioc.malware}</td>
                    <td className="py-3 px-3 text-slate-300 font-bold">{ioc.conf}</td>
                    <td className="py-3 px-3 text-slate-400 text-[11px]">{ioc.source || 'LE-SOC Threat Hub'}</td>
                    <td className="py-3 px-3 text-right space-x-2">
                      <button
                        onClick={() => handleCopy(ioc.val)}
                        title="Copy Indicator"
                        className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] px-2.5 py-1 rounded transition"
                      >
                        <i className="fa-regular fa-copy mr-1"></i> Copy
                      </button>
                      <span className="px-2 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 text-[10px]">
                        {ioc.status || 'Verified'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl relative font-mono">
            <button
              onClick={() => setShowAddModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <i className="fa-solid fa-xmark text-lg"></i>
            </button>

            <h3 className="text-base font-bold text-white flex items-center font-sans">
              <i className="fa-solid fa-plus-circle text-rose-500 mr-2"></i> Register New IOC Indicator
            </h3>

            <form onSubmit={handleCreateIoc} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Indicator Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as GlobalIocItem['type'])}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-rose-500"
                >
                  <option value="Domain">Domain</option>
                  <option value="IP Address">IP Address</option>
                  <option value="File Hash (MD5)">File Hash (MD5)</option>
                  <option value="File Hash (SHA256)">File Hash (SHA256)</option>
                  <option value="URL">URL</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Indicator Value</label>
                <input
                  type="text"
                  required
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  placeholder="e.g. 185.220.101.5 or bad-c2.net"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Associated Malware / Campaign</label>
                <input
                  type="text"
                  required
                  value={newMalware}
                  onChange={(e) => setNewMalware(e.target.value)}
                  placeholder="e.g. SharkBot Banking Trojan"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Confidence</label>
                  <input
                    type="text"
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-rose-500"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Source Agency</label>
                  <input
                    type="text"
                    value={newSource}
                    onChange={(e) => setNewSource(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-rose-500"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-2 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-rose-600 hover:bg-rose-500 text-white px-4 py-2 rounded-xl shadow-lg shadow-rose-900/40 transition"
                >
                  Save Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
