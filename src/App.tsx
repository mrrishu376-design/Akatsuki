import React, { useEffect, useState } from 'react';
import { AuthModal } from './components/AuthModal';
import { ComparisonView } from './components/ComparisonView';
import { DashboardView } from './components/DashboardView';
import { Header } from './components/Header';
import { PrivacyModal } from './components/PrivacyModal';
import { Sidebar } from './components/Sidebar';
import { SupabaseModal } from './components/SupabaseModal';
import { ThreatIntelView } from './components/ThreatIntelView';
import { Toast, ToastMessage } from './components/Toast';
import { UploadModal } from './components/UploadModal';
import { WorkspaceView } from './components/WorkspaceView';
import { AuthProvider, useAuth } from './context/AuthContext';
import { downloadPdfReport } from './services/pdfReport';
import {
  addStoredCase,
  addStoredIoc,
  deleteStoredCase,
  getStoredCases,
  getStoredIocs,
  saveCases,
} from './services/storage';
import {
  deleteCaseFromSupabase,
  fetchCasesFromSupabase,
  fetchIocsFromSupabase,
  isSupabaseConfigured,
  syncCaseToSupabase,
  syncIocToSupabase,
} from './services/supabaseClient';
import { ForensicCase, GlobalIocItem } from './types/forensic';

function AppContent() {
  const { user } = useAuth();

  const [currentView, setCurrentView] = useState<'dashboard' | 'workspace' | 'comparison' | 'threatintel'>('dashboard');
  const [cases, setCases] = useState<ForensicCase[]>(() => getStoredCases());
  const [activeCaseIndex, setActiveCaseIndex] = useState<number>(0);
  const [iocs, setIocs] = useState<GlobalIocItem[]>(() => getStoredIocs());

  // Modals
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [isPrivacyOpen, setIsPrivacyOpen] = useState(false);
  const [isSupabaseOpen, setIsSupabaseOpen] = useState(false);

  // Toast
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const showToast = (title: string, desc: string, type: ToastMessage['type'] = 'success') => {
    setToast({ title, desc, type });
    setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  // Sync with Supabase on mount if configured
  useEffect(() => {
    if (isSupabaseConfigured()) {
      fetchCasesFromSupabase().then((remoteCases) => {
        if (remoteCases && remoteCases.length > 0) {
          setCases(remoteCases);
          saveCases(remoteCases);
          showToast('Supabase Synced', `Synchronized ${remoteCases.length} forensic cases from PostgreSQL.`, 'info');
        }
      });

      fetchIocsFromSupabase().then((remoteIocs) => {
        if (remoteIocs && remoteIocs.length > 0) {
          setIocs(remoteIocs);
        }
      });
    }
  }, []);

  const handleAnalysisComplete = (newCase: ForensicCase) => {
    const updated = addStoredCase(newCase);
    setCases(updated);
    setActiveCaseIndex(0); // newly inserted at beginning
    setCurrentView('workspace');

    // Sync to Supabase PostgreSQL in background if configured
    if (isSupabaseConfigured()) {
      syncCaseToSupabase(newCase, user?.email).then((remoteId) => {
        if (remoteId) {
          showToast('PostgreSQL Saved', `Case ${newCase.filename} synced to Supabase database.`, 'info');
        }
      });
    }

    // Also extract new C2 / IP indicators into global IOC feed
    newCase.iocs.forEach((ioc) => {
      if (ioc.type === 'Domain' || ioc.type === 'IP Address') {
        const iocItem: GlobalIocItem = {
          type: ioc.type,
          val: ioc.value,
          malware: newCase.filename.replace(/\.apk$/i, ''),
          conf: '96%',
          source: 'Automated Static & Sandbox Ingestion',
          firstSeen: new Date().toISOString().slice(0, 10),
          status: 'Active Case Extraction',
        };
        addStoredIoc(iocItem);
        if (isSupabaseConfigured()) {
          syncIocToSupabase(iocItem);
        }
      }
    });
    setIocs(getStoredIocs());

    showToast('Analysis Complete', `Successfully ingested and analyzed ${newCase.filename}. Risk Score: ${newCase.riskScore}/100.`, 'success');
  };

  const handleDeleteCase = (id: string | number) => {
    const updated = deleteStoredCase(id);
    setCases(updated);
    if (activeCaseIndex >= updated.length) {
      setActiveCaseIndex(Math.max(0, updated.length - 1));
    }
    if (isSupabaseConfigured()) {
      deleteCaseFromSupabase(id);
    }
    showToast('Case Removed', 'Forensic investigation record deleted from workstation.', 'info');
  };

  const handleBatchReport = () => {
    if (cases.length === 0) {
      showToast('No Cases', 'No forensic cases available to export.', 'warning');
      return;
    }
    // Generate report for active case and bundle
    const active = cases[activeCaseIndex] || cases[0];
    downloadPdfReport(active);
    showToast('Batch Summary', `Forensic summary report generated and downloaded.`, 'success');
  };

  const activeCase = cases[activeCaseIndex] || cases[0];

  return (
    <div className="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-rose-500 selection:text-white">
      {/* Top Navigation Header */}
      <Header
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenAuth={() => setIsAuthOpen(true)}
        onOpenPrivacy={() => setIsPrivacyOpen(true)}
        onOpenSupabase={() => setIsSupabaseOpen(true)}
      />

      {/* Main Workspace Container */}
      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar
          currentView={currentView}
          onSelectView={setCurrentView}
          cases={cases}
          activeCaseIndex={activeCaseIndex}
          onSelectCase={(idx) => {
            setActiveCaseIndex(idx);
            setCurrentView('workspace');
          }}
        />

        {/* Main Content Area */}
        <main className="flex-1 flex flex-col overflow-hidden bg-slate-950">
          {currentView === 'dashboard' && (
            <DashboardView
              cases={cases}
              onOpenUpload={() => setIsUploadOpen(true)}
              onOpenCase={(idx) => {
                setActiveCaseIndex(idx);
                setCurrentView('workspace');
              }}
              onDeleteCase={handleDeleteCase}
              onExportBatchReport={handleBatchReport}
            />
          )}

          {currentView === 'workspace' && activeCase && (
            <WorkspaceView
              forensicCase={activeCase}
              allCases={cases}
              activeCaseIndex={activeCaseIndex}
              onSelectCase={setActiveCaseIndex}
              onBackToDashboard={() => setCurrentView('dashboard')}
              onShowToast={showToast}
            />
          )}

          {currentView === 'comparison' && (
            <ComparisonView cases={cases} onShowToast={showToast} />
          )}

          {currentView === 'threatintel' && (
            <ThreatIntelView
              iocs={iocs}
              onAddIoc={(newIoc) => {
                const updated = addStoredIoc(newIoc);
                setIocs(updated);
                if (isSupabaseConfigured()) {
                  syncIocToSupabase(newIoc);
                }
              }}
              onShowToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Modals */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onAnalysisComplete={handleAnalysisComplete}
      />

      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onSuccess={() => showToast('Authenticated', 'Investigator session verified.', 'success')}
      />

      <PrivacyModal
        isOpen={isPrivacyOpen}
        onClose={() => setIsPrivacyOpen(false)}
      />

      <SupabaseModal
        isOpen={isSupabaseOpen}
        onClose={() => setIsSupabaseOpen(false)}
        onShowToast={showToast}
      />

      {/* Toast Notification */}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
