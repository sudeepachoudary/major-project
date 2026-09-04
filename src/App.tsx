import React, { useState, useEffect } from 'react';
import { Target, Scan, Finding, AuditLog, TargetType, ScanProfile, EnvironmentType, DiscoveredEndpoint, SecurityToolStatus, RemediationTask } from './types';
import { Navbar } from './components/Navbar';
import { Dashboard } from './components/Dashboard';
import { TargetInventory } from './components/TargetInventory';
import { AddTargetModal } from './components/AddTargetModal';
import { ScanConfigModal } from './components/ScanConfigModal';
import { ScanProgress } from './components/ScanProgress';
import { VulnerabilityCenter } from './components/VulnerabilityCenter';
import { AISecurityAnalysisModal } from './components/AISecurityAnalysis';
import { ReportViewer } from './components/ReportViewer';
import { ScanHistory } from './components/ScanHistory';
import { ScanCompareModal } from './components/ScanCompareModal';
import { AuditLogsViewer } from './components/AuditLogsViewer';
import { ReconnaissanceView } from './components/ReconnaissanceView';
import { ToolAdaptersView } from './components/ToolAdaptersView';
import { RemediationCenter } from './components/RemediationCenter';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [demoMode, setDemoMode] = useState(true);

  // Core Data States
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [tools, setTools] = useState<SecurityToolStatus[]>([]);
  const [remediations, setRemediations] = useState<RemediationTask[]>([]);

  // Selection state for target isolation (independent target IDs)
  const [selectedTargetIds, setSelectedTargetIds] = useState<string[]>(['target_123']);

  // Modals & Active Viewers
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isScanConfigOpen, setIsScanConfigOpen] = useState(false);
  const [isAIModalOpen, setIsAIModalOpen] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isCompareOpen, setIsCompareOpen] = useState(false);

  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  // Poll backend API for data & scan progress updates
  useEffect(() => {
    fetchInitialData();
    const interval = setInterval(fetchInitialData, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchInitialData = async () => {
    try {
      const [targetsRes, scansRes, findingsRes, auditRes, endpointsRes, toolsRes, remediationsRes] = await Promise.all([
        fetch('/api/targets'),
        fetch('/api/scans'),
        fetch('/api/findings'),
        fetch('/api/audit-logs'),
        fetch('/api/endpoints'),
        fetch('/api/tools'),
        fetch('/api/remediations')
      ]);

      if (targetsRes.ok) setTargets(await targetsRes.json());
      if (scansRes.ok) setScans(await scansRes.json());
      if (findingsRes.ok) setFindings(await findingsRes.json());
      if (auditRes.ok) setAuditLogs(await auditRes.json());
      if (endpointsRes.ok) setEndpoints(await endpointsRes.json());
      if (toolsRes.ok) setTools(await toolsRes.json());
      if (remediationsRes.ok) setRemediations(await remediationsRes.json());
    } catch (err) {
      console.warn('Backend server not connected or initializing:', err);
    }
  };

  // Independent target selection toggle (Fixes global checkbox issue)
  const handleToggleTargetSelect = (id: string) => {
    setSelectedTargetIds((prev) =>
      prev.includes(id) ? prev.filter((tId) => tId !== id) : [...prev, id]
    );
  };

  // Add Target Handler
  const handleAddTarget = async (targetData: {
    name: string;
    url: string;
    type: TargetType;
    roeId: string;
    scope: string;
    notes?: string;
    authConfirmed: boolean;
  }) => {
    try {
      const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(targetData)
      });
      if (res.ok) {
        const created = await res.json();
        setTargets((prev) => [...prev, created]);
        setSelectedTargetIds((prev) => [...prev, created.id]);
      }
    } catch (err) {
      console.error('Error adding target:', err);
    }
  };

  // Launch Authorized Scan Handler
  const handleLaunchScan = async (config: {
    targetIds: string[];
    scanProfile: ScanProfile;
    safeMode: boolean;
    rateLimit: number;
    timeout: number;
    optInPathDiscovery: boolean;
  }) => {
    try {
      const res = await fetch('/api/scans/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });

      if (res.ok) {
        const data = await res.json();
        setActiveScanId(data.scanId);
        setActiveTab('progress');
      } else {
        const errData = await res.json();
        alert(`Backend Scope Violation: ${errData.error}`);
      }
    } catch (err) {
      console.error('Error launching scan:', err);
    }
  };

  // Delete Target Handler
  const handleDeleteTarget = async (id: string) => {
    try {
      const res = await fetch(`/api/targets/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setTargets((prev) => prev.filter((t) => t.id !== id));
        setSelectedTargetIds((prev) => prev.filter((tId) => tId !== id));
      }
    } catch (err) {
      console.error('Error deleting target:', err);
    }
  };

  const selectedTargetsObjects = targets.filter((t) => selectedTargetIds.includes(t.id));
  const activeScan = scans.find((s) => s.id === activeScanId) || scans[0];

  const scansRunningCount = scans.filter(
    (s) => s.status === 'running' || s.status === 'validating'
  ).length;

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans flex flex-col">
      
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        demoMode={demoMode}
        setDemoMode={setDemoMode}
        scansRunningCount={scansRunningCount}
      />

      {/* Main Workspace Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <Dashboard
            targets={targets}
            scans={scans}
            findings={findings}
            onNavigate={setActiveTab}
            onSelectScanForProgress={(id) => {
              setActiveScanId(id);
              setActiveTab('progress');
            }}
          />
        )}

        {activeTab === 'targets' && (
          <TargetInventory
            targets={targets}
            selectedTargetIds={selectedTargetIds}
            onToggleTargetSelect={handleToggleTargetSelect}
            onOpenAddModal={() => setIsAddModalOpen(true)}
            onOpenScanConfigModal={() => setIsScanConfigOpen(true)}
            onDeleteTarget={handleDeleteTarget}
          />
        )}

        {activeTab === 'progress' && activeScan && (
          <ScanProgress
            scan={activeScan}
            onViewResults={() => setActiveTab('vulnerabilities')}
          />
        )}

        {activeTab === 'recon' && (
          <ReconnaissanceView endpoints={endpoints} targets={targets} />
        )}

        {activeTab === 'tools' && (
          <ToolAdaptersView tools={tools} onImportSuccess={fetchInitialData} />
        )}

        {activeTab === 'remediation' && (
          <RemediationCenter
            remediations={remediations}
            findings={findings}
            onUpdateRemediation={async (task) => {
              await fetch('/api/remediations', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(task)
              });
              fetchInitialData();
            }}
          />
        )}

        {activeTab === 'vulnerabilities' && (
          <VulnerabilityCenter
            findings={findings}
            targets={targets}
            onOpenReportModal={() => setIsReportOpen(true)}
            onOpenAIAnalysis={() => setIsAIModalOpen(true)}
            onRefreshFindings={fetchInitialData}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistory
            scans={scans}
            onSelectScan={(id) => {
              setActiveScanId(id);
              setIsReportOpen(true);
            }}
            onOpenCompareModal={() => setIsCompareOpen(true)}
          />
        )}

        {activeTab === 'audit' && (
          <AuditLogsViewer logs={auditLogs} />
        )}
      </main>

      {/* Modals & Dialogs */}
      <AddTargetModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onAddTarget={handleAddTarget}
      />

      <ScanConfigModal
        isOpen={isScanConfigOpen}
        onClose={() => setIsScanConfigOpen(false)}
        selectedTargets={selectedTargetsObjects}
        onLaunchScan={handleLaunchScan}
      />

      <AISecurityAnalysisModal
        isOpen={isAIModalOpen}
        onClose={() => setIsAIModalOpen(false)}
        scanId={activeScan?.id || 'SCAN-2026-001'}
        findings={findings}
      />

      <ReportViewer
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        scan={activeScan}
        findings={findings}
      />

      <ScanCompareModal
        isOpen={isCompareOpen}
        onClose={() => setIsCompareOpen(false)}
        scans={scans}
      />

      {/* Footer */}
      <footer className="bg-slate-950 border-t border-slate-800/80 py-4 text-center text-xs text-slate-500 font-mono">
        <p>AegisScan Enterprise — Authorized Penetration Testing Platform © 2026. Non-Destructive Lab Auditor.</p>
      </footer>
    </div>
  );
}

export default App;
