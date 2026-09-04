import React from 'react';
import { Scan, Finding } from '../types';
import { jsPDF } from 'jspdf';
import { FileText, Download, ShieldCheck, Printer, X } from 'lucide-react';

interface ReportViewerProps {
  isOpen: boolean;
  onClose: () => void;
  scan: Scan;
  findings: Finding[];
}

export const ReportViewer: React.FC<ReportViewerProps> = ({
  isOpen,
  onClose,
  scan,
  findings
}) => {
  if (!isOpen || !scan) return null;

  // 1. Target Isolation: Filter findings belonging ONLY to targets in scan.targetIds / scan.targetsSnapshot
  const targetIds = new Set(scan.targetIds || scan.targetsSnapshot.map(t => t.id));
  const targetUrls = new Set(scan.targetsSnapshot.map(t => t.url.toLowerCase()));

  const targetFindings = findings.filter(f => 
    targetIds.has(f.targetId) || targetUrls.has(f.targetUrl?.toLowerCase())
  );

  // 2. Clean obsolete port 443 findings if new informational port 443 finding exists
  const hasNewPort443Info = targetFindings.some(f => f.name.includes('HTTPS Service Detected on Port 443'));
  const cleanedFindings = targetFindings.map(f => {
    if (f.name.includes('Open Port Discovered: 443')) {
      return {
        ...f,
        name: 'Informational: HTTPS Service Detected on Port 443',
        severity: 'INFO' as const,
        cvssScore: 0.0,
        cweId: undefined,
        description: 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.',
        simpleExplanation: 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.',
        remediation: 'No remediation is required for an HTTPS service on port 443. Keep port 443 available if HTTPS access is required. TLS configuration should be assessed separately.'
      };
    }
    return f;
  });

  // 3. Strict Deduplication: Deduplicate identical findings by targetId + name
  const deduplicatedMap = new Map<string, Finding>();
  cleanedFindings.forEach(f => {
    const key = `${f.targetId}_${f.name}`;
    if (!deduplicatedMap.has(key)) {
      deduplicatedMap.set(key, f);
    }
  });
  const reportFindings = Array.from(deduplicatedMap.values());

  // 4. Recalculate Severity Counts
  const counts = {
    critical: reportFindings.filter(f => f.severity === 'CRITICAL').length,
    high: reportFindings.filter(f => f.severity === 'HIGH').length,
    medium: reportFindings.filter(f => f.severity === 'MEDIUM').length,
    low: reportFindings.filter(f => f.severity === 'LOW').length,
    info: reportFindings.filter(f => f.severity === 'INFO').length,
    total: reportFindings.length
  };

  // 5. Recalculate Security Score from valid target findings
  const totalDeductions = (counts.critical * 25) + (counts.high * 15) + (counts.medium * 10) + (counts.low * 5);
  const calculatedSecurityScore = Math.max(0, 100 - totalDeductions);

  const downloadPDF = () => {
    const doc = new jsPDF();
    
    // Header Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text('AegisScan Security Assessment Report', 14, 22);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Scan ID: ${scan.id} | Date: ${scan.startedAt.split('T')[0]}`, 14, 30);
    doc.text(`Overall Security Score: ${calculatedSecurityScore}/100`, 14, 36);

    doc.setLineWidth(0.5);
    doc.line(14, 40, 196, 40);

    // Targets Snapshot Section
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Authorized Scope & Target Snapshot', 14, 48);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    let yPos = 56;
    scan.targetsSnapshot.forEach((t) => {
      doc.text(`- Target: ${t.name} (${t.url})`, 16, yPos);
      doc.text(`  RoE ID: ${t.roeId} | Scope: ${t.scope}`, 16, yPos + 5);
      yPos += 12;
    });

    // Findings Summary Metrics
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('2. Vulnerability Findings Summary', 14, yPos + 6);
    yPos += 14;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low} | Info: ${counts.info} | Total: ${counts.total}`, 16, yPos);
    yPos += 10;

    // Detailed Findings
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('3. Detailed Audit Findings', 14, yPos + 6);
    yPos += 14;

    reportFindings.forEach((f, idx) => {
      if (yPos > 260) {
        doc.addPage();
        yPos = 20;
      }

      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(`${idx + 1}. [${f.severity}] ${f.name} (CVSS: ${f.cvssScore})`, 16, yPos);
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.text(`Target: ${f.targetName} (${f.targetUrl})`, 18, yPos + 5);
      doc.text(`Description: ${f.description.slice(0, 100)}...`, 18, yPos + 10);
      doc.text(`Remediation: ${f.remediation.slice(0, 100)}...`, 18, yPos + 15);
      
      yPos += 22;
    });

    doc.save(`AegisScan_Report_${scan.id}.pdf`);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto space-y-6 text-xs">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <FileText className="w-6 h-6 text-cyber-400" />
            <div>
              <h2 className="text-lg font-bold text-white">Executive Security & Compliance Report</h2>
              <p className="text-xs text-slate-400">Scan ID: {scan.id} — PDF Document Preview</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={downloadPDF}
              className="flex items-center space-x-2 bg-gradient-to-r from-cyber-600 to-indigo-600 hover:from-cyber-500 hover:to-indigo-500 text-white font-semibold px-4 py-2 rounded-xl shadow-lg transition"
            >
              <Download className="w-4 h-4" />
              <span>Download PDF</span>
            </button>

            <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Report Preview Document */}
        <div className="bg-slate-850 p-6 rounded-2xl border border-slate-800 space-y-6 text-slate-200 font-sans">
          
          {/* Title Header */}
          <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
            <div>
              <h1 className="text-xl font-bold text-white">Security Assessment & Compliance Report</h1>
              <p className="text-xs text-slate-400 mt-1">Platform: AegisScan Enterprise v2.4</p>
            </div>
            <div className="text-right font-mono">
              <span className="text-xs text-emerald-400 font-bold block">SECURITY SCORE: {calculatedSecurityScore}/100</span>
              <span className="text-[10px] text-slate-500">{scan.startedAt.split('T')[0]}</span>
            </div>
          </div>

          {/* Section 1: Scope & RoE */}
          <div>
            <h3 className="text-sm font-bold text-cyber-400 uppercase tracking-wider mb-2">1. Scope & Rules of Engagement Verification</h3>
            <div className="bg-slate-900 p-3.5 rounded-xl border border-slate-800 space-y-2">
              {scan.targetsSnapshot.map((t) => (
                <div key={t.id} className="flex justify-between items-center font-mono text-[11px]">
                  <span>Target: {t.name} ({t.url})</span>
                  <span className="text-emerald-400">RoE: {t.roeId}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Summary Metrics */}
          <div>
            <h3 className="text-sm font-bold text-cyber-400 uppercase tracking-wider mb-2">2. Vulnerability Findings Breakdown</h3>
            <div className="grid grid-cols-5 gap-2.5 text-center font-mono">
              <div className="bg-red-500/10 border border-red-500/30 p-2.5 rounded-xl text-red-400">
                <span className="text-lg font-bold block">{counts.critical}</span>
                <span className="text-[10px] uppercase">Critical</span>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/30 p-2.5 rounded-xl text-amber-400">
                <span className="text-lg font-bold block">{counts.high}</span>
                <span className="text-[10px] uppercase">High</span>
              </div>
              <div className="bg-yellow-500/10 border border-yellow-500/30 p-2.5 rounded-xl text-yellow-400">
                <span className="text-lg font-bold block">{counts.medium}</span>
                <span className="text-[10px] uppercase">Medium</span>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 p-2.5 rounded-xl text-blue-400">
                <span className="text-lg font-bold block">{counts.low}</span>
                <span className="text-[10px] uppercase">Low</span>
              </div>
              <div className="bg-slate-500/10 border border-slate-500/30 p-2.5 rounded-xl text-slate-400">
                <span className="text-lg font-bold block">{counts.info}</span>
                <span className="text-[10px] uppercase">Info</span>
              </div>
            </div>
          </div>

          {/* Section 3: Detailed Findings */}
          <div>
            <h3 className="text-sm font-bold text-cyber-400 uppercase tracking-wider mb-2">3. Detailed Security Findings ({reportFindings.length})</h3>
            <div className="space-y-3">
              {reportFindings.length > 0 ? (
                reportFindings.map((f, idx) => (
                  <div key={f.id} className="bg-slate-900 p-3.5 rounded-xl border border-slate-800 space-y-1">
                    <div className="flex justify-between font-semibold text-white">
                      <span>{idx + 1}. {f.name}</span>
                      <span className="text-amber-400 font-mono text-[11px]">
                        {f.severity} | CVSS: {f.cvssScore} {f.cweId ? `| ${f.cweId}` : ''}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-500 font-mono">Target: {f.targetName} ({f.targetUrl})</p>
                    <p className="text-[11px] text-slate-400">{f.description}</p>
                    <p className="text-[11px] text-emerald-400/90 font-medium pt-1">Fix: {f.remediation}</p>
                  </div>
                ))
              ) : (
                <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 text-center text-slate-400 font-mono">
                  No vulnerabilities detected for the authorized target scope.
                </div>
              )}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
