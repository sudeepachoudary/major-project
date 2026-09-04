import React from 'react';
import { Scan } from '../types';
import { History, Eye, ArrowRightLeft, ShieldCheck, CheckCircle2, Clock } from 'lucide-react';

interface ScanHistoryProps {
  scans: Scan[];
  onSelectScan: (scanId: string) => void;
  onOpenCompareModal: () => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  scans,
  onSelectScan,
  onOpenCompareModal
}) => {
  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Header */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <History className="w-6 h-6 text-cyber-400" />
            <h1 className="text-xl font-bold text-white font-sans">Scan History & Comparisons</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {scans.length} Completed Scans
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Historical audit logs of previous security assessments with side-by-side scan comparison tools.
          </p>
        </div>

        <button
          onClick={onOpenCompareModal}
          disabled={scans.length < 2}
          className={`flex items-center space-x-2 text-xs font-semibold px-4 py-2.5 rounded-xl border transition ${
            scans.length >= 2
              ? 'bg-slate-800 hover:bg-slate-750 text-slate-200 border-slate-700'
              : 'bg-slate-900 text-slate-600 border-slate-850 cursor-not-allowed'
          }`}
        >
          <ArrowRightLeft className="w-4 h-4 text-cyber-400" />
          <span>Compare Previous Scans</span>
        </button>
      </div>

      {/* Scans Data Grid */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Scan ID</th>
                <th className="py-3 px-4">Target Host(s)</th>
                <th className="py-3 px-4">Scan Profile</th>
                <th className="py-3 px-4">Date & Time</th>
                <th className="py-3 px-4">Total Findings</th>
                <th className="py-3 px-4">Security Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-3.5 px-4 font-mono font-bold text-white">
                    {scan.id}
                  </td>

                  <td className="py-3.5 px-4 font-semibold text-slate-200">
                    {scan.targetsSnapshot.map(t => t.name).join(', ')}
                  </td>

                  <td className="py-3.5 px-4 font-mono text-cyber-300">
                    {scan.scanProfile.toUpperCase()}
                  </td>

                  <td className="py-3.5 px-4 text-slate-400 font-mono">
                    {scan.startedAt.split('T')[0]} {scan.startedAt.split('T')[1]?.slice(0, 5)}
                  </td>

                  <td className="py-3.5 px-4 font-mono">
                    <span className="text-amber-400 font-bold">{scan.findingsCount.total}</span>
                    <span className="text-slate-500 text-[10px] ml-1.5">
                      ({scan.findingsCount.critical} Crit / {scan.findingsCount.high} High)
                    </span>
                  </td>

                  <td className="py-3.5 px-4 font-mono font-bold text-emerald-400">
                    {scan.securityScore}/100
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => onSelectScan(scan.id)}
                      className="text-cyber-400 hover:text-cyber-300 font-semibold inline-flex items-center space-x-1 bg-cyber-600/10 px-3 py-1.5 rounded-lg border border-cyber-500/20"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>View Report</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
