import React, { useState } from 'react';
import { Scan } from '../types';
import { X, ArrowRightLeft, ShieldCheck, TrendingDown, TrendingUp } from 'lucide-react';

interface ScanCompareModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: Scan[];
}

export const ScanCompareModal: React.FC<ScanCompareModalProps> = ({
  isOpen,
  onClose,
  scans
}) => {
  const [scanIdA, setScanIdA] = useState(scans[0]?.id || '');
  const [scanIdB, setScanIdB] = useState(scans[1]?.id || scans[0]?.id || '');

  if (!isOpen) return null;

  const scanA = scans.find(s => s.id === scanIdA) || scans[0];
  const scanB = scans.find(s => s.id === scanIdB) || scans[1] || scans[0];

  const scoreDiff = (scanB?.securityScore || 0) - (scanA?.securityScore || 0);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto space-y-5 text-xs">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <ArrowRightLeft className="w-5 h-5 text-cyber-400" />
            <div>
              <h2 className="text-lg font-bold text-white">Side-by-Side Scan Comparison</h2>
              <p className="text-xs text-slate-400">Compare security posture trends across different scan dates</p>
            </div>
          </div>

          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scan Selectors */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-slate-300 font-semibold mb-1">Baseline Scan A:</label>
            <select
              value={scanIdA}
              onChange={(e) => setScanIdA(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.startedAt.split('T')[0]}) — Score: {s.securityScore}/100
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">Comparison Scan B:</label>
            <select
              value={scanIdB}
              onChange={(e) => setScanIdB(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.startedAt.split('T')[0]}) — Score: {s.securityScore}/100
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Delta Comparison Cards */}
        {scanA && scanB && (
          <div className="space-y-4">
            
            {/* Score Delta Banner */}
            <div className="bg-slate-850 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-[11px] block">SECURITY SCORE DELTA</span>
                <div className="flex items-center space-x-2 mt-0.5">
                  <span className="text-xl font-mono font-extrabold text-white">{scanA.securityScore} → {scanB.securityScore}</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${
                    scoreDiff >= 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                  }`}>
                    {scoreDiff >= 0 ? `+${scoreDiff} Improved` : `${scoreDiff} Declined`}
                  </span>
                </div>
              </div>

              {scoreDiff >= 0 ? (
                <TrendingUp className="w-8 h-8 text-emerald-400" />
              ) : (
                <TrendingDown className="w-8 h-8 text-red-400" />
              )}
            </div>

            {/* Metrics Comparison Grid */}
            <div className="grid grid-cols-2 gap-4">
              
              {/* Scan A Details */}
              <div className="bg-slate-850 p-4 rounded-xl border border-slate-800 space-y-2">
                <h4 className="font-bold text-cyber-300 font-mono text-xs border-b border-slate-800 pb-1.5">
                  Baseline: {scanA.id}
                </h4>
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Findings:</span>
                    <span className="font-mono font-bold">{scanA.findingsCount.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Critical Issues:</span>
                    <span className="font-mono text-red-400 font-bold">{scanA.findingsCount.critical}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">High Issues:</span>
                    <span className="font-mono text-amber-400 font-bold">{scanA.findingsCount.high}</span>
                  </div>
                </div>
              </div>

              {/* Scan B Details */}
              <div className="bg-slate-850 p-4 rounded-xl border border-slate-800 space-y-2">
                <h4 className="font-bold text-indigo-300 font-mono text-xs border-b border-slate-800 pb-1.5">
                  Comparison: {scanB.id}
                </h4>
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Findings:</span>
                    <span className="font-mono font-bold">{scanB.findingsCount.total}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Critical Issues:</span>
                    <span className="font-mono text-red-400 font-bold">{scanB.findingsCount.critical}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">High Issues:</span>
                    <span className="font-mono text-amber-400 font-bold">{scanB.findingsCount.high}</span>
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
