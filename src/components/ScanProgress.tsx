import React from 'react';
import { Scan, ScanStage } from '../types';
import { ShieldCheck, CheckCircle2, Loader2, AlertCircle, Clock, FileText, ArrowRight } from 'lucide-react';

interface ScanProgressProps {
  scan: Scan;
  onViewResults: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ scan, onViewResults }) => {
  const stages: { id: ScanStage; label: string }[] = [
    { id: 'scope_validation', label: 'Scope Validation' },
    { id: 'authorization_check', label: 'Authorization Validation' },
    { id: 'reconnaissance', label: 'Reconnaissance' },
    { id: 'security_checks', label: 'Security Checks' },
    { id: 'vulnerability_analysis', label: 'Vulnerability Analysis' },
    { id: 'risk_classification', label: 'Risk Classification' },
    { id: 'report_generation', label: 'Report Generation' },
  ];

  const getStageIndex = (stage: ScanStage) => stages.findIndex((s) => s.id === stage);
  const currentStageIdx = getStageIndex(scan.currentStage);
  const isCompleted = scan.status === 'completed';
  const isFailed = scan.status === 'failed';

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Header Banner */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <span className="text-xl font-bold font-mono text-white">{scan.id}</span>
            <span className={`px-2.5 py-0.5 text-xs font-mono rounded-full font-semibold border ${
              isCompleted
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : isFailed
                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse'
            }`}>
              {scan.status.toUpperCase()}
            </span>
            <span className="text-xs text-slate-400 font-mono">Profile: {scan.scanProfile.toUpperCase()}</span>
          </div>
          
          <p className="text-xs text-slate-400 mt-1">
            Targets Snapshot: <span className="text-slate-200 font-semibold">{scan.targetsSnapshot.map(t => t.name).join(', ')}</span>
          </p>
        </div>

        {isCompleted && (
          <button
            onClick={onViewResults}
            className="flex items-center space-x-2 bg-gradient-to-r from-emerald-600 to-cyber-600 hover:from-emerald-500 hover:to-cyber-500 text-white font-semibold text-xs px-5 py-2.5 rounded-xl shadow-lg transition"
          >
            <span>View Scan Results & Findings</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Progress Bar & Percentage */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex justify-between items-center text-xs">
          <span className="font-semibold text-slate-300">
            Pipeline Stage: <span className="text-cyber-400 uppercase font-mono">{scan.currentStage.replace(/_/g, ' ')}</span>
          </span>
          <span className="font-mono font-bold text-white text-sm">{scan.progressPercentage}%</span>
        </div>

        <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800 p-0.5">
          <div
            className="bg-gradient-to-r from-cyber-600 via-cyber-400 to-emerald-400 h-full rounded-full transition-all duration-500"
            style={{ width: `${scan.progressPercentage}%` }}
          />
        </div>

        {/* Multi-stage Stepper Pipeline */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 pt-2">
          {stages.map((stage, idx) => {
            const isFinished = idx < currentStageIdx || isCompleted;
            const isCurrent = idx === currentStageIdx && !isCompleted;

            return (
              <div
                key={stage.id}
                className={`p-2.5 rounded-xl border text-center transition-all ${
                  isFinished
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                    : isCurrent
                    ? 'bg-cyber-950/80 border-cyber-500 text-white ring-1 ring-cyber-500/40'
                    : 'bg-slate-900 border-slate-800 text-slate-500'
                }`}
              >
                <div className="flex justify-center mb-1">
                  {isFinished ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 text-cyber-400 animate-spin" />
                  ) : (
                    <span className="w-4 h-4 text-[10px] font-mono rounded-full border border-slate-700 flex items-center justify-center">
                      {idx + 1}
                    </span>
                  )}
                </div>
                <span className="text-[10px] font-semibold block leading-tight">{stage.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Metrics Row & Live Log Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Real-time Execution Metrics */}
        <div className="bg-slate-850 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
          <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2">Execution Metrics</h3>
          
          <div className="space-y-3 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Security Checks Executed:</span>
              <span className="font-mono font-bold text-white">{scan.checksCompleted}</span>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Findings Discovered:</span>
              <span className="font-mono font-bold text-amber-400">{scan.findingsCount.total}</span>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Current Security Score:</span>
              <span className="font-mono font-bold text-emerald-400">{scan.securityScore}/100</span>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Elapsed Time:</span>
              <span className="font-mono text-slate-300 flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-400" />
                {scan.durationSeconds || 12}s
              </span>
            </div>
          </div>
        </div>

        {/* Live Execution Logs */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl p-5 shadow-xl font-mono text-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-850 pb-2 mb-3">
              <span className="text-slate-300 font-sans font-bold flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyber-400" />
                Live Execution Logs Stream
              </span>
              <span className="text-[10px] text-slate-500">{scan.logs.length} Log entries</span>
            </div>

            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-2">
              {scan.logs.map((log, idx) => (
                <div key={idx} className="flex items-start space-x-2 text-[11px] leading-relaxed">
                  <span className="text-slate-600 flex-shrink-0">[{log.timestamp.split('T')[1].slice(0, 8)}]</span>
                  <span className={`px-1.5 py-0.2 text-[9px] rounded uppercase font-bold flex-shrink-0 ${
                    log.level === 'success' ? 'bg-emerald-500/20 text-emerald-400' :
                    log.level === 'error' ? 'bg-red-500/20 text-red-400' :
                    log.level === 'warn' ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-800 text-cyber-300'
                  }`}>
                    {log.stage}
                  </span>
                  <span className={log.level === 'error' ? 'text-red-400' : 'text-slate-300'}>
                    {log.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

    </div>
  );
};
