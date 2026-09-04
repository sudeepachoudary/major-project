import React from 'react';
import { AuditLog } from '../types';
import { ScrollText, ShieldCheck, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';

interface AuditLogsViewerProps {
  logs: AuditLog[];
}

export const AuditLogsViewer: React.FC<AuditLogsViewerProps> = ({ logs }) => {
  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Header */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <ScrollText className="w-6 h-6 text-cyber-400" />
            <h1 className="text-xl font-bold text-white font-sans">Immutable Audit Trail</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {logs.length} Compliance Log Entries
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time immutable log stream tracking authorization checks, scope validation events, target additions, and scan launches.
          </p>
        </div>
      </div>

      {/* Audit Logs Table */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl shadow-xl overflow-hidden font-mono text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Action Event</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Target / RoE ID</th>
                <th className="py-3 px-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {logs.map((log) => {
                const isAllowed = log.result === 'ALLOWED' || log.result === 'SUCCESS';
                return (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4 text-slate-400">
                      {log.timestamp.split('T')[0]} {log.timestamp.split('T')[1]?.slice(0, 8)}
                    </td>

                    <td className="py-3.5 px-4 font-semibold text-slate-200 font-sans">
                      {log.user}
                    </td>

                    <td className="py-3.5 px-4 font-bold text-cyber-300">
                      {log.action}
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 text-[10px] rounded font-bold border flex items-center gap-1 w-max ${
                        isAllowed 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                          : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}>
                        {isAllowed ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {log.result}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      {log.targetName || log.targetId || '-'} {log.roeId ? `(${log.roeId})` : ''}
                    </td>

                    <td className="py-3.5 px-4 text-slate-400 font-sans max-w-xs truncate">
                      {log.details}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
