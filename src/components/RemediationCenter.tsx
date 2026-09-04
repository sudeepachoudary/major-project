import React, { useState } from 'react';
import { RemediationTask, Finding } from '../types';
import { CheckSquare, Clock, User, AlertTriangle, ShieldCheck, Plus, CheckCircle2 } from 'lucide-react';

interface RemediationCenterProps {
  remediations: RemediationTask[];
  findings: Finding[];
  onUpdateRemediation: (task: RemediationTask) => void;
}

export const RemediationCenter: React.FC<RemediationCenterProps> = ({
  remediations,
  findings,
  onUpdateRemediation
}) => {
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  const filteredTasks = filterStatus === 'ALL'
    ? remediations
    : remediations.filter(r => r.status === filterStatus);

  const getPriorityBadge = (p: string) => {
    switch (p) {
      case 'P1': return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'P2': return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'P3': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const handleCreateFromFinding = (f: Finding) => {
    const newTask: RemediationTask = {
      id: `rem_${Date.now()}`,
      findingId: f.id,
      findingTitle: f.name,
      severity: f.severity,
      owner: 'SecOps Team Lead',
      priority: f.severity === 'CRITICAL' ? 'P1' : f.severity === 'HIGH' ? 'P2' : 'P3',
      dueDate: new Date(Date.now() + 86400000 * 7).toISOString().split('T')[0],
      status: 'Assigned',
      updatedAt: new Date().toISOString()
    };

    onUpdateRemediation(newTask);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <CheckSquare className="w-6 h-6 text-cyber-400" />
            <h1 className="text-xl font-bold text-white font-sans">Remediation Governance Center</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {remediations.length} Tracked Tasks
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Assign security fixes, track remediation SLAs, add verification notes, and verify developer bug patches.
          </p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-3 text-xs overflow-x-auto">
        {['ALL', 'Open', 'Assigned', 'In Progress', 'Resolved', 'Verified'].map((st) => {
          const count = st === 'ALL' ? remediations.length : remediations.filter(r => r.status === st).length;
          const isSelected = filterStatus === st;
          return (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3 py-1.5 rounded-lg font-semibold transition font-mono ${
                isSelected
                  ? 'bg-cyber-600/20 text-cyber-300 border border-cyber-500/40 shadow-sm'
                  : 'bg-slate-850 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {st} ({count})
            </button>
          );
        })}
      </div>

      {/* Remediation Tasks Data Table */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl shadow-xl overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Vulnerability Finding Title</th>
                <th className="py-3 px-4">Assigned Owner</th>
                <th className="py-3 px-4">Due Date</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredTasks.length > 0 ? (
                filteredTasks.map((task) => (
                  <tr key={task.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getPriorityBadge(task.priority)}`}>
                        {task.priority}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 font-semibold text-white font-sans max-w-md truncate">
                      {task.findingTitle}
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      <span className="flex items-center gap-1.5 font-sans">
                        <User className="w-3.5 h-3.5 text-slate-400" />
                        {task.owner}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-slate-400">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {task.dueDate}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                        task.status === 'Verified' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                        task.status === 'Resolved' ? 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30' :
                        'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {task.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      {task.status !== 'Verified' && (
                        <button
                          onClick={() => onUpdateRemediation({ ...task, status: 'Verified', updatedAt: new Date().toISOString() })}
                          className="text-emerald-400 hover:text-emerald-300 font-semibold text-[11px] bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20"
                        >
                          Mark Verified
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No active remediation tasks match the selected filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Convert Findings to Remediation Tasks */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
        <h2 className="text-sm font-bold text-white">Convert Unassigned Findings into Remediation Tickets</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {findings.slice(0, 4).map((f) => (
            <div key={f.id} className="bg-slate-900 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-semibold text-white block truncate max-w-xs">{f.name}</span>
                <span className="text-[10px] text-slate-400 font-mono">Target: {f.targetName} | {f.severity}</span>
              </div>
              <button
                onClick={() => handleCreateFromFinding(f)}
                className="flex items-center space-x-1 bg-cyber-600/20 text-cyber-300 hover:bg-cyber-600 hover:text-white px-3 py-1.5 rounded-lg font-semibold transition border border-cyber-500/30 text-[11px]"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Task</span>
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
