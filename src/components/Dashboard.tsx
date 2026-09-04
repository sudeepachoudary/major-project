import React from 'react';
import { Target, Scan, Finding } from '../types';
import { Target as TargetIcon, ShieldCheck, Activity, CheckCircle2, AlertTriangle, ShieldAlert, TrendingUp, Clock, Play, Terminal, Cpu } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

interface DashboardProps {
  targets: Target[];
  scans: Scan[];
  findings: Finding[];
  onNavigate: (tab: string) => void;
  onSelectScanForProgress: (scanId: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  targets,
  scans,
  findings,
  onNavigate,
  onSelectScanForProgress
}) => {
  const totalTargets = targets.length;
  const authorizedTargets = targets.filter(t => t.status === 'Authorized').length;
  const scansRunning = scans.filter(s => s.status === 'running' || s.status === 'validating').length;
  const completedScans = scans.filter(s => s.status === 'completed').length;

  // Deduplicate findings by targetId + name
  const deduplicatedMap = new Map<string, Finding>();
  findings.forEach(f => {
    const key = `${f.targetId}_${f.name}`;
    if (!deduplicatedMap.has(key)) {
      deduplicatedMap.set(key, f);
    }
  });
  const cleanFindings = Array.from(deduplicatedMap.values());

  const criticalFindings = cleanFindings.filter(f => f.severity === 'CRITICAL').length;
  const highFindings = cleanFindings.filter(f => f.severity === 'HIGH').length;
  const mediumFindings = cleanFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowFindings = cleanFindings.filter(f => f.severity === 'LOW').length;

  // Aggregate security score average
  const scores = scans.filter(s => s.securityScore).map(s => s.securityScore);
  const avgSecurityScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 88;

  // Chart data for vulnerability trend over scans
  const trendData = [
    { name: 'Aug 11', Critical: 1, High: 2, Medium: 3, Low: 4 },
    { name: 'Aug 12', Critical: 1, High: 3, Medium: 2, Low: 5 },
    { name: 'Aug 13', Critical: 0, High: 2, Medium: 4, Low: 3 },
    { name: 'Aug 14', Critical: 2, High: 1, Medium: 3, Low: 6 },
    { name: 'Aug 15', Critical: 1, High: 2, Medium: 4, Low: 2 },
    { name: 'Aug 16', Critical: criticalFindings, High: highFindings, Medium: mediumFindings, Low: lowFindings },
  ];

  const severityBarData = [
    { severity: 'Critical', count: criticalFindings, color: '#ef4444' },
    { severity: 'High', count: highFindings, color: '#f97316' },
    { severity: 'Medium', count: mediumFindings, color: '#eab308' },
    { severity: 'Low', count: lowFindings, color: '#3b82f6' },
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* SOC Command Header */}
      <div className="bg-[#0b1224] border border-cyan-900/40 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
        
        <div className="space-y-1 z-10">
          <div className="flex items-center space-x-2.5">
            <Cpu className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Operations Command Center</h1>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Real-time authorized target governance, multi-stage scanner orchestration, and threat analysis.
          </p>
        </div>

        {/* Security Health Rating Gauge Callout */}
        <div className="z-10 bg-[#070c18] border border-cyan-500/30 p-4 rounded-xl flex items-center space-x-4 shadow-lg glow-cyan">
          <div className="relative flex items-center justify-center">
            <svg className="w-16 h-16 transform -rotate-90">
              <circle cx="32" cy="32" r="26" stroke="currentColor" strokeWidth="6" className="text-slate-800" fill="transparent" />
              <circle
                cx="32"
                cy="32"
                r="26"
                stroke="currentColor"
                strokeWidth="6"
                strokeDasharray={163}
                strokeDashoffset={163 - (163 * avgSecurityScore) / 100}
                className="text-cyan-400 transition-all duration-1000"
                strokeLinecap="round"
                fill="transparent"
              />
            </svg>
            <span className="absolute font-mono font-bold text-white text-base">{avgSecurityScore}</span>
          </div>

          <div>
            <span className="text-[10px] uppercase tracking-wider font-mono font-bold text-cyan-400 block">Posture Index</span>
            <span className="text-sm font-bold text-white">Overall Security Score</span>
            <span className="text-[11px] text-emerald-400 block font-mono font-semibold">Protected & Authorized</span>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="bg-[#0b1224] border border-cyan-900/40 rounded-xl p-4 shadow-lg hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Total Targets</span>
            <TargetIcon className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-white font-mono">{totalTargets}</span>
            <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
              {authorizedTargets} Authorized
            </span>
          </div>
        </div>

        <div className="bg-[#0b1224] border border-cyan-900/40 rounded-xl p-4 shadow-lg hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Active Scans</span>
            <Activity className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-white font-mono">{scansRunning}</span>
            <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
              {completedScans} Completed
            </span>
          </div>
        </div>

        <div className="bg-[#0b1224] border border-cyan-900/40 rounded-xl p-4 shadow-lg hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Critical Findings</span>
            <ShieldAlert className="w-5 h-5 text-red-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-red-400 font-mono">{criticalFindings}</span>
            <span className="text-xs font-mono font-bold text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded border border-orange-500/30">
              {highFindings} High
            </span>
          </div>
        </div>

        <div className="bg-[#0b1224] border border-cyan-900/40 rounded-xl p-4 shadow-lg hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Medium / Low</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-extrabold text-amber-400 font-mono">{mediumFindings}</span>
            <span className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/30">
              {lowFindings} Low
            </span>
          </div>
        </div>

      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Vulnerability Trend Chart */}
        <div className="lg:col-span-2 bg-[#0b1224] border border-cyan-900/40 rounded-2xl p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-white font-sans">Security Assessment Finding Trends</h2>
            </div>
            <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">Last 6 Runs</span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="criticalGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <Tooltip contentStyle={{ backgroundColor: '#070c18', borderColor: '#06b6d4', fontSize: '11px', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="Critical" stroke="#ef4444" fillOpacity={1} fill="url(#criticalGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="High" stroke="#f97316" fillOpacity={1} fill="url(#highGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-[#0b1224] border border-cyan-900/40 rounded-2xl p-5 shadow-xl space-y-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white font-sans">Active Severity Distribution</h2>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="severity" stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" />
                <Tooltip contentStyle={{ backgroundColor: '#070c18', borderColor: '#06b6d4', fontSize: '11px', borderRadius: '8px' }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {severityBarData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      {/* Target Quick Access Table */}
      <div className="bg-[#0b1224] border border-cyan-900/40 rounded-2xl p-5 shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white font-sans">Authorized Security Target Scope</h2>
          </div>

          <button
            onClick={() => onNavigate('targets')}
            className="text-xs font-mono font-bold text-cyan-400 hover:text-cyan-300 transition"
          >
            Manage Targets ({targets.length}) →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#070c18] border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-4">Target Name</th>
                <th className="py-2.5 px-4">Target URL / Host</th>
                <th className="py-2.5 px-4">Environment</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">RoE Document ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {targets.map((t) => (
                <tr key={t.id} className="hover:bg-slate-900/60 transition">
                  <td className="py-3 px-4 font-bold text-white">{t.name}</td>
                  <td className="py-3 px-4 text-cyan-400 truncate max-w-xs">{t.url}</td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/30 font-semibold">
                      {t.environment}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold">
                      {t.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-slate-400">{t.roeId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
