import React, { useState } from 'react';
import { DiscoveredEndpoint, Target } from '../types';
import { Compass, Globe, Server, Code, Search, ShieldCheck, ShieldAlert } from 'lucide-react';

interface ReconnaissanceViewProps {
  endpoints: DiscoveredEndpoint[];
  targets: Target[];
}

export const ReconnaissanceView: React.FC<ReconnaissanceViewProps> = ({ endpoints, targets }) => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredEndpoints = endpoints.filter((e) => {
    const matchesTarget = selectedTargetId === 'ALL' || e.targetId === selectedTargetId;
    const matchesQuery = e.url.toLowerCase().includes(searchQuery.toLowerCase()) || e.method.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesTarget && matchesQuery;
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <Compass className="w-6 h-6 text-cyber-400" />
            <h1 className="text-xl font-bold text-white font-sans">Endpoint Reconnaissance & Route Explorer</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {endpoints.length} Discovered Endpoints
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated route discovery via HTML links, robots.txt, sitemap parsing, and OpenAPI documentation discovery.
          </p>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-850 p-4 rounded-xl border border-slate-800 text-xs">
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <label className="text-slate-400 font-medium">Filter Target:</label>
          <select
            value={selectedTargetId}
            onChange={(e) => setSelectedTargetId(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-white rounded-lg px-3 py-1.5 font-mono focus:outline-none focus:border-cyber-500"
          >
            <option value="ALL">All Authorized Targets ({targets.length})</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search discovered routes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 text-white rounded-lg pl-9 pr-3 py-1.5 font-mono focus:outline-none focus:border-cyber-500"
          />
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl shadow-xl overflow-hidden text-xs font-mono">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">HTTP Method</th>
                <th className="py-3 px-4">Discovered Endpoint URL</th>
                <th className="py-3 px-4">Discovery Source</th>
                <th className="py-3 px-4">Auth Requirement</th>
                <th className="py-3 px-4">Risk Weight</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredEndpoints.length > 0 ? (
                filteredEndpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        ep.method === 'GET' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                        ep.method === 'POST' ? 'bg-cyber-500/10 text-cyber-300 border-cyber-500/30' :
                        'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {ep.method}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-white font-semibold truncate max-w-md">
                      {ep.url}
                    </td>

                    <td className="py-3 px-4 text-slate-300">
                      <span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-750 text-[10px]">
                        {ep.source}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      {ep.authenticated ? (
                        <span className="text-amber-400 flex items-center gap-1 font-sans">
                          <ShieldAlert className="w-3 h-3" /> Auth Required
                        </span>
                      ) : (
                        <span className="text-emerald-400 flex items-center gap-1 font-sans">
                          <ShieldCheck className="w-3 h-3" /> Public Endpoint
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 font-bold text-amber-400">
                      Score: {ep.riskScore}/5
                    </td>

                    <td className="py-3 px-4 text-slate-500">
                      {ep.discoveredAt.split('T')[0]}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No discovered endpoints matched the active filter criteria. Run an authorized scan to populate routes.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
