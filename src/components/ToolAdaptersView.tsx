import React, { useState } from 'react';
import { SecurityToolStatus } from '../types';
import { Wrench, CheckCircle2, XCircle, Upload, ShieldCheck, FileText } from 'lucide-react';

interface ToolAdaptersViewProps {
  tools: SecurityToolStatus[];
  onImportSuccess: () => void;
}

export const ToolAdaptersView: React.FC<ToolAdaptersViewProps> = ({ tools, onImportSuccess }) => {
  const [importTool, setImportTool] = useState('OWASP ZAP Adapter');
  const [targetId, setTargetId] = useState('target_123');
  const [jsonInput, setJsonInput] = useState('');
  const [importStatus, setImportStatus] = useState<string | null>(null);

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let parsed = [];
      if (jsonInput.trim()) {
        parsed = JSON.parse(jsonInput);
      } else {
        // Fallback sample import payload
        parsed = [
          {
            title: 'Unencrypted Password Transmission Indicator',
            severity: 'HIGH',
            cvssScore: 7.4,
            cweId: 'CWE-319',
            description: 'Authentication form submits credentials over HTTP without TLS enforcement.',
            evidence: 'POST /api/login HTTP/1.1 (Unencrypted transmission)',
            remediation: 'Enforce HTTPS for all authentication and form submission endpoints.'
          }
        ];
      }

      const res = await fetch('/api/import-results', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetId,
          sourceTool: importTool,
          findingsData: Array.isArray(parsed) ? parsed : [parsed]
        })
      });

      if (res.ok) {
        const data = await res.json();
        setImportStatus(`Successfully imported ${data.count} finding(s) into vulnerability store.`);
        setJsonInput('');
        onImportSuccess();
      } else {
        const err = await res.json();
        setImportStatus(`Import Error: ${err.error}`);
      }
    } catch (err: any) {
      setImportStatus(`JSON Parsing Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <Wrench className="w-6 h-6 text-cyber-400" />
            <h1 className="text-xl font-bold text-white font-sans">Security Tool Adapters & Result Ingestion</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {tools.length} Registered Adapters
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Pluggable SARIF & JSON result import adapters for enterprise security toolchains (OWASP ZAP, Nmap, WhatWeb).
          </p>
        </div>
      </div>

      {/* Tool Status Table */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <h2 className="text-sm font-bold text-white mb-3">Tool Availability & Configuration Matrix</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          {tools.map((tool) => {
            const isAvailable = tool.status === 'Available' || tool.status === 'Installed';
            return (
              <div
                key={tool.id}
                className={`p-4 rounded-xl border flex flex-col justify-between ${
                  isAvailable
                    ? 'bg-slate-900 border-slate-800 text-slate-200'
                    : 'bg-slate-900/60 border-slate-800/80 text-slate-500'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-white text-sm">{tool.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                      isAvailable
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-500 border-slate-750'
                    }`}>
                      {tool.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{tool.description}</p>
                </div>

                <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                  <span>Category: {tool.category}</span>
                  <span>{tool.version || 'Unconfigured'}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Result Import Adapter Box */}
      <div className="bg-slate-850 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 text-xs">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Upload className="w-4 h-4 text-cyber-400" />
          <h2 className="text-sm font-bold text-white">Manual SARIF / JSON Result Ingestion Adapter</h2>
        </div>

        {importStatus && (
          <div className="p-3 bg-cyber-950 border border-cyber-500/40 rounded-xl text-cyber-300 font-mono">
            {importStatus}
          </div>
        )}

        <form onSubmit={handleImport} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Select Source Tool Adapter *</label>
              <select
                value={importTool}
                onChange={(e) => setImportTool(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
              >
                <option value="OWASP ZAP Adapter">OWASP ZAP Adapter (SARIF/JSON)</option>
                <option value="Nmap Network Adapter">Nmap Network Probe Adapter</option>
                <option value="WhatWeb Tech Adapter">WhatWeb Technology Adapter</option>
                <option value="Generic SARIF Adapter">Generic SARIF Vulnerability Ingest</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Associate Target *</label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
              >
                <option value="target_123">OWASP Juice Shop Sandbox (target_123)</option>
                <option value="target_456">Local Vulnerable Lab App (target_456)</option>
                <option value="target_789">DevSecOps Test Gateway (target_789)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">
              JSON / SARIF Result Payload (Leave blank to import sample validation result)
            </label>
            <textarea
              rows={4}
              placeholder={`[\n  {\n    "title": "SQL Injection Indicator in Search Field",\n    "severity": "HIGH",\n    "cvssScore": 8.1,\n    "evidence": "Internal DB syntax error returned on query"\n  }\n]`}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 text-cyber-300 font-mono text-[11px] focus:outline-none focus:border-cyber-500"
            />
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              className="flex items-center space-x-2 bg-gradient-to-r from-cyber-600 to-indigo-600 hover:from-cyber-500 hover:to-indigo-500 text-white font-semibold px-5 py-2.5 rounded-xl shadow-lg transition"
            >
              <Upload className="w-4 h-4" />
              <span>Import Assessment Results</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
