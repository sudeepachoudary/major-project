import React, { useState } from 'react';
import { TargetType } from '../types';
import { X, ShieldCheck, AlertCircle, FileText, CheckSquare, Square } from 'lucide-react';

interface AddTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddTarget: (targetData: {
    name: string;
    url: string;
    type: TargetType;
    environment: 'LAB' | 'DEVELOPMENT' | 'ENTERPRISE';
    roeId: string;
    scope: string;
    notes?: string;
    authConfirmed: boolean;
  }) => void;
}

export const AddTargetModal: React.FC<AddTargetModalProps> = ({
  isOpen,
  onClose,
  onAddTarget
}) => {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [type, setType] = useState<TargetType>('Web App');
  const [environment, setEnvironment] = useState<'LAB' | 'DEVELOPMENT' | 'ENTERPRISE'>('LAB');
  const [roeId, setRoeId] = useState(`AUTH-2026-${Math.floor(1000 + Math.random() * 9000)}`);
  const [scope, setScope] = useState('Single Host / Domain');
  const [notes, setNotes] = useState('');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !url || !roeId || !scope) {
      setError('Please complete all required fields.');
      return;
    }

    if (!authConfirmed) {
      setError('You must explicitly confirm legal authorization before adding this target.');
      return;
    }

    onAddTarget({
      name,
      url,
      type,
      environment,
      roeId,
      scope,
      notes,
      authConfirmed: true
    });

    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center text-cyber-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Add Authorized Target</h2>
              <p className="text-xs text-slate-400">Define target boundary and link RoE authorization document</p>
            </div>
          </div>

          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center space-x-2 text-red-400 text-xs">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-4 space-y-4 text-xs">
          
          {/* Target Name & Type */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1">Target Name *</label>
              <input
                type="text"
                placeholder="e.g. Staging Auth Server"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyber-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Target Type *</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value as TargetType)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyber-500"
              >
                <option value="Web App">Web Application</option>
                <option value="API Endpoint">API Endpoint</option>
                <option value="Network Host">Network Host</option>
                <option value="Cloud Endpoint">Cloud Endpoint</option>
              </select>
            </div>
          </div>

          {/* URL / Host */}
          <div>
            <label className="block text-slate-300 font-medium mb-1">Target URL / Host Address *</label>
            <input
              type="url"
              placeholder="http://localhost:3000 or https://target-app.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
              required
            />
          </div>

          {/* RoE ID & Scope */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-medium mb-1 flex items-center gap-1">
                <FileText className="w-3.5 h-3.5 text-cyber-400" />
                <span>RoE Document ID *</span>
              </label>
              <input
                type="text"
                value={roeId}
                onChange={(e) => setRoeId(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyber-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">Scope Limit *</label>
              <input
                type="text"
                placeholder="e.g. Single Domain, Subdomains Only"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyber-500"
                required
              />
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="block text-slate-300 font-medium mb-1">Testing Authorization Notes (Optional)</label>
            <textarea
              rows={2}
              placeholder="e.g. Security assessment authorized by SecOps lab manager for demo labs."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyber-500"
            />
          </div>

          {/* Legal Authorization Mandatory Checkbox */}
          <div className="p-3.5 bg-cyber-950/80 border border-cyber-500/40 rounded-xl">
            <button
              type="button"
              onClick={() => setAuthConfirmed(!authConfirmed)}
              className="flex items-start space-x-3 text-left focus:outline-none group"
            >
              {authConfirmed ? (
                <CheckSquare className="w-5 h-5 text-cyber-400 fill-cyber-950 flex-shrink-0 mt-0.5" />
              ) : (
                <Square className="w-5 h-5 text-slate-500 group-hover:text-slate-300 flex-shrink-0 mt-0.5" />
              )}
              <span className="text-[11px] text-slate-200 leading-relaxed font-medium">
                I hereby certify and warrant that I have explicit written authorization to perform security testing against this target under the specified Rules of Engagement (RoE).
              </span>
            </button>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl font-medium"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={!authConfirmed}
              className={`px-5 py-2 rounded-xl font-semibold text-white shadow-lg transition ${
                authConfirmed
                  ? 'bg-gradient-to-r from-cyber-600 to-indigo-600 hover:from-cyber-500 hover:to-indigo-500 shadow-cyber-600/30'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-750'
              }`}
            >
              Add Authorized Target
            </button>
          </div>

        </form>
      </div>
    </div>
  );
};
