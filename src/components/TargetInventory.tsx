import React from 'react';
import { Target } from '../types';
import { Plus, ShieldCheck, Play, Globe, Server, Cpu, Trash2, ExternalLink, CheckSquare, Square, Info } from 'lucide-react';

interface TargetInventoryProps {
  targets: Target[];
  selectedTargetIds: string[];
  onToggleTargetSelect: (id: string) => void;
  onOpenAddModal: () => void;
  onOpenScanConfigModal: () => void;
  onDeleteTarget: (id: string) => void;
}

export const TargetInventory: React.FC<TargetInventoryProps> = ({
  targets,
  selectedTargetIds,
  onToggleTargetSelect,
  onOpenAddModal,
  onOpenScanConfigModal,
  onDeleteTarget
}) => {
  const selectedCount = selectedTargetIds.length;

  return (
    <div className="space-y-6">
      
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-850 p-5 rounded-2xl border border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-white font-sans">Target Inventory & Scope Controls</h1>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyber-500/20 text-cyber-300 border border-cyber-500/30 rounded-full">
              {targets.length} Total Targets
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Manage authorized targets and define Rules of Engagement (RoE) boundaries. Each target selection state is isolated.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={onOpenAddModal}
            className="flex items-center space-x-2 bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-semibold px-4 py-2.5 rounded-xl border border-slate-700 transition"
          >
            <Plus className="w-4 h-4 text-cyber-400" />
            <span>Add New Target</span>
          </button>

          <button
            onClick={onOpenScanConfigModal}
            disabled={selectedCount === 0}
            className={`flex items-center space-x-2 text-xs font-semibold px-4 py-2.5 rounded-xl shadow-lg transition active:scale-95 ${
              selectedCount > 0
                ? 'bg-gradient-to-r from-cyber-600 to-indigo-600 hover:from-cyber-500 hover:to-indigo-500 text-white shadow-cyber-600/30 cursor-pointer'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-750'
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Configure & Scan ({selectedCount} Selected)</span>
          </button>
        </div>
      </div>

      {/* Target Isolation Notice */}
      <div className="bg-cyber-950/60 border border-cyber-500/30 rounded-xl p-4 flex items-start space-x-3">
        <Info className="w-5 h-5 text-cyber-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300">
          <span className="font-semibold text-cyber-300">Independent Target Isolation Enforced:</span> Toggling checkboxes modifies only that target's explicit ID (`selectedTargetIds`). Unselected targets are never included in scan payloads. Backend validation re-verifies every selected ID before execution.
        </div>
      </div>

      {/* Targets Cards / Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets.map((target) => {
          const isSelected = selectedTargetIds.includes(target.id);
          
          return (
            <div
              key={target.id}
              className={`relative bg-slate-850 rounded-2xl border transition-all duration-200 p-5 flex flex-col justify-between ${
                isSelected
                  ? 'border-cyber-500 ring-2 ring-cyber-500/30 bg-slate-850/90 shadow-xl shadow-cyber-500/10'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              {/* Top Row: Checkbox & Type Badge */}
              <div>
                <div className="flex items-start justify-between">
                  
                  {/* Independent Target Checkbox */}
                  <button
                    type="button"
                    onClick={() => onToggleTargetSelect(target.id)}
                    className="flex items-center space-x-2 text-left group focus:outline-none"
                  >
                    {isSelected ? (
                      <CheckSquare className="w-5 h-5 text-cyber-400 fill-cyber-950 flex-shrink-0 transition-transform group-hover:scale-110" />
                    ) : (
                      <Square className="w-5 h-5 text-slate-600 group-hover:text-slate-400 flex-shrink-0 transition-transform group-hover:scale-110" />
                    )}
                    <span className="text-xs font-mono font-semibold text-slate-400 group-hover:text-slate-200">
                      ID: {target.id}
                    </span>
                  </button>

                  <div className="flex items-center space-x-1.5">
                    {target.environment === 'LAB' && (
                      <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                        AUTHORIZED LAB
                      </span>
                    )}
                    <span className="px-2.5 py-0.5 text-[11px] font-mono font-medium rounded-full bg-slate-800 text-cyber-300 border border-slate-700 flex items-center gap-1">
                      {target.type === 'Web App' && <Globe className="w-3 h-3 text-cyber-400" />}
                      {target.type === 'API Endpoint' && <Server className="w-3 h-3 text-indigo-400" />}
                      {target.type === 'Network Host' && <Cpu className="w-3 h-3 text-emerald-400" />}
                      {target.type}
                    </span>
                  </div>
                </div>

                {/* Target Name & URL */}
                <div className="mt-4">
                  <h3 className="text-base font-bold text-white group-hover:text-cyber-300 transition">
                    {target.name}
                  </h3>
                  <a
                    href={target.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center space-x-1 text-xs font-mono text-cyber-400 hover:underline mt-1"
                  >
                    <span className="truncate max-w-[220px]">{target.url}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                {/* RoE Details & Authorization */}
                <div className="mt-4 pt-3 border-t border-slate-800 space-y-2 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Authorization Status:</span>
                    <span className="inline-flex items-center space-x-1 font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      <ShieldCheck className="w-3 h-3" />
                      <span>{target.status}</span>
                    </span>
                  </div>

                  <div className="flex justify-between items-center font-mono">
                    <span className="text-slate-400 font-sans">RoE Document ID:</span>
                    <span className="text-slate-200 bg-slate-800 px-2 py-0.5 rounded border border-slate-750">
                      {target.roeId}
                    </span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Allowed Scope:</span>
                    <span className="text-slate-300 font-medium">{target.scope}</span>
                  </div>
                </div>

                {target.notes && (
                  <p className="text-[11px] text-slate-400 italic mt-3 bg-slate-900/60 p-2 rounded border border-slate-800">
                    "{target.notes}"
                  </p>
                )}
              </div>

              {/* Bottom Actions */}
              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] text-slate-500 font-mono">
                  {target.lastScanDate ? `Last Scan: ${target.lastScanDate}` : 'Never Scanned'}
                </span>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => onDeleteTarget(target.id)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition"
                    title="Remove Target"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>

                  <button
                    onClick={() => {
                      if (!isSelected) onToggleTargetSelect(target.id);
                      onOpenScanConfigModal();
                    }}
                    className="flex items-center space-x-1 bg-cyber-600/20 text-cyber-300 hover:bg-cyber-600 hover:text-white px-3 py-1.5 rounded-lg text-xs font-medium transition border border-cyber-500/30"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Scan Target</span>
                  </button>
                </div>
              </div>

            </div>
          );
        })}
      </div>

    </div>
  );
};
