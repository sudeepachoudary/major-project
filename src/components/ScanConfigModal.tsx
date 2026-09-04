import React, { useState } from 'react';
import { Target, ScanProfile } from '../types';
import { X, Play, ShieldAlert, Zap, Radio, Search, CheckSquare, Square, Info } from 'lucide-react';

interface ScanConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedTargets: Target[];
  onLaunchScan: (config: {
    targetIds: string[];
    scanProfile: ScanProfile;
    safeMode: boolean;
    rateLimit: number;
    timeout: number;
    optInPathDiscovery: boolean;
  }) => void;
}

export const ScanConfigModal: React.FC<ScanConfigModalProps> = ({
  isOpen,
  onClose,
  selectedTargets,
  onLaunchScan
}) => {
  const [profile, setProfile] = useState<ScanProfile>('standard');
  const [safeMode, setSafeMode] = useState(true);
  const [rateLimit, setRateLimit] = useState(10);
  const [timeout, setTimeoutVal] = useState(30);
  const [optInPathDiscovery, setOptInPathDiscovery] = useState(false);
  const [showPreFlight, setShowPreFlight] = useState(false);

  if (!isOpen) return null;

  const profiles: { id: ScanProfile; title: string; desc: string; icon: any }[] = [
    {
      id: 'quick',
      title: 'Quick Scan',
      desc: 'HTTP Security Headers, SSL/TLS certificate configuration, technology fingerprinting.',
      icon: Zap
    },
    {
      id: 'standard',
      title: 'Standard Security Assessment',
      desc: 'Quick Scan + CORS policies, Session Cookie flags, OWASP header compliance.',
      icon: ShieldAlert
    },
    {
      id: 'port_service',
      title: 'Port & Service Assessment (Explicit)',
      desc: 'Probes common network web service ports (80, 443, 8080, 8443, 3000) for reachability.',
      icon: Radio
    },
    {
      id: 'comprehensive',
      title: 'Comprehensive Assessment',
      desc: 'Standard + Port Discovery + Opt-in sensitive path exposures (.git, robots.txt).',
      icon: Search
    }
  ];

  const handleStartClick = () => {
    setShowPreFlight(true);
  };

  const handleConfirmLaunch = () => {
    onLaunchScan({
      targetIds: selectedTargets.map(t => t.id),
      scanProfile: profile,
      safeMode,
      rateLimit,
      timeout,
      optInPathDiscovery
    });
    setShowPreFlight(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-bold text-white">Scan Configuration & Scope Guard</h2>
            <p className="text-xs text-slate-400">Configure profile options before launching authorized scan</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {!showPreFlight ? (
          /* Step 1: Configuration Form */
          <div className="mt-4 space-y-5 text-xs">
            
            {/* Selected Targets List Display */}
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Selected Targets ({selectedTargets.length}):
              </label>
              <div className="bg-slate-850 p-3 rounded-xl border border-slate-800 space-y-1.5 max-h-32 overflow-y-auto">
                {selectedTargets.map((t) => (
                  <div key={t.id} className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-white font-semibold">{t.name}</span>
                    <span className="text-slate-400">{t.url}</span>
                    <span className="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      {t.roeId}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan Profile Selection */}
            <div>
              <label className="block text-slate-300 font-semibold mb-2">Select Scan Profile *</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {profiles.map((p) => {
                  const Icon = p.icon;
                  const isSelected = profile === p.id;
                  return (
                    <div
                      key={p.id}
                      onClick={() => setProfile(p.id)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition ${
                        isSelected
                          ? 'bg-cyber-950/80 border-cyber-500 text-white ring-1 ring-cyber-500/40'
                          : 'bg-slate-850 border-slate-800 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center space-x-2 mb-1">
                        <Icon className={`w-4 h-4 ${isSelected ? 'text-cyber-400' : 'text-slate-400'}`} />
                        <span className="font-bold">{p.title}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-relaxed">{p.desc}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Advanced Checkboxes */}
            <div className="space-y-2 bg-slate-850 p-3.5 rounded-xl border border-slate-800">
              
              {/* Safe Non-destructive Mode */}
              <button
                type="button"
                onClick={() => setSafeMode(!safeMode)}
                className="flex items-center space-x-2 text-left focus:outline-none w-full"
              >
                {safeMode ? (
                  <CheckSquare className="w-4 h-4 text-cyber-400 fill-cyber-950 flex-shrink-0" />
                ) : (
                  <Square className="w-4 h-4 text-slate-500 flex-shrink-0" />
                )}
                <span className="text-slate-200 font-medium">Safe / Non-destructive Testing Mode (Enforced)</span>
              </button>

              {/* Opt-In Path Discovery */}
              <button
                type="button"
                onClick={() => setOptInPathDiscovery(!optInPathDiscovery)}
                className="flex items-center space-x-2 text-left focus:outline-none w-full"
              >
                {optInPathDiscovery ? (
                  <CheckSquare className="w-4 h-4 text-cyber-400 fill-cyber-950 flex-shrink-0" />
                ) : (
                  <Square className="w-4 h-4 text-slate-500 flex-shrink-0" />
                )}
                <span className="text-slate-200 font-medium">Opt-In Sensitive Path Exposure Probes (.git, robots.txt)</span>
              </button>
            </div>

            {/* Footer Buttons */}
            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl font-medium"
              >
                Cancel
              </button>

              <button
                onClick={handleStartClick}
                className="flex items-center space-x-2 px-5 py-2 rounded-xl font-semibold text-white bg-gradient-to-r from-cyber-600 to-indigo-600 hover:from-cyber-500 hover:to-indigo-500 shadow-lg shadow-cyber-600/30"
              >
                <span>Proceed to Pre-Flight Check →</span>
              </button>
            </div>
          </div>
        ) : (
          /* Step 2: Pre-Flight Confirmation Modal */
          <div className="mt-4 space-y-4 text-xs animate-fadeIn">
            
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start space-x-3 text-amber-300">
              <Info className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-amber-200">Pre-Flight Authorized Scope Confirmation</h4>
                <p className="text-[11px] text-amber-300/90 mt-0.5">
                  Confirm active scan configuration before backend scope validation locks the scan record.
                </p>
              </div>
            </div>

            <div className="bg-slate-850 p-4 rounded-xl border border-slate-800 space-y-2">
              <div className="flex justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400">Selected Targets Count:</span>
                <span className="font-mono font-bold text-white">{selectedTargets.length} Host(s)</span>
              </div>

              <div className="flex justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400">Target Names:</span>
                <span className="font-semibold text-cyber-300">{selectedTargets.map(t => t.name).join(', ')}</span>
              </div>

              <div className="flex justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400">Linked RoE Document:</span>
                <span className="font-mono text-emerald-400">{selectedTargets[0]?.roeId || 'AUTH-VERIFIED'}</span>
              </div>

              <div className="flex justify-between border-b border-slate-800 pb-2">
                <span className="text-slate-400">Chosen Scan Profile:</span>
                <span className="font-mono font-bold text-indigo-400 uppercase">{profile}</span>
              </div>

              <div className="flex justify-between">
                <span className="text-slate-400">Execution Engine:</span>
                <span className="text-emerald-400 font-semibold">Rate-Limited Safe Engine</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <button
                onClick={() => setShowPreFlight(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl font-medium"
              >
                ← Back to Edit
              </button>

              <button
                onClick={handleConfirmLaunch}
                className="flex items-center space-x-2 px-6 py-2.5 rounded-xl font-bold text-white bg-gradient-to-r from-emerald-600 to-cyber-600 hover:from-emerald-500 hover:to-cyber-500 shadow-xl shadow-emerald-600/30 transition active:scale-95"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Start Authorized Scan</span>
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
