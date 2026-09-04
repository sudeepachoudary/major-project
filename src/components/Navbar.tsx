import React from 'react';
import { Shield, ShieldAlert, Target, Play, History, ScrollText, Wrench, Compass, CheckSquare, Server, Terminal } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  demoMode: boolean;
  setDemoMode: (val: boolean) => void;
  scansRunningCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  demoMode,
  setDemoMode,
  scansRunningCount
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'targets', label: 'Target Inventory', icon: Target },
    { id: 'recon', label: 'Endpoint Recon', icon: Compass },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'remediation', label: 'Remediation Center', icon: CheckSquare },
    { id: 'tools', label: 'Tool Adapters', icon: Wrench },
    { id: 'history', label: 'History & Compare', icon: History },
    { id: 'audit', label: 'Audit Logs', icon: ScrollText },
  ];

  return (
    <header className="bg-[#0a101d] border-b border-slate-800/90 sticky top-0 z-40 shadow-md">
      <div className="max-w-[1536px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Logo | SOC Version */}
          <div className="flex items-center space-x-3 flex-shrink-0 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-600 flex items-center justify-center shadow-sm border border-blue-400/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold tracking-tight text-white font-sans">
                Aegis<span className="text-blue-400">Scan</span>
              </span>
              <span className="px-2 py-0.5 text-[10px] font-mono font-semibold bg-blue-500/10 text-blue-300 border border-blue-500/25 rounded">
                SOC v2.4
              </span>
            </div>
          </div>

          {/* Main Navigation Bar */}
          <nav className="hidden xl:flex items-center space-x-1.5 overflow-x-auto py-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all duration-150 ${
                    isActive
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm'
                      : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right-side Controls (Lab Mode + Launch Assessment Button) */}
          <div className="flex items-center space-x-3 flex-shrink-0 pl-3 border-l border-slate-800/80">
            
            {/* Active Scan Indicator */}
            {scansRunningCount > 0 && (
              <div className="flex items-center space-x-2 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono font-medium">
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
                <span className="hidden sm:inline">{scansRunningCount} Running</span>
              </div>
            )}

            {/* Lab Mode Toggle */}
            <div className="flex items-center space-x-2 bg-[#0e172a] px-2.5 py-1 rounded-lg border border-slate-800">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span className="text-xs text-slate-300 font-medium hidden sm:inline">Lab Mode</span>
              <button
                onClick={() => setDemoMode(!demoMode)}
                className={`relative inline-flex h-4.5 w-8 flex-shrink-0 cursor-pointer rounded-full border-1 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  demoMode ? 'bg-blue-600' : 'bg-slate-700'
                }`}
                role="switch"
                aria-checked={demoMode}
              >
                <span
                  className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
                    demoMode ? 'translate-x-3.5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Launch Assessment Button */}
            <button
              onClick={() => setActiveTab('targets')}
              className="flex items-center space-x-2 bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold px-3.5 py-2 rounded-lg shadow-sm border border-blue-400/25 transition-all active:scale-95 whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Launch Assessment</span>
            </button>
          </div>

        </div>
      </div>
    </header>
  );
};
