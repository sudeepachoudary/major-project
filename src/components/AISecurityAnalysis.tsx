import React, { useState, useEffect } from 'react';
import { AISecuritySummary, Finding } from '../types';
import { Sparkles, Brain, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw, X } from 'lucide-react';

interface AISecurityAnalysisProps {
  isOpen: boolean;
  onClose: () => void;
  scanId: string;
  findings: Finding[];
}

export const AISecurityAnalysisModal: React.FC<AISecurityAnalysisProps> = ({
  isOpen,
  onClose,
  scanId,
  findings
}) => {
  const [summary, setSummary] = useState<AISecuritySummary | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen && scanId) {
      fetchAISummary();
    }
  }, [isOpen, scanId]);

  const fetchAISummary = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/ai-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId })
      });
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (err) {
      console.error('Failed to fetch AI analysis:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto space-y-5 text-xs">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-cyber-500 flex items-center justify-center text-white shadow-lg shadow-indigo-500/30">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-white">AI Executive Security Synthesis</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-full">
                  Gemini LLM Powered
                </span>
              </div>
              <p className="text-xs text-slate-400">Scan ID: {scanId}</p>
            </div>
          </div>

          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading ? (
          <div className="py-12 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-cyber-400 animate-spin mx-auto" />
            <p className="text-slate-300 font-semibold">Synthesizing Vulnerability Findings & Risk Correlation...</p>
            <p className="text-slate-500 text-[11px]">Evaluating business risk, CVSS metrics, and developer remediation plan.</p>
          </div>
        ) : summary ? (
          <div className="space-y-4">
            
            {/* Risk Rating Banner */}
            <div className="bg-gradient-to-r from-slate-850 to-slate-900 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-[11px] block uppercase font-mono">Overall Risk Rating</span>
                <span className="text-lg font-extrabold text-amber-400 font-mono">{summary.overallRiskRating} RISK</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">Generated: {summary.generatedAt.split('T')[0]}</span>
            </div>

            {/* Executive Summary */}
            <div>
              <h3 className="font-bold text-white mb-1.5 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-cyber-400" />
                Executive Summary
              </h3>
              <p className="text-slate-300 leading-relaxed bg-slate-850 p-3.5 rounded-xl border border-slate-800">
                {summary.executiveSummary}
              </p>
            </div>

            {/* Business Impact */}
            <div>
              <h3 className="font-bold text-amber-300 mb-1.5 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Business Impact Analysis
              </h3>
              <p className="text-amber-200/90 leading-relaxed bg-amber-500/10 p-3.5 rounded-xl border border-amber-500/20">
                {summary.businessImpact}
              </p>
            </div>

            {/* Technical Root Cause */}
            <div>
              <h3 className="font-bold text-slate-200 mb-1.5">Technical Root Cause Correlation</h3>
              <p className="text-slate-300 leading-relaxed bg-slate-850 p-3.5 rounded-xl border border-slate-800">
                {summary.technicalRootCause}
              </p>
            </div>

            {/* Prioritized Remediation Roadmap */}
            <div>
              <h3 className="font-bold text-emerald-300 mb-1.5 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Prioritized Remediation Roadmap
              </h3>
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3.5 space-y-2">
                {summary.prioritizedRemediation.map((item, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-emerald-200/90 leading-relaxed">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        ) : (
          <p className="text-slate-400 text-center py-6">Failed to load AI Security Analysis.</p>
        )}

      </div>
    </div>
  );
};
