import fs from 'fs';
import path from 'path';
import { Target, Scan, Finding, AuditLog, AISecuritySummary, DiscoveredEndpoint, SecurityToolStatus, RemediationTask } from '../../../src/types/index';

const DATA_DIR = path.join(process.cwd(), 'data_store');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const TARGETS_FILE = path.join(DATA_DIR, 'targets.json');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');
const FINDINGS_FILE = path.join(DATA_DIR, 'findings.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit_logs.json');
const AI_FILE = path.join(DATA_DIR, 'ai_summaries.json');

// Initial seed data for security lab targets
const INITIAL_TARGETS: Target[] = [
  {
    id: 'target_123',
    name: 'OWASP Juice Shop Sandbox',
    url: 'https://juice-shop.herokuapp.com',
    type: 'Web App',
    environment: 'LAB',
    status: 'Authorized',
    roeId: 'AUTH-2026-OWASP-01',
    scope: 'Single Domain & REST API',
    addedDate: '2026-08-10',
    lastScanDate: '2026-08-15',
    notes: 'Authorized sandbox instance for OWASP vulnerability verification labs.',
    authConfirmed: true
  },
  {
    id: 'target_456',
    name: 'Local Vulnerable Lab App',
    url: 'http://localhost:3000',
    type: 'Web App',
    environment: 'LAB',
    status: 'Authorized',
    roeId: 'AUTH-2026-LAB-02',
    scope: 'Localhost Web Application',
    addedDate: '2026-08-12',
    lastScanDate: undefined,
    notes: 'Intentionally vulnerable Node.js/Express lab target running in container.',
    authConfirmed: true
  },
  {
    id: 'target_789',
    name: 'DevSecOps Test Gateway',
    url: 'http://127.0.0.1:8080',
    type: 'API Endpoint',
    environment: 'DEVELOPMENT',
    status: 'Authorized',
    roeId: 'AUTH-2026-DEV-03',
    scope: 'Internal Microservice Gateway',
    addedDate: '2026-08-14',
    lastScanDate: undefined,
    notes: 'Staging API gateway for header compliance and CORS policy checks.',
    authConfirmed: true
  }
];

const INITIAL_TOOLS: SecurityToolStatus[] = [
  { id: 'tool_1', name: 'OWASP ZAP Adapter', category: 'WEB', status: 'Available', version: 'v2.14.0', description: 'SARIF & JSON Result Import Adapter for OWASP ZAP' },
  { id: 'tool_2', name: 'Nmap Network Scanner', category: 'NETWORK', status: 'Available', version: 'v7.94', description: 'Pluggable Port & Service Identification Engine' },
  { id: 'tool_3', name: 'Nuclei Vulnerability Scanner', category: 'WEB', status: 'Not Configured', description: 'Template-based security scanner adapter' },
  { id: 'tool_4', name: 'WhatWeb Tech Finder', category: 'RECON', status: 'Available', version: 'v0.5.5', description: 'Web Technology Fingerprinting Engine' },
  { id: 'tool_5', name: 'Nikto Web Scanner', category: 'WEB', status: 'Not Configured', description: 'Web server security assessment adapter' }
];

const INITIAL_AUDIT_LOGS: AuditLog[] = [
  {
    id: 'audit_001',
    timestamp: new Date(Date.now() - 3600000 * 24).toISOString(),
    user: 'Security Admin (AdminUser)',
    action: 'TARGET_ADDED',
    targetId: 'target_123',
    targetName: 'OWASP Juice Shop Sandbox',
    roeId: 'AUTH-2026-OWASP-01',
    scope: 'Single Domain & REST API',
    result: 'ALLOWED',
    details: 'Target added to authorized inventory with verified RoE document.',
    clientIp: '192.168.1.50'
  },
  {
    id: 'audit_002',
    timestamp: new Date(Date.now() - 3600000 * 12).toISOString(),
    user: 'Security Admin (AdminUser)',
    action: 'SCOPE_VALIDATED',
    targetId: 'target_123',
    targetName: 'OWASP Juice Shop Sandbox',
    roeId: 'AUTH-2026-OWASP-01',
    scope: 'Single Domain & REST API',
    result: 'ALLOWED',
    details: 'Backend pre-flight verification passed for target scope.',
    clientIp: '192.168.1.50'
  }
];

class MemoryStore {
  private targets: Map<string, Target> = new Map();
  private scans: Map<string, Scan> = new Map();
  private findings: Map<string, Finding> = new Map();
  private auditLogs: AuditLog[] = [];
  private aiSummaries: Map<string, AISecuritySummary> = new Map();
  private endpoints: Map<string, DiscoveredEndpoint> = new Map();
  private tools: Map<string, SecurityToolStatus> = new Map();
  private remediations: Map<string, RemediationTask> = new Map();

  constructor() {
    INITIAL_TOOLS.forEach(t => this.tools.set(t.id, t));
    this.loadFromDisk();
  }

  private loadFromDisk() {
    try {
      if (fs.existsSync(TARGETS_FILE)) {
        const data: Target[] = JSON.parse(fs.readFileSync(TARGETS_FILE, 'utf-8'));
        data.forEach(t => this.targets.set(t.id, t));
      } else {
        INITIAL_TARGETS.forEach(t => this.targets.set(t.id, t));
        this.saveTargets();
      }

      if (fs.existsSync(SCANS_FILE)) {
        const data: Scan[] = JSON.parse(fs.readFileSync(SCANS_FILE, 'utf-8'));
        data.forEach(s => this.scans.set(s.id, s));
      }

      if (fs.existsSync(FINDINGS_FILE)) {
        const data: Finding[] = JSON.parse(fs.readFileSync(FINDINGS_FILE, 'utf-8'));
        data.forEach(f => this.deduplicateAndStoreFinding(f));
        this.saveFindings();
      }

      if (fs.existsSync(AUDIT_FILE)) {
        this.auditLogs = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf-8'));
      } else {
        this.auditLogs = [...INITIAL_AUDIT_LOGS];
        this.saveAuditLogs();
      }

      if (fs.existsSync(AI_FILE)) {
        const data: AISecuritySummary[] = JSON.parse(fs.readFileSync(AI_FILE, 'utf-8'));
        data.forEach(ai => this.aiSummaries.set(ai.scanId, ai));
      }
    } catch (err) {
      console.error('Error loading data from disk, using fallback initial data:', err);
      INITIAL_TARGETS.forEach(t => this.targets.set(t.id, t));
      this.auditLogs = [...INITIAL_AUDIT_LOGS];
    }
  }

  private saveTargets() {
    fs.writeFileSync(TARGETS_FILE, JSON.stringify(Array.from(this.targets.values()), null, 2));
  }

  private saveScans() {
    fs.writeFileSync(SCANS_FILE, JSON.stringify(Array.from(this.scans.values()), null, 2));
  }

  private saveFindings() {
    fs.writeFileSync(FINDINGS_FILE, JSON.stringify(Array.from(this.findings.values()), null, 2));
  }

  private saveAuditLogs() {
    fs.writeFileSync(AUDIT_FILE, JSON.stringify(this.auditLogs, null, 2));
  }

  private saveAISummaries() {
    fs.writeFileSync(AI_FILE, JSON.stringify(Array.from(this.aiSummaries.values()), null, 2));
  }

  // Targets
  getTargets(): Target[] {
    return Array.from(this.targets.values());
  }

  getTargetById(id: string): Target | undefined {
    return this.targets.get(id);
  }

  addTarget(target: Target): Target {
    this.targets.set(target.id, target);
    this.saveTargets();
    return target;
  }

  updateTarget(target: Target): Target {
    this.targets.set(target.id, target);
    this.saveTargets();
    return target;
  }

  deleteTarget(id: string): boolean {
    const deleted = this.targets.delete(id);
    if (deleted) this.saveTargets();
    return deleted;
  }

  // Scans
  getScans(): Scan[] {
    return Array.from(this.scans.values()).sort((a, b) => 
      new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }

  getScanById(id: string): Scan | undefined {
    return this.scans.get(id);
  }

  addScan(scan: Scan): Scan {
    this.scans.set(scan.id, scan);
    this.saveScans();
    return scan;
  }

  updateScan(scan: Scan): Scan {
    this.scans.set(scan.id, scan);
    this.saveScans();
    return scan;
  }

  private deduplicateAndStoreFinding(f: Finding) {
    // 1. Convert obsolete Port 443 findings
    if (f.name.includes('Open Port Discovered: 443')) {
      f.name = 'Informational: HTTPS Service Detected on Port 443';
      f.severity = 'INFO';
      f.cvssScore = 0.0;
      f.cweId = undefined;
      f.description = 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.';
      f.simpleExplanation = 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.';
      f.technicalImpact = 'Exposes standard encrypted web service port (443).';
      f.userImpact = 'No direct user impact identified from port 443 exposure alone.';
      f.businessImpact = 'No direct business impact identified from port 443 exposure alone.';
      f.remediation = 'No remediation is required for an HTTPS service on port 443. Keep port 443 available if HTTPS access is required. TLS configuration should be assessed separately.';
      f.beforeState = '✅ Port 443 reachable (HTTPS TLS Web Service)';
      f.afterState = '✅ Expected HTTPS service active on port 443';
    }

    // 2. Target ID + Name Deduplication
    const existingKey = Array.from(this.findings.keys()).find(k => {
      const ex = this.findings.get(k);
      return ex && (ex.id === f.id || (ex.targetId === f.targetId && ex.name === f.name));
    });

    if (existingKey) {
      const existing = this.findings.get(existingKey)!;
      Object.assign(existing, {
        scanId: f.scanId,
        evidence: f.evidence,
        discoveredAt: f.discoveredAt,
        description: f.description,
        severity: f.severity,
        cvssScore: f.cvssScore,
        cweId: f.cweId,
        simpleExplanation: f.simpleExplanation || existing.simpleExplanation,
        technicalImpact: f.technicalImpact || existing.technicalImpact,
        userImpact: f.userImpact || existing.userImpact,
        businessImpact: f.businessImpact || existing.businessImpact,
        remediation: f.remediation || existing.remediation,
        remediationSteps: f.remediationSteps || existing.remediationSteps,
        exampleConfiguration: f.exampleConfiguration || existing.exampleConfiguration,
        typicalFixLocation: f.typicalFixLocation || existing.typicalFixLocation,
        beforeState: f.beforeState || existing.beforeState,
        afterState: f.afterState || existing.afterState
      });
    } else {
      this.findings.set(f.id, f);
    }
  }

  // Findings
  getFindings(): Finding[] {
    return Array.from(this.findings.values());
  }

  getFindingsByScanId(scanId: string): Finding[] {
    return Array.from(this.findings.values()).filter(f => f.scanId === scanId);
  }

  getFindingsByTargetId(targetId: string): Finding[] {
    return Array.from(this.findings.values()).filter(f => f.targetId === targetId);
  }

  addFindings(newFindings: Finding[]) {
    newFindings.forEach(f => this.deduplicateAndStoreFinding(f));
    this.saveFindings();
  }

  deleteFinding(id: string): boolean {
    const deleted = this.findings.delete(id);
    if (deleted) {
      this.saveFindings();
    }
    return deleted;
  }

  // Audit Logs
  getAuditLogs(): AuditLog[] {
    return [...this.auditLogs].sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  addAuditLog(log: AuditLog): AuditLog {
    this.auditLogs.unshift(log);
    this.saveAuditLogs();
    return log;
  }

  // Endpoints
  getEndpoints(): DiscoveredEndpoint[] {
    return Array.from(this.endpoints.values());
  }

  addEndpoints(newEndpoints: DiscoveredEndpoint[]) {
    newEndpoints.forEach(e => this.endpoints.set(e.id, e));
  }

  // Tools
  getTools(): SecurityToolStatus[] {
    return Array.from(this.tools.values());
  }

  // Remediation Tasks
  getRemediations(): RemediationTask[] {
    return Array.from(this.remediations.values());
  }

  addRemediation(task: RemediationTask): RemediationTask {
    this.remediations.set(task.id, task);
    return task;
  }

  updateRemediation(task: RemediationTask): RemediationTask {
    this.remediations.set(task.id, task);
    return task;
  }

  // AI Summaries
  getAISummary(scanId: string): AISecuritySummary | undefined {
    return this.aiSummaries.get(scanId);
  }

  saveAISummary(summary: AISecuritySummary): AISecuritySummary {
    this.aiSummaries.set(summary.scanId, summary);
    this.saveAISummaries();
    return summary;
  }
}

export const dbStore = new MemoryStore();
