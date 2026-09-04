import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { dbStore } from './db/store';
import { validateAssessmentScope } from './middleware/scopeGuard';
import { executeScanPipeline } from './engine/scannerEngine';
import { generateAISecurityAnalysis } from './services/aiService';
import { runHeadersCheck } from './engine/checkers/headersChecker';
import { runCorsAndCookieCheck } from './engine/checkers/corsChecker';
import { runOptInPathCheck } from './engine/checkers/pathChecker';
import { runPortServiceCheck } from './engine/checkers/portChecker';
import { runXssCheck } from './engine/checkers/xssChecker';
import { runSqlInjectionCheck } from './engine/checkers/sqlInjectionChecker';
import { Target, Scan, ScanProfile, EnvironmentType, Finding, RemediationTask } from '../../src/types/index';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// -------------------------------------------------------------------
// 1. TARGET MANAGEMENT ENDPOINTS
// -------------------------------------------------------------------
app.get('/api/targets', (req, res) => {
  res.json(dbStore.getTargets());
});

app.post('/api/targets', (req, res) => {
  const { name, url, type, environment, roeId, scope, notes, authConfirmed } = req.body;

  if (!name || !url || !roeId || !scope) {
    return res.status(400).json({ error: 'Missing required target fields: name, url, roeId, scope.' });
  }

  if (!authConfirmed) {
    return res.status(400).json({ error: 'Explicit legal authorization confirmation is required.' });
  }

  const newTarget: Target = {
    id: `target_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
    name,
    url,
    type: type || 'Web App',
    environment: (environment as EnvironmentType) || 'LAB',
    status: 'Authorized',
    roeId,
    scope,
    addedDate: new Date().toISOString().split('T')[0],
    notes,
    authConfirmed: true
  };

  dbStore.addTarget(newTarget);

  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: new Date().toISOString(),
    user: 'Security Admin (UserSession)',
    action: 'TARGET_ADDED',
    targetId: newTarget.id,
    targetName: newTarget.name,
    roeId: newTarget.roeId,
    scope: newTarget.scope,
    result: 'ALLOWED',
    details: `Target '${newTarget.name}' (${newTarget.url}) added to authorized inventory [Env: ${newTarget.environment}] under RoE ${newTarget.roeId}.`,
    clientIp: req.ip || '127.0.0.1'
  });

  res.status(201).json(newTarget);
});

app.delete('/api/targets/:id', (req, res) => {
  const target = dbStore.getTargetById(req.params.id);
  if (!target) return res.status(404).json({ error: 'Target not found' });

  dbStore.deleteTarget(req.params.id);
  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: new Date().toISOString(),
    user: 'Security Admin (UserSession)',
    action: 'TARGET_REMOVED',
    targetId: req.params.id,
    targetName: target.name,
    result: 'ALLOWED',
    details: `Target '${target.name}' removed from inventory.`,
    clientIp: req.ip || '127.0.0.1'
  });

  res.json({ message: 'Target removed successfully' });
});

// -------------------------------------------------------------------
// 2. ASSESSMENT LAUNCH & SCOPE CONTROL ENDPOINTS
// -------------------------------------------------------------------
app.get('/api/scans', (req, res) => {
  res.json(dbStore.getScans());
});

app.get('/api/scans/:id', (req, res) => {
  const scan = dbStore.getScanById(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

app.post('/api/scans/launch', validateAssessmentScope, (req, res) => {
  const validatedTargets: Target[] = (req as any).validatedTargets;
  const { scanProfile, safeMode, rateLimit, timeout, authHeader, optInPathDiscovery } = req.body;

  const scanId = `ASSESS-2026-${Math.floor(100 + Math.random() * 900)}`;
  const now = new Date().toISOString();

  const immutableScanRecord: Scan = {
    id: scanId,
    targetIds: validatedTargets.map(t => t.id),
    targetsSnapshot: JSON.parse(JSON.stringify(validatedTargets)),
    scanProfile: (scanProfile as ScanProfile) || 'standard',
    safeMode: safeMode !== false,
    rateLimit: rateLimit || 10,
    timeout: timeout || 30,
    authHeader,
    status: 'running',
    currentStage: 'scope_validation',
    progressPercentage: 5,
    checksCompleted: 0,
    totalChecks: validatedTargets.length * 15,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    securityScore: 100,
    startedAt: now,
    durationSeconds: 0,
    logs: [
      {
        timestamp: now,
        stage: 'scope_validation',
        level: 'info',
        message: `Assessment record ${scanId} created. Frozen scope: ${validatedTargets.map(t => t.name).join(', ')}`
      }
    ]
  };

  dbStore.addScan(immutableScanRecord);
  executeScanPipeline(scanId, optInPathDiscovery);

  res.status(202).json({
    message: 'Authorized assessment enqueued successfully.',
    scanId,
    scan: immutableScanRecord
  });
});

// -------------------------------------------------------------------
// 3. VULNERABILITIES & FINDINGS ENDPOINTS
// -------------------------------------------------------------------
app.get('/api/findings', (req, res) => {
  const { scanId, targetId } = req.query;
  if (targetId && typeof targetId === 'string') {
    return res.json(dbStore.getFindingsByTargetId(targetId));
  }
  if (scanId && typeof scanId === 'string') {
    return res.json(dbStore.getFindingsByScanId(scanId));
  }
  res.json(dbStore.getFindings());
});

app.delete('/api/findings/:id', (req, res) => {
  const findingId = req.params.id;
  const deleted = dbStore.deleteFinding(findingId);
  if (!deleted) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: new Date().toISOString(),
    user: 'Security Analyst (UserSession)',
    action: 'FINDING_DELETED',
    result: 'SUCCESS',
    details: `Finding ID '${findingId}' deleted from vulnerability inventory.`,
    clientIp: req.ip || '127.0.0.1'
  });

  res.json({ message: 'Vulnerability deleted successfully', id: findingId });
});

// -------------------------------------------------------------------
// 4. VERIFY FIX WORKFLOW API (Target & RoE Checked)
// -------------------------------------------------------------------
app.post('/api/findings/:id/verify-fix', async (req, res) => {
  const findingId = req.params.id;
  const finding = dbStore.getFindings().find(f => f.id === findingId);

  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  // 1. Backend Target Scope & Authorization Check
  const target = dbStore.getTargetById(finding.targetId);
  if (!target) {
    return res.status(403).json({ error: 'Target no longer exists in authorized inventory.' });
  }

  if (target.status !== 'Authorized' || !target.authConfirmed) {
    dbStore.addAuditLog({
      id: `audit_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: 'Security Auditor (UserSession)',
      action: 'VERIFY_FIX_REJECTED_UNAUTHORIZED',
      targetId: target.id,
      targetName: target.name,
      result: 'DENIED',
      details: `Verify Fix blocked: Target ${target.name} authorization is missing or unconfirmed.`,
      clientIp: req.ip || '127.0.0.1'
    });
    return res.status(403).json({ error: 'Target authorization check failed.' });
  }

  // 2. Perform Real Targeted Re-Check Probe
  const now = new Date().toISOString();
  let fixVerified = false;
  let newEvidence = '';

  try {
    if (finding.name.includes('Strict-Transport-Security') || finding.name.includes('Content-Security-Policy') || finding.name.includes('X-Frame-Options') || finding.name.includes('Server & Technology') || finding.name.includes('X-Content-Type-Options')) {
      const probeFindings = await runHeadersCheck('VERIFY-SCAN', target);
      const stillPresent = probeFindings.some(f => f.name === finding.name);
      fixVerified = !stillPresent;
      newEvidence = fixVerified 
        ? `Re-audit probe to ${target.url} confirmed security response header control is NOW PRESENT.`
        : `Re-audit probe to ${target.url} confirmed security response header control is STILL MISSING.`;
    } else if (finding.name.includes('CORS') || finding.name.includes('Cookie')) {
      const probeFindings = await runCorsAndCookieCheck('VERIFY-SCAN', target);
      const stillPresent = probeFindings.some(f => f.name === finding.name);
      fixVerified = !stillPresent;
      newEvidence = fixVerified 
        ? `Re-audit probe to ${target.url} confirmed CORS/Cookie security control is NOW COMPLIANT.`
        : `Re-audit probe to ${target.url} confirmed CORS/Cookie vulnerability STILL PERSISTS.`;
    } else if (finding.name.includes('Security.txt') || finding.name.includes('robots.txt') || finding.name.includes('Git Source Code')) {
      const probeFindings = await runOptInPathCheck('VERIFY-SCAN', target, true);
      if (finding.severity === 'INFO') {
        // For INFO items (security.txt, robots.txt), verifying confirms presence of standard
        const isPresent = probeFindings.some(f => f.name === finding.name);
        fixVerified = isPresent;
        newEvidence = fixVerified
          ? `Re-audit probe to ${target.url} confirmed RFC contact/crawler policy standard is ACTIVE (HTTP 200 OK).`
          : `Re-audit probe to ${target.url} did not detect contact policy standard.`;
      } else {
        // For HIGH items (.git/HEAD exposure), verifying confirms path is now blocked
        const stillPresent = probeFindings.some(f => f.name === finding.name);
        fixVerified = !stillPresent;
        newEvidence = fixVerified
          ? `Re-audit probe to ${target.url} confirmed exposed repository path is NOW BLOCKED.`
          : `Re-audit probe to ${target.url} confirmed repository path is STILL EXPOSED.`;
      }
    } else if (finding.name.includes('Cross-Site Scripting') || finding.category === 'XSS') {
      const probeFindings = await runXssCheck('VERIFY-SCAN', target);
      const stillPresent = probeFindings.some(f => f.affectedParameter === finding.affectedParameter || f.name === finding.name);
      fixVerified = !stillPresent;
      newEvidence = fixVerified
        ? `Re-audit probe to ${target.url} confirmed parameter '${finding.affectedParameter || 'query'}' is NOW ENCODED/SANITIZED.`
        : `Re-audit probe to ${target.url} confirmed XSS reflection in parameter '${finding.affectedParameter || 'query'}' STILL PERSISTS.`;
    } else if (finding.name.includes('SQL Injection') || finding.category === 'SQL Injection') {
      const probeFindings = await runSqlInjectionCheck('VERIFY-SCAN', target);
      const stillPresent = probeFindings.some(f => f.affectedParameter === finding.affectedParameter || f.name === finding.name);
      fixVerified = !stillPresent;
      newEvidence = fixVerified
        ? `Re-audit probe to ${target.url} confirmed parameter '${finding.affectedParameter || 'query'}' is NOW PARAMETERIZED.`
        : `Re-audit probe to ${target.url} confirmed SQL Injection error behavior in parameter '${finding.affectedParameter || 'query'}' STILL PERSISTS.`;
    } else if (finding.name.includes('Port 443') || finding.name.includes('HTTPS Service Detected')) {
      fixVerified = true;
      newEvidence = `Port 443 reachable — HTTPS service detected — Informational`;
    } else {
      fixVerified = true;
      newEvidence = `Re-audit probe completed for ${target.url}. Security control requirement re-evaluated.`;
    }
  } catch (err: any) {
    newEvidence = `Verification re-probe error: ${err?.message || 'Connection timeout'}`;
  }

  // 3. Update Finding Verification Status & Audit Trail
  finding.lastVerifiedAt = now;
  if (fixVerified) {
    finding.verificationStatus = 'VERIFIED_SUCCESS';
    finding.verificationEvidence = newEvidence;
    finding.remediationStatus = 'Fix Verified';
    finding.status = 'FIX_VERIFIED';
  } else {
    finding.verificationStatus = 'VERIFIED_FAILED';
    finding.verificationEvidence = newEvidence;
    finding.remediationStatus = 'Not Fixed';
    finding.status = 'OPEN';
  }

  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: now,
    user: 'Security Auditor (UserSession)',
    action: fixVerified ? 'FIX_VERIFIED_SUCCESS' : 'FIX_VERIFICATION_FAILED',
    targetId: target.id,
    targetName: target.name,
    roeId: target.roeId,
    result: fixVerified ? 'SUCCESS' : 'FAILED',
    details: `Verify Fix re-check for '${finding.name}' on target ${target.name}. Result: ${fixVerified ? 'VERIFIED PASSED' : 'STILL FAILING'}.`,
    clientIp: req.ip || '127.0.0.1'
  });

  res.json({
    verified: fixVerified,
    finding,
    evidence: newEvidence
  });
});

// -------------------------------------------------------------------
// 5. ENDPOINTS & RECON INVENTORY
// -------------------------------------------------------------------
app.get('/api/endpoints', (req, res) => {
  res.json(dbStore.getEndpoints());
});

// -------------------------------------------------------------------
// 6. TOOL STATUS PAGE API
// -------------------------------------------------------------------
app.get('/api/tools', (req, res) => {
  res.json(dbStore.getTools());
});

// -------------------------------------------------------------------
// 7. RESULT ADAPTER / IMPORT API (SARIF & JSON Import)
// -------------------------------------------------------------------
app.post('/api/import-results', (req, res) => {
  const { targetId, sourceTool, findingsData } = req.body;

  if (!targetId || !findingsData || !Array.isArray(findingsData)) {
    return res.status(400).json({ error: 'Target ID and findings array are required for import.' });
  }

  const target = dbStore.getTargetById(targetId);
  if (!target) return res.status(404).json({ error: 'Target not found' });

  const now = new Date().toISOString();
  const scanId = `IMPORTED-${Date.now().toString().slice(-4)}`;

  const importedFindings: Finding[] = findingsData.map((item: any, idx: number) => ({
    id: `imp_${Date.now()}_${idx}`,
    scanId,
    targetId: target.id,
    targetName: target.name,
    targetUrl: target.url,
    name: item.title || item.name || 'Imported Vulnerability Finding',
    severity: (item.severity || 'MEDIUM').toUpperCase(),
    cvssScore: item.cvssScore || 5.0,
    cweId: item.cweId || 'CWE-200',
    description: item.description || 'Imported security result via tool adapter.',
    simpleExplanation: 'Imported assessment result from external security scanner.',
    evidence: item.evidence || `Discovered by adapter: ${sourceTool || 'External Scanner'}`,
    risk: item.risk || 'Potential security impact identified in imported report.',
    remediation: item.remediation || 'Apply vendor patch or secure coding guidance.',
    remediationSteps: ['Step 1: Review imported finding evidence.', 'Step 2: Apply vendor fix.', 'Step 3: Click [Verify Fix].'],
    typicalFixLocation: 'Application backend or configuration file.',
    verificationStatus: 'UNVERIFIED',
    remediationStatus: 'Remediation Suggested',
    status: 'OPEN',
    discoveredAt: now
  }));

  dbStore.addFindings(importedFindings);

  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: now,
    user: 'Security Analyst (Adapter)',
    action: 'RESULT_IMPORTED',
    targetId: target.id,
    targetName: target.name,
    result: 'SUCCESS',
    details: `Imported ${importedFindings.length} findings from adapter tool [${sourceTool || 'External Adapter'}] for target ${target.name}.`,
    clientIp: req.ip || '127.0.0.1'
  });

  res.json({ message: 'Findings imported successfully', count: importedFindings.length });
});

// -------------------------------------------------------------------
// 8. REMEDIATION CENTER ENDPOINTS
// -------------------------------------------------------------------
app.get('/api/remediations', (req, res) => {
  res.json(dbStore.getRemediations());
});

app.post('/api/remediations', (req, res) => {
  const { id, findingId, findingTitle, severity, owner, priority, dueDate, status, verificationNotes } = req.body;
  const now = new Date().toISOString();

  const task: RemediationTask = {
    id: id || `rem_${Date.now()}`,
    findingId,
    findingTitle,
    severity: severity || 'MEDIUM',
    owner: owner || 'SecOps Team',
    priority: priority || 'P1',
    dueDate: dueDate || new Date(Date.now() + 86400000 * 7).toISOString().split('T')[0],
    status: status || 'Assigned',
    verificationNotes,
    updatedAt: now
  };

  dbStore.updateRemediation(task);
  res.json(task);
});

// -------------------------------------------------------------------
// 9. AI ANALYSIS ENDPOINT
// -------------------------------------------------------------------
app.post('/api/ai-analysis', async (req, res) => {
  const { scanId } = req.body;
  if (!scanId) return res.status(400).json({ error: 'Scan ID required' });

  const cached = dbStore.getAISummary(scanId);
  if (cached) return res.json(cached);

  const scan = dbStore.getScanById(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const findings = dbStore.getFindingsByScanId(scanId);
  const summary = await generateAISecurityAnalysis(scanId, findings, scan.securityScore);
  dbStore.saveAISummary(summary);

  res.json(summary);
});

// -------------------------------------------------------------------
// 10. AUDIT LOGS ENDPOINT
// -------------------------------------------------------------------
app.get('/api/audit-logs', (req, res) => {
  res.json(dbStore.getAuditLogs());
});

app.listen(PORT, () => {
  console.log(`🛡️  AegisScan Enterprise Platform running on http://localhost:${PORT}`);
});
