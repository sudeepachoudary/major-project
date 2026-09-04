import { Request, Response, NextFunction } from 'express';
import { dbStore } from '../db/store';

export function validateAssessmentScope(req: Request, res: Response, next: NextFunction) {
  const { targetIds, scanProfile } = req.body;
  const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';

  // 1. Verify targetIds array is present and non-empty
  if (!targetIds || !Array.isArray(targetIds) || targetIds.length === 0) {
    dbStore.addAuditLog({
      id: `audit_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user: 'Security Officer (UserSession)',
      action: 'ASSESSMENT_REJECTED_NO_TARGETS',
      result: 'DENIED',
      details: 'Assessment launch rejected: No target IDs specified in request payload.',
      clientIp
    });
    return res.status(400).json({ error: 'At least one target ID must be explicitly selected.' });
  }

  // 2. Validate EACH target independently against backend inventory
  const validatedTargets = [];
  for (const id of targetIds) {
    const target = dbStore.getTargetById(id);

    if (!target) {
      dbStore.addAuditLog({
        id: `audit_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user: 'Security Officer (UserSession)',
        action: 'SCOPE_VIOLATION_UNKNOWN_TARGET',
        targetId: id,
        result: 'DENIED',
        details: `Backend scope guard blocked request: Target ID ${id} does not exist in authorized target inventory.`,
        clientIp
      });
      return res.status(403).json({ error: `Backend scope violation: Target ID ${id} is invalid or non-existent.` });
    }

    if (target.status !== 'Authorized') {
      dbStore.addAuditLog({
        id: `audit_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user: 'Security Officer (UserSession)',
        action: 'SCOPE_VIOLATION_UNAUTHORIZED_TARGET',
        targetId: target.id,
        targetName: target.name,
        roeId: target.roeId,
        scope: target.scope,
        result: 'DENIED',
        details: `Backend scope guard blocked assessment: Target ${target.name} authorization status is '${target.status}'.`,
        clientIp
      });
      return res.status(403).json({ error: `Target '${target.name}' status is '${target.status}'. Only AUTHORIZED targets can enter assessment.` });
    }

    if (!target.authConfirmed) {
      dbStore.addAuditLog({
        id: `audit_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user: 'Security Officer (UserSession)',
        action: 'SCOPE_VIOLATION_UNCONFIRMED_ROE',
        targetId: target.id,
        targetName: target.name,
        roeId: target.roeId,
        result: 'DENIED',
        details: `Backend scope guard blocked assessment: RoE authorization confirmation missing for target ${target.name}.`,
        clientIp
      });
      return res.status(403).json({ error: `RoE authorization confirmation required for '${target.name}'.` });
    }

    validatedTargets.push(target);
  }

  (req as any).validatedTargets = validatedTargets;

  dbStore.addAuditLog({
    id: `audit_${Date.now()}`,
    timestamp: new Date().toISOString(),
    user: 'Security Officer (UserSession)',
    action: 'SCOPE_PASSED_ASSESSMENT_ALLOWED',
    profile: scanProfile || 'standard',
    result: 'ALLOWED',
    details: `Backend scope guard approved ${validatedTargets.length} target(s): ${validatedTargets.map(t => t.name).join(', ')}. RoE & Scope boundaries verified.`,
    clientIp
  });

  next();
}
