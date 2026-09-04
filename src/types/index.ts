export type TargetType = 'Web App' | 'API Endpoint' | 'Network Host' | 'Cloud Endpoint';
export type EnvironmentType = 'LAB' | 'DEVELOPMENT' | 'ENTERPRISE';
export type AuthorizationStatus = 'Authorized' | 'Pending Authorization' | 'Expired' | 'Revoked';

export interface Target {
  id: string;
  name: string;
  url: string;
  type: TargetType;
  environment: EnvironmentType;
  status: AuthorizationStatus;
  roeId: string;
  scope: string;
  addedDate: string;
  lastScanDate?: string;
  notes?: string;
  authConfirmed: boolean;
}

export interface DiscoveredEndpoint {
  id: string;
  targetId: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD';
  contentType?: string;
  authenticated: boolean;
  source: 'RECON' | 'SITEMAP' | 'ROBOTS' | 'JS_PARSER' | 'OPENAPI' | 'IMPORTED';
  riskScore: number;
  discoveredAt: string;
}

export interface SecurityToolStatus {
  id: string;
  name: string;
  category: 'NETWORK' | 'WEB' | 'RECON' | 'STATIC' | 'ADAPTER';
  status: 'Available' | 'Not Configured' | 'Installed' | 'Error';
  version?: string;
  description: string;
}

export interface RemediationTask {
  id: string;
  findingId: string;
  findingTitle: string;
  severity: SeverityLevel;
  owner: string;
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  dueDate: string;
  status: 'Open' | 'Assigned' | 'In Progress' | 'Resolved' | 'Verified' | 'Accepted Risk';
  verificationNotes?: string;
  updatedAt: string;
}

export type ScanProfile = 'quick' | 'standard' | 'port_service' | 'comprehensive';

export type ScanStage = 
  | 'scope_validation'
  | 'authorization_check'
  | 'reconnaissance'
  | 'security_checks'
  | 'vulnerability_analysis'
  | 'risk_classification'
  | 'report_generation';

export type ScanStatus = 'queued' | 'validating' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScanLogEntry {
  timestamp: string;
  stage: ScanStage;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
}

export interface ScanFindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface Scan {
  id: string;
  targetIds: string[];
  targetsSnapshot: Target[];
  scanProfile: ScanProfile;
  safeMode: boolean;
  rateLimit: number;
  timeout: number;
  authHeader?: string;
  status: ScanStatus;
  currentStage: ScanStage;
  progressPercentage: number;
  checksCompleted: number;
  totalChecks: number;
  findingsCount: ScanFindingsSummary;
  securityScore: number;
  startedAt: string;
  completedAt?: string;
  durationSeconds: number;
  logs: ScanLogEntry[];
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'REMEDIATED' | 'FALSE_POSITIVE' | 'FIX_VERIFIED';
export type RemediationStatus = 'Open' | 'Remediation Suggested' | 'Fix In Progress' | 'Fix Verified' | 'Not Fixed' | 'Accepted Risk';

export interface Finding {
  id: string;
  scanId: string;
  targetId: string;
  targetName: string;
  targetUrl: string;
  name: string;
  severity: SeverityLevel;
  cvssScore: number;
  cweId?: string;
  description: string;
  simpleExplanation?: string;
  evidence: string;
  technicalImpact?: string;
  userImpact?: string;
  businessImpact?: string;
  risk: string;
  remediation: string;
  remediationSteps?: string[];
  exampleConfiguration?: string;
  typicalFixLocation?: string;
  verificationSteps?: string[];
  verificationStatus?: 'UNVERIFIED' | 'VERIFIED_SUCCESS' | 'VERIFIED_FAILED';
  verificationEvidence?: string;
  remediationStatus?: RemediationStatus;
  beforeState?: string;
  afterState?: string;
  lastVerifiedAt?: string;
  detectionSource?: string;
  referenceUrl?: string;
  category?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  affectedEndpoint?: string;
  affectedParameter?: string;
  firstDetected?: string;
  lastDetected?: string;
  status: FindingStatus;
  discoveredAt: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  targetId?: string;
  targetName?: string;
  roeId?: string;
  scope?: string;
  profile?: string;
  result: 'ALLOWED' | 'DENIED' | 'SUCCESS' | 'FAILED';
  details: string;
  clientIp: string;
}

export interface AISecuritySummary {
  scanId: string;
  executiveSummary: string;
  businessImpact: string;
  technicalRootCause: string;
  prioritizedRemediation: string[];
  overallRiskRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  generatedAt: string;
}

export interface ScanConfigRequest {
  targetIds: string[];
  scanProfile: ScanProfile;
  safeMode: boolean;
  rateLimit?: number;
  timeout?: number;
  authHeader?: string;
  optInPathDiscovery?: boolean;
}
