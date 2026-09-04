import { Target, Finding } from '../../../../src/types/index';

export async function runPortServiceCheck(scanId: string, target: Target): Promise<Finding[]> {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  const commonPorts = [
    { port: 80, name: 'HTTP Web Service', desc: 'Standard HTTP service' },
    { port: 443, name: 'HTTPS TLS Web Service', desc: 'Encrypted HTTPS web service' },
    { port: 8080, name: 'Alternative HTTP / Proxy Port', desc: 'Often used for dev servers or web gateways' },
    { port: 8443, name: 'Alternative HTTPS Port', desc: 'Secondary encrypted SSL/TLS web management port' },
    { port: 3000, name: 'Node.js / React Dev Server Port', desc: 'Front-end development server port' }
  ];

  try {
    const parsedUrl = new URL(target.url);
    const host = parsedUrl.hostname;

    for (const p of commonPorts) {
      const testUrl = `${parsedUrl.protocol}//${host}:${p.port}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const reachable = await fetch(testUrl, { method: 'HEAD', signal: controller.signal })
        .then(() => true)
        .catch(() => false);

      clearTimeout(timeoutId);

      if (reachable) {
        if (p.port === 443) {
          findings.push({
            id: `find_${Date.now()}_port_443`,
            scanId,
            targetId: target.id,
            targetName: target.name,
            targetUrl: target.url,
            name: 'Informational: HTTPS Service Detected on Port 443',
            severity: 'INFO',
            cvssScore: 0.0,
            cweId: undefined,
            description: 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.',
            simpleExplanation: 'Port 443 is reachable and provides an HTTPS/TLS web service. This is expected behavior for an HTTPS-enabled website and is not a vulnerability by itself.',
            evidence: `Observed Service: HTTPS service listening on port 443 on host ${host}`,
            technicalImpact: 'Exposes standard encrypted web service port (443).',
            userImpact: 'No direct user impact identified from port 443 exposure alone.',
            businessImpact: 'No direct business impact identified from port 443 exposure alone.',
            risk: 'No risk identified from port 443 exposure alone.',
            remediation: 'No remediation is required for an HTTPS service on port 443. Keep port 443 available if HTTPS access is required. TLS configuration should be assessed separately.',
            remediationSteps: [
              'Step 1: Keep port 443 open if HTTPS access is required for your web application.',
              'Step 2: Ensure strong TLS cipher suites and valid certificates are configured (assessed separately).',
              'Step 3: Click [Verify Fix] to confirm HTTPS port reachability.'
            ],
            typicalFixLocation: 'Network firewall or web server configuration. Exact source file cannot be determined because source code is not connected to AegisScan.',
            verificationSteps: [
              '1. Confirm port 443 remains open for HTTPS traffic.',
              '2. Click [Verify Fix] in AegisScan.',
              '3. Confirm informational status.'
            ],
            verificationStatus: 'UNVERIFIED',
            remediationStatus: 'Fix Verified',
            beforeState: '✅ Port 443 reachable (HTTPS TLS Web Service)',
            afterState: '✅ Expected HTTPS service active on port 443',
            detectionSource: 'AegisScan Network Port Probe',
            referenceUrl: 'https://nmap.org/',
            status: 'OPEN',
            discoveredAt: now
          });
        } else {
          findings.push({
            id: `find_${Date.now()}_port_${p.port}`,
            scanId,
            targetId: target.id,
            targetName: target.name,
            targetUrl: target.url,
            name: `Open Port Discovered: ${p.port} (${p.name})`,
            severity: p.port === 8080 || p.port === 3000 ? 'MEDIUM' : 'INFO',
            cvssScore: p.port === 8080 || p.port === 3000 ? 5.3 : 0.0,
            cweId: p.port === 8080 || p.port === 3000 ? 'CWE-200' : undefined,
            description: `Discovered active network service listening on port ${p.port} (${p.desc}).`,
            simpleExplanation: `Service detected listening on port ${p.port}.`,
            evidence: `Service on host ${host}:${p.port} responded to authorized probe.`,
            technicalImpact: `Port ${p.port} is accessible remotely.`,
            userImpact: p.port === 3000 ? 'Unintended access to development interface.' : 'No direct user impact.',
            businessImpact: p.port === 3000 ? 'Development exposure risk.' : 'Standard network service exposure.',
            risk: p.port === 3000 ? 'Development servers running in production increase attack surface.' : 'Normal web service exposure.',
            remediation: 'Ensure non-standard development ports (e.g. 3000, 8080) are firewall restricted in production environments.',
            remediationSteps: [
              `Step 1: Audit if port ${p.port} is necessary in production.`,
              'Step 2: Restrict non-standard ports behind a firewall.',
              'Step 3: Run [Verify Fix].'
            ],
            typicalFixLocation: 'Firewall rules or web server configuration. Exact source file cannot be determined because source code is not connected to AegisScan.',
            beforeState: `Port ${p.port} listening`,
            afterState: `Port ${p.port} audited`,
            detectionSource: 'AegisScan Network Port Probe',
            referenceUrl: 'https://nmap.org/',
            status: 'OPEN',
            discoveredAt: now
          });
        }
      }
    }
  } catch (err) {
    console.error('Error in port checker:', err);
  }

  return findings;
}
