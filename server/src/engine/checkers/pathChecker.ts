import { Target, Finding } from '../../../../src/types/index';

export async function runOptInPathCheck(scanId: string, target: Target, isOptIn: boolean): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (!isOptIn) return findings;

  const now = new Date().toISOString();
  const testPaths = [
    { path: '/robots.txt', name: 'Exposed robots.txt Crawler Policy', severity: 'INFO' as const, cvss: 0.0, cwe: 'CWE-200' },
    { path: '/.well-known/security.txt', name: 'Security.txt Contact Standard Present', severity: 'INFO' as const, cvss: 0.0, cwe: 'CWE-200' },
    { path: '/.git/HEAD', name: 'Exposed Git Source Code Repository Metadata', severity: 'HIGH' as const, cvss: 7.5, cwe: 'CWE-538' }
  ];

  for (const item of testPaths) {
    try {
      const url = new URL(item.path, target.url).toString();
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      // Use GET request to inspect response body and eliminate SPA router false positives
      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'AegisScan-OptIn-Path-Auditor/2.4' }
      }).catch(() => null);

      clearTimeout(timeoutId);

      if (res && res.status === 200) {
        const bodyText = await res.text().catch(() => '');

        // 1. Check for /.git/HEAD
        if (item.path === '/.git/HEAD') {
          // Verify body actually contains Git HEAD metadata ('ref: refs/') and NOT HTML SPA fallback page
          const isActualGitHead = bodyText.includes('ref: refs/') || /^[0-9a-f]{40}/i.test(bodyText.trim());
          const isHtmlFallback = bodyText.toLowerCase().includes('<!doctype html') || bodyText.toLowerCase().includes('<html');

          if (isActualGitHead && !isHtmlFallback) {
            findings.push({
              id: `find_${Date.now()}_git_exposed`,
              scanId,
              targetId: target.id,
              targetName: target.name,
              targetUrl: target.url,
              name: item.name,
              severity: 'HIGH',
              cvssScore: 7.5,
              cweId: 'CWE-538',
              description: 'The .git folder is publicly accessible. Attackers can download repository index and source code history.',
              simpleExplanation: 'The web server publicly exposes internal Git version control metadata (.git/HEAD), allowing anyone to download the full source code repository.',
              evidence: `Observed Response Body Content: ${bodyText.slice(0, 100).trim()}`,
              technicalImpact: 'Enables complete source code reconstruction, commit history analysis, and internal route discovery.',
              userImpact: 'Exposes application logic and hardcoded secret tokens, risking widespread platform compromise.',
              businessImpact: 'Intellectual property theft, secret exposure, and critical data breach risk.',
              risk: 'Complete source code disclosure, potential hardcoded credentials disclosure.',
              remediation: 'Deny web server directory access to hidden .git/ folder.',
              remediationSteps: [
                'Step 1: Configure web server or reverse proxy to block requests to hidden directories starting with dot (e.g. location ~ /\\.git).',
                'Step 2: Ensure .git directories are stripped during production deployment builds.',
                'Step 3: Deploy configuration change.',
                'Step 4: Click [Verify Fix] in AegisScan.'
              ],
              exampleConfiguration: `Nginx Security Block:
location ~ /\\.git {
  deny all;
  return 404;
}`,
              typicalFixLocation: 'Web server directory block configuration or deployment build script. Exact source file cannot be determined because source code is not connected to AegisScan.',
              verificationSteps: [
                '1. Block HTTP access to .git directory.',
                '2. Click [Verify Fix] in AegisScan.',
                '3. Confirm HTTP GET /.git/HEAD returns 403 Forbidden or 404 Not Found.',
                '4. Confirm status changes to ✅ FIX VERIFIED.'
              ],
              verificationStatus: 'UNVERIFIED',
              remediationStatus: 'Remediation Suggested',
              beforeState: `❌ Response Body: ${bodyText.slice(0, 40)}... (Git HEAD metadata confirmed)`,
              afterState: '✅ HTTP GET /.git/HEAD returns 403 Forbidden / 404 Not Found',
              detectionSource: 'AegisScan Resource Path Auditor',
              referenceUrl: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
              status: 'OPEN',
              discoveredAt: now
            });
          }
        } 
        // 2. Check for /.well-known/security.txt
        else if (item.path === '/.well-known/security.txt') {
          // Ensure it's not an SPA HTML fallback
          const isHtmlFallback = bodyText.toLowerCase().includes('<!doctype html') || bodyText.toLowerCase().includes('<html');
          if (!isHtmlFallback) {
            findings.push({
              id: `find_${Date.now()}_security_txt`,
              scanId,
              targetId: target.id,
              targetName: target.name,
              targetUrl: target.url,
              name: 'Security.txt Contact Standard Present',
              severity: 'INFO',
              cvssScore: 0.0,
              cweId: 'CWE-200',
              description: 'The target host publishes an RFC 9116 security.txt file at /.well-known/security.txt to facilitate responsible vulnerability reporting.',
              simpleExplanation: 'Security.txt (RFC 9116) is a security BEST PRACTICE. It provides security researchers and ethical hackers with official contact channels to report vulnerabilities directly to your security team.',
              evidence: `Observed Response Body Content: ${bodyText.slice(0, 100).trim()}`,
              technicalImpact: 'Provides standardized security contact channels and encryption keys (PGP) for vulnerability disclosure.',
              userImpact: 'Enhances user safety by facilitating rapid vulnerability remediation before malicious exploitation.',
              businessImpact: 'Demonstrates DevSecOps maturity, compliance with RFC 9116, and alignment with ISO 27001 disclosure standards.',
              risk: 'No risk. This is a beneficial security contact disclosure file.',
              remediation: 'No remediation required. Maintain valid security contact emails, PGP keys, and expiration dates in /.well-known/security.txt.',
              remediationSteps: [
                'Step 1: Periodically review contact email addresses listed in security.txt.',
                'Step 2: Ensure the Expires field is kept up to date.',
                'Step 3: Keep PGP keys active for encrypted reports.'
              ],
              exampleConfiguration: `RFC 9116 Security.txt Example:
Contact: mailto:security@example.com
Contact: https://example.com/security/report
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en`,
              typicalFixLocation: 'Static asset directory or /.well-known/ route handler. Exact source file cannot be determined because source code is not connected to AegisScan.',
              verificationSteps: [
                '1. Verify /.well-known/security.txt contains valid contact email addresses.',
                '2. Click [Verify Fix] in AegisScan.',
                '3. Confirm HTTP 200 OK response with contact payload.'
              ],
              verificationStatus: 'UNVERIFIED',
              remediationStatus: 'Fix Verified',
              beforeState: '✅ Security.txt standard present (RFC 9116 compliant)',
              afterState: '✅ Contact standard maintained at /.well-known/security.txt',
              detectionSource: 'AegisScan Resource Path Auditor',
              referenceUrl: 'https://securitytxt.org/',
              status: 'OPEN',
              discoveredAt: now
            });
          }
        } 
        // 3. Check for /robots.txt
        else if (item.path === '/robots.txt') {
          const isHtmlFallback = bodyText.toLowerCase().includes('<!doctype html') || bodyText.toLowerCase().includes('<html');
          if (!isHtmlFallback) {
            findings.push({
              id: `find_${Date.now()}_robots_txt`,
              scanId,
              targetId: target.id,
              targetName: target.name,
              targetUrl: target.url,
              name: 'Exposed robots.txt Crawler Policy',
              severity: 'INFO',
              cvssScore: 0.0,
              cweId: 'CWE-200',
              description: 'The target exposes a robots.txt file guiding search engine web crawlers.',
              simpleExplanation: 'Robots.txt is a standard file instructing search engine crawlers which application paths to index or avoid.',
              evidence: `Observed Response Body Content: ${bodyText.slice(0, 100).trim()}`,
              technicalImpact: 'Informs web crawlers of indexing boundaries.',
              userImpact: 'Prevents search engines from indexing sensitive administrative or staging sub-paths.',
              businessImpact: 'Standard web crawl management.',
              risk: 'Ensure Disallow directives in robots.txt do not disclose confidential internal staging paths.',
              remediation: 'Audit Disallow directives to ensure no sensitive internal directory paths are advertised.',
              remediationSteps: [
                'Step 1: Open robots.txt and review Disallow directives.',
                'Step 2: Remove references to secret administrative paths or unlinked internal endpoints.',
                'Step 3: Click [Verify Fix] in AegisScan.'
              ],
              exampleConfiguration: `Robots.txt Example:
User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml`,
              typicalFixLocation: 'Static web root directory. Exact source file cannot be determined because source code is not connected to AegisScan.',
              verificationSteps: [
                '1. Verify robots.txt contains no sensitive internal paths.',
                '2. Trigger [Verify Fix].',
                '3. Confirm policy compliance.'
              ],
              verificationStatus: 'UNVERIFIED',
              remediationStatus: 'Fix Verified',
              beforeState: '✅ Robots.txt crawler policy present',
              afterState: '✅ Robots.txt policy verified',
              detectionSource: 'AegisScan Resource Path Auditor',
              referenceUrl: 'https://developers.google.com/search/docs/crawling-indexing/robots/intro',
              status: 'OPEN',
              discoveredAt: now
            });
          }
        }
      }
    } catch (err) {
      // Safe fail
    }
  }

  return findings;
}
