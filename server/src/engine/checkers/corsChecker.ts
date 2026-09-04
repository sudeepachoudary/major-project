import { Target, Finding } from '../../../../src/types/index';

export async function runCorsAndCookieCheck(scanId: string, target: Target): Promise<Finding[]> {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    // Send OPTIONS request for CORS check
    const res = await fetch(target.url, {
      method: 'OPTIONS',
      signal: controller.signal,
      headers: {
        'Origin': 'https://evil-unauthorized-origin.com',
        'Access-Control-Request-Method': 'POST'
      }
    }).catch(() => null);

    clearTimeout(timeoutId);

    if (res) {
      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');

      if (acao === '*' && acac === 'true') {
        findings.push({
          id: `find_${target.id}_cors_wildcard`,
          scanId,
          targetId: target.id,
          targetName: target.name,
          targetUrl: target.url,
          name: 'Critical Permissive CORS Policy with Credentials',
          severity: 'CRITICAL',
          cvssScore: 9.1,
          cweId: 'CWE-942',
          description: 'The target reflects wildcard Access-Control-Allow-Origin header alongside Access-Control-Allow-Credentials: true. Cross-origin domain scripts can read authenticated API payloads.',
          simpleExplanation: 'The API configuration permits any arbitrary external site to make authenticated requests and read sensitive private responses.',
          evidence: `Observed Response Headers: Access-Control-Allow-Origin: ${acao} | Access-Control-Allow-Credentials: ${acac}`,
          technicalImpact: 'Cross-origin domain scripts can execute authenticated requests using victim session cookies.',
          userImpact: 'Private user account data and sensitive transactions can be stolen by malicious third-party websites.',
          businessImpact: 'Mass data exfiltration and session takeover vulnerability.',
          risk: 'Malicious websites can execute cross-domain authenticated requests and steal user account session data.',
          remediation: 'Restrict CORS policy to explicit whitelisted origins. Never allow wildcard origins with credentials.',
          remediationSteps: [
            'Step 1: Replace wildcard Access-Control-Allow-Origin: * with explicit allowed origin domains.',
            'Step 2: Never allow wildcard origins combined with Access-Control-Allow-Credentials: true.',
            'Step 3: Deploy CORS policy changes.',
            'Step 4: Click [Verify Fix] in AegisScan.'
          ],
          exampleConfiguration: `Express CORS Middleware:
app.use(cors({
  origin: ['https://authorized-domain.com'],
  credentials: true
}));`,
          typicalFixLocation: 'API Gateway or application CORS configuration middleware. Exact source file cannot be determined because source code is not connected to AegisScan.',
          verificationSteps: [
            '1. Whitelist explicit origins in CORS configuration.',
            '2. Click [Verify Fix] in AegisScan.',
            '3. Confirm wildcard origin with credentials is no longer returned.',
            '4. Verify status updates to FIX VERIFIED.'
          ],
          verificationStatus: 'UNVERIFIED',
          remediationStatus: 'Remediation Suggested',
          beforeState: '❌ Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true',
          afterState: '✅ Access-Control-Allow-Origin: https://authorized-domain.com',
          detectionSource: 'AegisScan CORS Audit Checker',
          referenceUrl: 'https://portswigger.net/web-security/cors',
          status: 'OPEN',
          discoveredAt: now
        });
      } else if (acao === '*') {
        findings.push({
          id: `find_${target.id}_cors_star`,
          scanId,
          targetId: target.id,
          targetName: target.name,
          targetUrl: target.url,
          name: 'Wildcard CORS Access Control Header',
          severity: 'LOW',
          cvssScore: 3.7,
          cweId: 'CWE-942',
          description: 'Access-Control-Allow-Origin is set to wildcard (*).',
          simpleExplanation: 'The API permits any external domain to read unauthenticated public API responses.',
          evidence: `Observed Header: Access-Control-Allow-Origin: *`,
          technicalImpact: 'Unauthenticated public resource exposure to arbitrary cross-origin domains.',
          userImpact: 'Minor privacy risk if API responses contain sensitive data.',
          businessImpact: 'Unrestricted cross-domain data scraping.',
          risk: 'Unauthenticated public resource exposure to arbitrary cross-origin domains.',
          remediation: 'Specify strict origin domain lists for CORS response headers if resources contain sensitive data.',
          remediationSteps: [
            'Step 1: Specify explicit domain origin whitelist for CORS response headers.',
            'Step 2: Deploy CORS policy.',
            'Step 3: Click [Verify Fix].'
          ],
          exampleConfiguration: `Header Example:
Access-Control-Allow-Origin: https://app.example.com`,
          typicalFixLocation: 'Application API CORS middleware or web server headers. Exact source file cannot be determined because source code is not connected to AegisScan.',
          verificationSteps: [
            '1. Configure explicit origin whitelist.',
            '2. Run [Verify Fix] in AegisScan.',
            '3. Confirm wildcard origin removed.'
          ],
          verificationStatus: 'UNVERIFIED',
          remediationStatus: 'Remediation Suggested',
          beforeState: '❌ Access-Control-Allow-Origin: *',
          afterState: '✅ Access-Control-Allow-Origin: https://app.example.com',
          detectionSource: 'AegisScan CORS Audit Checker',
          referenceUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
          status: 'OPEN',
          discoveredAt: now
        });
      }

      // Cookie Security Flags Inspection
      const rawCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get('set-cookie')].filter(Boolean) as string[];
      rawCookies.forEach(cookieStr => {
        const lower = cookieStr.toLowerCase();
        const rawName = cookieStr.split('=')[0]?.trim();
        const cookieName = rawName || 'SESSION';

        if (!lower.includes('httponly')) {
          findings.push({
            id: `find_${target.id}_cookie_httponly_${cookieName}`,
            scanId,
            targetId: target.id,
            targetName: target.name,
            targetUrl: target.url,
            name: `Missing HttpOnly Flag on Cookie (${cookieName})`,
            severity: 'MEDIUM',
            cvssScore: 6.1,
            cweId: 'CWE-1004',
            description: `Session cookie "${cookieName}" lacks the HttpOnly attribute.`,
            simpleExplanation: 'Session cookies lack the HttpOnly flag, permitting client-side JavaScript to access sensitive session identifiers.',
            evidence: `Observed Set-Cookie Header: ${cookieStr} (HttpOnly attribute MISSING)`,
            technicalImpact: 'Enables attackers to steal session cookies via XSS payloads using document.cookie.',
            userImpact: 'User accounts can be compromised if an XSS vulnerability exists anywhere on the site.',
            businessImpact: 'Account takeover and session theft risks.',
            risk: 'Allows client-side JavaScript access to sensitive authentication cookies during XSS exploitation.',
            remediation: 'Append HttpOnly flag to Set-Cookie header.',
            remediationSteps: [
              'Step 1: Set httpOnly: true attribute when setting session cookies in your web framework.',
              'Step 2: Ensure all authentication cookies include HttpOnly.',
              'Step 3: Deploy code fix.',
              'Step 4: Click [Verify Fix] in AegisScan.'
            ],
            exampleConfiguration: `Express.js Session Cookie Config:
res.cookie('${cookieName}', token, { httpOnly: true, secure: true, sameSite: 'lax' });`,
            typicalFixLocation: 'Cookie creation and session management middleware. Exact source file cannot be determined because source code is not connected to AegisScan.',
            verificationSteps: [
              '1. Set httpOnly: true on session cookies.',
              '2. Trigger [Verify Fix] in AegisScan.',
              '3. Confirm HttpOnly attribute is present in Set-Cookie header.',
              '4. Confirm status changes to FIX VERIFIED.'
            ],
            verificationStatus: 'UNVERIFIED',
            remediationStatus: 'Remediation Suggested',
            beforeState: `❌ Set-Cookie: ${cookieName}=xyz (HttpOnly missing)`,
            afterState: `✅ Set-Cookie: ${cookieName}=xyz; HttpOnly; Secure; SameSite=Lax`,
            detectionSource: 'AegisScan Session Cookie Auditor',
            referenceUrl: 'https://owasp.org/www-community/HttpOnly',
            status: 'OPEN',
            discoveredAt: now
          });
        }

        if (!lower.includes('secure') && target.url.startsWith('https')) {
          findings.push({
            id: `find_${target.id}_cookie_secure_${cookieName}`,
            scanId,
            targetId: target.id,
            targetName: target.name,
            targetUrl: target.url,
            name: `Missing Secure Flag on Cookie (${cookieName})`,
            severity: 'MEDIUM',
            cvssScore: 5.4,
            cweId: 'CWE-614',
            description: `Cookie "${cookieName}" is missing the Secure attribute over HTTPS.`,
            simpleExplanation: 'Session cookies lack the Secure attribute over HTTPS, allowing them to be transmitted in plain unencrypted HTTP requests.',
            evidence: `Observed Set-Cookie Header: ${cookieStr} (Secure attribute MISSING)`,
            technicalImpact: 'Cookies may be transmitted in unencrypted HTTP requests during network interception.',
            userImpact: 'Eavesdroppers on unencrypted Wi-Fi can capture authentication cookies.',
            businessImpact: 'Session hijacking over unencrypted transport.',
            risk: 'Cookie could be transmitted over unencrypted HTTP during network eavesdropping.',
            remediation: 'Append Secure flag to Set-Cookie header.',
            remediationSteps: [
              'Step 1: Set secure: true attribute on Set-Cookie headers over HTTPS.',
              'Step 2: Deploy configuration change.',
              'Step 3: Click [Verify Fix] in AegisScan.'
            ],
            exampleConfiguration: `Cookie Header Example:
Set-Cookie: ${cookieName}=xyz; Secure; HttpOnly; SameSite=Lax`,
            typicalFixLocation: 'Session cookie creation settings. Exact source file cannot be determined because source code is not connected to AegisScan.',
            verificationSteps: [
              '1. Set Secure flag on HTTPS session cookies.',
              '2. Click [Verify Fix] in AegisScan.',
              '3. Confirm Secure attribute is present in Set-Cookie header.',
              '4. Confirm status changes to FIX VERIFIED.'
            ],
            verificationStatus: 'UNVERIFIED',
            remediationStatus: 'Remediation Suggested',
            beforeState: `❌ Set-Cookie: ${cookieName}=xyz (Secure missing)`,
            afterState: `✅ Set-Cookie: ${cookieName}=xyz; Secure; HttpOnly`,
            detectionSource: 'AegisScan Session Cookie Auditor',
            referenceUrl: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
            status: 'OPEN',
            discoveredAt: now
          });
        }
      });
    }
  } catch (err) {
    console.error('Error in CORS and Cookie checker:', err);
  }

  return findings;
}
