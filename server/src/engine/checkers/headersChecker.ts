import { Target, Finding } from '../../../../src/types/index';

export async function runHeadersCheck(scanId: string, target: Target): Promise<Finding[]> {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);
    
    // Non-destructive HEAD request to analyze HTTP response headers
    const res = await fetch(target.url, { 
      method: 'HEAD', 
      signal: controller.signal,
      headers: { 'User-Agent': 'AegisScan-Authorized-Auditor/2.4' }
    }).catch(() => null);

    clearTimeout(timeoutId);

    if (!res) {
      findings.push({
        id: `find_${Date.now()}_hdr_unreachable`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Target Connection Warning / Header Inspection Limited',
        severity: 'LOW',
        cvssScore: 2.1,
        cweId: 'CWE-1188',
        description: `Target HTTP response HEAD request timed out or was unreachable at ${target.url}. Falling back to configuration policy assessment.`,
        simpleExplanation: 'AegisScan could not reach the target host to verify HTTP response headers.',
        evidence: `HTTP HEAD request to ${target.url} did not respond within 6000ms.`,
        technicalImpact: 'Security response headers could not be retrieved or verified remotely.',
        userImpact: 'No immediate direct user impact.',
        businessImpact: 'Unverified network host configuration.',
        risk: 'Header security controls could not be verified remotely.',
        remediation: 'Ensure the host is online and accessible within the authorized network scope.',
        remediationSteps: [
          'Step 1: Check target host network connectivity.',
          'Step 2: Ensure target firewall allows incoming HTTP/HTTPS probes.',
          'Step 3: Click [Verify Fix] in AegisScan once host is reachable.'
        ],
        typicalFixLocation: 'Network firewall or target DNS configuration. Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Ensure target web service is online.',
          '2. Click [Verify Fix] to re-probe HTTP headers.',
          '3. Confirm connection succeeds.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Open',
        beforeState: '❌ HTTP HEAD request failed / timed out',
        afterState: '✅ HTTP HEAD request returned 200 OK with response headers',
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://owasp.org/www-project-secure-headers/',
        status: 'OPEN',
        discoveredAt: now
      });
      return findings;
    }

    const headers = res.headers;

    // 1. Strict-Transport-Security (HSTS)
    if (!headers.get('strict-transport-security') && target.url.startsWith('https')) {
      findings.push({
        id: `find_${Date.now()}_hsts`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Missing Strict-Transport-Security (HSTS) Header',
        severity: 'MEDIUM',
        cvssScore: 5.3,
        cweId: 'CWE-523',
        description: 'The HTTP Strict-Transport-Security (HSTS) header is missing. Without HSTS, attackers can perform Man-in-the-Middle (MitM) SSL stripping attacks.',
        simpleExplanation: 'The application uses HTTPS, but its response does not instruct browsers to always use HTTPS for future requests.',
        evidence: 'Observed Response Header: Strict-Transport-Security is NOT PRESENT',
        technicalImpact: 'Users can be downgraded from HTTPS to unencrypted HTTP via SSL stripping attacks during transit.',
        userImpact: 'Session tokens and confidential user data transmitted over unencrypted HTTP can be intercepted on public Wi-Fi networks.',
        businessImpact: 'Exposes customer accounts to session hijacking, leading to compliance failures under PCI-DSS and GDPR.',
        risk: 'Users may be downgraded from HTTPS to unencrypted HTTP communication during transit.',
        remediation: 'Configure response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        remediationSteps: [
          "Step 1: Configure the application's HTTP response / security-header configuration.",
          "Step 2: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          "Step 3: Deploy the change to your authorized environment.",
          "Step 4: Run AegisScan again or click [Verify Fix] to confirm protection."
        ],
        exampleConfiguration: `Express.js Security Middleware:
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

Nginx Server Config:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
        typicalFixLocation: 'Reverse proxy (Nginx / Apache / Cloudflare) or web framework security middleware (e.g. Helmet.js in Express). Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Deploy the HSTS configuration to your authorized server.',
          '2. Click [Verify Fix] in AegisScan.',
          '3. Confirm Strict-Transport-Security header is detected.',
          '4. Verify status updates to ✅ FIX VERIFIED.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Remediation Suggested',
        beforeState: '❌ Strict-Transport-Security: NOT PRESENT',
        afterState: '✅ Strict-Transport-Security: max-age=31536000; includeSubDomains',
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
        status: 'OPEN',
        discoveredAt: now
      });
    }

    // 2. Content-Security-Policy (CSP)
    if (!headers.get('content-security-policy')) {
      findings.push({
        id: `find_${Date.now()}_csp`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Missing Content-Security-Policy (CSP) Header',
        severity: 'HIGH',
        cvssScore: 7.2,
        cweId: 'CWE-1021',
        description: 'No Content-Security-Policy (CSP) header detected. A robust CSP mitigates Cross-Site Scripting (XSS) and data injection attacks by restricting trusted script origins.',
        simpleExplanation: 'The website does not specify a Content-Security-Policy header to control which scripts, styles, and external resources are allowed to execute.',
        evidence: 'Observed Response Header: Content-Security-Policy is NOT PRESENT',
        technicalImpact: 'Enables untrusted inline JavaScript execution, leading to Cross-Site Scripting (XSS) and client-side data exfiltration.',
        userImpact: 'Malicious scripts could steal session tokens or log user keystrokes.',
        businessImpact: 'Increases vulnerability to client-side data theft and website defacement.',
        risk: 'Enables client-side code injection, unauthorized inline script execution, and sensitive token exfiltration.',
        remediation: "Implement CSP header defining strict script-src, style-src, and object-src directives.",
        remediationSteps: [
          "Step 1: Audit your application's required scripts, styles, fonts, images, and API endpoints.",
          "Step 2: Define a tailored CSP policy (e.g. Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedcdn.com). Note: Do NOT blindly copy example policies; adjust directives based on your application's actual resource needs.",
          "Step 3: Deploy the CSP header to your web server.",
          "Step 4: Click [Verify Fix] in AegisScan to confirm response header detection."
        ],
        exampleConfiguration: `HTTP Response Header Example:
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;

Express.js Middleware:
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});`,
        typicalFixLocation: 'Web application HTTP response middleware or reverse proxy configuration. Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Deploy customized CSP header to authorized target.',
          '2. Trigger [Verify Fix] workflow in AegisScan.',
          '3. Ensure Content-Security-Policy header is returned in response.',
          '4. Confirm finding status changes to ✅ FIX VERIFIED.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Remediation Suggested',
        beforeState: '❌ Content-Security-Policy: MISSING',
        afterState: "✅ Content-Security-Policy: default-src 'self'",
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        status: 'OPEN',
        discoveredAt: now
      });
    }

    // 3. X-Frame-Options / Clickjacking
    const frameOptions = headers.get('x-frame-options');
    if (!frameOptions && !headers.get('content-security-policy')?.includes('frame-ancestors')) {
      findings.push({
        id: `find_${Date.now()}_clickjacking`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Missing Clickjacking Protection (X-Frame-Options)',
        severity: 'MEDIUM',
        cvssScore: 4.7,
        cweId: 'CWE-1021',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors directive was detected. The application can be embedded inside an invisible <iframe> on malicious websites.',
        simpleExplanation: 'The web application does not restrict embedding, allowing malicious sites to load it inside an invisible iframe.',
        evidence: 'Observed Response Header: X-Frame-Options is NOT PRESENT',
        technicalImpact: 'Attacker sites can perform Clickjacking (UI Redress) attacks to trick users into executing unintended actions.',
        userImpact: 'Users might unknowingly click hidden administrative buttons or transfer funds while viewing a decoy site.',
        businessImpact: 'Unauthorized state-changing transactions performed on behalf of authenticated victims.',
        risk: 'Attracts UI redress / clickjacking attacks forcing victim to click hidden administrative action buttons.',
        remediation: 'Add header X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN.',
        remediationSteps: [
          "Step 1: Configure response header X-Frame-Options to DENY or SAMEORIGIN.",
          "Step 2: Alternatively, specify frame-ancestors 'self' in your CSP header.",
          "Step 3: Deploy configuration to authorized target.",
          "Step 4: Run [Verify Fix] to confirm protection."
        ],
        exampleConfiguration: `HTTP Response Header:
X-Frame-Options: SAMEORIGIN

Or CSP directive:
Content-Security-Policy: frame-ancestors 'self';`,
        typicalFixLocation: 'Global HTTP response header middleware or reverse proxy configuration. Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Add X-Frame-Options: SAMEORIGIN to response headers.',
          '2. Click [Verify Fix] in AegisScan.',
          '3. Confirm header presence in HTTP response.',
          '4. Verify status updates to FIX VERIFIED.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Remediation Suggested',
        beforeState: '❌ X-Frame-Options: MISSING',
        afterState: '✅ X-Frame-Options: SAMEORIGIN',
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
        status: 'OPEN',
        discoveredAt: now
      });
    }

    // 4. Server Version Disclosure
    const serverHeader = headers.get('server');
    const xPoweredBy = headers.get('x-powered-by');
    if (serverHeader || xPoweredBy) {
      const details = [serverHeader && `Server: ${serverHeader}`, xPoweredBy && `X-Powered-By: ${xPoweredBy}`].filter(Boolean).join(' | ');
      findings.push({
        id: `find_${Date.now()}_server_disc`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Server & Technology Banner Information Disclosure',
        severity: 'LOW',
        cvssScore: 3.1,
        cweId: 'CWE-200',
        description: 'Server or runtime version information is disclosed in response headers, simplifying attacker target fingerprinting.',
        simpleExplanation: 'The web server returns explicit version banners in HTTP headers, revealing internal technology details to public clients.',
        evidence: `Observed Header Detail: ${details}`,
        technicalImpact: 'Simplifies attacker reconnaissance by advertising exact web server and application framework versions.',
        userImpact: 'No direct user impact, but increases likelihood of targeted automated exploits.',
        businessImpact: 'Exposes unpatched software versions to automated vulnerability bots.',
        risk: 'Allows targeted exploits against specific web server or application framework versions.',
        remediation: 'Disable Server header disclosure and strip X-Powered-By header in web server configuration.',
        remediationSteps: [
          'Step 1: Disable Server header disclosure in web server config.',
          'Step 2: Strip X-Powered-By header in application framework settings.',
          'Step 3: Deploy configuration change.',
          'Step 4: Run [Verify Fix] in AegisScan.'
        ],
        exampleConfiguration: `Nginx Server Config:
server_tokens off;

Express.js Framework:
app.disable('x-powered-by');`,
        typicalFixLocation: 'Web server software configuration (Nginx/Apache) or framework initialization file. Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Disable version disclosures in server configuration.',
          '2. Click [Verify Fix] in AegisScan.',
          '3. Confirm server headers are stripped or generic.',
          '4. Verify status updates to FIX VERIFIED.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Remediation Suggested',
        beforeState: `❌ Server disclosure: ${details}`,
        afterState: '✅ Server disclosure: Hidden / Generic',
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
        status: 'OPEN',
        discoveredAt: now
      });
    }

    // 5. X-Content-Type-Options
    if (!headers.get('x-content-type-options')) {
      findings.push({
        id: `find_${Date.now()}_nosniff`,
        scanId,
        targetId: target.id,
        targetName: target.name,
        targetUrl: target.url,
        name: 'Missing X-Content-Type-Options Header',
        severity: 'LOW',
        cvssScore: 3.8,
        cweId: 'CWE-116',
        description: 'The X-Content-Type-Options header is absent, permitting browsers to MIME-sniff response content types.',
        simpleExplanation: 'The browser is permitted to guess (MIME-sniff) file types when the Content-Type header is ambiguous.',
        evidence: 'Observed Response Header: X-Content-Type-Options is NOT PRESENT',
        technicalImpact: 'Non-executable files containing text/HTML content might be interpreted and executed as JavaScript.',
        userImpact: 'Risk of drive-by script execution when viewing uploaded files.',
        businessImpact: 'Client-side code execution vulnerabilities on user upload features.',
        risk: 'Non-executable files (e.g. images) containing malicious HTML/JS payloads might be executed as script code.',
        remediation: 'Set header: X-Content-Type-Options: nosniff',
        remediationSteps: [
          'Step 1: Add response header X-Content-Type-Options: nosniff.',
          'Step 2: Deploy header configuration.',
          'Step 3: Click [Verify Fix] in AegisScan.'
        ],
        exampleConfiguration: `HTTP Response Header:
X-Content-Type-Options: nosniff`,
        typicalFixLocation: 'HTTP response header middleware or reverse proxy. Exact source file cannot be determined because source code is not connected to AegisScan.',
        verificationSteps: [
          '1. Add X-Content-Type-Options: nosniff to response headers.',
          '2. Trigger [Verify Fix] in AegisScan.',
          '3. Confirm header presence.',
          '4. Confirm status changes to FIX VERIFIED.'
        ],
        verificationStatus: 'UNVERIFIED',
        remediationStatus: 'Remediation Suggested',
        beforeState: '❌ X-Content-Type-Options: MISSING',
        afterState: '✅ X-Content-Type-Options: nosniff',
        detectionSource: 'AegisScan HTTP Headers Audit Checker',
        referenceUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
        status: 'OPEN',
        discoveredAt: now
      });
    }

  } catch (err) {
    console.error('Error in headers checker:', err);
  }

  return findings;
}
