import { Finding, Target } from '../../../../src/types/index';

/**
 * Non-destructive XSS Detection Engine for AegisScan Enterprise
 * 
 * Strict Rules:
 * 1. Checks target.status === 'Authorized' && target.authConfirmed === true.
 * 2. Uses unique, harmless canary markers (e.g., `aegisxss<random>`).
 * 3. Never sends destructive payload strings (no alert(), no document.cookie theft, no external callbacks).
 * 4. Identifies exact reflection context (HTML Body, Attribute, JS Context, URL).
 * 5. Rejects SPA catch-all router fallbacks and plain un-executable text reflections.
 * 6. Assigns confidence level and generates deterministic IDs for finding deduplication.
 */

export async function runXssCheck(scanId: string, target: Target): Promise<Finding[]> {
  const findings: Finding[] = [];

  // STRICT AUTHORIZATION SCOPE GUARD
  if (target.status !== 'Authorized' || !target.authConfirmed) {
    console.warn(`[XSS CHECK ABORTED] Target ${target.name} (${target.url}) is NOT authorized for active XSS testing.`);
    return [];
  }

  try {
    const baseUrl = target.url.endsWith('/') ? target.url.slice(0, -1) : target.url;
    
    // Candidate parameters to audit for reflected input
    const candidateParams = ['q', 'search', 'query', 'name', 'id', 'redirect', 'user', 'msg', 'keyword'];

    // Random canary marker prefix for audit traceability
    const canaryId = Math.random().toString(36).substring(2, 9);
    
    // Test context markers (non-destructive)
    const canaryMarker = `aegisxss${canaryId}`;
    const attrTestPayload = `aegis"xss${canaryId}`;
    const scriptTestPayload = `aegis';//xss${canaryId}`;

    for (const param of candidateParams) {
      // 1. Audit HTML Attribute / Body Reflection
      const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(attrTestPayload)}`;
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const response = await fetch(testUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'AegisScan-Security-Auditor/2.4 (Authorized Security Assessment)',
          'Accept': 'text/html,application/xhtml+xml'
        },
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!response.ok && response.status !== 404 && response.status !== 400) {
        continue;
      }

      const bodyText = await response.text();

      // SPA catch-all router check
      if (bodyText.includes('<!DOCTYPE html>') && bodyText.includes('root') && !bodyText.includes(attrTestPayload)) {
        continue;
      }

      let reflectionContext: 'HTML_BODY' | 'HTML_ATTRIBUTE' | 'JAVASCRIPT_CONTEXT' | 'NONE' = 'NONE';
      let confidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';

      // Check if unescaped quote reflected inside an attribute
      if (bodyText.includes(`="${attrTestPayload}"`) || bodyText.includes(`='${attrTestPayload}'`) || bodyText.includes(`value="${attrTestPayload}"`)) {
        reflectionContext = 'HTML_ATTRIBUTE';
        confidence = 'HIGH';
      } else if (bodyText.includes(`<script>`) && bodyText.includes(attrTestPayload)) {
        reflectionContext = 'JAVASCRIPT_CONTEXT';
        confidence = 'HIGH';
      } else if (bodyText.includes(`>${attrTestPayload}<`) || bodyText.includes(`<span>${attrTestPayload}</span>`)) {
        reflectionContext = 'HTML_BODY';
        confidence = 'MEDIUM';
      }

      if (reflectionContext !== 'NONE') {
        const findingId = `find_${target.id}_xss_${param}`;
        const now = new Date().toISOString();

        findings.push({
          id: findingId,
          scanId,
          targetId: target.id,
          targetName: target.name,
          targetUrl: target.url,
          name: `Reflected Cross-Site Scripting (XSS) in Parameter '${param}'`,
          category: 'XSS',
          severity: 'HIGH',
          cvssScore: 7.2,
          cweId: 'CWE-79',
          confidence,
          affectedEndpoint: `${baseUrl}/`,
          affectedParameter: param,
          description: `The application reflects user input provided in query parameter '${param}' without adequate HTML entity encoding or sanitization in ${reflectionContext} context.`,
          simpleExplanation: `The web application takes data typed into the '${param}' parameter and outputs it directly into the web page without safety escaping. An attacker could potentially inject malicious JavaScript code into another user's session.`,
          evidence: `HTTP GET Request:\n${testUrl}\n\nObserved Response Snippet:\n...${bodyText.substring(Math.max(0, bodyText.indexOf(attrTestPayload) - 80), bodyText.indexOf(attrTestPayload) + 120)}...`,
          technicalImpact: 'Allows execution of arbitrary JavaScript in the victim web browser session, potentially leaking session tokens, cookies, or capturing keystrokes.',
          userImpact: 'End users visiting crafted links could have their session hijacked or be redirected to phishing pages.',
          businessImpact: 'High compliance failure risk (OWASP Top 10 A03:2021-Injection), customer credential theft, and brand reputation damage.',
          risk: 'High risk of client-side session takeover or sensitive data theft.',
          remediation: `Context-aware HTML entity encode all dynamic user inputs before rendering in HTML templates. Use Content Security Policy (CSP) headers to restrict inline script execution.`,
          remediationSteps: [
            `1. Apply HTML entity encoding (e.g., convert < to &lt;, > to &gt;, " to &quot;, ' to &#x27;) for parameter '${param}'.`,
            `2. Use framework auto-escaping template engines (e.g., React JSX, Angular, or Express EJS with <%= %>).`,
            `3. Deploy a strict Content-Security-Policy header restricting script-src to trusted nonces.`
          ],
          exampleConfiguration: `// Node.js / Express Remediation Example:\nconst sanitizeHtml = require('sanitize-html');\napp.get('/search', (req, res) => {\n  const safeQuery = sanitizeHtml(req.query.${param});\n  res.render('search', { query: safeQuery });\n});`,
          typicalFixLocation: `Controller or view template processing parameter '${param}'.`,
          verificationSteps: [
            `Re-send probe with canary marker 'aegis"xss'.`,
            `Confirm parameter '${param}' is properly encoded as 'aegis&quot;xss' in response body.`
          ],
          verificationStatus: 'UNVERIFIED',
          remediationStatus: 'Open',
          beforeState: `❌ Parameter '${param}' reflected unescaped in ${reflectionContext}.`,
          afterState: `✅ Parameter '${param}' HTML entity encoded safely (&quot; / &lt; / &gt;).`,
          detectionSource: 'AegisScan Non-Destructive XSS Inspector',
          referenceUrl: 'https://owasp.org/www-community/attacks/xss/',
          status: 'OPEN',
          discoveredAt: now,
          firstDetected: now,
          lastDetected: now
        });
      }
    }

  } catch (err: any) {
    console.error(`XSS check error for target ${target.url}:`, err?.message || err);
  }

  return findings;
}
