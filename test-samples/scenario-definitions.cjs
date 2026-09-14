/**
 * Canonical Scenario Definitions (Phase 04 Batch C)
 * 
 * Defines the canonical code templates, browser contexts, threat models,
 * and curated expected findings for all 8 simulated browser application scenarios.
 * 
 * Scenarios represent realistic, multi-flaw browser application workloads
 * and are evaluated separately from the controlled single-flaw V/C confusion matrix.
 */

const CANONICAL_CATEGORIES = {
  'A01': 'A01:2021-Broken Access Control',
  'A02': 'A02:2021-Cryptographic Failures',
  'A03': 'A03:2021-Injection',
  'A05': 'A05:2021-Security Misconfiguration',
  'A06': 'A06:2021-Vulnerable and Outdated Components',
  'A07': 'A07:2021-Identification and Authentication Failures',
  'A08': 'A08:2021-Software and Data Integrity Failures'
};

const scenarioDefinitions = [
  // ==========================================================
  // SCENARIO-001: admin-dashboard.jsx
  // ==========================================================
  {
    id: 'SCENARIO-001',
    fileName: 'admin-dashboard.jsx',
    primaryScenarioName: 'admin-dashboard',
    browserContext: 'React single-page administration dashboard component managing user reports, live analytics widgets, DOM notifications, legacy widget rendering, and navigation links.',
    intendedBehavior: 'Simulated React browser administration dashboard with multiple embedded client-side access control, dynamic markup rendering, and open redirect vulnerabilities.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side React rendering boundary receiving user profile data, organization report HTML, and user-supplied notification strings.',
      attackerControlledInput: 'currentUser.preferredApi, report HTML markup, notification strings, and navigation destination parameters.',
      executionEnvironment: 'Browser DOM / React client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to MEDIUM: DOM XSS via innerHTML/document.write/dangerouslySetInnerHTML, open redirects, and client role check bypasses.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Simulated React component; live browser rendering and DOM event dispatching NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html',
      'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A01-002',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'MEDIUM',
        location: { line: 16, column: 4 },
        weaknessDescription: 'Client-side role check condition currentUser.role === "admin" controls administrative access logging.'
      },
      {
        ruleId: 'OWASP-A03-008',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 43, column: 21 },
        weaknessDescription: 'React dangerouslySetInnerHTML sink assigned unsanitized rawHtml property.'
      },
      {
        ruleId: 'OWASP-A03-004',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 53, column: 12 },
        weaknessDescription: 'Dynamic template literal containing user content assigned directly to container.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-005',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 56, column: 12 },
        weaknessDescription: 'Dynamic function return value formatNotification(content) assigned directly to container.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-007',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 62, column: 8 },
        weaknessDescription: 'document.write invoked with dynamically concatenated widgetData markup.'
      },
      {
        ruleId: 'OWASP-A03-006',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 69, column: 12 },
        weaknessDescription: 'String concatenation of user-supplied menuItems array assigned directly to sidebar.innerHTML.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 81, column: 8 },
        weaknessDescription: 'Unvalidated user destination parameter assigned directly to window.location.href.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 87, column: 8 },
        weaknessDescription: 'Unvalidated partnerRedirect URL passed directly to location.replace().'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 8, column: 0 },
        weaknessDescription: 'Component review advisory for client HTTP library import: axios.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        location: { line: 28, column: 8 },
        weaknessDescription: 'Client-side fetch targeting unvalidated dynamic URL from currentUser.preferredApi.'
      }
    ],
    code: `// ==========================================================
// Admin Dashboard React Component
// Simulates a React-based admin panel with XSS vectors,
// unsafe rendering, and client-side authorization logic.
// ==========================================================

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const AdminDashboard = ({ currentUser }) => {
    const [reports, setReports] = useState([]);
    const [userHtml, setUserHtml] = useState('');
    const [announcements, setAnnouncements] = useState('');

    // Client-side admin authorization check
    if (currentUser.role === "admin") {
        console.log("Admin access granted for:", currentUser);
    }

    // Client-side authentication gate
    if (!currentUser.isAuthenticated) {
        return <div>Access denied. Please log in.</div>;
    }

    // Fetching reports from a dynamic user-controlled endpoint
    useEffect(() => {
        const endpoint = currentUser.preferredApi;
        fetch(endpoint).then(res => res.json()).then(data => {
            setReports(data.reports);
        });

        // Dynamic axios call with template literal URL
        axios.get(\`/api/admin/\${currentUser.orgId}/reports\`).then(res => {
            setAnnouncements(res.data.html);
        });
    }, [currentUser]);

    // Building analytics display using dangerouslySetInnerHTML
    const AnalyticsWidget = ({ rawHtml }) => {
        return (
            <div className="analytics-container">
                <h3>Live Analytics</h3>
                <div dangerouslySetInnerHTML={{ __html: rawHtml }} />
            </div>
        );
    };

    // Rendering user-submitted HTML content
    const renderNotification = (content) => {
        const container = document.getElementById('notification-area');
        if (container) {
            // innerHTML with template literal containing user variable
            container.innerHTML = \`<div class="notification">\${content}</div>\`;
            
            // innerHTML assigned from function return value
            container.innerHTML = formatNotification(content);
        }
    };

    // Writing dynamic content to the page
    const renderLegacyWidget = (widgetData) => {
        document.write("<div class='widget'>" + widgetData + "</div>");
    };

    // Direct innerHTML assignment with concatenation
    const updateSidebar = (menuItems) => {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.innerHTML = "<ul>" + menuItems.join("") + "</ul>";
        }
    };

    // Report export handler
    const exportReport = (reportId) => {
        const exportUrl = \`/api/reports/\${reportId}/export\`;
        window.open(exportUrl, '_blank');
    };

    // Redirect handler with user-controlled destination
    const handleExternalLink = (destination) => {
        window.location.href = destination;
    };

    // Alternative redirect using location.replace
    const navigateToPartner = () => {
        const partnerUrl = currentUser.partnerRedirect;
        location.replace(partnerUrl);
    };

    return (
        <div className="admin-dashboard">
            <header>
                <h1>Administration Panel</h1>
                <p>Welcome, {currentUser.name}</p>
            </header>

            <section className="analytics">
                <AnalyticsWidget rawHtml={announcements} />
            </section>

            <section className="reports">
                <h2>Recent Reports</h2>
                {reports.map((report, index) => (
                    <div key={index} className="report-card">
                        <h3>{report.title}</h3>
                        <p>{report.summary}</p>
                        <button onClick={() => exportReport(report.id)}>
                            Export
                        </button>
                    </div>
                ))}
            </section>

            <section className="quick-actions">
                <button onClick={() => renderLegacyWidget("System Status: Online")}>
                    Load Legacy Widget
                </button>
                <button onClick={() => handleExternalLink("/partner")}>
                    Visit Partner Portal
                </button>
            </section>
        </div>
    );
};

// Helper function for notification formatting
function formatNotification(text) {
    return \`<div class="formatted">\${text}</div>\`;
}

export default AdminDashboard;
`
  },

  // ==========================================================
  // SCENARIO-002: api-gateway.js
  // ==========================================================
  {
    id: 'SCENARIO-002',
    fileName: 'api-gateway.js',
    primaryScenarioName: 'api-gateway',
    browserContext: 'Client-side API gateway and request routing dispatcher for single-page web applications. Manages upstream service endpoints, dynamic routing rule evaluation, webhook data ingestion, client health monitoring, and external navigation redirects.',
    intendedBehavior: 'Simulated browser API client routing module containing code evaluation, prototype pollution, string-based timers, open redirect, and sensitive object logging flaws.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side routing boundary receiving dynamic routing rules, webhook payloads, and redirect URLs from upstream API configurations.',
      attackerControlledInput: 'ruleCode, legacyRule, webhookData overrides/extensions, and destination redirect parameters.',
      executionEnvironment: 'Browser client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution via Function/eval, prototype pollution, unvalidated redirects, and credential exposure in console.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side API routing module; server-side network proxying NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 10, column: 6 },
        weaknessDescription: 'Hardcoded synthetic client API gateway secret in variable clientGatewaySecret.'
      },
      {
        ruleId: 'OWASP-A03-003',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 15, column: 21 },
        weaknessDescription: 'Unsafe Function constructor invoked with untrusted ruleCode input.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 19, column: 25 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied legacyRule string.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 47, column: 24 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated external webhook payload.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 51, column: 4 },
        weaknessDescription: 'Direct __proto__ assignment from untrusted webhookData.overrides object.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 54, column: 4 },
        weaknessDescription: 'Constructor prototype pollution assignment from webhookData.extensions.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 61, column: 4 },
        weaknessDescription: 'Logging sensitive configuration object config to console.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 62, column: 4 },
        weaknessDescription: 'Logging sensitive credentials object credentials to console.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 70, column: 4 },
        weaknessDescription: 'String argument in setInterval for periodic health checking.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 73, column: 4 },
        weaknessDescription: 'Dynamic template literal string in setTimeout for delayed health reporting.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 79, column: 4 },
        weaknessDescription: 'Unvalidated user destination parameter assigned directly to window.location.href.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 80, column: 4 },
        weaknessDescription: 'Unvalidated user destination parameter passed directly to location.replace().'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 7, column: 0 },
        weaknessDescription: 'Component review advisory for client HTTP library import: axios.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        location: { line: 26, column: 4 },
        weaknessDescription: 'Client-side fetch to unvalidated external destination targetService.'
      }
    ],
    code: `// ==========================================================
// Client API Gateway & Proxy Dispatcher
// Simulates a browser client-side API gateway and request
// routing dispatcher for single-page web applications.
// ==========================================================

import axios from 'axios';

// Synthetic client API gateway authentication secret
const clientGatewaySecret = "gateway_secret_synthetic_pr0d_9941";

// Dynamic code execution for custom client routing rules
function executeRoutingRule(ruleCode, legacyRule, requestContext) {
    // Using Function constructor with user input
    const executor = new Function("request", ruleCode);
    const result = executor(requestContext);

    // Using eval for legacy client rule compatibility
    const legacyResult = eval(legacyRule);

    return { result, legacyResult };
}

// Request proxy dispatcher with dynamic target URL
function proxyRequest(targetService, endpoint, payload) {
    // Dynamic URL constructed from user input (client fetch)
    fetch(targetService).then(response => {
        return response.json();
    }).then(data => {
        console.log("Proxy response received:", data);
    });

    // Dynamic axios call with template literal URL
    axios.get(\`\${targetService}/\${endpoint}\`).then(response => {
        console.log("Axios proxy response:", response.data);
    });

    // Dynamic axios post
    axios.post(targetService, payload).then(response => {
        console.log("Posted to target:", response.data);
    });
}

// Webhook payload processor with unsafe deserialization
function processWebhookData(rawPayload, credentials, requestContext) {
    // Unsafe JSON deserialization of external webhook data
    const webhookData = JSON.parse(rawPayload);

    // Prototype pollution through direct __proto__ manipulation
    const config = {};
    config.__proto__ = webhookData.overrides;

    // Prototype pollution through constructor.prototype
    config.constructor.prototype = webhookData.extensions;

    // Unsafe Object.assign with user-controlled source
    const mergedConfig = Object.assign({}, webhookData);

    // Logging full request and configuration objects
    console.log("Webhook received:", requestContext);
    console.log("Processed configuration:", config);
    console.log("Merged credentials:", credentials);

    return { processed: true, config: mergedConfig };
}

// Health check monitor with string-based timers
function startGatewayMonitoring(serviceId) {
    // String argument in setInterval
    setInterval("checkUpstreamServices()", 30000);

    // Dynamic template literal in setTimeout
    setTimeout(\`reportHealth('\${serviceId}')\`, 5000);
}

// Client redirect handler for partner integrations
function dispatchExternalRedirect(destination) {
    // Open redirect vulnerabilities
    window.location.href = destination;
    location.replace(destination);
}

function checkUpstreamServices() {
    return true;
}

function reportHealth(id) {
    return id;
}

export { executeRoutingRule, proxyRequest, processWebhookData, startGatewayMonitoring, dispatchExternalRedirect };
`
  },

  // ==========================================================
  // SCENARIO-003: chat-application.js
  // ==========================================================
  {
    id: 'SCENARIO-003',
    fileName: 'chat-application.js',
    primaryScenarioName: 'chat-application',
    browserContext: 'Browser client-side real-time chat application client module. Manages incoming message feeds, message previews in DOM, file sharing validation, client presence cookies/storage, and interactive bot commands.',
    intendedBehavior: 'Simulated browser real-time chat application containing hardcoded secrets, DOM XSS, eval execution, insecure cookies, local storage tokens, prototype pollution, and string timers.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side message ingestion boundary receiving peer messages, file attachment metadata, and bot commands over WebSocket/HTTP.',
      attackerControlledInput: 'senderId, message, metadata.processingScript, metadata.validationRule, roomConfig overrides, and command strings.',
      executionEnvironment: 'Browser DOM / Client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution via eval/Function, DOM XSS, prototype pollution, session hijacking via cleartext cookies/localStorage.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side chat messaging interface; live WebSocket server connection NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 10, column: 6 },
        weaknessDescription: 'Hardcoded synthetic WebSocket signing secret in variable wsSecret.'
      },
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 13, column: 6 },
        weaknessDescription: 'Hardcoded synthetic Firebase API key in variable firebaseApiKey.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 16, column: 21 },
        weaknessDescription: 'Hardcoded internal IPv4 address string 172.16.0.42.'
      },
      {
        ruleId: 'OWASP-A03-004',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 24, column: 8 },
        weaknessDescription: 'Dynamic template literal containing user senderId and message assigned directly to preview.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-005',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 27, column: 8 },
        weaknessDescription: 'Function return value formatMessage(senderId, message) assigned directly to preview.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-007',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 31, column: 4 },
        weaknessDescription: 'document.write invoked with dynamically concatenated senderId and message strings.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 34, column: 4 },
        weaknessDescription: 'Logging sensitive session object session to console.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 35, column: 4 },
        weaknessDescription: 'Logging sensitive user context object user to console.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 48, column: 23 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated external file metadata.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 51, column: 26 },
        weaknessDescription: 'Dangerous eval() executed with parsed file processingScript.'
      },
      {
        ruleId: 'OWASP-A03-003',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 54, column: 22 },
        weaknessDescription: 'Unsafe Function constructor invoked with user-controlled validationRule.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 62, column: 4 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via dynamic concatenation.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 65, column: 4 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via template literal.'
      },
      {
        ruleId: 'OWASP-A02-003',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'HIGH',
        location: { line: 68, column: 10 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for sensitive session salt.'
      },
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: CANONICAL_CATEGORIES['A07'],
        severity: 'HIGH',
        location: { line: 71, column: 4 },
        weaknessDescription: 'Sensitive authentication token stored directly in unencrypted localStorage.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 78, column: 19 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated room configuration.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 82, column: 4 },
        weaknessDescription: 'Direct __proto__ assignment from untrusted parsed.overrides object.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 88, column: 4 },
        weaknessDescription: 'Constructor prototype pollution assignment from parsed.globalSettings.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 96, column: 19 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied bot command string.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 99, column: 4 },
        weaknessDescription: 'String argument in setTimeout for scheduled bot task execution.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 100, column: 4 },
        weaknessDescription: 'String argument in setInterval for periodic bot queue polling.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 111, column: 24 },
        weaknessDescription: 'Sensitive authentication token embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 118, column: 4 },
        weaknessDescription: 'Unvalidated appUrl parameter assigned directly to window.location.href.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 119, column: 4 },
        weaknessDescription: 'Unvalidated appUrl parameter passed directly to location.replace().'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 7, column: 0 },
        weaknessDescription: 'Component review advisory for client HTTP library import: axios.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        location: { line: 43, column: 4 },
        weaknessDescription: 'Client-side fetch targeting arbitrary user-provided fileUrl.'
      }
    ],
    code: `// ==========================================================
// Browser Real-Time Chat Application Client
// Simulates a client-side real-time messaging client with
// DOM previews, presence tracking, and command execution.
// ==========================================================

import axios from 'axios';

// Hardcoded synthetic WebSocket server secret for message signing
const wsSecret = "ws_signing_key_PartnerChat_Synthetic_2026";

// Hardcoded synthetic Firebase API key for push notifications
const firebaseApiKey = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO";

// Chat server internal IP address
const chatServerIp = "172.16.0.42";

// Message handler with DOM XSS vulnerabilities
function handleIncomingMessage(senderId, message, session, user) {
    // Rendering message preview using innerHTML
    const preview = document.getElementById('preview');
    if (preview) {
        // innerHTML with template literal containing user message
        preview.innerHTML = \`<div class="msg"><strong>\${senderId}</strong>: \${message}</div>\`;

        // innerHTML from function return
        preview.innerHTML = formatMessage(senderId, message);
    }

    // Writing message to legacy display using document.write
    document.write("<p>" + senderId + ": " + message + "</p>");

    // Logging session and user data
    console.log("Message sent in room:", session);
    console.log("User context:", user);

    return { delivered: true };
}

// File sharing handler with dynamic execution risks
function handleSharedFile(fileUrl, metadata) {
    // Dynamic client fetch from user-provided URL
    fetch(fileUrl).then(response => {
        return response.blob();
    });

    // Parsing file metadata from untrusted source
    const parsedMeta = JSON.parse(metadata);

    // Dynamic file processor using eval
    const processResult = eval(parsedMeta.processingScript);

    // Using Function constructor for custom file validators
    const validator = new Function("file", parsedMeta.validationRule);

    return { shared: true, processResult, validator };
}

// User presence tracker with insecure cookie & storage
function trackUserPresence(userId) {
    // Insecure cookie for tracking presence
    document.cookie = "presence=" + userId + "; path=/chat";

    // Template literal cookie assignment
    document.cookie = \`last_active=\${Date.now()}; user=\${userId}\`;

    // Generating insecure session salt
    const sessionSalt = Math.random();

    // Storing session in localStorage
    localStorage.setItem('chatToken', userId);

    return { online: true, userId, sessionSalt };
}

// Room configuration with prototype pollution
function configureChatRoom(roomConfig) {
    const parsed = JSON.parse(roomConfig);

    // Prototype pollution through __proto__
    const defaults = {};
    defaults.__proto__ = parsed.overrides;

    // Unsafe object merge
    const finalConfig = Object.assign({}, parsed);

    // Constructor prototype pollution
    defaults.constructor.prototype = parsed.globalSettings;

    return { configured: true, finalConfig };
}

// Chat bot with dynamic command execution
function executeBotCommand(command) {
    // Executing bot commands via eval
    const output = eval(command);

    // Scheduled bot tasks with string timers
    setTimeout("executeBotTask()", 5000);
    setInterval("checkBotQueue()", 10000);

    return { output };
}

// Notification dispatcher with tracking token
function dispatchNotification(recipientId, content, callbackUrl) {
    // Client POST to callback URL
    axios.post(callbackUrl, { recipient: recipientId, message: content });

    // Notification URL with token in query string
    const trackingUrl = "https://notify.chat.com/track?token=notify_track_tk_123&key=push_service_key";

    return { notified: true, tracking: trackingUrl };
}

// Redirect to companion mobile app
function redirectToMobileApp(appUrl) {
    window.location.href = appUrl;
    location.replace(appUrl);
}

// Message formatting helper
function formatMessage(sender, text) {
    return "<div class='formatted-msg'><b>" + sender + "</b>: " + text + "</div>";
}

function executeBotTask() {
    return true;
}

function checkBotQueue() {
    return true;
}

export {
    handleIncomingMessage,
    handleSharedFile,
    trackUserPresence,
    configureChatRoom,
    executeBotCommand,
    dispatchNotification,
    redirectToMobileApp
};
`
  },

  // ==========================================================
  // SCENARIO-004: data-pipeline.js
  // ==========================================================
  {
    id: 'SCENARIO-004',
    fileName: 'data-pipeline.js',
    primaryScenarioName: 'data-pipeline',
    browserContext: 'Client-side web application data pipeline and analytics worker module. Manages browser-based ETL extraction, record transformations, prototype schemas, analytics export, and recurring telemetry health checks.',
    intendedBehavior: 'Simulated client data processing pipeline containing hardcoded secrets, plaintext network endpoints, Function constructor, eval expressions, prototype pollution, and string timers.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side analytics ingestion boundary receiving query strings, transformation rules, and warehouse credentials.',
      attackerControlledInput: 'sourceQuery, transformRules, validationExpression, patchData globalDefaults, and webhookUrl.',
      executionEnvironment: 'Browser client ECMAScript runtime / Web Worker context.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution via dynamic queries/eval, prototype pollution, cleartext data-in-transit, and credential leakage.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side analytics pipeline simulation; live external warehouse loading NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 13, column: 6 },
        weaknessDescription: 'Hardcoded synthetic AES encryption key in variable encryptionKey.'
      },
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 16, column: 6 },
        weaknessDescription: 'Hardcoded synthetic database connection string containing credentials in mongoSecret.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 19, column: 22 },
        weaknessDescription: 'Hardcoded internal staging server IPv4 address string 10.0.2.15.'
      },
      {
        ruleId: 'OWASP-A03-003',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 32, column: 21 },
        weaknessDescription: 'Unsafe Function constructor invoked with dynamically interpolated sourceQuery.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 44, column: 18 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated transformation rules.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 51, column: 4 },
        weaknessDescription: 'Direct __proto__ assignment from untrusted rules.schemaOverrides object.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 64, column: 22 },
        weaknessDescription: 'Sensitive API key and master secret embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 67, column: 4 },
        weaknessDescription: 'Logging sensitive credentials object credentials to console.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 79, column: 20 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied validationExpression.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 85, column: 18 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated schema patch data.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 88, column: 4 },
        weaknessDescription: 'Constructor prototype pollution assignment from patch.globalDefaults.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 99, column: 4 },
        weaknessDescription: 'String argument in setInterval for periodic pipeline health checking.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 102, column: 4 },
        weaknessDescription: 'String argument in setTimeout for scheduled batch cleanup.'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 7, column: 0 },
        weaknessDescription: 'Component review advisory for library import: lodash.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 8, column: 0 },
        weaknessDescription: 'Component review advisory for library import: axios.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 9, column: 0 },
        weaknessDescription: 'Component review advisory for library import: mongoose.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 10, column: 0 },
        weaknessDescription: 'Component review advisory for library import: jsonwebtoken.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        location: { line: 23, column: 12 },
        weaknessDescription: 'Unencrypted cleartext HTTP endpoint in pipelineConfig.source.'
      },
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        location: { line: 24, column: 17 },
        weaknessDescription: 'Unencrypted cleartext HTTP endpoint in pipelineConfig.destination.'
      }
    ],
    code: `// ==========================================================
// Data Processing Pipeline
// Simulates an ETL data pipeline for ingesting, transforming,
// and exporting datasets with multiple integrity flaws.
// ==========================================================

import lodash from 'lodash';
import axios from 'axios';
import mongoose from 'mongoose';
import jsonwebtoken from 'jsonwebtoken';

// Hardcoded encryption key for data-at-rest
const encryptionKey = "aes256-pipeline-secret-key-prod-v3";

// Hardcoded connection secret for MongoDB
const mongoSecret = "mongodb+srv://admin:Pr0dP@ssw0rd@cluster0.abc123.mongodb.net";

// Internal staging server IP
const stagingServer = "10.0.2.15";

// Pipeline configuration with plaintext endpoints
const pipelineConfig = {
    source: "http://data-lake.internal.corp/api/v2/extract",
    destination: "http://warehouse.staging.corp/api/v1/load",
    retryCount: 3,
    batchSize: 500
};

// Data ingestion with dynamic code evaluation
function ingestData(sourceQuery) {
    // Using Function constructor to build dynamic query filters
    const filterFn = new Function("record", \`return \${sourceQuery}\`);
    
    // Fetching data from pipeline source
    const sourceUrl = pipelineConfig.source;
    fetch(sourceUrl);

    return { status: "ingesting", filter: filterFn };
}

// Transform phase with prototype pollution risks
function transformRecords(records, transformRules) {
    // Parsing transformation rules from external config
    const rules = JSON.parse(transformRules);
    
    // Unsafe merge of user-provided transform config
    const activeConfig = Object.assign({}, rules);
    
    // Direct prototype manipulation for schema extensions
    const schema = {};
    schema.__proto__ = rules.schemaOverrides;

    return records.map(record => {
        const transformed = {};
        for (const key in rules.mappings) {
            transformed[key] = record[rules.mappings[key]];
        }
        return transformed;
    });
}

// Export handler with sensitive data in URL parameters
function exportToWarehouse(dataset, credentials) {
    const exportUrl = "https://warehouse.corp.com/import?key=wh_prod_api_key_9x8z7y&secret=export_master_secret";
    
    // Logging credentials object to console
    console.log("Export initiated with credentials:", credentials);
    
    // Dynamic SSRF endpoint
    const callbackUrl = credentials.webhookUrl;
    axios.post(callbackUrl, { status: "export_complete", records: dataset.length });

    return { exported: true, url: exportUrl };
}

// Data validation with eval-based expression engine
function validateRecord(record, validationExpression) {
    // Using eval for dynamic validation logic
    const isValid = eval(validationExpression);
    return isValid;
}

// Schema migration handler
function migrateSchema(oldSchema, patchData) {
    const patch = JSON.parse(patchData);
    
    // Prototype pollution via constructor.prototype
    oldSchema.constructor.prototype = patch.globalDefaults;
    
    // Unsafe object merge
    const newSchema = Object.assign({}, patch);
    
    return newSchema;
}

// Pipeline monitoring with string-based timers
function startMonitoring() {
    // String argument in setInterval for periodic health checks
    setInterval("checkPipelineHealth()", 60000);
    
    // String argument in setTimeout for delayed cleanup
    setTimeout("cleanupStaleBatches()", 300000);
}

// Batch retry mechanism
function retryFailedBatch(batchId, attempt) {
    if (attempt >= pipelineConfig.retryCount) {
        console.log("Maximum retry attempts reached for batch:", batchId);
        return false;
    }
    
    const delay = Math.pow(2, attempt) * 1000;
    
    setTimeout(() => {
        console.log(\`Retrying batch \${batchId}, attempt \${attempt + 1}\`);
        processBatch(batchId);
    }, delay);
    
    return true;
}

// Batch processor
function processBatch(batchId) {
    const batchData = loadBatch(batchId);
    
    if (!batchData) {
        return { success: false, error: "Batch not found" };
    }
    
    const transformed = batchData.map(record => ({
        id: record.id,
        value: record.rawValue,
        processedAt: new Date().toISOString()
    }));
    
    return { success: true, count: transformed.length };
}

function loadBatch(batchId) {
    return null;
}

startMonitoring();
`
  },

  // ==========================================================
  // SCENARIO-005: ecommerce-checkout.js
  // ==========================================================
  {
    id: 'SCENARIO-005',
    fileName: 'ecommerce-checkout.js',
    primaryScenarioName: 'ecommerce-checkout',
    browserContext: 'Browser client-side e-commerce shopping cart and checkout flow module in a single-page web application. Manages client cart price calculations, session cookies, payment confirmation telemetry, and inventory synchronizations.',
    intendedBehavior: 'Simulated browser e-commerce checkout module containing hardcoded credentials, plaintext HTTP URLs, eval pricing formulas, insecure cookies, string timers, and query string tokens.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client checkout boundary receiving discount formulas, order metadata, and inventory synchronizations.',
      attackerControlledInput: 'discount formula string, orderData metadata, and rawPayload inventory records.',
      executionEnvironment: 'Browser client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution via discount eval, cleartext credential transmission, cookie tampering, and console token leakage.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side checkout flow; live payment gateway charge transaction NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-001',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 13, column: 6 },
        weaknessDescription: 'Hardcoded database password in variable dbPassword.'
      },
      {
        ruleId: 'OWASP-A02-004',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 16, column: 23 },
        weaknessDescription: 'Hardcoded plaintext HTTP connection URL for payment gateway.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 21, column: 21 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied discount formula.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 28, column: 4 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via dynamic concatenation.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 31, column: 4 },
        weaknessDescription: 'String argument in setTimeout for delayed analytics dispatch.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 38, column: 19 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated order metadata.'
      },
      {
        ruleId: 'OWASP-A05-001',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 42, column: 4 },
        weaknessDescription: 'Sensitive paymentToken variable logged to console.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 45, column: 23 },
        weaknessDescription: 'Sensitive paymentToken credential embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 45, column: 80 },
        weaknessDescription: 'Sensitive receipt verification key embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 69, column: 22 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated inventory payload.'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 7, column: 0 },
        weaknessDescription: 'Component review advisory for client HTTP library import: axios.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        location: { line: 27, column: 22 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for checkout session identifier.'
      },
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        location: { line: 48, column: 4 },
        weaknessDescription: 'Unencrypted cleartext HTTP fetch to legacy order status endpoint.'
      }
    ],
    code: `// ==========================================================
// E-Commerce Cart & Checkout Client Module
// Simulates a browser client-side checkout flow with
// pricing evaluation, session cookies, and inventory sync.
// ==========================================================

import axios from 'axios';

// Hardcoded synthetic Stripe API key for client checkout
const stripeApiKey = "sk_test_synthetic_key_stripe_12345";

// Hardcoded synthetic order database password
const dbPassword = "SuperSecretOrderDB!2026";

// Plaintext HTTP endpoint for payment gateway
const paymentGateway = "http://payments.internal-api.com/v2/charge";

// Cart pricing engine using eval to compute discount formulas
function applyDiscount(cart, formula) {
    const total = cart.reduce((sum, item) => sum + item.price, 0);
    const discount = eval(formula);
    return total - discount;
}

// Session cookie set without security flags
function createCheckoutSession(userId, cartId) {
    const sessionId = Math.random().toString(36).substring(7);
    document.cookie = "checkout_session=" + sessionId + "; path=/checkout";

    // Delayed analytics ping with string-based timer
    setTimeout("sendAnalytics('checkout_started')", 2000);

    return sessionId;
}

// Order confirmation handler
function confirmOrder(orderData) {
    const parsed = JSON.parse(orderData.metadata);

    // Logging sensitive payment token to console for debugging
    const paymentToken = parsed.token;
    console.log("Payment confirmation received:", paymentToken);

    // Building a receipt URL with embedded credentials
    const receiptUrl = "https://api.store.com/receipts?token=" + paymentToken + "&key=receipt_verify_key";

    // Fetching order status from plaintext endpoint
    fetch("http://orders.legacy-system.local/status/" + parsed.orderId);

    return { success: true, receipt: receiptUrl };
}

// Tax calculation engine
function calculateTax(items, region) {
    const taxRates = {
        US: 0.08,
        EU: 0.21,
        PH: 0.12
    };

    const rate = taxRates[region] || 0;
    return items.reduce((total, item) => {
        return total + (item.price * rate);
    }, 0);
}

// Inventory check with insecure deserialization
function syncInventory(rawPayload) {
    const inventory = JSON.parse(rawPayload);
    const merged = Object.assign({}, inventory);

    inventory.forEach(item => {
        if (item.stock <= 0) {
            console.log("Out of stock alert for:", item.name);
        }
    });

    return merged;
}

// Shipping rate calculator
function getShippingRate(weight, destination) {
    const baseRates = {
        domestic: 5.99,
        international: 24.99
    };

    if (destination === "PH") {
        return baseRates.domestic;
    }

    return baseRates.international + (weight * 0.5);
}

function sendAnalytics(event) {
    return event;
}

export { applyDiscount, createCheckoutSession, confirmOrder, calculateTax, syncInventory, getShippingRate };
`
  },

  // ==========================================================
  // SCENARIO-006: payment-processor.js
  // ==========================================================
  {
    id: 'SCENARIO-006',
    fileName: 'payment-processor.js',
    primaryScenarioName: 'payment-processor',
    browserContext: 'Browser client-side payment integration SDK and checkout payment client module for single-page applications. Handles customer payment intent creation, refund fee rule evaluations, transaction reconciliation, DOM receipt rendering, and recurring charge scheduling.',
    intendedBehavior: 'Simulated browser payment processing client containing hardcoded merchant keys, plaintext endpoints, localStorage tokens, eval rules, DOM XSS sinks, prototype pollution, and string timers.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side payment integration boundary receiving customer intent parameters, refund policies, and transaction reconciliation feeds.',
      attackerControlledInput: 'refundPolicy, feeFormula, rawData transaction overrides, and portalUrl.',
      executionEnvironment: 'Browser DOM / Client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution, DOM XSS in receipt rendering, prototype pollution, and cleartext credential leakage.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side payment client integration; PCI compliance checks and live payment processing NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 10, column: 6 },
        weaknessDescription: 'Hardcoded synthetic merchant API key in variable merchantApiKey.'
      },
      {
        ruleId: 'OWASP-A02-001',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 11, column: 6 },
        weaknessDescription: 'Hardcoded payment processor password in variable processorPassword.'
      },
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 12, column: 6 },
        weaknessDescription: 'Hardcoded synthetic webhook signing secret in variable webhookSecret.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 15, column: 20 },
        weaknessDescription: 'Hardcoded internal payment processor IPv4 address string 10.128.0.55.'
      },
      {
        ruleId: 'OWASP-A02-004',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 18, column: 23 },
        weaknessDescription: 'Hardcoded plaintext HTTP callback connection URL.'
      },
      {
        ruleId: 'OWASP-A02-003',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'HIGH',
        location: { line: 23, column: 10 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for sensitive transactionKey.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 26, column: 4 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via dynamic concatenation.'
      },
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: CANONICAL_CATEGORIES['A07'],
        severity: 'HIGH',
        location: { line: 29, column: 4 },
        weaknessDescription: 'Sensitive payment authentication token stored directly in unencrypted localStorage.'
      },
      {
        ruleId: 'OWASP-A05-001',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 33, column: 4 },
        weaknessDescription: 'Sensitive apiKey variable logged to console.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 45, column: 25 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied refundPolicy.'
      },
      {
        ruleId: 'OWASP-A03-003',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 48, column: 26 },
        weaknessDescription: 'Unsafe Function constructor invoked with feeFormula string concatenation.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 52, column: 28 },
        weaknessDescription: 'Sensitive refund secret key and merchant verify token embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 64, column: 25 },
        weaknessDescription: 'JSON.parse() deserialization of unvalidated transaction reconciliation data.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 68, column: 4 },
        weaknessDescription: 'Direct __proto__ assignment from untrusted transactions.overrides object.'
      },
      {
        ruleId: 'OWASP-A08-002',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'HIGH',
        location: { line: 74, column: 4 },
        weaknessDescription: 'Constructor prototype pollution assignment from transactions.config.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 77, column: 4 },
        weaknessDescription: 'Logging sensitive credentials object credentials to console.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 78, column: 4 },
        weaknessDescription: 'Logging sensitive session object session to console.'
      },
      {
        ruleId: 'OWASP-A03-004',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 89, column: 8 },
        weaknessDescription: 'Dynamic template literal containing receipt data assigned directly to container.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-005',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 96, column: 8 },
        weaknessDescription: 'Function return value renderReceiptTemplate(receiptData) assigned directly to container.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-007',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 100, column: 4 },
        weaknessDescription: 'document.write invoked with dynamically concatenated receiptData.html.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 106, column: 4 },
        weaknessDescription: 'String argument in setInterval for periodic recurring charge execution.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 107, column: 4 },
        weaknessDescription: 'String argument in setTimeout for scheduled payment reminder dispatch.'
      },
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'HIGH',
        location: { line: 112, column: 4 },
        weaknessDescription: 'Unvalidated portalUrl parameter assigned directly to window.location.href.'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 7, column: 0 },
        weaknessDescription: 'Component review advisory for client HTTP library import: axios.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        location: { line: 55, column: 4 },
        weaknessDescription: 'Client-side fetch targeting dynamic merchant webhook URL.'
      }
    ],
    code: `// ==========================================================
// Browser Payment Integration Client SDK
// Simulates a client-side payment processor with credential
// leaks, unsafe data handling, and receipt DOM rendering.
// ==========================================================

import axios from 'axios';

// Hardcoded payment processing credentials
const merchantApiKey = "pk_live_51N4e2rKj8mHgT3yBw0p9xQzR";
const processorPassword = "PaymentGateway_Pr0d_2026!";
const webhookSecret = "whsec_5a8b9c0d1e2f3g4h5i6j7k8l9m0n";

// Internal payment processor IP
const processorIp = "10.128.0.55";

// Plaintext HTTP callback endpoint
const legacyCallback = "http://legacy-payments.internal.net/callback";

// Payment intent creator
function createPaymentIntent(amount, currency, customerId) {
    // Insecure random transaction token
    const transactionKey = Math.random();

    // Cookie without security flags for payment session
    document.cookie = "payment_session=" + customerId + "; path=/pay";

    // Storing payment token in localStorage
    localStorage.setItem('paymentAuthToken', transactionKey.toString());

    // Logging payment credentials
    const apiKey = merchantApiKey;
    console.log("Processing payment with key:", apiKey);

    return {
        intentId: "pi_" + Date.now(),
        amount,
        currency
    };
}

// Refund processor with dynamic code evaluation
function processRefund(transactionId, reason, refundPolicy, feeFormula, webhookUrl) {
    // Using eval to process refund policy rules
    const refundAmount = eval(refundPolicy);

    // Using Function constructor for custom fee calculation
    const feeCalculator = new Function("amount", "return " + feeFormula);
    const fee = feeCalculator(refundAmount);

    // Sending refund notification with credentials in URL
    const notificationUrl = "https://payments.example.com/notify?secret=refund_webhook_secret_key&token=merchant_verify_tk";

    // Client fetch to merchant webhook
    fetch(webhookUrl);
    axios.post(webhookUrl, { refunded: true, amount: refundAmount });

    return { refunded: true, amount: refundAmount, fee, notificationUrl };
}

// Transaction reconciliation
function reconcileTransactions(rawData, credentials, session, requestContext) {
    // Parsing transaction data from external source
    const transactions = JSON.parse(rawData);

    // Prototype pollution in transaction merge
    const defaults = {};
    defaults.__proto__ = transactions.overrides;

    // Object.assign with untrusted data
    const merged = Object.assign({}, transactions);

    // Constructor prototype manipulation
    defaults.constructor.prototype = transactions.config;

    // Logging full credentials and config
    console.log("Reconciliation data:", credentials);
    console.log("Session details:", session);
    console.log("Full request:", requestContext);

    return { reconciled: true, merged };
}

// Receipt generator with DOM XSS vectors
function renderPaymentReceipt(receiptData) {
    // innerHTML with template literal
    const container = document.getElementById('receipt');
    if (container) {
        container.innerHTML = \`<div class="receipt">
            <h2>Payment Receipt</h2>
            <p>Amount: \${receiptData.amount}</p>
            <p>Status: \${receiptData.status}</p>
        </div>\`;

        // innerHTML from function call
        container.innerHTML = renderReceiptTemplate(receiptData);
    }

    // document.write for legacy printer view
    document.write("<html><body>" + receiptData.html + "</body></html>");
}

// Scheduled payment processor
function scheduleRecurringPayment(customerId, interval) {
    // String-based timer for recurring charges
    setInterval("processRecurringCharge()", interval);
    setTimeout("sendPaymentReminder()", 86400000);
}

// Redirect to payment portal
function redirectToPortal(portalUrl) {
    window.location.href = portalUrl;
}

function processRecurringCharge() {
    return true;
}

function sendPaymentReminder() {
    return true;
}

function renderReceiptTemplate(data) {
    return "<div>" + data.html + "</div>";
}

export {
    createPaymentIntent,
    processRefund,
    reconcileTransactions,
    renderPaymentReceipt,
    scheduleRecurringPayment,
    redirectToPortal
};
`
  },

  // ==========================================================
  // SCENARIO-007: student-portal.jsx
  // ==========================================================
  {
    id: 'SCENARIO-007',
    fileName: 'student-portal.jsx',
    primaryScenarioName: 'student-portal',
    browserContext: 'React student academic portal single-page application component (StudentPortal). Manages student grade viewing, course catalog presentation, student inbox messaging, and course enrollment.',
    intendedBehavior: 'Simulated React student academic portal containing hardcoded credentials, client role check, open redirect, innerHTML rendering, dangerouslySetInnerHTML, insecure cookies, localStorage tokens, eval GPA calculation, and Function constructors.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side React component receiving student profile data, dynamic grade endpoints, course catalog HTML, and message bodies.',
      attackerControlledInput: 'student.isAdmin, student.loginRedirectUrl, student.apiEndpoint, course catalog HTML, message rawContent, and GPA formula.',
      executionEnvironment: 'Browser DOM / React client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Arbitrary code execution via eval/Function, DOM XSS via innerHTML/dangerouslySetInnerHTML, open redirects, and credential exposure.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Simulated student portal React component; live browser rendering NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 16, column: 6 },
        weaknessDescription: 'Hardcoded synthetic portal API key in variable portalApiKey.'
      },
      {
        ruleId: 'OWASP-A02-001',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 19, column: 6 },
        weaknessDescription: 'Hardcoded database password in variable gradeDbPassword.'
      },
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 22, column: 6 },
        weaknessDescription: 'Hardcoded synthetic enrollment system token in variable enrollmentToken.'
      },
      {
        ruleId: 'OWASP-A01-002',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'MEDIUM',
        location: { line: 30, column: 4 },
        weaknessDescription: 'Client-side role check condition student.isAdmin controls admin mode logging.'
      },
      {
        ruleId: 'OWASP-A03-004',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 58, column: 12 },
        weaknessDescription: 'Dynamic template literal containing courseName and grade assigned directly to card.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-005',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 69, column: 12 },
        weaknessDescription: 'Function return value fetchCourseDescription(courseId) assigned directly to descriptionEl.innerHTML.'
      },
      {
        ruleId: 'OWASP-A03-007',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 75, column: 8 },
        weaknessDescription: 'document.write invoked with dynamically passed htmlContent.'
      },
      {
        ruleId: 'OWASP-A03-008',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 83, column: 21 },
        weaknessDescription: 'React dangerouslySetInnerHTML sink assigned unsanitized rawContent message body.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 90, column: 8 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via dynamic concatenation.'
      },
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: CANONICAL_CATEGORIES['A07'],
        severity: 'HIGH',
        location: { line: 93, column: 8 },
        weaknessDescription: 'Sensitive enrollmentToken stored directly in unencrypted localStorage.'
      },
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 96, column: 8 },
        weaknessDescription: 'String argument in setTimeout for delayed enrollment confirmation.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 101, column: 20 },
        weaknessDescription: 'Dangerous eval() executed with user-supplied formula to calculate GPA.'
      },
      {
        ruleId: 'OWASP-A03-003',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'CRITICAL',
        location: { line: 107, column: 27 },
        weaknessDescription: 'Unsafe Function constructor invoked with custom grade weighting string.'
      },
      {
        ruleId: 'OWASP-A02-003',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'HIGH',
        location: { line: 113, column: 14 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for sensitive enrollment OTP.'
      },
      {
        ruleId: 'OWASP-A03-008',
        owasp2021Category: CANONICAL_CATEGORIES['A03'],
        severity: 'HIGH',
        location: { line: 136, column: 21 },
        weaknessDescription: 'React dangerouslySetInnerHTML sink assigned unsanitized courseHtml catalog markup.'
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 9, column: 0 },
        weaknessDescription: 'Component review advisory for library import: serialize-javascript.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 10, column: 0 },
        weaknessDescription: 'Component review advisory for library import: markdown-it.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 11, column: 0 },
        weaknessDescription: 'Component review advisory for library import: js-yaml.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 12, column: 0 },
        weaknessDescription: 'Component review advisory for library import: node-fetch.'
      },
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: CANONICAL_CATEGORIES['A06'],
        severity: 'INFORMATIONAL',
        location: { line: 13, column: 0 },
        weaknessDescription: 'Component review advisory for library import: vm2.'
      }
    ],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        location: { line: 37, column: 8 },
        weaknessDescription: 'Unvalidated redirect via window.location.href to student.loginRedirectUrl.'
      }
    ],
    code: `// ==========================================================
// Student Portal React Component
// Simulates a university student portal with grade viewing,
// enrollment, and messaging features. Contains multiple
// categories of vulnerabilities typical of student projects.
// ==========================================================

import React, { useState, useEffect } from 'react';
import serialize from 'serialize-javascript';
import markdownIt from 'markdown-it';
import jsYaml from 'js-yaml';
import nodeFetch from 'node-fetch';
import vm2 from 'vm2';

// Hardcoded API credentials for the student portal backend
const portalApiKey = "portal_prod_key_Xk9mN2pL7qR4sT6w";

// Hardcoded database password for grade records
const gradeDbPassword = "GradeDB_Admin_2026!";

// Hardcoded enrollment system token
const enrollmentToken = "enroll_sys_tk_8hJ3kL5mN7pQ9rSt";

const StudentPortal = ({ student }) => {
    const [grades, setGrades] = useState([]);
    const [messages, setMessages] = useState([]);
    const [courseHtml, setCourseHtml] = useState('');

    // Client-side admin check for grade override panel
    if (student.isAdmin) {
        console.log("Admin mode activated for student:", student);
    }

    // Client-side authentication gate
    if (!student.isAuthenticated) {
        // Open redirect to login page using dynamic variable
        window.location.href = student.loginRedirectUrl;
        return null;
    }

    useEffect(() => {
        // Fetching grades from dynamic student endpoint
        const gradesUrl = student.apiEndpoint;
        fetch(gradesUrl).then(res => res.json()).then(data => {
            setGrades(data.grades);
        });

        // Loading course catalog
        axios.get(\`/api/courses/\${student.departmentId}/catalog\`).then(res => {
            setCourseHtml(res.data.htmlContent);
        });
    }, [student]);

    // Grade display using innerHTML with template literal
    const renderGradeCard = (courseName, grade) => {
        const card = document.getElementById('grade-display');
        if (card) {
            card.innerHTML = \`<div class="grade-card">
                <h3>\${courseName}</h3>
                <span class="grade">\${grade}</span>
            </div>\`;
        }
    };

    // Course description renderer using innerHTML from function
    const renderCourseDescription = (courseId) => {
        const descriptionEl = document.getElementById('course-desc');
        if (descriptionEl) {
            descriptionEl.innerHTML = fetchCourseDescription(courseId);
        }
    };

    // Announcement board using document.write
    const loadAnnouncement = (htmlContent) => {
        document.write(htmlContent);
    };

    // Message composer with dangerouslySetInnerHTML
    const MessagePreview = ({ rawContent }) => {
        return (
            <div className="message-preview">
                <h4>Message Preview</h4>
                <div dangerouslySetInnerHTML={{ __html: rawContent }} />
            </div>
        );
    };

    // Enrollment handler with insecure cookie
    const enrollInCourse = (courseId) => {
        document.cookie = "enrollment_session=" + courseId + "; path=/enroll";

        // Storing enrollment token in localStorage
        localStorage.setItem('enrollmentToken', enrollmentToken);

        // Using setTimeout with string for delayed confirmation
        setTimeout("confirmEnrollment()", 3000);
    };

    // Grade calculator using eval
    const calculateGPA = (formula) => {
        const gpa = eval(formula);
        return gpa;
    };

    // Dynamic code execution for custom grade weighting
    const applyWeighting = (weights) => {
        const calculator = new Function("grades", weights);
        return calculator(grades);
    };

    // Insecure random OTP for two-factor enrollment verification
    const generateEnrollmentOtp = () => {
        const otp = Math.random();
        return otp.toString().slice(2, 8);
    };

    return (
        <div className="student-portal">
            <header>
                <h1>Student Academic Portal</h1>
                <p>Student: {student.name} ({student.studentId})</p>
            </header>

            <section className="grades">
                <h2>Current Grades</h2>
                {grades.map((g, i) => (
                    <div key={i} className="grade-entry">
                        <span>{g.course}</span>
                        <span className="grade-value">{g.value}</span>
                    </div>
                ))}
            </section>

            <section className="course-catalog">
                <h2>Course Catalog</h2>
                <div dangerouslySetInnerHTML={{ __html: courseHtml }} />
            </section>

            <section className="messages">
                <h2>Inbox</h2>
                {messages.map((msg, i) => (
                    <MessagePreview key={i} rawContent={msg.body} />
                ))}
            </section>
        </div>
    );
};

// Helper: fetch course description from API
function fetchCourseDescription(courseId) {
    return "<p>Loading description for course " + courseId + "...</p>";
}

export default StudentPortal;
`
  },

  // ==========================================================
  // SCENARIO-008: user-auth-service.js
  // ==========================================================
  {
    id: 'SCENARIO-008',
    fileName: 'user-auth-service.js',
    primaryScenarioName: 'user-auth-service',
    browserContext: 'Browser client-side user authentication and session management module for single-page applications. Manages client-side login validation, token storage in localStorage, insecure session cookies, password reset callbacks, and client role verification.',
    intendedBehavior: 'Simulated client user authentication module containing hardcoded admin master passwords, JWT secrets, AWS access keys, internal IP strings, query string reset tokens, plaintext verification endpoints, insecure random tokens, unencrypted localStorage tokens, and insecure session cookies.',
    threatModelAndAssumptions: {
      trustBoundary: 'Client-side authentication state boundary receiving user credentials, session headers, and password reset responses.',
      attackerControlledInput: 'username, password, email, and sessionData payload.',
      executionEnvironment: 'Browser client ECMAScript runtime.',
      impactSupportingSeverity: 'CRITICAL to LOW: Credential exposure, privilege escalation via client role bypass, cleartext transmission of sensitive data, and token theft from localStorage.',
      safePartnerAssumptions: 'N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled single-flaw V/C pairs.'
    },
    limitations: 'Client-side authentication service simulation; backend user database and live authentication server NOT RUN.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ],
    expectedFindings: [
      {
        ruleId: 'OWASP-A02-001',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 8, column: 6 },
        weaknessDescription: 'Hardcoded admin master password in variable masterPassword.'
      },
      {
        ruleId: 'OWASP-A02-006',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 11, column: 6 },
        weaknessDescription: 'Hardcoded API key or secret found in variable jwtSecret.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 11, column: 18 },
        weaknessDescription: 'Hardcoded JWT Token detected in string.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'CRITICAL',
        location: { line: 14, column: 21 },
        weaknessDescription: 'Hardcoded AWS Access Key detected in string.'
      },
      {
        ruleId: 'OWASP-A02-005',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 17, column: 15 },
        weaknessDescription: 'Hardcoded internal database server IPv4 address string 192.168.1.105.'
      },
      {
        ruleId: 'OWASP-A02-003',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'HIGH',
        location: { line: 21, column: 10 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for sensitive token.'
      },
      {
        ruleId: 'OWASP-A02-003',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'HIGH',
        location: { line: 22, column: 10 },
        weaknessDescription: 'Insecure pseudo-random number generator Math.random() used for sensitive otpCode.'
      },
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: CANONICAL_CATEGORIES['A07'],
        severity: 'HIGH',
        location: { line: 25, column: 4 },
        weaknessDescription: 'Sensitive authentication token stored directly in unencrypted localStorage.'
      },
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: CANONICAL_CATEGORIES['A07'],
        severity: 'HIGH',
        location: { line: 26, column: 4 },
        weaknessDescription: 'Sensitive JWT session secret stored directly in unencrypted localStorage.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 36, column: 8 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via dynamic concatenation.'
      },
      {
        ruleId: 'OWASP-A02-002',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 39, column: 8 },
        weaknessDescription: 'document.cookie written without Secure or HttpOnly protection via template literal.'
      },
      {
        ruleId: 'OWASP-A05-001',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 42, column: 8 },
        weaknessDescription: 'Sensitive password variable logged to console.'
      },
      {
        ruleId: 'OWASP-A02-007',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 53, column: 22 },
        weaknessDescription: 'Sensitive password reset token and temporary password embedded in URL query string.'
      },
      {
        ruleId: 'OWASP-A02-004',
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        severity: 'MEDIUM',
        location: { line: 56, column: 27 },
        weaknessDescription: 'Hardcoded plaintext HTTP verification callback URL.'
      },
      {
        ruleId: 'OWASP-A08-001',
        owasp2021Category: CANONICAL_CATEGORIES['A08'],
        severity: 'LOW',
        location: { line: 70, column: 20 },
        weaknessDescription: 'JSON.parse() deserialization of untrusted sessionData string.'
      },
      {
        ruleId: 'OWASP-A01-002',
        owasp2021Category: CANONICAL_CATEGORIES['A01'],
        severity: 'MEDIUM',
        location: { line: 74, column: 4 },
        weaknessDescription: 'Client-side role check condition session.role === "admin" assigns admin status.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 84, column: 4 },
        weaknessDescription: 'Logging sensitive user object user to console.'
      },
      {
        ruleId: 'OWASP-A05-003',
        owasp2021Category: CANONICAL_CATEGORIES['A05'],
        severity: 'MEDIUM',
        location: { line: 85, column: 4 },
        weaknessDescription: 'Logging sensitive session object session to console.'
      }
    ],
    expectedAdvisories: [],
    unsupportedWeaknesses: [
      {
        ruleId: null,
        unsupported: true,
        owasp2021Category: CANONICAL_CATEGORIES['A02'],
        location: { line: 33, column: 4 },
        weaknessDescription: 'Direct plain-text password comparison against staging credential constant.'
      }
    ],
    code: `// ==========================================================
// Browser Client User Authentication Service
// Simulates client-side login, session management, and
// token storage with realistic broken authentication flaws.
// ==========================================================

// Hardcoded admin master password for fallback access
const masterPassword = "Admin@FallbackAccess_2026!";

// Hardcoded JWT signing secret
const jwtSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

// AWS Access Key left in source code
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";

// Internal database server IP address
const dbHost = "192.168.1.105";

// Insecure token generation using Math.random
function generateResetToken(userId) {
    const token = Math.random();
    const otpCode = Math.random();

    // Storing auth token in localStorage
    localStorage.setItem('authToken', token.toString());
    localStorage.setItem('jwt_session', jwtSecret);

    return { token, otpCode, userId };
}

// Login handler with hardcoded credential comparison
function handleUserLogin(username, password) {
    // Comparing user input against a hardcoded password
    if (password === "StagingPassword123!") {
        // Insecure session cookie without HttpOnly or Secure
        document.cookie = "sid=" + username + "; path=/";

        // Template literal cookie assignment
        document.cookie = \`auth_level=admin; user=\${username}\`;

        // Logging sensitive credentials to console
        console.log("Login successful for user:", password);

        return { authenticated: true };
    }

    return { authenticated: false, error: "Invalid credentials" };
}

// Password reset with embedded secrets in query string
function requestPasswordReset(email) {
    // Password reset link with token in URL
    const resetLink = "https://app.example.com/reset?token=abc123def456&password=temporary_reset_pw";

    // Using insecure HTTP for verification callback
    const verifyEndpoint = "http://verify.internal-auth.com/validate";
    fetch(verifyEndpoint);

    console.log("Password reset initiated for:", email);
    return { message: "Reset email dispatched", link: resetLink };
}

// Session validation helper
function validateClientSession(sessionData) {
    if (!sessionData) {
        return { valid: false, error: "No session found" };
    }

    // Parsing untrusted session data
    const session = JSON.parse(sessionData);

    // Client-side role check for admin privileges
    let isAdmin = false;
    if (session.role === "admin") {
        isAdmin = true;
    }

    return { valid: session.isAuthenticated, isAdmin };
}

// Account deletion with console logging of sensitive objects
function processAccountDeletion(user, session, requestContext) {
    // Logging complete user and session objects
    console.log("Account deletion requested:", user);
    console.log("Active session state:", session);
    console.log("Full request context:", requestContext);

    return { deleted: true };
}

export {
    generateResetToken,
    handleUserLogin,
    requestPasswordReset,
    validateClientSession,
    processAccountDeletion
};
`
  }
];

module.exports = { scenarioDefinitions, CANONICAL_CATEGORIES };
