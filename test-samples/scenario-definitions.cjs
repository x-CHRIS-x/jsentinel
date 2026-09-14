/**
 * Canonical Scenario Definitions (Phase 04 Batch C - Curated Ground Truth)
 * 
 * Defines canonical templates, browser contexts, threat models, and strictly
 * curated expected findings, advisories, and unsupported weaknesses for all 8 scenarios.
 * 
 * Evaluated separately from the controlled V/C dataset.
 */

const CANONICAL_CATEGORIES = {
  "A01": "A01:2021-Broken Access Control",
  "A02": "A02:2021-Cryptographic Failures",
  "A03": "A03:2021-Injection",
  "A05": "A05:2021-Security Misconfiguration",
  "A06": "A06:2021-Vulnerable and Outdated Components",
  "A07": "A07:2021-Identification and Authentication Failures",
  "A08": "A08:2021-Software and Data Integrity Failures",
  "A10": "A10:2021-Server-Side Request Forgery"
};

const scenarioDefinitions = [
  {
    "id": "SCENARIO-001",
    "fileName": "admin-dashboard.jsx",
    "primaryScenarioName": "admin-dashboard",
    "browserContext": "React single-page administration dashboard component managing user reports, live analytics widgets, DOM notifications, legacy widget rendering, and navigation links.",
    "intendedBehavior": "Simulated React browser administration dashboard with multiple embedded client-side access control, dynamic markup rendering, and open redirect vulnerabilities.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Client-side React rendering boundary receiving user profile data, organization report HTML, and user-supplied notification strings.",
      "attackerControlledInput": "currentUser.partnerRedirect, report HTML markup, and notification strings.",
      "executionEnvironment": "Browser DOM / React client ECMAScript runtime.",
      "impactSupportingSeverity": "CRITICAL to HIGH: DOM XSS via innerHTML/document.write/dangerouslySetInnerHTML and open redirects.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Simulated React component; live browser rendering and DOM event dispatching NOT RUN. Scanner hit at line 16 (currentUser.role === \"admin\") is omitted from expected findings as it only gates console.log with no authorization decision.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html",
      "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A03-008",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 43,
          "column": 21
        },
        "weaknessDescription": "React dangerouslySetInnerHTML sink assigned unsanitized report HTML announcements in demonstrated component flow."
      },
      {
        "ruleId": "OWASP-A03-004",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 53,
          "column": 12
        },
        "weaknessDescription": "Callable helper renderNotification assigns unescaped content in template literal directly to container.innerHTML sink."
      },
      {
        "ruleId": "OWASP-A03-005",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 56,
          "column": 12
        },
        "weaknessDescription": "Callable helper renderNotification assigns unescaped helper return value directly to container.innerHTML sink."
      },
      {
        "ruleId": "OWASP-A03-007",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 62,
          "column": 8
        },
        "weaknessDescription": "Callable helper renderLegacyWidget passes widgetData directly to document.write(); note demonstrated flow at line 115 passes a fixed constant string."
      },
      {
        "ruleId": "OWASP-A03-006",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 69,
          "column": 12
        },
        "weaknessDescription": "Callable helper updateSidebar concatenates unescaped menuItems directly into sidebar.innerHTML."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 81,
          "column": 8
        },
        "weaknessDescription": "Callable helper handleExternalLink assigns unvalidated destination to window.location.href; note demonstrated flow at line 118 passes static relative path \"/partner\"."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 87,
          "column": 8
        },
        "weaknessDescription": "Callable helper navigateToPartner assigns unvalidated user-controlled property currentUser.partnerRedirect directly to location.replace()."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 8,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client HTTP library import: axios."
      }
    ],
    "unsupportedWeaknesses": [],
    "code": "// ==========================================================\r\n// Admin Dashboard React Component\r\n// Simulates a React-based admin panel with XSS vectors,\r\n// unsafe rendering, and client-side authorization logic.\r\n// ==========================================================\r\n\r\nimport React, { useState, useEffect } from 'react';\r\nimport axios from 'axios';\r\n\r\nconst AdminDashboard = ({ currentUser }) => {\r\n    const [reports, setReports] = useState([]);\r\n    const [userHtml, setUserHtml] = useState('');\r\n    const [announcements, setAnnouncements] = useState('');\r\n\r\n    // Client-side admin authorization check\r\n    if (currentUser.role === \"admin\") {\r\n        console.log(\"Admin access granted for:\", currentUser);\r\n    }\r\n\r\n    // Client-side authentication gate\r\n    if (!currentUser.isAuthenticated) {\r\n        return <div>Access denied. Please log in.</div>;\r\n    }\r\n\r\n    // Fetching reports from a dynamic user-controlled endpoint\r\n    useEffect(() => {\r\n        const endpoint = currentUser.preferredApi;\r\n        fetch(endpoint).then(res => res.json()).then(data => {\r\n            setReports(data.reports);\r\n        });\r\n\r\n        // Dynamic axios call with template literal URL\r\n        axios.get(`/api/admin/${currentUser.orgId}/reports`).then(res => {\r\n            setAnnouncements(res.data.html);\r\n        });\r\n    }, [currentUser]);\r\n\r\n    // Building analytics display using dangerouslySetInnerHTML\r\n    const AnalyticsWidget = ({ rawHtml }) => {\r\n        return (\r\n            <div className=\"analytics-container\">\r\n                <h3>Live Analytics</h3>\r\n                <div dangerouslySetInnerHTML={{ __html: rawHtml }} />\r\n            </div>\r\n        );\r\n    };\r\n\r\n    // Rendering user-submitted HTML content\r\n    const renderNotification = (content) => {\r\n        const container = document.getElementById('notification-area');\r\n        if (container) {\r\n            // innerHTML with template literal containing user variable\r\n            container.innerHTML = `<div class=\"notification\">${content}</div>`;\r\n            \r\n            // innerHTML assigned from function return value\r\n            container.innerHTML = formatNotification(content);\r\n        }\r\n    };\r\n\r\n    // Writing dynamic content to the page\r\n    const renderLegacyWidget = (widgetData) => {\r\n        document.write(\"<div class='widget'>\" + widgetData + \"</div>\");\r\n    };\r\n\r\n    // Direct innerHTML assignment with concatenation\r\n    const updateSidebar = (menuItems) => {\r\n        const sidebar = document.getElementById('sidebar');\r\n        if (sidebar) {\r\n            sidebar.innerHTML = \"<ul>\" + menuItems.join(\"\") + \"</ul>\";\r\n        }\r\n    };\r\n\r\n    // Report export handler\r\n    const exportReport = (reportId) => {\r\n        const exportUrl = `/api/reports/${reportId}/export`;\r\n        window.open(exportUrl, '_blank');\r\n    };\r\n\r\n    // Redirect handler with user-controlled destination\r\n    const handleExternalLink = (destination) => {\r\n        window.location.href = destination;\r\n    };\r\n\r\n    // Alternative redirect using location.replace\r\n    const navigateToPartner = () => {\r\n        const partnerUrl = currentUser.partnerRedirect;\r\n        location.replace(partnerUrl);\r\n    };\r\n\r\n    return (\r\n        <div className=\"admin-dashboard\">\r\n            <header>\r\n                <h1>Administration Panel</h1>\r\n                <p>Welcome, {currentUser.name}</p>\r\n            </header>\r\n\r\n            <section className=\"analytics\">\r\n                <AnalyticsWidget rawHtml={announcements} />\r\n            </section>\r\n\r\n            <section className=\"reports\">\r\n                <h2>Recent Reports</h2>\r\n                {reports.map((report, index) => (\r\n                    <div key={index} className=\"report-card\">\r\n                        <h3>{report.title}</h3>\r\n                        <p>{report.summary}</p>\r\n                        <button onClick={() => exportReport(report.id)}>\r\n                            Export\r\n                        </button>\r\n                    </div>\r\n                ))}\r\n            </section>\r\n\r\n            <section className=\"quick-actions\">\r\n                <button onClick={() => renderLegacyWidget(\"System Status: Online\")}>\r\n                    Load Legacy Widget\r\n                </button>\r\n                <button onClick={() => handleExternalLink(\"/partner\")}>\r\n                    Visit Partner Portal\r\n                </button>\r\n            </section>\r\n        </div>\r\n    );\r\n};\r\n\r\n// Helper function for notification formatting\r\nfunction formatNotification(text) {\r\n    return `<div class=\"formatted\">${text}</div>`;\r\n}\r\n\r\nexport default AdminDashboard;\r\n",
    "template": "// ==========================================================\r\n// Admin Dashboard React Component\r\n// Simulates a React-based admin panel with XSS vectors,\r\n// unsafe rendering, and client-side authorization logic.\r\n// ==========================================================\r\n\r\nimport React, { useState, useEffect } from 'react';\r\nimport axios from 'axios';\r\n\r\nconst AdminDashboard = ({ currentUser }) => {\r\n    const [reports, setReports] = useState([]);\r\n    const [userHtml, setUserHtml] = useState('');\r\n    const [announcements, setAnnouncements] = useState('');\r\n\r\n    // Client-side admin authorization check\r\n    if (currentUser.role === \"admin\") {\r\n        console.log(\"Admin access granted for:\", currentUser);\r\n    }\r\n\r\n    // Client-side authentication gate\r\n    if (!currentUser.isAuthenticated) {\r\n        return <div>Access denied. Please log in.</div>;\r\n    }\r\n\r\n    // Fetching reports from a dynamic user-controlled endpoint\r\n    useEffect(() => {\r\n        const endpoint = currentUser.preferredApi;\r\n        fetch(endpoint).then(res => res.json()).then(data => {\r\n            setReports(data.reports);\r\n        });\r\n\r\n        // Dynamic axios call with template literal URL\r\n        axios.get(`/api/admin/${currentUser.orgId}/reports`).then(res => {\r\n            setAnnouncements(res.data.html);\r\n        });\r\n    }, [currentUser]);\r\n\r\n    // Building analytics display using dangerouslySetInnerHTML\r\n    const AnalyticsWidget = ({ rawHtml }) => {\r\n        return (\r\n            <div className=\"analytics-container\">\r\n                <h3>Live Analytics</h3>\r\n                <div dangerouslySetInnerHTML={{ __html: rawHtml }} />\r\n            </div>\r\n        );\r\n    };\r\n\r\n    // Rendering user-submitted HTML content\r\n    const renderNotification = (content) => {\r\n        const container = document.getElementById('notification-area');\r\n        if (container) {\r\n            // innerHTML with template literal containing user variable\r\n            container.innerHTML = `<div class=\"notification\">${content}</div>`;\r\n            \r\n            // innerHTML assigned from function return value\r\n            container.innerHTML = formatNotification(content);\r\n        }\r\n    };\r\n\r\n    // Writing dynamic content to the page\r\n    const renderLegacyWidget = (widgetData) => {\r\n        document.write(\"<div class='widget'>\" + widgetData + \"</div>\");\r\n    };\r\n\r\n    // Direct innerHTML assignment with concatenation\r\n    const updateSidebar = (menuItems) => {\r\n        const sidebar = document.getElementById('sidebar');\r\n        if (sidebar) {\r\n            sidebar.innerHTML = \"<ul>\" + menuItems.join(\"\") + \"</ul>\";\r\n        }\r\n    };\r\n\r\n    // Report export handler\r\n    const exportReport = (reportId) => {\r\n        const exportUrl = `/api/reports/${reportId}/export`;\r\n        window.open(exportUrl, '_blank');\r\n    };\r\n\r\n    // Redirect handler with user-controlled destination\r\n    const handleExternalLink = (destination) => {\r\n        window.location.href = destination;\r\n    };\r\n\r\n    // Alternative redirect using location.replace\r\n    const navigateToPartner = () => {\r\n        const partnerUrl = currentUser.partnerRedirect;\r\n        location.replace(partnerUrl);\r\n    };\r\n\r\n    return (\r\n        <div className=\"admin-dashboard\">\r\n            <header>\r\n                <h1>Administration Panel</h1>\r\n                <p>Welcome, {currentUser.name}</p>\r\n            </header>\r\n\r\n            <section className=\"analytics\">\r\n                <AnalyticsWidget rawHtml={announcements} />\r\n            </section>\r\n\r\n            <section className=\"reports\">\r\n                <h2>Recent Reports</h2>\r\n                {reports.map((report, index) => (\r\n                    <div key={index} className=\"report-card\">\r\n                        <h3>{report.title}</h3>\r\n                        <p>{report.summary}</p>\r\n                        <button onClick={() => exportReport(report.id)}>\r\n                            Export\r\n                        </button>\r\n                    </div>\r\n                ))}\r\n            </section>\r\n\r\n            <section className=\"quick-actions\">\r\n                <button onClick={() => renderLegacyWidget(\"System Status: Online\")}>\r\n                    Load Legacy Widget\r\n                </button>\r\n                <button onClick={() => handleExternalLink(\"/partner\")}>\r\n                    Visit Partner Portal\r\n                </button>\r\n            </section>\r\n        </div>\r\n    );\r\n};\r\n\r\n// Helper function for notification formatting\r\nfunction formatNotification(text) {\r\n    return `<div class=\"formatted\">${text}</div>`;\r\n}\r\n\r\nexport default AdminDashboard;\r\n"
  },
  {
    "id": "SCENARIO-002",
    "fileName": "api-gateway.js",
    "primaryScenarioName": "api-gateway",
    "browserContext": "Browser client-side API request router and proxy dispatcher managing endpoint dispatching, JWT authorization headers, and custom rule execution.",
    "intendedBehavior": "Simulated client-side API routing dispatcher with dynamic code evaluation, hardcoded credentials, prototype pollution, and open redirect vulnerabilities.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Client-side routing boundary between external webhook/routing inputs and internal service dispatchers.",
      "attackerControlledInput": "ruleCode, legacyRule, webhookData overrides/extensions, and redirection destinations.",
      "executionEnvironment": "Browser ECMAScript runtime environment.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Arbitrary code execution via new Function/eval, prototype pollution, credential leaks in console, and open redirects.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client-side routing module; backend microservices and live network responses NOT RUN. Scanner hit at line 47 (JSON.parse) is omitted as a syntactic pattern hit.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 10,
          "column": 6
        },
        "weaknessDescription": "Hardcoded client API gateway secret key stored in client source code."
      },
      {
        "ruleId": "OWASP-A03-003",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 15,
          "column": 21
        },
        "weaknessDescription": "Unsafe use of Function constructor to execute dynamic user-controlled routing ruleCode."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 19,
          "column": 25
        },
        "weaknessDescription": "Dangerous use of eval() on unvalidated legacy routing rule string."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 51,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through direct __proto__ assignment with untrusted webhook data."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 54,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through constructor.prototype assignment with untrusted webhook data."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 62,
          "column": 4
        },
        "weaknessDescription": "Logging sensitive credentials object directly to browser console."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 70,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string argument in setInterval for periodic monitoring."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 73,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of dynamic template literal in setTimeout for health reporting."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 79,
          "column": 4
        },
        "weaknessDescription": "Open redirect via unvalidated destination assigned to window.location.href."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 80,
          "column": 4
        },
        "weaknessDescription": "Open redirect via unvalidated destination passed to location.replace()."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 7,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client HTTP library import: axios."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A10:2021-Server-Side Request Forgery",
        "severity": "MEDIUM",
        "severityAssumptions": "Transmits caller payload to arbitrary user-supplied targetService; scanner rules lack detection for axios.post dynamic target URLs.",
        "trustBoundary": "Client API gateway routing boundary to external endpoints.",
        "attackerControlledInput": "targetService and payload parameters.",
        "exploitCondition": "Attacker directs client request to internal intranet service or malicious exfiltration endpoint.",
        "securityImpact": "MEDIUM: Client-side request redirection / CSRF to internal network.",
        "location": {
          "line": 39,
          "column": 4
        },
        "weaknessDescription": "Client-side POST dispatching payload to unvalidated targetService URL."
      }
    ],
    "code": "// ==========================================================\r\n// Client API Gateway & Proxy Dispatcher\r\n// Simulates a browser client-side API gateway and request\r\n// routing dispatcher for single-page web applications.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Synthetic client API gateway authentication secret\r\nconst clientGatewaySecret = \"gateway_secret_synthetic_pr0d_9941\";\r\n\r\n// Dynamic code execution for custom client routing rules\r\nfunction executeRoutingRule(ruleCode, legacyRule, requestContext) {\r\n    // Using Function constructor with user input\r\n    const executor = new Function(\"request\", ruleCode);\r\n    const result = executor(requestContext);\r\n\r\n    // Using eval for legacy client rule compatibility\r\n    const legacyResult = eval(legacyRule);\r\n\r\n    return { result, legacyResult };\r\n}\r\n\r\n// Request proxy dispatcher with dynamic target URL\r\nfunction proxyRequest(targetService, endpoint, payload) {\r\n    // Dynamic URL constructed from user input (client fetch)\r\n    fetch(targetService).then(response => {\r\n        return response.json();\r\n    }).then(data => {\r\n        console.log(\"Proxy response received:\", data);\r\n    });\r\n\r\n    // Dynamic axios call with template literal URL\r\n    axios.get(`${targetService}/${endpoint}`).then(response => {\r\n        console.log(\"Axios proxy response:\", response.data);\r\n    });\r\n\r\n    // Dynamic axios post\r\n    axios.post(targetService, payload).then(response => {\r\n        console.log(\"Posted to target:\", response.data);\r\n    });\r\n}\r\n\r\n// Webhook payload processor with unsafe deserialization\r\nfunction processWebhookData(rawPayload, credentials, requestContext) {\r\n    // Unsafe JSON deserialization of external webhook data\r\n    const webhookData = JSON.parse(rawPayload);\r\n\r\n    // Prototype pollution through direct __proto__ manipulation\r\n    const config = {};\r\n    config.__proto__ = webhookData.overrides;\r\n\r\n    // Prototype pollution through constructor.prototype\r\n    config.constructor.prototype = webhookData.extensions;\r\n\r\n    // Unsafe Object.assign with user-controlled source\r\n    const mergedConfig = Object.assign({}, webhookData);\r\n\r\n    // Logging full request and configuration objects\r\n    console.log(\"Webhook received:\", requestContext);\r\n    console.log(\"Processed configuration:\", config);\r\n    console.log(\"Merged credentials:\", credentials);\r\n\r\n    return { processed: true, config: mergedConfig };\r\n}\r\n\r\n// Health check monitor with string-based timers\r\nfunction startGatewayMonitoring(serviceId) {\r\n    // String argument in setInterval\r\n    setInterval(\"checkUpstreamServices()\", 30000);\r\n\r\n    // Dynamic template literal in setTimeout\r\n    setTimeout(`reportHealth('${serviceId}')`, 5000);\r\n}\r\n\r\n// Client redirect handler for partner integrations\r\nfunction dispatchExternalRedirect(destination) {\r\n    // Open redirect vulnerabilities\r\n    window.location.href = destination;\r\n    location.replace(destination);\r\n}\r\n\r\nfunction checkUpstreamServices() {\r\n    return true;\r\n}\r\n\r\nfunction reportHealth(id) {\r\n    return id;\r\n}\r\n\r\nexport { executeRoutingRule, proxyRequest, processWebhookData, startGatewayMonitoring, dispatchExternalRedirect };\r\n",
    "template": "// ==========================================================\r\n// Client API Gateway & Proxy Dispatcher\r\n// Simulates a browser client-side API gateway and request\r\n// routing dispatcher for single-page web applications.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Synthetic client API gateway authentication secret\r\nconst clientGatewaySecret = \"gateway_secret_synthetic_pr0d_9941\";\r\n\r\n// Dynamic code execution for custom client routing rules\r\nfunction executeRoutingRule(ruleCode, legacyRule, requestContext) {\r\n    // Using Function constructor with user input\r\n    const executor = new Function(\"request\", ruleCode);\r\n    const result = executor(requestContext);\r\n\r\n    // Using eval for legacy client rule compatibility\r\n    const legacyResult = eval(legacyRule);\r\n\r\n    return { result, legacyResult };\r\n}\r\n\r\n// Request proxy dispatcher with dynamic target URL\r\nfunction proxyRequest(targetService, endpoint, payload) {\r\n    // Dynamic URL constructed from user input (client fetch)\r\n    fetch(targetService).then(response => {\r\n        return response.json();\r\n    }).then(data => {\r\n        console.log(\"Proxy response received:\", data);\r\n    });\r\n\r\n    // Dynamic axios call with template literal URL\r\n    axios.get(`${targetService}/${endpoint}`).then(response => {\r\n        console.log(\"Axios proxy response:\", response.data);\r\n    });\r\n\r\n    // Dynamic axios post\r\n    axios.post(targetService, payload).then(response => {\r\n        console.log(\"Posted to target:\", response.data);\r\n    });\r\n}\r\n\r\n// Webhook payload processor with unsafe deserialization\r\nfunction processWebhookData(rawPayload, credentials, requestContext) {\r\n    // Unsafe JSON deserialization of external webhook data\r\n    const webhookData = JSON.parse(rawPayload);\r\n\r\n    // Prototype pollution through direct __proto__ manipulation\r\n    const config = {};\r\n    config.__proto__ = webhookData.overrides;\r\n\r\n    // Prototype pollution through constructor.prototype\r\n    config.constructor.prototype = webhookData.extensions;\r\n\r\n    // Unsafe Object.assign with user-controlled source\r\n    const mergedConfig = Object.assign({}, webhookData);\r\n\r\n    // Logging full request and configuration objects\r\n    console.log(\"Webhook received:\", requestContext);\r\n    console.log(\"Processed configuration:\", config);\r\n    console.log(\"Merged credentials:\", credentials);\r\n\r\n    return { processed: true, config: mergedConfig };\r\n}\r\n\r\n// Health check monitor with string-based timers\r\nfunction startGatewayMonitoring(serviceId) {\r\n    // String argument in setInterval\r\n    setInterval(\"checkUpstreamServices()\", 30000);\r\n\r\n    // Dynamic template literal in setTimeout\r\n    setTimeout(`reportHealth('${serviceId}')`, 5000);\r\n}\r\n\r\n// Client redirect handler for partner integrations\r\nfunction dispatchExternalRedirect(destination) {\r\n    // Open redirect vulnerabilities\r\n    window.location.href = destination;\r\n    location.replace(destination);\r\n}\r\n\r\nfunction checkUpstreamServices() {\r\n    return true;\r\n}\r\n\r\nfunction reportHealth(id) {\r\n    return id;\r\n}\r\n\r\nexport { executeRoutingRule, proxyRequest, processWebhookData, startGatewayMonitoring, dispatchExternalRedirect };\r\n"
  },
  {
    "id": "SCENARIO-003",
    "fileName": "chat-application.js",
    "primaryScenarioName": "chat-application",
    "browserContext": "Browser WebSocket real-time messaging client managing room presence, live message preview rendering, command execution, and companion app handoffs.",
    "intendedBehavior": "Simulated client-side real-time chat application with DOM XSS, insecure token storage, prototype pollution, and code execution flaws.",
    "threatModelAndAssumptions": {
      "trustBoundary": "WebSocket message receipt boundary from other room participants and external chat bots.",
      "attackerControlledInput": "senderId, message text, metadata processingScript/validationRule, and bot commands.",
      "executionEnvironment": "Browser DOM / WebSocket client ECMAScript runtime.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Arbitrary code execution via eval/Function, DOM XSS, prototype pollution, and plaintext credential storage.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client-side chat client; live WebSocket connections and backend presence servers NOT RUN. Line 16 (internal IP) and lines 48, 78 (JSON.parse) are omitted as non-vulnerabilities.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 10,
          "column": 6
        },
        "weaknessDescription": "Hardcoded WebSocket signing key in client source code."
      },
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 13,
          "column": 6
        },
        "weaknessDescription": "Hardcoded Firebase API key in client source code."
      },
      {
        "ruleId": "OWASP-A03-004",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 24,
          "column": 8
        },
        "weaknessDescription": "Unsafe innerHTML assignment using dynamic template literal containing unescaped message."
      },
      {
        "ruleId": "OWASP-A03-005",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 27,
          "column": 8
        },
        "weaknessDescription": "Unsafe innerHTML assignment using formatMessage function return value."
      },
      {
        "ruleId": "OWASP-A03-007",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 31,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of document.write() to render unescaped chat messages."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 34,
          "column": 4
        },
        "weaknessDescription": "Logging sensitive room session object directly to browser console."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 35,
          "column": 4
        },
        "weaknessDescription": "Logging user context object containing profile data to console."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 51,
          "column": 24
        },
        "weaknessDescription": "Dangerous use of eval() on untrusted processingScript from file metadata."
      },
      {
        "ruleId": "OWASP-A03-003",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 54,
          "column": 22
        },
        "weaknessDescription": "Unsafe use of Function constructor to execute dynamic validationRule."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 62,
          "column": 4
        },
        "weaknessDescription": "Presence cookie written without Secure or HttpOnly flags."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 65,
          "column": 4
        },
        "weaknessDescription": "Active user cookie written via template literal without security flags."
      },
      {
        "ruleId": "OWASP-A02-003",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "location": {
          "line": 68,
          "column": 22
        },
        "weaknessDescription": "Insecure Math.random() used to generate sessionSalt."
      },
      {
        "ruleId": "OWASP-A07-001",
        "owasp2021Category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "location": {
          "line": 71,
          "column": 4
        },
        "weaknessDescription": "Sensitive chatToken stored in plaintext localStorage."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 82,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through direct __proto__ assignment with room overrides."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 88,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through constructor.prototype assignment with globalSettings."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 96,
          "column": 17
        },
        "weaknessDescription": "Arbitrary code execution via eval() on bot command."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 99,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string argument in setTimeout for scheduled bot task."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 100,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string argument in setInterval for bot queue checks."
      },
      {
        "ruleId": "OWASP-A02-007",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 111,
          "column": 23
        },
        "weaknessDescription": "Sensitive tracking token and service key embedded in URL query string."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 118,
          "column": 4
        },
        "weaknessDescription": "Open redirect via unvalidated destination assigned to window.location.href."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 119,
          "column": 4
        },
        "weaknessDescription": "Open redirect via unvalidated destination passed to location.replace()."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 7,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client HTTP library import: axios."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A10:2021-Server-Side Request Forgery",
        "severity": "MEDIUM",
        "severityAssumptions": "Notification posted to untrusted caller-supplied callbackUrl without destination allowlisting.",
        "trustBoundary": "Notification callback dispatch boundary.",
        "attackerControlledInput": "callbackUrl parameter.",
        "exploitCondition": "Attacker supplies internal loopback or intranet service URL to probe internal services.",
        "securityImpact": "MEDIUM: Client-side request forgery / intranet service probing.",
        "location": {
          "line": 108,
          "column": 4
        },
        "weaknessDescription": "Client-side POST notification to arbitrary unvalidated callbackUrl."
      }
    ],
    "code": "// ==========================================================\r\n// Browser Real-Time Chat Application Client\r\n// Simulates a client-side real-time messaging client with\r\n// DOM previews, presence tracking, and command execution.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded synthetic WebSocket server secret for message signing\r\nconst wsSecret = \"ws_signing_key_PartnerChat_Synthetic_2026\";\r\n\r\n// Hardcoded synthetic Firebase API key for push notifications\r\nconst firebaseApiKey = \"AIzaSyDOCAbC123dEf456GhI789jKl012-MnO\";\r\n\r\n// Chat server internal IP address\r\nconst chatServerIp = \"172.16.0.42\";\r\n\r\n// Message handler with DOM XSS vulnerabilities\r\nfunction handleIncomingMessage(senderId, message, session, user) {\r\n    // Rendering message preview using innerHTML\r\n    const preview = document.getElementById('preview');\r\n    if (preview) {\r\n        // innerHTML with template literal containing user message\r\n        preview.innerHTML = `<div class=\"msg\"><strong>${senderId}</strong>: ${message}</div>`;\r\n\r\n        // innerHTML from function return\r\n        preview.innerHTML = formatMessage(senderId, message);\r\n    }\r\n\r\n    // Writing message to legacy display using document.write\r\n    document.write(\"<p>\" + senderId + \": \" + message + \"</p>\");\r\n\r\n    // Logging session and user data\r\n    console.log(\"Message sent in room:\", session);\r\n    console.log(\"User context:\", user);\r\n\r\n    return { delivered: true };\r\n}\r\n\r\n// File sharing handler with dynamic execution risks\r\nfunction handleSharedFile(fileUrl, metadata) {\r\n    // Dynamic client fetch from user-provided URL\r\n    fetch(fileUrl).then(response => {\r\n        return response.blob();\r\n    });\r\n\r\n    // Parsing file metadata from untrusted source\r\n    const parsedMeta = JSON.parse(metadata);\r\n\r\n    // Dynamic file processor using eval\r\n    const processResult = eval(parsedMeta.processingScript);\r\n\r\n    // Using Function constructor for custom file validators\r\n    const validator = new Function(\"file\", parsedMeta.validationRule);\r\n\r\n    return { shared: true, processResult, validator };\r\n}\r\n\r\n// User presence tracker with insecure cookie & storage\r\nfunction trackUserPresence(userId) {\r\n    // Insecure cookie for tracking presence\r\n    document.cookie = \"presence=\" + userId + \"; path=/chat\";\r\n\r\n    // Template literal cookie assignment\r\n    document.cookie = `last_active=${Date.now()}; user=${userId}`;\r\n\r\n    // Generating insecure session salt\r\n    const sessionSalt = Math.random();\r\n\r\n    // Storing session in localStorage\r\n    localStorage.setItem('chatToken', userId);\r\n\r\n    return { online: true, userId, sessionSalt };\r\n}\r\n\r\n// Room configuration with prototype pollution\r\nfunction configureChatRoom(roomConfig) {\r\n    const parsed = JSON.parse(roomConfig);\r\n\r\n    // Prototype pollution through __proto__\r\n    const defaults = {};\r\n    defaults.__proto__ = parsed.overrides;\r\n\r\n    // Unsafe object merge\r\n    const finalConfig = Object.assign({}, parsed);\r\n\r\n    // Constructor prototype pollution\r\n    defaults.constructor.prototype = parsed.globalSettings;\r\n\r\n    return { configured: true, finalConfig };\r\n}\r\n\r\n// Chat bot with dynamic command execution\r\nfunction executeBotCommand(command) {\r\n    // Executing bot commands via eval\r\n    const output = eval(command);\r\n\r\n    // Scheduled bot tasks with string timers\r\n    setTimeout(\"executeBotTask()\", 5000);\r\n    setInterval(\"checkBotQueue()\", 10000);\r\n\r\n    return { output };\r\n}\r\n\r\n// Notification dispatcher with tracking token\r\nfunction dispatchNotification(recipientId, content, callbackUrl) {\r\n    // Client POST to callback URL\r\n    axios.post(callbackUrl, { recipient: recipientId, message: content });\r\n\r\n    // Notification URL with token in query string\r\n    const trackingUrl = \"https://notify.chat.com/track?token=notify_track_tk_123&key=push_service_key\";\r\n\r\n    return { notified: true, tracking: trackingUrl };\r\n}\r\n\r\n// Redirect to companion mobile app\r\nfunction redirectToMobileApp(appUrl) {\r\n    window.location.href = appUrl;\r\n    location.replace(appUrl);\r\n}\r\n\r\n// Message formatting helper\r\nfunction formatMessage(sender, text) {\r\n    return \"<div class='formatted-msg'><b>\" + sender + \"</b>: \" + text + \"</div>\";\r\n}\r\n\r\nfunction executeBotTask() {\r\n    return true;\r\n}\r\n\r\nfunction checkBotQueue() {\r\n    return true;\r\n}\r\n\r\nexport {\r\n    handleIncomingMessage,\r\n    handleSharedFile,\r\n    trackUserPresence,\r\n    configureChatRoom,\r\n    executeBotCommand,\r\n    dispatchNotification,\r\n    redirectToMobileApp\r\n};\r\n",
    "template": "// ==========================================================\r\n// Browser Real-Time Chat Application Client\r\n// Simulates a client-side real-time messaging client with\r\n// DOM previews, presence tracking, and command execution.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded synthetic WebSocket server secret for message signing\r\nconst wsSecret = \"ws_signing_key_PartnerChat_Synthetic_2026\";\r\n\r\n// Hardcoded synthetic Firebase API key for push notifications\r\nconst firebaseApiKey = \"AIzaSyDOCAbC123dEf456GhI789jKl012-MnO\";\r\n\r\n// Chat server internal IP address\r\nconst chatServerIp = \"172.16.0.42\";\r\n\r\n// Message handler with DOM XSS vulnerabilities\r\nfunction handleIncomingMessage(senderId, message, session, user) {\r\n    // Rendering message preview using innerHTML\r\n    const preview = document.getElementById('preview');\r\n    if (preview) {\r\n        // innerHTML with template literal containing user message\r\n        preview.innerHTML = `<div class=\"msg\"><strong>${senderId}</strong>: ${message}</div>`;\r\n\r\n        // innerHTML from function return\r\n        preview.innerHTML = formatMessage(senderId, message);\r\n    }\r\n\r\n    // Writing message to legacy display using document.write\r\n    document.write(\"<p>\" + senderId + \": \" + message + \"</p>\");\r\n\r\n    // Logging session and user data\r\n    console.log(\"Message sent in room:\", session);\r\n    console.log(\"User context:\", user);\r\n\r\n    return { delivered: true };\r\n}\r\n\r\n// File sharing handler with dynamic execution risks\r\nfunction handleSharedFile(fileUrl, metadata) {\r\n    // Dynamic client fetch from user-provided URL\r\n    fetch(fileUrl).then(response => {\r\n        return response.blob();\r\n    });\r\n\r\n    // Parsing file metadata from untrusted source\r\n    const parsedMeta = JSON.parse(metadata);\r\n\r\n    // Dynamic file processor using eval\r\n    const processResult = eval(parsedMeta.processingScript);\r\n\r\n    // Using Function constructor for custom file validators\r\n    const validator = new Function(\"file\", parsedMeta.validationRule);\r\n\r\n    return { shared: true, processResult, validator };\r\n}\r\n\r\n// User presence tracker with insecure cookie & storage\r\nfunction trackUserPresence(userId) {\r\n    // Insecure cookie for tracking presence\r\n    document.cookie = \"presence=\" + userId + \"; path=/chat\";\r\n\r\n    // Template literal cookie assignment\r\n    document.cookie = `last_active=${Date.now()}; user=${userId}`;\r\n\r\n    // Generating insecure session salt\r\n    const sessionSalt = Math.random();\r\n\r\n    // Storing session in localStorage\r\n    localStorage.setItem('chatToken', userId);\r\n\r\n    return { online: true, userId, sessionSalt };\r\n}\r\n\r\n// Room configuration with prototype pollution\r\nfunction configureChatRoom(roomConfig) {\r\n    const parsed = JSON.parse(roomConfig);\r\n\r\n    // Prototype pollution through __proto__\r\n    const defaults = {};\r\n    defaults.__proto__ = parsed.overrides;\r\n\r\n    // Unsafe object merge\r\n    const finalConfig = Object.assign({}, parsed);\r\n\r\n    // Constructor prototype pollution\r\n    defaults.constructor.prototype = parsed.globalSettings;\r\n\r\n    return { configured: true, finalConfig };\r\n}\r\n\r\n// Chat bot with dynamic command execution\r\nfunction executeBotCommand(command) {\r\n    // Executing bot commands via eval\r\n    const output = eval(command);\r\n\r\n    // Scheduled bot tasks with string timers\r\n    setTimeout(\"executeBotTask()\", 5000);\r\n    setInterval(\"checkBotQueue()\", 10000);\r\n\r\n    return { output };\r\n}\r\n\r\n// Notification dispatcher with tracking token\r\nfunction dispatchNotification(recipientId, content, callbackUrl) {\r\n    // Client POST to callback URL\r\n    axios.post(callbackUrl, { recipient: recipientId, message: content });\r\n\r\n    // Notification URL with token in query string\r\n    const trackingUrl = \"https://notify.chat.com/track?token=notify_track_tk_123&key=push_service_key\";\r\n\r\n    return { notified: true, tracking: trackingUrl };\r\n}\r\n\r\n// Redirect to companion mobile app\r\nfunction redirectToMobileApp(appUrl) {\r\n    window.location.href = appUrl;\r\n    location.replace(appUrl);\r\n}\r\n\r\n// Message formatting helper\r\nfunction formatMessage(sender, text) {\r\n    return \"<div class='formatted-msg'><b>\" + sender + \"</b>: \" + text + \"</div>\";\r\n}\r\n\r\nfunction executeBotTask() {\r\n    return true;\r\n}\r\n\r\nfunction checkBotQueue() {\r\n    return true;\r\n}\r\n\r\nexport {\r\n    handleIncomingMessage,\r\n    handleSharedFile,\r\n    trackUserPresence,\r\n    configureChatRoom,\r\n    executeBotCommand,\r\n    dispatchNotification,\r\n    redirectToMobileApp\r\n};\r\n"
  },
  {
    "id": "SCENARIO-004",
    "fileName": "data-pipeline.js",
    "primaryScenarioName": "data-pipeline",
    "browserContext": "Client-side data analytics and batch processing module managing data transformation, schema extensions, and export callbacks.",
    "intendedBehavior": "Simulated client data pipeline with dynamic code evaluation, hardcoded credentials, prototype pollution, and credentials in URL query strings.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Pipeline configuration and transformation rule boundary from external integration sources.",
      "attackerControlledInput": "sourceQuery, transformRules, and credentials.webhookUrl.",
      "executionEnvironment": "Browser ECMAScript runtime.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Arbitrary code execution via Function/eval, prototype pollution, credential leaks, and insecure timers.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client data pipeline module; live database connections and warehouse services NOT RUN. Line 19 (internal IP) and lines 44, 85 (JSON.parse) are omitted as non-vulnerabilities.",
    "refs": [
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 13,
          "column": 6
        },
        "weaknessDescription": "Hardcoded encryption key in pipeline source code."
      },
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 16,
          "column": 6
        },
        "weaknessDescription": "Hardcoded MongoDB connection credentials with embedded password."
      },
      {
        "ruleId": "OWASP-A03-003",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 32,
          "column": 21
        },
        "weaknessDescription": "Dynamic query filter built using Function constructor with unsanitized sourceQuery."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 51,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through direct __proto__ assignment with schemaOverrides."
      },
      {
        "ruleId": "OWASP-A02-007",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 64,
          "column": 22
        },
        "weaknessDescription": "Warehouse API key and master secret exposed in export URL query string."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 67,
          "column": 4
        },
        "weaknessDescription": "Logging credentials object containing secrets directly to console."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 79,
          "column": 20
        },
        "weaknessDescription": "Dynamic validation expression evaluated using eval()."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 88,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through constructor.prototype assignment with globalDefaults."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 99,
          "column": 4
        },
        "weaknessDescription": "String argument passed to setInterval for periodic health checks."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 102,
          "column": 4
        },
        "weaknessDescription": "String argument passed to setTimeout for delayed cleanup."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 7,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: lodash."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 8,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: axios."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 9,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: mongoose."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 10,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: jsonwebtoken."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A10:2021-Server-Side Request Forgery",
        "severity": "MEDIUM",
        "severityAssumptions": "Pipeline export notification posted to untrusted webhook URL provided in credentials.",
        "trustBoundary": "ETL export completion webhook notification boundary.",
        "attackerControlledInput": "credentials.webhookUrl parameter.",
        "exploitCondition": "Attacker injects arbitrary URL into credentials configuration.",
        "securityImpact": "MEDIUM: Client-side request forgery targeting internal services.",
        "location": {
          "line": 71,
          "column": 4
        },
        "weaknessDescription": "Export completion webhook dispatched to unvalidated credentials.webhookUrl."
      }
    ],
    "code": "// ==========================================================\r\n// Data Processing Pipeline\r\n// Simulates an ETL data pipeline for ingesting, transforming,\r\n// and exporting datasets with multiple integrity flaws.\r\n// ==========================================================\r\n\r\nimport lodash from 'lodash';\r\nimport axios from 'axios';\r\nimport mongoose from 'mongoose';\r\nimport jsonwebtoken from 'jsonwebtoken';\r\n\r\n// Hardcoded encryption key for data-at-rest\r\nconst encryptionKey = \"aes256-pipeline-secret-key-prod-v3\";\r\n\r\n// Hardcoded connection secret for MongoDB\r\nconst mongoSecret = \"mongodb+srv://admin:Pr0dP@ssw0rd@cluster0.abc123.mongodb.net\";\r\n\r\n// Internal staging server IP\r\nconst stagingServer = \"10.0.2.15\";\r\n\r\n// Pipeline configuration with plaintext endpoints\r\nconst pipelineConfig = {\r\n    source: \"http://data-lake.internal.corp/api/v2/extract\",\r\n    destination: \"http://warehouse.staging.corp/api/v1/load\",\r\n    retryCount: 3,\r\n    batchSize: 500\r\n};\r\n\r\n// Data ingestion with dynamic code evaluation\r\nfunction ingestData(sourceQuery) {\r\n    // Using Function constructor to build dynamic query filters\r\n    const filterFn = new Function(\"record\", `return ${sourceQuery}`);\r\n    \r\n    // Fetching data from pipeline source\r\n    const sourceUrl = pipelineConfig.source;\r\n    fetch(sourceUrl);\r\n\r\n    return { status: \"ingesting\", filter: filterFn };\r\n}\r\n\r\n// Transform phase with prototype pollution risks\r\nfunction transformRecords(records, transformRules) {\r\n    // Parsing transformation rules from external config\r\n    const rules = JSON.parse(transformRules);\r\n    \r\n    // Unsafe merge of user-provided transform config\r\n    const activeConfig = Object.assign({}, rules);\r\n    \r\n    // Direct prototype manipulation for schema extensions\r\n    const schema = {};\r\n    schema.__proto__ = rules.schemaOverrides;\r\n\r\n    return records.map(record => {\r\n        const transformed = {};\r\n        for (const key in rules.mappings) {\r\n            transformed[key] = record[rules.mappings[key]];\r\n        }\r\n        return transformed;\r\n    });\r\n}\r\n\r\n// Export handler with sensitive data in URL parameters\r\nfunction exportToWarehouse(dataset, credentials) {\r\n    const exportUrl = \"https://warehouse.corp.com/import?key=wh_prod_api_key_9x8z7y&secret=export_master_secret\";\r\n    \r\n    // Logging credentials object to console\r\n    console.log(\"Export initiated with credentials:\", credentials);\r\n    \r\n    // Dynamic SSRF endpoint\r\n    const callbackUrl = credentials.webhookUrl;\r\n    axios.post(callbackUrl, { status: \"export_complete\", records: dataset.length });\r\n\r\n    return { exported: true, url: exportUrl };\r\n}\r\n\r\n// Data validation with eval-based expression engine\r\nfunction validateRecord(record, validationExpression) {\r\n    // Using eval for dynamic validation logic\r\n    const isValid = eval(validationExpression);\r\n    return isValid;\r\n}\r\n\r\n// Schema migration handler\r\nfunction migrateSchema(oldSchema, patchData) {\r\n    const patch = JSON.parse(patchData);\r\n    \r\n    // Prototype pollution via constructor.prototype\r\n    oldSchema.constructor.prototype = patch.globalDefaults;\r\n    \r\n    // Unsafe object merge\r\n    const newSchema = Object.assign({}, patch);\r\n    \r\n    return newSchema;\r\n}\r\n\r\n// Pipeline monitoring with string-based timers\r\nfunction startMonitoring() {\r\n    // String argument in setInterval for periodic health checks\r\n    setInterval(\"checkPipelineHealth()\", 60000);\r\n    \r\n    // String argument in setTimeout for delayed cleanup\r\n    setTimeout(\"cleanupStaleBatches()\", 300000);\r\n}\r\n\r\n// Batch retry mechanism\r\nfunction retryFailedBatch(batchId, attempt) {\r\n    if (attempt >= pipelineConfig.retryCount) {\r\n        console.log(\"Maximum retry attempts reached for batch:\", batchId);\r\n        return false;\r\n    }\r\n    \r\n    const delay = Math.pow(2, attempt) * 1000;\r\n    \r\n    setTimeout(() => {\r\n        console.log(`Retrying batch ${batchId}, attempt ${attempt + 1}`);\r\n        processBatch(batchId);\r\n    }, delay);\r\n    \r\n    return true;\r\n}\r\n\r\n// Batch processor\r\nfunction processBatch(batchId) {\r\n    const batchData = loadBatch(batchId);\r\n    \r\n    if (!batchData) {\r\n        return { success: false, error: \"Batch not found\" };\r\n    }\r\n    \r\n    const transformed = batchData.map(record => ({\r\n        id: record.id,\r\n        value: record.rawValue,\r\n        processedAt: new Date().toISOString()\r\n    }));\r\n    \r\n    return { success: true, count: transformed.length };\r\n}\r\n\r\nfunction loadBatch(batchId) {\r\n    return null;\r\n}\r\n\r\nstartMonitoring();\r\n",
    "template": "// ==========================================================\r\n// Data Processing Pipeline\r\n// Simulates an ETL data pipeline for ingesting, transforming,\r\n// and exporting datasets with multiple integrity flaws.\r\n// ==========================================================\r\n\r\nimport lodash from 'lodash';\r\nimport axios from 'axios';\r\nimport mongoose from 'mongoose';\r\nimport jsonwebtoken from 'jsonwebtoken';\r\n\r\n// Hardcoded encryption key for data-at-rest\r\nconst encryptionKey = \"aes256-pipeline-secret-key-prod-v3\";\r\n\r\n// Hardcoded connection secret for MongoDB\r\nconst mongoSecret = \"mongodb+srv://admin:Pr0dP@ssw0rd@cluster0.abc123.mongodb.net\";\r\n\r\n// Internal staging server IP\r\nconst stagingServer = \"10.0.2.15\";\r\n\r\n// Pipeline configuration with plaintext endpoints\r\nconst pipelineConfig = {\r\n    source: \"http://data-lake.internal.corp/api/v2/extract\",\r\n    destination: \"http://warehouse.staging.corp/api/v1/load\",\r\n    retryCount: 3,\r\n    batchSize: 500\r\n};\r\n\r\n// Data ingestion with dynamic code evaluation\r\nfunction ingestData(sourceQuery) {\r\n    // Using Function constructor to build dynamic query filters\r\n    const filterFn = new Function(\"record\", `return ${sourceQuery}`);\r\n    \r\n    // Fetching data from pipeline source\r\n    const sourceUrl = pipelineConfig.source;\r\n    fetch(sourceUrl);\r\n\r\n    return { status: \"ingesting\", filter: filterFn };\r\n}\r\n\r\n// Transform phase with prototype pollution risks\r\nfunction transformRecords(records, transformRules) {\r\n    // Parsing transformation rules from external config\r\n    const rules = JSON.parse(transformRules);\r\n    \r\n    // Unsafe merge of user-provided transform config\r\n    const activeConfig = Object.assign({}, rules);\r\n    \r\n    // Direct prototype manipulation for schema extensions\r\n    const schema = {};\r\n    schema.__proto__ = rules.schemaOverrides;\r\n\r\n    return records.map(record => {\r\n        const transformed = {};\r\n        for (const key in rules.mappings) {\r\n            transformed[key] = record[rules.mappings[key]];\r\n        }\r\n        return transformed;\r\n    });\r\n}\r\n\r\n// Export handler with sensitive data in URL parameters\r\nfunction exportToWarehouse(dataset, credentials) {\r\n    const exportUrl = \"https://warehouse.corp.com/import?key=wh_prod_api_key_9x8z7y&secret=export_master_secret\";\r\n    \r\n    // Logging credentials object to console\r\n    console.log(\"Export initiated with credentials:\", credentials);\r\n    \r\n    // Dynamic SSRF endpoint\r\n    const callbackUrl = credentials.webhookUrl;\r\n    axios.post(callbackUrl, { status: \"export_complete\", records: dataset.length });\r\n\r\n    return { exported: true, url: exportUrl };\r\n}\r\n\r\n// Data validation with eval-based expression engine\r\nfunction validateRecord(record, validationExpression) {\r\n    // Using eval for dynamic validation logic\r\n    const isValid = eval(validationExpression);\r\n    return isValid;\r\n}\r\n\r\n// Schema migration handler\r\nfunction migrateSchema(oldSchema, patchData) {\r\n    const patch = JSON.parse(patchData);\r\n    \r\n    // Prototype pollution via constructor.prototype\r\n    oldSchema.constructor.prototype = patch.globalDefaults;\r\n    \r\n    // Unsafe object merge\r\n    const newSchema = Object.assign({}, patch);\r\n    \r\n    return newSchema;\r\n}\r\n\r\n// Pipeline monitoring with string-based timers\r\nfunction startMonitoring() {\r\n    // String argument in setInterval for periodic health checks\r\n    setInterval(\"checkPipelineHealth()\", 60000);\r\n    \r\n    // String argument in setTimeout for delayed cleanup\r\n    setTimeout(\"cleanupStaleBatches()\", 300000);\r\n}\r\n\r\n// Batch retry mechanism\r\nfunction retryFailedBatch(batchId, attempt) {\r\n    if (attempt >= pipelineConfig.retryCount) {\r\n        console.log(\"Maximum retry attempts reached for batch:\", batchId);\r\n        return false;\r\n    }\r\n    \r\n    const delay = Math.pow(2, attempt) * 1000;\r\n    \r\n    setTimeout(() => {\r\n        console.log(`Retrying batch ${batchId}, attempt ${attempt + 1}`);\r\n        processBatch(batchId);\r\n    }, delay);\r\n    \r\n    return true;\r\n}\r\n\r\n// Batch processor\r\nfunction processBatch(batchId) {\r\n    const batchData = loadBatch(batchId);\r\n    \r\n    if (!batchData) {\r\n        return { success: false, error: \"Batch not found\" };\r\n    }\r\n    \r\n    const transformed = batchData.map(record => ({\r\n        id: record.id,\r\n        value: record.rawValue,\r\n        processedAt: new Date().toISOString()\r\n    }));\r\n    \r\n    return { success: true, count: transformed.length };\r\n}\r\n\r\nfunction loadBatch(batchId) {\r\n    return null;\r\n}\r\n\r\nstartMonitoring();\r\n"
  },
  {
    "id": "SCENARIO-005",
    "fileName": "ecommerce-checkout.js",
    "primaryScenarioName": "ecommerce-checkout",
    "browserContext": "Browser client checkout workflow managing shopping cart state, discount formula calculation, session cookies, and payment confirmations.",
    "intendedBehavior": "Simulated client-side checkout flow with dynamic formula evaluation, hardcoded credentials, cleartext endpoints, and sensitive token logging.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Client-side checkout calculation boundary receiving user cart data and coupon discount formulas.",
      "attackerControlledInput": "formula string and orderData metadata.",
      "executionEnvironment": "Browser ECMAScript client runtime.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Arbitrary code execution via eval in discount calculation, credential exposure, and cleartext payment endpoints.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client-side checkout workflow; live payment gateway servers and merchant banks NOT RUN. Lines 38, 69 (JSON.parse) are omitted as pattern warnings.",
    "refs": [
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-001",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 13,
          "column": 6
        },
        "weaknessDescription": "Hardcoded database password for order storage."
      },
      {
        "ruleId": "OWASP-A02-004",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 16,
          "column": 23
        },
        "weaknessDescription": "Insecure plaintext HTTP endpoint for payment charge requests."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 21,
          "column": 21
        },
        "weaknessDescription": "Dangerous use of eval() to evaluate dynamic discount formula."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 28,
          "column": 4
        },
        "weaknessDescription": "Checkout session cookie set via concatenation without Secure flag."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 31,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string code in setTimeout for analytics ping."
      },
      {
        "ruleId": "OWASP-A05-001",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 42,
          "column": 4
        },
        "weaknessDescription": "Logging sensitive paymentToken variable directly to console."
      },
      {
        "ruleId": "OWASP-A02-007",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 45,
          "column": 23
        },
        "weaknessDescription": "Receipt URL includes paymentToken and verification key in query string."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 7,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client HTTP library import: axios."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "severityAssumptions": "Hardcoded payment API credential present in source; scanner skips API key tokens containing \"test\" substring.",
        "trustBoundary": "Client source code bundle.",
        "attackerControlledInput": "Static source code inspection.",
        "exploitCondition": "Attacker extracts payment processing secret from client bundle.",
        "securityImpact": "HIGH: Exposure of payment processing API credentials.",
        "location": {
          "line": 10,
          "column": 6
        },
        "weaknessDescription": "Hardcoded Stripe API key token ignored by scanner due to test substring suppression rule."
      }
    ],
    "code": "// ==========================================================\r\n// E-Commerce Cart & Checkout Client Module\r\n// Simulates a browser client-side checkout flow with\r\n// pricing evaluation, session cookies, and inventory sync.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded synthetic Stripe API key for client checkout\r\nconst stripeApiKey = \"sk_test_synthetic_key_stripe_12345\";\r\n\r\n// Hardcoded synthetic order database password\r\nconst dbPassword = \"SuperSecretOrderDB!2026\";\r\n\r\n// Plaintext HTTP endpoint for payment gateway\r\nconst paymentGateway = \"http://payments.internal-api.com/v2/charge\";\r\n\r\n// Cart pricing engine using eval to compute discount formulas\r\nfunction applyDiscount(cart, formula) {\r\n    const total = cart.reduce((sum, item) => sum + item.price, 0);\r\n    const discount = eval(formula);\r\n    return total - discount;\r\n}\r\n\r\n// Session cookie set without security flags\r\nfunction createCheckoutSession(userId, cartId) {\r\n    const sessionId = Math.random().toString(36).substring(7);\r\n    document.cookie = \"checkout_session=\" + sessionId + \"; path=/checkout\";\r\n\r\n    // Delayed analytics ping with string-based timer\r\n    setTimeout(\"sendAnalytics('checkout_started')\", 2000);\r\n\r\n    return sessionId;\r\n}\r\n\r\n// Order confirmation handler\r\nfunction confirmOrder(orderData) {\r\n    const parsed = JSON.parse(orderData.metadata);\r\n\r\n    // Logging sensitive payment token to console for debugging\r\n    const paymentToken = parsed.token;\r\n    console.log(\"Payment confirmation received:\", paymentToken);\r\n\r\n    // Building a receipt URL with embedded credentials\r\n    const receiptUrl = \"https://api.store.com/receipts?token=\" + paymentToken + \"&key=receipt_verify_key\";\r\n\r\n    // Fetching order status from plaintext endpoint\r\n    fetch(\"http://orders.legacy-system.local/status/\" + parsed.orderId);\r\n\r\n    return { success: true, receipt: receiptUrl };\r\n}\r\n\r\n// Tax calculation engine\r\nfunction calculateTax(items, region) {\r\n    const taxRates = {\r\n        US: 0.08,\r\n        EU: 0.21,\r\n        PH: 0.12\r\n    };\r\n\r\n    const rate = taxRates[region] || 0;\r\n    return items.reduce((total, item) => {\r\n        return total + (item.price * rate);\r\n    }, 0);\r\n}\r\n\r\n// Inventory check with insecure deserialization\r\nfunction syncInventory(rawPayload) {\r\n    const inventory = JSON.parse(rawPayload);\r\n    const merged = Object.assign({}, inventory);\r\n\r\n    inventory.forEach(item => {\r\n        if (item.stock <= 0) {\r\n            console.log(\"Out of stock alert for:\", item.name);\r\n        }\r\n    });\r\n\r\n    return merged;\r\n}\r\n\r\n// Shipping rate calculator\r\nfunction getShippingRate(weight, destination) {\r\n    const baseRates = {\r\n        domestic: 5.99,\r\n        international: 24.99\r\n    };\r\n\r\n    if (destination === \"PH\") {\r\n        return baseRates.domestic;\r\n    }\r\n\r\n    return baseRates.international + (weight * 0.5);\r\n}\r\n\r\nfunction sendAnalytics(event) {\r\n    return event;\r\n}\r\n\r\nexport { applyDiscount, createCheckoutSession, confirmOrder, calculateTax, syncInventory, getShippingRate };\r\n",
    "template": "// ==========================================================\r\n// E-Commerce Cart & Checkout Client Module\r\n// Simulates a browser client-side checkout flow with\r\n// pricing evaluation, session cookies, and inventory sync.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded synthetic Stripe API key for client checkout\r\nconst stripeApiKey = \"sk_test_synthetic_key_stripe_12345\";\r\n\r\n// Hardcoded synthetic order database password\r\nconst dbPassword = \"SuperSecretOrderDB!2026\";\r\n\r\n// Plaintext HTTP endpoint for payment gateway\r\nconst paymentGateway = \"http://payments.internal-api.com/v2/charge\";\r\n\r\n// Cart pricing engine using eval to compute discount formulas\r\nfunction applyDiscount(cart, formula) {\r\n    const total = cart.reduce((sum, item) => sum + item.price, 0);\r\n    const discount = eval(formula);\r\n    return total - discount;\r\n}\r\n\r\n// Session cookie set without security flags\r\nfunction createCheckoutSession(userId, cartId) {\r\n    const sessionId = Math.random().toString(36).substring(7);\r\n    document.cookie = \"checkout_session=\" + sessionId + \"; path=/checkout\";\r\n\r\n    // Delayed analytics ping with string-based timer\r\n    setTimeout(\"sendAnalytics('checkout_started')\", 2000);\r\n\r\n    return sessionId;\r\n}\r\n\r\n// Order confirmation handler\r\nfunction confirmOrder(orderData) {\r\n    const parsed = JSON.parse(orderData.metadata);\r\n\r\n    // Logging sensitive payment token to console for debugging\r\n    const paymentToken = parsed.token;\r\n    console.log(\"Payment confirmation received:\", paymentToken);\r\n\r\n    // Building a receipt URL with embedded credentials\r\n    const receiptUrl = \"https://api.store.com/receipts?token=\" + paymentToken + \"&key=receipt_verify_key\";\r\n\r\n    // Fetching order status from plaintext endpoint\r\n    fetch(\"http://orders.legacy-system.local/status/\" + parsed.orderId);\r\n\r\n    return { success: true, receipt: receiptUrl };\r\n}\r\n\r\n// Tax calculation engine\r\nfunction calculateTax(items, region) {\r\n    const taxRates = {\r\n        US: 0.08,\r\n        EU: 0.21,\r\n        PH: 0.12\r\n    };\r\n\r\n    const rate = taxRates[region] || 0;\r\n    return items.reduce((total, item) => {\r\n        return total + (item.price * rate);\r\n    }, 0);\r\n}\r\n\r\n// Inventory check with insecure deserialization\r\nfunction syncInventory(rawPayload) {\r\n    const inventory = JSON.parse(rawPayload);\r\n    const merged = Object.assign({}, inventory);\r\n\r\n    inventory.forEach(item => {\r\n        if (item.stock <= 0) {\r\n            console.log(\"Out of stock alert for:\", item.name);\r\n        }\r\n    });\r\n\r\n    return merged;\r\n}\r\n\r\n// Shipping rate calculator\r\nfunction getShippingRate(weight, destination) {\r\n    const baseRates = {\r\n        domestic: 5.99,\r\n        international: 24.99\r\n    };\r\n\r\n    if (destination === \"PH\") {\r\n        return baseRates.domestic;\r\n    }\r\n\r\n    return baseRates.international + (weight * 0.5);\r\n}\r\n\r\nfunction sendAnalytics(event) {\r\n    return event;\r\n}\r\n\r\nexport { applyDiscount, createCheckoutSession, confirmOrder, calculateTax, syncInventory, getShippingRate };\r\n"
  },
  {
    "id": "SCENARIO-006",
    "fileName": "payment-processor.js",
    "primaryScenarioName": "payment-processor",
    "browserContext": "Browser client-side payment processor SDK handling transaction intents, refund policy formulas, prototype configuration merges, and receipt rendering.",
    "intendedBehavior": "Simulated client payment processing SDK with hardcoded secrets, DOM XSS, prototype pollution, and dynamic code evaluation.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Payment processor SDK boundary receiving customer payment parameters, refund rules, and transaction data.",
      "attackerControlledInput": "refundPolicy, feeFormula, rawData overrides/config, and portalUrl.",
      "executionEnvironment": "Browser DOM / payment client ECMAScript runtime.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Arbitrary code execution via eval/Function, DOM XSS via innerHTML/document.write, prototype pollution, and credential leaks.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client payment processor SDK; live banking APIs and card networks NOT RUN. Line 15 (internal IP), line 64 (JSON.parse), and line 79 (requestContext log) are omitted as non-vulnerabilities.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 10,
          "column": 6
        },
        "weaknessDescription": "Hardcoded merchant live API key."
      },
      {
        "ruleId": "OWASP-A02-001",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 11,
          "column": 6
        },
        "weaknessDescription": "Hardcoded payment processor production password."
      },
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 12,
          "column": 6
        },
        "weaknessDescription": "Hardcoded webhook secret for payment callback verification."
      },
      {
        "ruleId": "OWASP-A02-004",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 18,
          "column": 23
        },
        "weaknessDescription": "Insecure plaintext HTTP payment callback endpoint."
      },
      {
        "ruleId": "OWASP-A02-003",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "location": {
          "line": 23,
          "column": 10
        },
        "weaknessDescription": "Insecure Math.random() used to generate transactionKey."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 26,
          "column": 4
        },
        "weaknessDescription": "Payment session cookie set without Secure flag."
      },
      {
        "ruleId": "OWASP-A07-001",
        "owasp2021Category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "location": {
          "line": 29,
          "column": 4
        },
        "weaknessDescription": "Sensitive paymentAuthToken stored in plaintext localStorage."
      },
      {
        "ruleId": "OWASP-A05-001",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 33,
          "column": 4
        },
        "weaknessDescription": "Logging merchant apiKey variable directly to console."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 45,
          "column": 25
        },
        "weaknessDescription": "Dangerous use of eval() on refund policy formula."
      },
      {
        "ruleId": "OWASP-A03-003",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 48,
          "column": 26
        },
        "weaknessDescription": "Unsafe use of Function constructor to evaluate feeFormula."
      },
      {
        "ruleId": "OWASP-A02-007",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 52,
          "column": 28
        },
        "weaknessDescription": "Refund webhook secret and verification token exposed in notification URL."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 68,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through direct __proto__ assignment with transaction overrides."
      },
      {
        "ruleId": "OWASP-A08-002",
        "owasp2021Category": "A08:2021-Software and Data Integrity Failures",
        "severity": "HIGH",
        "location": {
          "line": 74,
          "column": 4
        },
        "weaknessDescription": "Prototype pollution through constructor.prototype assignment with transaction config."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 77,
          "column": 4
        },
        "weaknessDescription": "Logging sensitive reconciliation credentials object to console."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 78,
          "column": 4
        },
        "weaknessDescription": "Logging sensitive session details to console."
      },
      {
        "ruleId": "OWASP-A03-004",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 89,
          "column": 8
        },
        "weaknessDescription": "Unsafe innerHTML assignment using dynamic template literal containing receipt data."
      },
      {
        "ruleId": "OWASP-A03-005",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 96,
          "column": 8
        },
        "weaknessDescription": "Unsafe innerHTML assignment using renderReceiptTemplate return value."
      },
      {
        "ruleId": "OWASP-A03-007",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 100,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of document.write() to render unescaped receipt HTML."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 106,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string argument in setInterval for recurring charges."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 107,
          "column": 4
        },
        "weaknessDescription": "Dangerous use of string argument in setTimeout for payment reminder."
      },
      {
        "ruleId": "OWASP-A01-001",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "location": {
          "line": 112,
          "column": 4
        },
        "weaknessDescription": "Open redirect via unvalidated portalUrl assigned to window.location.href."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 7,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client HTTP library import: axios."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A10:2021-Server-Side Request Forgery",
        "severity": "MEDIUM",
        "severityAssumptions": "Refund notification posted to unvalidated webhookUrl.",
        "trustBoundary": "Payment processor refund notification boundary.",
        "attackerControlledInput": "webhookUrl parameter.",
        "exploitCondition": "Attacker supplies internal URL triggering unauthorized intranet state changes.",
        "securityImpact": "MEDIUM: Client-side request forgery against internal endpoints.",
        "location": {
          "line": 56,
          "column": 4
        },
        "weaknessDescription": "Client-side refund notification dispatched to unvalidated webhookUrl."
      }
    ],
    "code": "// ==========================================================\r\n// Browser Payment Integration Client SDK\r\n// Simulates a client-side payment processor with credential\r\n// leaks, unsafe data handling, and receipt DOM rendering.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded payment processing credentials\r\nconst merchantApiKey = \"pk_live_51N4e2rKj8mHgT3yBw0p9xQzR\";\r\nconst processorPassword = \"PaymentGateway_Pr0d_2026!\";\r\nconst webhookSecret = \"whsec_5a8b9c0d1e2f3g4h5i6j7k8l9m0n\";\r\n\r\n// Internal payment processor IP\r\nconst processorIp = \"10.128.0.55\";\r\n\r\n// Plaintext HTTP callback endpoint\r\nconst legacyCallback = \"http://legacy-payments.internal.net/callback\";\r\n\r\n// Payment intent creator\r\nfunction createPaymentIntent(amount, currency, customerId) {\r\n    // Insecure random transaction token\r\n    const transactionKey = Math.random();\r\n\r\n    // Cookie without security flags for payment session\r\n    document.cookie = \"payment_session=\" + customerId + \"; path=/pay\";\r\n\r\n    // Storing payment token in localStorage\r\n    localStorage.setItem('paymentAuthToken', transactionKey.toString());\r\n\r\n    // Logging payment credentials\r\n    const apiKey = merchantApiKey;\r\n    console.log(\"Processing payment with key:\", apiKey);\r\n\r\n    return {\r\n        intentId: \"pi_\" + Date.now(),\r\n        amount,\r\n        currency\r\n    };\r\n}\r\n\r\n// Refund processor with dynamic code evaluation\r\nfunction processRefund(transactionId, reason, refundPolicy, feeFormula, webhookUrl) {\r\n    // Using eval to process refund policy rules\r\n    const refundAmount = eval(refundPolicy);\r\n\r\n    // Using Function constructor for custom fee calculation\r\n    const feeCalculator = new Function(\"amount\", \"return \" + feeFormula);\r\n    const fee = feeCalculator(refundAmount);\r\n\r\n    // Sending refund notification with credentials in URL\r\n    const notificationUrl = \"https://payments.example.com/notify?secret=refund_webhook_secret_key&token=merchant_verify_tk\";\r\n\r\n    // Client fetch to merchant webhook\r\n    fetch(webhookUrl);\r\n    axios.post(webhookUrl, { refunded: true, amount: refundAmount });\r\n\r\n    return { refunded: true, amount: refundAmount, fee, notificationUrl };\r\n}\r\n\r\n// Transaction reconciliation\r\nfunction reconcileTransactions(rawData, credentials, session, requestContext) {\r\n    // Parsing transaction data from external source\r\n    const transactions = JSON.parse(rawData);\r\n\r\n    // Prototype pollution in transaction merge\r\n    const defaults = {};\r\n    defaults.__proto__ = transactions.overrides;\r\n\r\n    // Object.assign with untrusted data\r\n    const merged = Object.assign({}, transactions);\r\n\r\n    // Constructor prototype manipulation\r\n    defaults.constructor.prototype = transactions.config;\r\n\r\n    // Logging full credentials and config\r\n    console.log(\"Reconciliation data:\", credentials);\r\n    console.log(\"Session details:\", session);\r\n    console.log(\"Full request:\", requestContext);\r\n\r\n    return { reconciled: true, merged };\r\n}\r\n\r\n// Receipt generator with DOM XSS vectors\r\nfunction renderPaymentReceipt(receiptData) {\r\n    // innerHTML with template literal\r\n    const container = document.getElementById('receipt');\r\n    if (container) {\r\n        container.innerHTML = `<div class=\"receipt\">\r\n            <h2>Payment Receipt</h2>\r\n            <p>Amount: ${receiptData.amount}</p>\r\n            <p>Status: ${receiptData.status}</p>\r\n        </div>`;\r\n\r\n        // innerHTML from function call\r\n        container.innerHTML = renderReceiptTemplate(receiptData);\r\n    }\r\n\r\n    // document.write for legacy printer view\r\n    document.write(\"<html><body>\" + receiptData.html + \"</body></html>\");\r\n}\r\n\r\n// Scheduled payment processor\r\nfunction scheduleRecurringPayment(customerId, interval) {\r\n    // String-based timer for recurring charges\r\n    setInterval(\"processRecurringCharge()\", interval);\r\n    setTimeout(\"sendPaymentReminder()\", 86400000);\r\n}\r\n\r\n// Redirect to payment portal\r\nfunction redirectToPortal(portalUrl) {\r\n    window.location.href = portalUrl;\r\n}\r\n\r\nfunction processRecurringCharge() {\r\n    return true;\r\n}\r\n\r\nfunction sendPaymentReminder() {\r\n    return true;\r\n}\r\n\r\nfunction renderReceiptTemplate(data) {\r\n    return \"<div>\" + data.html + \"</div>\";\r\n}\r\n\r\nexport {\r\n    createPaymentIntent,\r\n    processRefund,\r\n    reconcileTransactions,\r\n    renderPaymentReceipt,\r\n    scheduleRecurringPayment,\r\n    redirectToPortal\r\n};\r\n",
    "template": "// ==========================================================\r\n// Browser Payment Integration Client SDK\r\n// Simulates a client-side payment processor with credential\r\n// leaks, unsafe data handling, and receipt DOM rendering.\r\n// ==========================================================\r\n\r\nimport axios from 'axios';\r\n\r\n// Hardcoded payment processing credentials\r\nconst merchantApiKey = \"pk_live_51N4e2rKj8mHgT3yBw0p9xQzR\";\r\nconst processorPassword = \"PaymentGateway_Pr0d_2026!\";\r\nconst webhookSecret = \"whsec_5a8b9c0d1e2f3g4h5i6j7k8l9m0n\";\r\n\r\n// Internal payment processor IP\r\nconst processorIp = \"10.128.0.55\";\r\n\r\n// Plaintext HTTP callback endpoint\r\nconst legacyCallback = \"http://legacy-payments.internal.net/callback\";\r\n\r\n// Payment intent creator\r\nfunction createPaymentIntent(amount, currency, customerId) {\r\n    // Insecure random transaction token\r\n    const transactionKey = Math.random();\r\n\r\n    // Cookie without security flags for payment session\r\n    document.cookie = \"payment_session=\" + customerId + \"; path=/pay\";\r\n\r\n    // Storing payment token in localStorage\r\n    localStorage.setItem('paymentAuthToken', transactionKey.toString());\r\n\r\n    // Logging payment credentials\r\n    const apiKey = merchantApiKey;\r\n    console.log(\"Processing payment with key:\", apiKey);\r\n\r\n    return {\r\n        intentId: \"pi_\" + Date.now(),\r\n        amount,\r\n        currency\r\n    };\r\n}\r\n\r\n// Refund processor with dynamic code evaluation\r\nfunction processRefund(transactionId, reason, refundPolicy, feeFormula, webhookUrl) {\r\n    // Using eval to process refund policy rules\r\n    const refundAmount = eval(refundPolicy);\r\n\r\n    // Using Function constructor for custom fee calculation\r\n    const feeCalculator = new Function(\"amount\", \"return \" + feeFormula);\r\n    const fee = feeCalculator(refundAmount);\r\n\r\n    // Sending refund notification with credentials in URL\r\n    const notificationUrl = \"https://payments.example.com/notify?secret=refund_webhook_secret_key&token=merchant_verify_tk\";\r\n\r\n    // Client fetch to merchant webhook\r\n    fetch(webhookUrl);\r\n    axios.post(webhookUrl, { refunded: true, amount: refundAmount });\r\n\r\n    return { refunded: true, amount: refundAmount, fee, notificationUrl };\r\n}\r\n\r\n// Transaction reconciliation\r\nfunction reconcileTransactions(rawData, credentials, session, requestContext) {\r\n    // Parsing transaction data from external source\r\n    const transactions = JSON.parse(rawData);\r\n\r\n    // Prototype pollution in transaction merge\r\n    const defaults = {};\r\n    defaults.__proto__ = transactions.overrides;\r\n\r\n    // Object.assign with untrusted data\r\n    const merged = Object.assign({}, transactions);\r\n\r\n    // Constructor prototype manipulation\r\n    defaults.constructor.prototype = transactions.config;\r\n\r\n    // Logging full credentials and config\r\n    console.log(\"Reconciliation data:\", credentials);\r\n    console.log(\"Session details:\", session);\r\n    console.log(\"Full request:\", requestContext);\r\n\r\n    return { reconciled: true, merged };\r\n}\r\n\r\n// Receipt generator with DOM XSS vectors\r\nfunction renderPaymentReceipt(receiptData) {\r\n    // innerHTML with template literal\r\n    const container = document.getElementById('receipt');\r\n    if (container) {\r\n        container.innerHTML = `<div class=\"receipt\">\r\n            <h2>Payment Receipt</h2>\r\n            <p>Amount: ${receiptData.amount}</p>\r\n            <p>Status: ${receiptData.status}</p>\r\n        </div>`;\r\n\r\n        // innerHTML from function call\r\n        container.innerHTML = renderReceiptTemplate(receiptData);\r\n    }\r\n\r\n    // document.write for legacy printer view\r\n    document.write(\"<html><body>\" + receiptData.html + \"</body></html>\");\r\n}\r\n\r\n// Scheduled payment processor\r\nfunction scheduleRecurringPayment(customerId, interval) {\r\n    // String-based timer for recurring charges\r\n    setInterval(\"processRecurringCharge()\", interval);\r\n    setTimeout(\"sendPaymentReminder()\", 86400000);\r\n}\r\n\r\n// Redirect to payment portal\r\nfunction redirectToPortal(portalUrl) {\r\n    window.location.href = portalUrl;\r\n}\r\n\r\nfunction processRecurringCharge() {\r\n    return true;\r\n}\r\n\r\nfunction sendPaymentReminder() {\r\n    return true;\r\n}\r\n\r\nfunction renderReceiptTemplate(data) {\r\n    return \"<div>\" + data.html + \"</div>\";\r\n}\r\n\r\nexport {\r\n    createPaymentIntent,\r\n    processRefund,\r\n    reconcileTransactions,\r\n    renderPaymentReceipt,\r\n    scheduleRecurringPayment,\r\n    redirectToPortal\r\n};\r\n"
  },
  {
    "id": "SCENARIO-007",
    "fileName": "student-portal.jsx",
    "primaryScenarioName": "student-portal",
    "browserContext": "React single-page student academic portal managing course enrollment, grade viewing, inbox message previews, and external redirects.",
    "intendedBehavior": "Simulated React student academic portal with hardcoded credentials, dangerouslySetInnerHTML sinks, eval formula execution, and insecure session cookies.",
    "threatModelAndAssumptions": {
      "trustBoundary": "React component boundary receiving student profile, API endpoints, message previews, and formula weights.",
      "attackerControlledInput": "student.loginRedirectUrl, message body, formula strings, and course HTML.",
      "executionEnvironment": "Browser DOM / React client ECMAScript runtime.",
      "impactSupportingSeverity": "CRITICAL to HIGH: Hardcoded credentials, DOM XSS in message/catalog views, arbitrary code execution in GPA formulas, and open redirects.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Simulated React component; live student information servers and enrollment databases NOT RUN. Scanner hit at line 30 (student.isAdmin) is omitted as it only gates console.log.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 16,
          "column": 6
        },
        "weaknessDescription": "Hardcoded student portal API key."
      },
      {
        "ruleId": "OWASP-A02-001",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 19,
          "column": 6
        },
        "weaknessDescription": "Hardcoded database administrator password for grades."
      },
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 22,
          "column": 6
        },
        "weaknessDescription": "Hardcoded enrollment system token."
      },
      {
        "ruleId": "OWASP-A03-004",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 58,
          "column": 12
        },
        "weaknessDescription": "Callable helper renderGradeCard assigns template literal with unescaped grade to innerHTML."
      },
      {
        "ruleId": "OWASP-A03-005",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 69,
          "column": 12
        },
        "weaknessDescription": "Callable helper renderCourseDescription assigns helper return value to innerHTML."
      },
      {
        "ruleId": "OWASP-A03-007",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 75,
          "column": 8
        },
        "weaknessDescription": "Callable helper loadAnnouncement passes unescaped htmlContent directly to document.write()."
      },
      {
        "ruleId": "OWASP-A03-008",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 83,
          "column": 21
        },
        "weaknessDescription": "React dangerouslySetInnerHTML in MessagePreview renders unescaped message body in demonstrated flow."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 90,
          "column": 8
        },
        "weaknessDescription": "Enrollment session cookie set without Secure flag."
      },
      {
        "ruleId": "OWASP-A07-001",
        "owasp2021Category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "location": {
          "line": 93,
          "column": 8
        },
        "weaknessDescription": "Sensitive enrollmentToken stored in plaintext localStorage."
      },
      {
        "ruleId": "OWASP-A03-002",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 96,
          "column": 8
        },
        "weaknessDescription": "Dangerous use of string argument in setTimeout for enrollment confirmation."
      },
      {
        "ruleId": "OWASP-A03-001",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 101,
          "column": 20
        },
        "weaknessDescription": "Dangerous use of eval() to evaluate grade calculation formula."
      },
      {
        "ruleId": "OWASP-A03-003",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "CRITICAL",
        "location": {
          "line": 107,
          "column": 27
        },
        "weaknessDescription": "Unsafe use of Function constructor to evaluate grade weighting."
      },
      {
        "ruleId": "OWASP-A02-003",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "location": {
          "line": 113,
          "column": 14
        },
        "weaknessDescription": "Insecure Math.random() used to generate two-factor enrollment OTP."
      },
      {
        "ruleId": "OWASP-A03-008",
        "owasp2021Category": "A03:2021-Injection",
        "severity": "HIGH",
        "location": {
          "line": 136,
          "column": 21
        },
        "weaknessDescription": "React dangerouslySetInnerHTML renders unescaped course catalog HTML from API in demonstrated flow."
      }
    ],
    "expectedAdvisories": [
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 9,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: serialize-javascript."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 10,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: markdown-it."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 11,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: js-yaml."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 12,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: node-fetch."
      },
      {
        "ruleId": "OWASP-A06-001",
        "owasp2021Category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "INFORMATIONAL",
        "location": {
          "line": 13,
          "column": 0
        },
        "weaknessDescription": "Component review advisory for client library import: vm2."
      }
    ],
    "unsupportedWeaknesses": [
      {
        "ruleId": null,
        "unsupported": true,
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "severityAssumptions": "Direct navigation to unvalidated user-controlled redirect URL on unauthenticated state.",
        "trustBoundary": "Authentication gate redirect boundary.",
        "attackerControlledInput": "student.loginRedirectUrl object property.",
        "exploitCondition": "Attacker controls student profile data or query param to specify an external phishing origin.",
        "securityImpact": "HIGH: Open redirect / credential phishing targeting unauthenticated students.",
        "location": {
          "line": 37,
          "column": 8
        },
        "weaknessDescription": "Unauthenticated gate assigns unvalidated student.loginRedirectUrl to window.location.href."
      }
    ],
    "code": "// ==========================================================\r\n// Student Portal React Component\r\n// Simulates a university student portal with grade viewing,\r\n// enrollment, and messaging features. Contains multiple\r\n// categories of vulnerabilities typical of student projects.\r\n// ==========================================================\r\n\r\nimport React, { useState, useEffect } from 'react';\r\nimport serialize from 'serialize-javascript';\r\nimport markdownIt from 'markdown-it';\r\nimport jsYaml from 'js-yaml';\r\nimport nodeFetch from 'node-fetch';\r\nimport vm2 from 'vm2';\r\n\r\n// Hardcoded API credentials for the student portal backend\r\nconst portalApiKey = \"portal_prod_key_Xk9mN2pL7qR4sT6w\";\r\n\r\n// Hardcoded database password for grade records\r\nconst gradeDbPassword = \"GradeDB_Admin_2026!\";\r\n\r\n// Hardcoded enrollment system token\r\nconst enrollmentToken = \"enroll_sys_tk_8hJ3kL5mN7pQ9rSt\";\r\n\r\nconst StudentPortal = ({ student }) => {\r\n    const [grades, setGrades] = useState([]);\r\n    const [messages, setMessages] = useState([]);\r\n    const [courseHtml, setCourseHtml] = useState('');\r\n\r\n    // Client-side admin check for grade override panel\r\n    if (student.isAdmin) {\r\n        console.log(\"Admin mode activated for student:\", student);\r\n    }\r\n\r\n    // Client-side authentication gate\r\n    if (!student.isAuthenticated) {\r\n        // Open redirect to login page using dynamic variable\r\n        window.location.href = student.loginRedirectUrl;\r\n        return null;\r\n    }\r\n\r\n    useEffect(() => {\r\n        // Fetching grades from dynamic student endpoint\r\n        const gradesUrl = student.apiEndpoint;\r\n        fetch(gradesUrl).then(res => res.json()).then(data => {\r\n            setGrades(data.grades);\r\n        });\r\n\r\n        // Loading course catalog\r\n        axios.get(`/api/courses/${student.departmentId}/catalog`).then(res => {\r\n            setCourseHtml(res.data.htmlContent);\r\n        });\r\n    }, [student]);\r\n\r\n    // Grade display using innerHTML with template literal\r\n    const renderGradeCard = (courseName, grade) => {\r\n        const card = document.getElementById('grade-display');\r\n        if (card) {\r\n            card.innerHTML = `<div class=\"grade-card\">\r\n                <h3>${courseName}</h3>\r\n                <span class=\"grade\">${grade}</span>\r\n            </div>`;\r\n        }\r\n    };\r\n\r\n    // Course description renderer using innerHTML from function\r\n    const renderCourseDescription = (courseId) => {\r\n        const descriptionEl = document.getElementById('course-desc');\r\n        if (descriptionEl) {\r\n            descriptionEl.innerHTML = fetchCourseDescription(courseId);\r\n        }\r\n    };\r\n\r\n    // Announcement board using document.write\r\n    const loadAnnouncement = (htmlContent) => {\r\n        document.write(htmlContent);\r\n    };\r\n\r\n    // Message composer with dangerouslySetInnerHTML\r\n    const MessagePreview = ({ rawContent }) => {\r\n        return (\r\n            <div className=\"message-preview\">\r\n                <h4>Message Preview</h4>\r\n                <div dangerouslySetInnerHTML={{ __html: rawContent }} />\r\n            </div>\r\n        );\r\n    };\r\n\r\n    // Enrollment handler with insecure cookie\r\n    const enrollInCourse = (courseId) => {\r\n        document.cookie = \"enrollment_session=\" + courseId + \"; path=/enroll\";\r\n\r\n        // Storing enrollment token in localStorage\r\n        localStorage.setItem('enrollmentToken', enrollmentToken);\r\n\r\n        // Using setTimeout with string for delayed confirmation\r\n        setTimeout(\"confirmEnrollment()\", 3000);\r\n    };\r\n\r\n    // Grade calculator using eval\r\n    const calculateGPA = (formula) => {\r\n        const gpa = eval(formula);\r\n        return gpa;\r\n    };\r\n\r\n    // Dynamic code execution for custom grade weighting\r\n    const applyWeighting = (weights) => {\r\n        const calculator = new Function(\"grades\", weights);\r\n        return calculator(grades);\r\n    };\r\n\r\n    // Insecure random OTP for two-factor enrollment verification\r\n    const generateEnrollmentOtp = () => {\r\n        const otp = Math.random();\r\n        return otp.toString().slice(2, 8);\r\n    };\r\n\r\n    return (\r\n        <div className=\"student-portal\">\r\n            <header>\r\n                <h1>Student Academic Portal</h1>\r\n                <p>Student: {student.name} ({student.studentId})</p>\r\n            </header>\r\n\r\n            <section className=\"grades\">\r\n                <h2>Current Grades</h2>\r\n                {grades.map((g, i) => (\r\n                    <div key={i} className=\"grade-entry\">\r\n                        <span>{g.course}</span>\r\n                        <span className=\"grade-value\">{g.value}</span>\r\n                    </div>\r\n                ))}\r\n            </section>\r\n\r\n            <section className=\"course-catalog\">\r\n                <h2>Course Catalog</h2>\r\n                <div dangerouslySetInnerHTML={{ __html: courseHtml }} />\r\n            </section>\r\n\r\n            <section className=\"messages\">\r\n                <h2>Inbox</h2>\r\n                {messages.map((msg, i) => (\r\n                    <MessagePreview key={i} rawContent={msg.body} />\r\n                ))}\r\n            </section>\r\n        </div>\r\n    );\r\n};\r\n\r\n// Helper: fetch course description from API\r\nfunction fetchCourseDescription(courseId) {\r\n    return \"<p>Loading description for course \" + courseId + \"...</p>\";\r\n}\r\n\r\nexport default StudentPortal;\r\n",
    "template": "// ==========================================================\r\n// Student Portal React Component\r\n// Simulates a university student portal with grade viewing,\r\n// enrollment, and messaging features. Contains multiple\r\n// categories of vulnerabilities typical of student projects.\r\n// ==========================================================\r\n\r\nimport React, { useState, useEffect } from 'react';\r\nimport serialize from 'serialize-javascript';\r\nimport markdownIt from 'markdown-it';\r\nimport jsYaml from 'js-yaml';\r\nimport nodeFetch from 'node-fetch';\r\nimport vm2 from 'vm2';\r\n\r\n// Hardcoded API credentials for the student portal backend\r\nconst portalApiKey = \"portal_prod_key_Xk9mN2pL7qR4sT6w\";\r\n\r\n// Hardcoded database password for grade records\r\nconst gradeDbPassword = \"GradeDB_Admin_2026!\";\r\n\r\n// Hardcoded enrollment system token\r\nconst enrollmentToken = \"enroll_sys_tk_8hJ3kL5mN7pQ9rSt\";\r\n\r\nconst StudentPortal = ({ student }) => {\r\n    const [grades, setGrades] = useState([]);\r\n    const [messages, setMessages] = useState([]);\r\n    const [courseHtml, setCourseHtml] = useState('');\r\n\r\n    // Client-side admin check for grade override panel\r\n    if (student.isAdmin) {\r\n        console.log(\"Admin mode activated for student:\", student);\r\n    }\r\n\r\n    // Client-side authentication gate\r\n    if (!student.isAuthenticated) {\r\n        // Open redirect to login page using dynamic variable\r\n        window.location.href = student.loginRedirectUrl;\r\n        return null;\r\n    }\r\n\r\n    useEffect(() => {\r\n        // Fetching grades from dynamic student endpoint\r\n        const gradesUrl = student.apiEndpoint;\r\n        fetch(gradesUrl).then(res => res.json()).then(data => {\r\n            setGrades(data.grades);\r\n        });\r\n\r\n        // Loading course catalog\r\n        axios.get(`/api/courses/${student.departmentId}/catalog`).then(res => {\r\n            setCourseHtml(res.data.htmlContent);\r\n        });\r\n    }, [student]);\r\n\r\n    // Grade display using innerHTML with template literal\r\n    const renderGradeCard = (courseName, grade) => {\r\n        const card = document.getElementById('grade-display');\r\n        if (card) {\r\n            card.innerHTML = `<div class=\"grade-card\">\r\n                <h3>${courseName}</h3>\r\n                <span class=\"grade\">${grade}</span>\r\n            </div>`;\r\n        }\r\n    };\r\n\r\n    // Course description renderer using innerHTML from function\r\n    const renderCourseDescription = (courseId) => {\r\n        const descriptionEl = document.getElementById('course-desc');\r\n        if (descriptionEl) {\r\n            descriptionEl.innerHTML = fetchCourseDescription(courseId);\r\n        }\r\n    };\r\n\r\n    // Announcement board using document.write\r\n    const loadAnnouncement = (htmlContent) => {\r\n        document.write(htmlContent);\r\n    };\r\n\r\n    // Message composer with dangerouslySetInnerHTML\r\n    const MessagePreview = ({ rawContent }) => {\r\n        return (\r\n            <div className=\"message-preview\">\r\n                <h4>Message Preview</h4>\r\n                <div dangerouslySetInnerHTML={{ __html: rawContent }} />\r\n            </div>\r\n        );\r\n    };\r\n\r\n    // Enrollment handler with insecure cookie\r\n    const enrollInCourse = (courseId) => {\r\n        document.cookie = \"enrollment_session=\" + courseId + \"; path=/enroll\";\r\n\r\n        // Storing enrollment token in localStorage\r\n        localStorage.setItem('enrollmentToken', enrollmentToken);\r\n\r\n        // Using setTimeout with string for delayed confirmation\r\n        setTimeout(\"confirmEnrollment()\", 3000);\r\n    };\r\n\r\n    // Grade calculator using eval\r\n    const calculateGPA = (formula) => {\r\n        const gpa = eval(formula);\r\n        return gpa;\r\n    };\r\n\r\n    // Dynamic code execution for custom grade weighting\r\n    const applyWeighting = (weights) => {\r\n        const calculator = new Function(\"grades\", weights);\r\n        return calculator(grades);\r\n    };\r\n\r\n    // Insecure random OTP for two-factor enrollment verification\r\n    const generateEnrollmentOtp = () => {\r\n        const otp = Math.random();\r\n        return otp.toString().slice(2, 8);\r\n    };\r\n\r\n    return (\r\n        <div className=\"student-portal\">\r\n            <header>\r\n                <h1>Student Academic Portal</h1>\r\n                <p>Student: {student.name} ({student.studentId})</p>\r\n            </header>\r\n\r\n            <section className=\"grades\">\r\n                <h2>Current Grades</h2>\r\n                {grades.map((g, i) => (\r\n                    <div key={i} className=\"grade-entry\">\r\n                        <span>{g.course}</span>\r\n                        <span className=\"grade-value\">{g.value}</span>\r\n                    </div>\r\n                ))}\r\n            </section>\r\n\r\n            <section className=\"course-catalog\">\r\n                <h2>Course Catalog</h2>\r\n                <div dangerouslySetInnerHTML={{ __html: courseHtml }} />\r\n            </section>\r\n\r\n            <section className=\"messages\">\r\n                <h2>Inbox</h2>\r\n                {messages.map((msg, i) => (\r\n                    <MessagePreview key={i} rawContent={msg.body} />\r\n                ))}\r\n            </section>\r\n        </div>\r\n    );\r\n};\r\n\r\n// Helper: fetch course description from API\r\nfunction fetchCourseDescription(courseId) {\r\n    return \"<p>Loading description for course \" + courseId + \"...</p>\";\r\n}\r\n\r\nexport default StudentPortal;\r\n"
  },
  {
    "id": "SCENARIO-008",
    "fileName": "user-auth-service.js",
    "primaryScenarioName": "user-auth-service",
    "browserContext": "Browser client user authentication service handling login forms, session validation, password reset token generation, and account deletion logging.",
    "intendedBehavior": "Simulated client authentication service with hardcoded master credentials, JWT secret leaks, insecure random tokens, and client-side authorization checks.",
    "threatModelAndAssumptions": {
      "trustBoundary": "Client-side authentication service boundary receiving username, password, reset tokens, and session state.",
      "attackerControlledInput": "password input and sessionData role property.",
      "executionEnvironment": "Browser client ECMAScript runtime environment.",
      "impactSupportingSeverity": "CRITICAL to MEDIUM: Master credential leaks, client-side authorization gating, and insecure password reset tokens.",
      "safePartnerAssumptions": "N/A: Multi-flaw simulated scenario workload; evaluated separately from controlled V/C dataset."
    },
    "limitations": "Client-side authentication service; live backend authentication servers and identity providers NOT RUN. Line 14 (AWS Key ID without secret), line 17 (internal IP), line 70 (JSON.parse), and line 86 (requestContext log) are omitted as non-vulnerabilities.",
    "refs": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    ],
    "expectedFindings": [
      {
        "ruleId": "OWASP-A02-001",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 8,
          "column": 6
        },
        "weaknessDescription": "Hardcoded admin master password in source code."
      },
      {
        "ruleId": "OWASP-A02-006",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 11,
          "column": 6
        },
        "weaknessDescription": "Hardcoded JWT signing secret in source code."
      },
      {
        "ruleId": "OWASP-A02-005",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "CRITICAL",
        "location": {
          "line": 11,
          "column": 18
        },
        "weaknessDescription": "Hardcoded JWT token string detected in source code."
      },
      {
        "ruleId": "OWASP-A02-003",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "location": {
          "line": 21,
          "column": 10
        },
        "weaknessDescription": "Insecure Math.random() used to generate password reset token."
      },
      {
        "ruleId": "OWASP-A02-003",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "HIGH",
        "location": {
          "line": 22,
          "column": 10
        },
        "weaknessDescription": "Insecure Math.random() used to generate password reset OTP code."
      },
      {
        "ruleId": "OWASP-A07-001",
        "owasp2021Category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "location": {
          "line": 25,
          "column": 4
        },
        "weaknessDescription": "Sensitive authToken stored in plaintext localStorage."
      },
      {
        "ruleId": "OWASP-A07-001",
        "owasp2021Category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "location": {
          "line": 26,
          "column": 4
        },
        "weaknessDescription": "Sensitive jwt_session stored in plaintext localStorage."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 36,
          "column": 8
        },
        "weaknessDescription": "Session cookie set via concatenation without HttpOnly or Secure flags."
      },
      {
        "ruleId": "OWASP-A02-002",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 39,
          "column": 8
        },
        "weaknessDescription": "Admin authorization cookie set via template literal without security flags."
      },
      {
        "ruleId": "OWASP-A05-001",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 42,
          "column": 8
        },
        "weaknessDescription": "Plaintext password logged directly to console upon successful login."
      },
      {
        "ruleId": "OWASP-A02-007",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 53,
          "column": 22
        },
        "weaknessDescription": "Password reset link exposes reset token and temporary password in query parameters."
      },
      {
        "ruleId": "OWASP-A02-004",
        "owasp2021Category": "A02:2021-Cryptographic Failures",
        "severity": "MEDIUM",
        "location": {
          "line": 56,
          "column": 27
        },
        "weaknessDescription": "Insecure cleartext HTTP endpoint used for authentication verification callback."
      },
      {
        "ruleId": "OWASP-A01-002",
        "owasp2021Category": "A01:2021-Broken Access Control",
        "severity": "MEDIUM",
        "location": {
          "line": 74,
          "column": 4
        },
        "weaknessDescription": "Client-side authorization check: validateClientSession assigns isAdmin = true based on untrusted client role."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 84,
          "column": 4
        },
        "weaknessDescription": "Sensitive user object logged directly to console during account deletion."
      },
      {
        "ruleId": "OWASP-A05-003",
        "owasp2021Category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "location": {
          "line": 85,
          "column": 4
        },
        "weaknessDescription": "Active session state object logged directly to console during account deletion."
      }
    ],
    "expectedAdvisories": [],
    "unsupportedWeaknesses": [],
    "code": "// ==========================================================\r\n// Browser Client User Authentication Service\r\n// Simulates client-side login, session management, and\r\n// token storage with realistic broken authentication flaws.\r\n// ==========================================================\r\n\r\n// Hardcoded admin master password for fallback access\r\nconst masterPassword = \"Admin@FallbackAccess_2026!\";\r\n\r\n// Hardcoded JWT signing secret\r\nconst jwtSecret = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\";\r\n\r\n// AWS Access Key left in source code\r\nconst awsAccessKey = \"AKIAIOSFODNN7EXAMPLE\";\r\n\r\n// Internal database server IP address\r\nconst dbHost = \"192.168.1.105\";\r\n\r\n// Insecure token generation using Math.random\r\nfunction generateResetToken(userId) {\r\n    const token = Math.random();\r\n    const otpCode = Math.random();\r\n\r\n    // Storing auth token in localStorage\r\n    localStorage.setItem('authToken', token.toString());\r\n    localStorage.setItem('jwt_session', jwtSecret);\r\n\r\n    return { token, otpCode, userId };\r\n}\r\n\r\n// Login handler with hardcoded credential comparison\r\nfunction handleUserLogin(username, password) {\r\n    // Comparing user input against a hardcoded password\r\n    if (password === \"StagingPassword123!\") {\r\n        // Insecure session cookie without HttpOnly or Secure\r\n        document.cookie = \"sid=\" + username + \"; path=/\";\r\n\r\n        // Template literal cookie assignment\r\n        document.cookie = `auth_level=admin; user=${username}`;\r\n\r\n        // Logging sensitive credentials to console\r\n        console.log(\"Login successful for user:\", password);\r\n\r\n        return { authenticated: true };\r\n    }\r\n\r\n    return { authenticated: false, error: \"Invalid credentials\" };\r\n}\r\n\r\n// Password reset with embedded secrets in query string\r\nfunction requestPasswordReset(email) {\r\n    // Password reset link with token in URL\r\n    const resetLink = \"https://app.example.com/reset?token=abc123def456&password=temporary_reset_pw\";\r\n\r\n    // Using insecure HTTP for verification callback\r\n    const verifyEndpoint = \"http://verify.internal-auth.com/validate\";\r\n    fetch(verifyEndpoint);\r\n\r\n    console.log(\"Password reset initiated for:\", email);\r\n    return { message: \"Reset email dispatched\", link: resetLink };\r\n}\r\n\r\n// Session validation helper\r\nfunction validateClientSession(sessionData) {\r\n    if (!sessionData) {\r\n        return { valid: false, error: \"No session found\" };\r\n    }\r\n\r\n    // Parsing untrusted session data\r\n    const session = JSON.parse(sessionData);\r\n\r\n    // Client-side role check for admin privileges\r\n    let isAdmin = false;\r\n    if (session.role === \"admin\") {\r\n        isAdmin = true;\r\n    }\r\n\r\n    return { valid: session.isAuthenticated, isAdmin };\r\n}\r\n\r\n// Account deletion with console logging of sensitive objects\r\nfunction processAccountDeletion(user, session, requestContext) {\r\n    // Logging complete user and session objects\r\n    console.log(\"Account deletion requested:\", user);\r\n    console.log(\"Active session state:\", session);\r\n    console.log(\"Full request context:\", requestContext);\r\n\r\n    return { deleted: true };\r\n}\r\n\r\nexport {\r\n    generateResetToken,\r\n    handleUserLogin,\r\n    requestPasswordReset,\r\n    validateClientSession,\r\n    processAccountDeletion\r\n};\r\n",
    "template": "// ==========================================================\r\n// Browser Client User Authentication Service\r\n// Simulates client-side login, session management, and\r\n// token storage with realistic broken authentication flaws.\r\n// ==========================================================\r\n\r\n// Hardcoded admin master password for fallback access\r\nconst masterPassword = \"Admin@FallbackAccess_2026!\";\r\n\r\n// Hardcoded JWT signing secret\r\nconst jwtSecret = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\";\r\n\r\n// AWS Access Key left in source code\r\nconst awsAccessKey = \"AKIAIOSFODNN7EXAMPLE\";\r\n\r\n// Internal database server IP address\r\nconst dbHost = \"192.168.1.105\";\r\n\r\n// Insecure token generation using Math.random\r\nfunction generateResetToken(userId) {\r\n    const token = Math.random();\r\n    const otpCode = Math.random();\r\n\r\n    // Storing auth token in localStorage\r\n    localStorage.setItem('authToken', token.toString());\r\n    localStorage.setItem('jwt_session', jwtSecret);\r\n\r\n    return { token, otpCode, userId };\r\n}\r\n\r\n// Login handler with hardcoded credential comparison\r\nfunction handleUserLogin(username, password) {\r\n    // Comparing user input against a hardcoded password\r\n    if (password === \"StagingPassword123!\") {\r\n        // Insecure session cookie without HttpOnly or Secure\r\n        document.cookie = \"sid=\" + username + \"; path=/\";\r\n\r\n        // Template literal cookie assignment\r\n        document.cookie = `auth_level=admin; user=${username}`;\r\n\r\n        // Logging sensitive credentials to console\r\n        console.log(\"Login successful for user:\", password);\r\n\r\n        return { authenticated: true };\r\n    }\r\n\r\n    return { authenticated: false, error: \"Invalid credentials\" };\r\n}\r\n\r\n// Password reset with embedded secrets in query string\r\nfunction requestPasswordReset(email) {\r\n    // Password reset link with token in URL\r\n    const resetLink = \"https://app.example.com/reset?token=abc123def456&password=temporary_reset_pw\";\r\n\r\n    // Using insecure HTTP for verification callback\r\n    const verifyEndpoint = \"http://verify.internal-auth.com/validate\";\r\n    fetch(verifyEndpoint);\r\n\r\n    console.log(\"Password reset initiated for:\", email);\r\n    return { message: \"Reset email dispatched\", link: resetLink };\r\n}\r\n\r\n// Session validation helper\r\nfunction validateClientSession(sessionData) {\r\n    if (!sessionData) {\r\n        return { valid: false, error: \"No session found\" };\r\n    }\r\n\r\n    // Parsing untrusted session data\r\n    const session = JSON.parse(sessionData);\r\n\r\n    // Client-side role check for admin privileges\r\n    let isAdmin = false;\r\n    if (session.role === \"admin\") {\r\n        isAdmin = true;\r\n    }\r\n\r\n    return { valid: session.isAuthenticated, isAdmin };\r\n}\r\n\r\n// Account deletion with console logging of sensitive objects\r\nfunction processAccountDeletion(user, session, requestContext) {\r\n    // Logging complete user and session objects\r\n    console.log(\"Account deletion requested:\", user);\r\n    console.log(\"Active session state:\", session);\r\n    console.log(\"Full request context:\", requestContext);\r\n\r\n    return { deleted: true };\r\n}\r\n\r\nexport {\r\n    generateResetToken,\r\n    handleUserLogin,\r\n    requestPasswordReset,\r\n    validateClientSession,\r\n    processAccountDeletion\r\n};\r\n"
  }
];

module.exports = { scenarioDefinitions, CANONICAL_CATEGORIES };
