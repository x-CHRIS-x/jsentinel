import { useState, useRef, useMemo, useEffect } from 'react';
import { scanFile } from './utils/scannerEngine';
import { injectionRules } from './scanner/rules/injection';
import { xssRules } from './scanner/rules/xss';
import { authRules } from './scanner/rules/auth';
import { sensitiveDataRules } from './scanner/rules/sensitiveData';
import { misconfigRules } from './scanner/rules/misconfig';
import { deserializationRules } from './scanner/rules/deserialization';
import { knownVulnsRules } from './scanner/rules/knownVulns';
import { accessControlRules } from './scanner/rules/accessControl';
import { ssrfRules } from './scanner/rules/ssrf';
import { generatePDFReport } from './utils/pdfGenerator';
import { generateJSONReport } from './utils/jsonExporter';
import './App.css';

// Code Fix Dictionary for Arellano University Capstone Recommended Code Fix Report
const codeFixGuide = {
  'OWASP-A1-001': {
    bad: 'eval("const user = " + userInput);',
    good: 'const user = JSON.parse(userInput); // Parse structural data safely'
  },
  'OWASP-A1-002': {
    bad: 'setTimeout("executeCallback()", 1000);',
    good: 'setTimeout(executeCallback, 1000); // Pass function reference directly'
  },
  'OWASP-A1-003': {
    bad: 'const execute = new Function("x", "return " + userInput);',
    good: 'const execute = (x) => { return safeCallback(userInput, x); }; // Avoid dynamic code construction'
  },
  'OWASP-A1-004': {
    bad: 'element.innerHTML = `<p>${userInput}</p>`;',
    good: 'element.textContent = userInput; // Automatically sanitizes content to plaintext'
  },
  'OWASP-A1-005': {
    bad: 'element.innerHTML = retrieveData(userInput);',
    good: 'element.textContent = retrieveData(userInput); // Prevent execution of nested script tags'
  },
  'OWASP-A2-001': {
    bad: 'const password = "admin_credential_key_123";',
    good: 'const password = process.env.DATABASE_PASSWORD; // Retrieve credentials from environment context'
  },
  'OWASP-A2-002': {
    bad: 'localStorage.setItem("authToken", jsonWebToken);',
    good: 'document.cookie = "authToken=" + jsonWebToken + "; Secure; HttpOnly; SameSite=Strict;";'
  },
  'OWASP-A2-003': {
    bad: 'document.cookie = "session=" + sessionId;',
    good: 'document.cookie = "session=" + sessionId + "; Secure; HttpOnly; SameSite=Strict;";'
  },
  'OWASP-A2-004': {
    bad: 'const securityToken = Math.random().toString();',
    good: 'const securityToken = window.crypto.getRandomValues(new Uint32Array(1))[0].toString(); // Cryptographically secure random number generator'
  },
  'OWASP-A2-005': {
    bad: 'fetch("http://api.internal.service/authenticate");',
    good: 'fetch("https://api.internal.service/authenticate"); // Enforce encrypted HTTPS connections'
  },
  'OWASP-A3-001': {
    bad: 'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";',
    good: 'const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID; // Store secrets in secure server context'
  },
  'OWASP-A3-002': {
    bad: 'const apiKey = "sec_key_xyz123456789abc";',
    good: 'const apiKey = process.env.APP_SECRET_API_KEY; // Never expose authorization keys in source code'
  },
  'OWASP-A3-003': {
    bad: 'const authUrl = "/login?password=" + userPassword;',
    good: 'const response = await axios.post("/login", { password: userPassword }); // Pass sensitive credentials in post body'
  },
  'OWASP-A5-001': {
    bad: 'window.location.href = redirectTargetUrl;',
    good: 'if (trustedDomainWhitelist.includes(redirectTargetUrl)) {\n  window.location.href = redirectTargetUrl;\n} // Validate redirect target domain client side'
  },
  'OWASP-A5-002': {
    bad: 'if (userData.role === "admin") { renderDashboard(); }',
    good: '// Access control check must be enforced and validated on the backend API layer\nif (session.isAuthenticated) { renderDashboard(); }'
  },
  'OWASP-A6-001': {
    bad: 'console.log("User password payload: ", userPassword);',
    good: 'console.log("User login lifecycle triggered."); // Log non-sensitive transaction indicators only'
  },
  'OWASP-A6-002': {
    bad: 'response.setHeader("Access-Control-Allow-Origin", "*");',
    good: 'response.setHeader("Access-Control-Allow-Origin", "https://trusted.production.domain"); // Enforce restrictive CORS origins'
  },
  'OWASP-A6-003': {
    bad: 'console.log("Full request context logged: ", requestContext);',
    good: 'console.log("Request context received for path: ", requestContext.path);'
  },
  'OWASP-A6-004': {
    bad: 'const app = express();\napp.listen(3000);',
    good: 'const app = express();\nconst helmet = require("helmet");\napp.use(helmet()); // Enforce helmet secure response headers'
  },
  'OWASP-A7-001': {
    bad: 'targetDiv.innerHTML = untrustedHTMLString;',
    good: 'targetDiv.textContent = untrustedHTMLString; // Avoid DOM parsing of dynamic strings'
  },
  'OWASP-A7-002': {
    bad: 'document.write(userInputString);',
    good: 'const textNode = document.createTextNode(userInputString);\ndocument.body.appendChild(textNode);'
  },
  'OWASP-A7-003': {
    bad: '<div dangerouslySetInnerHTML={{ __html: dynamicMarkup }} />',
    good: '<div>{dynamicMarkup}</div> // Rely on React default rendering auto sanitization'
  },
  'OWASP-A8-001': {
    bad: 'const payload = JSON.parse(untrustedJSONInput);',
    good: 'const payload = secureSchemaParse(untrustedJSONInput); // Validate schema layout post deserialization'
  },
  'OWASP-A8-002': {
    bad: 'targetObject.__proto__.polluted = true;',
    good: 'const targetObject = Object.create(null); // Instantiate prototype-less objects'
  },
  'OWASP-A8-003': {
    bad: 'Object.assign(baseObject, JSON.parse(userInputPayload));',
    good: 'const sanitized = filterKeys(JSON.parse(userInputPayload));\nObject.assign(baseObject, sanitized); // Filter input keys to prevent injection'
  },
  'OWASP-A9-001': {
    bad: 'import lodash from "lodash"; // CVE-2019-10744 prototype pollution',
    good: 'import lodash from "lodash-es"; // Utilize updated or patched utility libraries'
  },
  'OWASP-A10-001': {
    bad: 'axios.get(dynamicRequestUrl);',
    good: 'if (isValidInternalEndpoint(dynamicRequestUrl)) {\n  axios.get(dynamicRequestUrl);\n} // Restrict connection targets to authenticated APIs'
  },
  'OWASP-A3-ENTROPY': {
    bad: 'const secretValue = "a8f3d6c1b9e0f2a4c5d8e7f9b0a1c2d3e4f5"; // Raw high entropy string',
    good: 'const secretValue = process.env.API_KEY; // Relocate raw strings to local environment configs'
  }
};

// Generates a local signature hash for audit log integrity
const generateSimulatedHash = (timestamp, action) => {
  const rawString = timestamp + action;
  let hashVal = 0;
  for (let i = 0; i < rawString.length; i++) {
    const charCode = rawString.charCodeAt(i);
    hashVal = (hashVal << 5) - hashVal + charCode;
    hashVal = hashVal & hashVal;
  }
  return "JSEC-" + Math.abs(hashVal).toString(16).toUpperCase().padStart(8, '0');
};

const getCurrentTimestamp = () => {
  return new Date().toLocaleString();
};

const createAuditLogRecord = (actionDescription) => {
  const timeVal = getCurrentTimestamp();
  const hash = generateSimulatedHash(timeVal, actionDescription);
  return {
    id: `act_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: timeVal,
    action: actionDescription,
    verificationHash: hash
  };
};

const createScanHistoryRecord = (projectName, updated, activeCount, critical, high, medium, low, finalScore) => {
  return {
    id: `scan_${Date.now()}`,
    timestamp: getCurrentTimestamp(),
    projectName,
    stats: {
      totalIssues: updated.reduce((acc, r) => acc + (r.issues?.length || 0), 0),
      activeIssuesCount: activeCount,
      criticalIssues: critical,
      highIssues: high,
      mediumIssues: medium,
      lowIssues: low,
      securityScore: finalScore
    },
    filesCount: updated.length,
    results: updated.map(res => ({
      fileName: res.fileName,
      success: res.success,
      hasError: res.hasError,
      issues: res.issues || []
    }))
  };
};

function App() {
  // Navigation tabs: 'scanner', 'history', 'activity', 'fp'
  const [activeTab, setActiveTab] = useState('scanner');
  
  // Scanned Files
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [selectedFileIdx, setSelectedFileIdx] = useState(null);
  const [selectedIssueIdx, setSelectedIssueIdx] = useState(null);
  const [darkMode, setDarkMode] = useState(false);
  const [largeProjectWarning, setLargeProjectWarning] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  // Phase 2 & 5: Filtering states
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [owaspFilter, setOwaspFilter] = useState('ALL');

  // Local Storage Data Structures
  const [scanHistory, setScanHistory] = useState(() => {
    const data = localStorage.getItem('jsentinel_scan_history');
    return data ? JSON.parse(data) : [];
  });
  
  const [activityLog, setActivityLog] = useState(() => {
    const data = localStorage.getItem('jsentinel_activity_log');
    return data ? JSON.parse(data) : [];
  });

  const [fpFlags, setFpFlags] = useState(() => {
    const data = localStorage.getItem('jsentinel_fp_flags');
    return data ? JSON.parse(data) : [];
  });

  // Track developer custom annotations for false positives
  const [fpAnnotations, setFpAnnotations] = useState(() => {
    const data = localStorage.getItem('jsentinel_fp_annotations');
    return data ? JSON.parse(data) : {};
  });

  // Comparison selector state
  const [compareScanA, setCompareScanA] = useState('');
  const [compareScanB, setCompareScanB] = useState('');
  const [comparisonResults, setComparisonResults] = useState(null);

  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  // Sync state changes to local storage
  useEffect(() => {
    localStorage.setItem('jsentinel_scan_history', JSON.stringify(scanHistory));
  }, [scanHistory]);

  useEffect(() => {
    localStorage.setItem('jsentinel_activity_log', JSON.stringify(activityLog));
  }, [activityLog]);

  useEffect(() => {
    localStorage.setItem('jsentinel_fp_flags', JSON.stringify(fpFlags));
  }, [fpFlags]);

  useEffect(() => {
    localStorage.setItem('jsentinel_fp_annotations', JSON.stringify(fpAnnotations));
  }, [fpAnnotations]);

  // Handle Dark Mode Class
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  // Logging function
  const addActivityLog = (actionDescription) => {
    const newLog = createAuditLogRecord(actionDescription);
    setActivityLog(prev => [newLog, ...prev]);
  };

  // Handle Line clicks in Code Viewer to highlight finding
  const handleLineClick = (lineNum) => {
    if (selectedResult?.issues) {
      const issueIdx = selectedResult.issues.findIndex(issue => issue.line === lineNum);
      if (issueIdx !== -1) {
        setSelectedIssueIdx(issueIdx);
      }
    }
  };

  const selectedResult = selectedFileIdx !== null ? results[selectedFileIdx] : null;

  // Filtered Issues for Interactive Findings List
  const filteredIssues = useMemo(() => {
    if (!selectedResult?.issues) return [];
    return selectedResult.issues.filter(issue => {
      if (severityFilter !== 'ALL' && issue.severity !== severityFilter) {
        return false;
      }
      if (owaspFilter !== 'ALL') {
        let cat = 'A1';
        if (issue.id.startsWith('OWASP-A1')) cat = 'A1';
        else if (issue.id.startsWith('OWASP-A2')) cat = 'A2';
        else if (issue.id.startsWith('OWASP-A3')) cat = 'A3';
        else if (issue.id.startsWith('OWASP-A5')) cat = 'A5';
        else if (issue.id.startsWith('OWASP-A6')) cat = 'A6';
        else if (issue.id.startsWith('OWASP-A7')) cat = 'A7';
        else if (issue.id.startsWith('OWASP-A8')) cat = 'A8';
        else if (issue.id.startsWith('OWASP-A9')) cat = 'A9';
        else if (issue.id.startsWith('OWASP-A10')) cat = 'A10';
        
        if (cat !== owaspFilter) return false;
      }
      return true;
    });
  }, [selectedResult, severityFilter, owaspFilter]);

  // Fixes Available Counter
  const fixesAvailableCount = useMemo(() => {
    if (!selectedResult?.issues) return 0;
    return selectedResult.issues.filter(issue => {
      const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
      const isFP = fpFlags.includes(fpKey);
      return !isFP && !!codeFixGuide[issue.id];
    }).length;
  }, [selectedResult, fpFlags]);

  // Scroll selected line into view in code viewer
  useEffect(() => {
    if (selectedIssueIdx !== null && selectedResult?.issues) {
      const issue = selectedResult.issues[selectedIssueIdx];
      if (issue) {
        setTimeout(() => {
          const el = document.getElementById(`code-line-${issue.line}`);
          if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        }, 50);
      }
    }
  }, [selectedIssueIdx, selectedFileIdx]);

  // Log filter alterations
  useEffect(() => {
    if (severityFilter !== 'ALL') {
      addActivityLog(`Applied severity filter: ${severityFilter}`);
    }
  }, [severityFilter]);

  useEffect(() => {
    if (owaspFilter !== 'ALL') {
      addActivityLog(`Applied OWASP category filter: ${owaspFilter}`);
    }
  }, [owaspFilter]);

  // Recalculates stats excluding items marked as False Positives (Report 1, 4, 5)
  const stats = useMemo(() => {
    if (results.length === 0) {
      return { 
        totalIssues: 0, 
        activeIssuesCount: 0, 
        criticalIssues: 0, 
        highIssues: 0, 
        mediumIssues: 0, 
        lowIssues: 0, 
        securityScore: 100 
      };
    }

    let totalIssues = 0;
    let activeIssuesCount = 0;
    let criticalIssues = 0;
    let highIssues = 0;
    let mediumIssues = 0;
    let lowIssues = 0;
    let penalty = 0;

    results.forEach(res => {
      if (res.issues) {
        res.issues.forEach(issue => {
          totalIssues++;
          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
          const isFP = fpFlags.includes(fpKey);

          if (!isFP) {
            activeIssuesCount++;
            if (issue.severity === 'CRITICAL') {
              criticalIssues++;
              penalty += 20.0;
            } else if (issue.severity === 'HIGH') {
              highIssues++;
              penalty += 10.0;
            } else if (issue.severity === 'MEDIUM') {
              mediumIssues++;
              penalty += 5.0;
            } else if (issue.severity === 'LOW') {
              lowIssues++;
              penalty += 1.0;
            }
          }
        });
      }
    });

    const securityScore = parseFloat(Math.max(0, 100 - penalty).toFixed(1));

    return { 
      totalIssues, 
      activeIssuesCount,
      criticalIssues, 
      highIssues, 
      mediumIssues, 
      lowIssues, 
      securityScore 
    };
  }, [results, fpFlags]);

  // OWASP Categories Mappings
  const owaspCategories = useMemo(() => {
    const list = {
      'A1': { name: 'A1:2021-Injection', count: 0, severity: 'HIGH' },
      'A2': { name: 'A2:2021-Broken Authentication', count: 0, severity: 'HIGH' },
      'A3': { name: 'A3:2021-Sensitive Data Exposure', count: 0, severity: 'CRITICAL' },
      'A5': { name: 'A5:2021-Broken Access Control', count: 0, severity: 'HIGH' },
      'A6': { name: 'A6:2021-Security Misconfiguration', count: 0, severity: 'MEDIUM' },
      'A7': { name: 'A7:2021-Cross-Site Scripting (XSS)', count: 0, severity: 'HIGH' },
      'A8': { name: 'A8:2021-Software and Data Integrity Failures', count: 0, severity: 'MEDIUM' },
      'A9': { name: 'A9:2021-Vulnerable and Outdated Components', count: 0, severity: 'MEDIUM' },
      'A10': { name: 'A10:2021-Server-Side Request Forgery', count: 0, severity: 'HIGH' }
    };

    results.forEach(res => {
      if (res.issues) {
        res.issues.forEach(issue => {
          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
          if (fpFlags.includes(fpKey)) return;

          let cat = 'A1';
          if (issue.id.startsWith('OWASP-A1')) cat = 'A1';
          else if (issue.id.startsWith('OWASP-A2')) cat = 'A2';
          else if (issue.id.startsWith('OWASP-A3')) cat = 'A3';
          else if (issue.id.startsWith('OWASP-A5')) cat = 'A5';
          else if (issue.id.startsWith('OWASP-A6')) cat = 'A6';
          else if (issue.id.startsWith('OWASP-A7')) cat = 'A7';
          else if (issue.id.startsWith('OWASP-A8')) cat = 'A8';
          else if (issue.id.startsWith('OWASP-A9')) cat = 'A9';
          else if (issue.id.startsWith('OWASP-A10')) cat = 'A10';

          if (list[cat]) list[cat].count++;
        });
      }
    });

    return Object.values(list);
  }, [results, fpFlags]);

  // Compliant OWASP Category counter
  const compliantCategoriesCount = useMemo(() => {
    return owaspCategories.filter(cat => cat.count === 0).length;
  }, [owaspCategories]);

  // File matrix list helper
  const fileMatrix = useMemo(() => {
    return results.map(res => {
      let filePenalty = 0;
      let activeCount = 0;
      if (res.issues) {
        res.issues.forEach(issue => {
          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
          if (fpFlags.includes(fpKey)) return;
          activeCount++;
          if (issue.severity === 'CRITICAL') filePenalty += 20.0;
          else if (issue.severity === 'HIGH') filePenalty += 10.0;
          else if (issue.severity === 'MEDIUM') filePenalty += 5.0;
          else if (issue.severity === 'LOW') filePenalty += 1.0;
        });
      }
      const score = Math.max(0, 100 - filePenalty);
      return {
        fileName: res.fileName,
        issuesCount: res.issues ? res.issues.length : 0,
        activeCount,
        score,
        success: res.success,
        hasError: res.hasError
      };
    });
  }, [results, fpFlags]);

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files);
    processFiles(uploadedFiles);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const items = e.dataTransfer.items;
    if (!items) return;

    const filesToProcess = [];
    
    const traverseFileTree = async (item, path = "") => {
      if (item.isFile) {
        return new Promise((resolve) => {
          item.file((file) => {
            Object.defineProperty(file, 'webkitRelativePath', {
              value: path + file.name,
              writable: false
            });
            filesToProcess.push(file);
            resolve();
          });
        });
      } else if (item.isDirectory) {
        const dirReader = item.createReader();
        const entries = await new Promise((resolve) => {
          dirReader.readEntries((entries) => resolve(entries));
        });
        for (const entry of entries) {
          await traverseFileTree(entry, path + item.name + "/");
        }
      }
    };

    const traversePromises = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i].webkitGetAsEntry();
      if (item) {
        traversePromises.push(traverseFileTree(item));
      }
    }

    await Promise.all(traversePromises);
    processFiles(filesToProcess);
  };

  const processFiles = async (fileList) => {
    setIsScanning(true);
    setSelectedFileIdx(null);
    setSelectedIssueIdx(null);
    setLargeProjectWarning(false);

    const filtered = fileList.filter(file => {
      const path = file.webkitRelativePath || file.name;
      const isHidden = path.split('/').some(part => part.startsWith('.'));
      const isNodeModules = path.includes('node_modules');
      const isDist = path.includes('dist') || path.includes('build');
      const extension = path.split('.').pop().toLowerCase();
      const isSupported = ['js', 'jsx', 'ts', 'tsx'].includes(extension);

      return !isHidden && !isNodeModules && !isDist && isSupported;
    });

    if (filtered.length > 50) {
      setLargeProjectWarning(true);
    }

    setFiles(prev => [...prev, ...filtered]);
    
    const scanResults = [];
    const allRules = [
      ...injectionRules, ...xssRules, ...authRules,
      ...sensitiveDataRules, ...misconfigRules,
      ...deserializationRules, ...knownVulnsRules,
      ...accessControlRules, ...ssrfRules
    ];

    for (const file of filtered) {
      const filePath = file.webkitRelativePath || file.name;
      if (results.some(r => r.fileName === filePath)) continue;

      const result = await scanFile(file, allRules);
      scanResults.push(result);
    }

    setResults(prev => {
      const updated = [...prev, ...scanResults];
      if (selectedFileIdx === null && updated.length > 0) setSelectedFileIdx(0);

      // Extract Project Name
      let projectName = "Uploaded Files";
      const firstWithRelative = filtered.find(f => f.webkitRelativePath);
      if (firstWithRelative) {
        const parts = firstWithRelative.webkitRelativePath.split('/');
        if (parts.length > 1) {
          projectName = parts[0];
        }
      }

      // Pre-compute local stats to save to history
      const currentFPFlags = JSON.parse(localStorage.getItem('jsentinel_fp_flags') || '[]');
      let penalty = 0;
      let critical = 0;
      let high = 0;
      let medium = 0;
      let low = 0;
      let activeCount = 0;

      updated.forEach(res => {
        if (res.issues) {
          res.issues.forEach(issue => {
            const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
            const isFP = currentFPFlags.includes(fpKey);
            if (!isFP) {
              activeCount++;
              if (issue.severity === 'CRITICAL') penalty += 20.0;
              else if (issue.severity === 'HIGH') penalty += 10.0;
              else if (issue.severity === 'MEDIUM') penalty += 5.0;
              else if (issue.severity === 'LOW') penalty += 1.0;
            }
          });
        }
      });

      const finalScore = parseFloat(Math.max(0, 100 - penalty).toFixed(1));

      const newHistoryRecord = createScanHistoryRecord(projectName, updated, activeCount, critical, high, medium, low, finalScore);
      setScanHistory(prevHist => [newHistoryRecord, ...prevHist]);
      addActivityLog(`Security scan completed for project "${projectName}" containing ${filtered.length} files.`);

      return updated;
    });

    setIsScanning(false);
  };

  // Toggle False Positive flag
  const toggleFalsePositive = (fileName, issue, customReason = "") => {
    const fpKey = `${fileName}:${issue.id}:${issue.line}:${issue.column}`;
    let isAdded = false;

    setFpFlags(prev => {
      let updated;
      if (prev.includes(fpKey)) {
        updated = prev.filter(k => k !== fpKey);
        isAdded = false;
      } else {
        updated = [...prev, fpKey];
        isAdded = true;
      }

      if (isAdded) {
        addActivityLog(`Flagged issue ${issue.id} (Line ${issue.line}) in file "${fileName.split('/').pop()}" as False Positive.`);
        if (customReason) {
          setFpAnnotations(prevAnn => ({
            ...prevAnn,
            [fpKey]: {
              reason: customReason,
              timestamp: getCurrentTimestamp()
            }
          }));
        }
      } else {
        addActivityLog(`Restored issue ${issue.id} (Line ${issue.line}) in file "${fileName.split('/').pop()}" from False Positive list.`);
        setFpAnnotations(prevAnn => {
          const next = { ...prevAnn };
          delete next[fpKey];
          return next;
        });
      }

      return updated;
    });
    setSelectedIssueIdx(null);
  };

  // Set FP Annotation manually
  const updateFpAnnotation = (fpKey, text) => {
    setFpAnnotations(prev => ({
      ...prev,
      [fpKey]: {
        reason: text,
        timestamp: getCurrentTimestamp()
      }
    }));
    addActivityLog(`Updated False Positive justification context for marked issue: ${fpKey.split(':')[1]}`);
  };

  // Compare scan logic
  const handleCompare = () => {
    if (!compareScanA || !compareScanB) return;
    const scanA = scanHistory.find(s => s.id === compareScanA);
    const scanB = scanHistory.find(s => s.id === compareScanB);
    if (!scanA || !scanB) return;

    const scoreDelta = parseFloat((scanB.stats.securityScore - scanA.stats.securityScore).toFixed(1));
    const issuesDelta = scanB.stats.activeIssuesCount - scanA.stats.activeIssuesCount;

    setComparisonResults({
      scanA,
      scanB,
      scoreDelta,
      issuesDelta
    });
    addActivityLog(`Executed historical comparison analysis between scan (${scanA.projectName} - ${scanA.timestamp}) and scan (${scanB.projectName} - ${scanB.timestamp})`);
  };

  // Reset audit log
  const handleClearAuditLog = () => {
    if (window.confirm("Are you sure you want to clear the audit activity log? This action cannot be undone.")) {
      setActivityLog([]);
      localStorage.removeItem('jsentinel_activity_log');
      // Set single first record post deletion
      const timeVal = new Date().toLocaleString();
      const action = "Audit activity log cleared by developer authorization request.";
      const newLog = {
        id: `act_${Date.now()}`,
        timestamp: timeVal,
        action,
        verificationHash: generateSimulatedHash(timeVal, action)
      };
      setActivityLog([newLog]);
    }
  };

  return (
    <div 
      className="min-h-screen bg-slate-50 transition-colors duration-300 dark:bg-zinc-950 font-sans text-slate-900 dark:text-zinc-100 relative"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag Overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-[100] bg-red-600/10 backdrop-blur-[2px] border-4 border-dashed border-red-600 m-4 rounded-3xl flex items-center justify-center pointer-events-none animate-in fade-in zoom-in duration-200">
          <div className="bg-white dark:bg-zinc-900 p-8 rounded-3xl shadow-2xl flex flex-col items-center gap-4 border border-slate-200 dark:border-zinc-800">
            <div className="w-16 h-16 bg-red-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-red-500/40">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2 2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
            <p className="text-xl font-black uppercase tracking-tight">Drop files to scan</p>
          </div>
        </div>
      )}
      
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full glass shadow-sm">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-red-600 text-white shadow-lg shadow-red-500/20 group hover:rotate-12 transition-transform duration-500">
              <span className="font-black text-sm">JS</span>
            </div>
            <div className="flex flex-col">
              <h1 className="text-xl font-display font-medium tracking-tight leading-tight">JSentinel</h1>
              <span className="text-[9px] font-black uppercase tracking-widest text-slate-400 dark:text-zinc-500">Static Security Guard</span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center bg-slate-100 dark:bg-zinc-900 p-1.5 rounded-2xl border border-slate-200/50 dark:border-zinc-800">
            {[
              { id: 'scanner', label: 'Vulnerability Scanner' },
              { id: 'history', label: 'Scan History' },
              { id: 'activity', label: 'Developer Activity' },
              { id: 'fp', label: 'False Positives' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-1.5 text-xs font-bold rounded-xl transition-all cursor-pointer ${activeTab === tab.id ? 'bg-white dark:bg-zinc-800 text-red-600 dark:text-red-400 shadow-sm border border-slate-200/50 dark:border-zinc-700' : 'text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200'}`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-3">
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors text-slate-500 dark:text-zinc-400 cursor-pointer btn-press border border-slate-200/50 dark:border-zinc-800"
              title="Toggle Theme"
            >
              {darkMode ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
            </button>
            
            <button 
              className="rounded-lg border border-slate-300 dark:border-zinc-700 px-4 py-2 text-xs font-bold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed flex items-center gap-2 btn-press" 
              disabled={results.length === 0}
              onClick={() => {
                addActivityLog(`Security report JSON export initiated for scanned files.`);
                generateJSONReport(results, stats, owaspCategories, fpFlags);
              }}
            >
              Export JSON
            </button>

            <button 
              className="rounded-lg bg-slate-900 dark:bg-zinc-100 px-4 py-2 text-xs font-bold text-white dark:text-zinc-900 hover:opacity-90 transition-all disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed flex items-center gap-2 btn-press" 
              disabled={results.length === 0 || isExporting}
              onClick={async () => {
                setIsExporting(true);
                // Trigger action logs
                addActivityLog(`Security report PDF export initiated for scanned files.`);
                setTimeout(() => {
                  generatePDFReport(results, stats, scanHistory, activityLog, fpFlags, fpAnnotations);
                  setIsExporting(false);
                }, 150);
              }}
            >
              {isExporting ? (
                <>
                  <div className="h-3 w-3 border-2 border-white/30 border-t-white dark:border-zinc-900/30 dark:border-t-zinc-900 rounded-full animate-spin"></div>
                  <span>Exporting...</span>
                </>
              ) : (
                'Export PDF'
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Navigation bar */}
      <div className="md:hidden w-full bg-white dark:bg-zinc-900 border-b border-slate-200 dark:border-zinc-800 p-2 flex justify-around">
        {[
          { id: 'scanner', label: 'Scanner' },
          { id: 'history', label: 'History' },
          { id: 'activity', label: 'Audit' },
          { id: 'fp', label: 'False Positives' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`text-xs font-bold px-3 py-1.5 rounded-xl cursor-pointer ${activeTab === tab.id ? 'bg-red-50 dark:bg-zinc-800 text-red-600 dark:text-red-400' : 'text-slate-500'}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <main className="container mx-auto px-4 py-8 max-w-7xl">
        
        {/* Tab 1: Scanner Dashboard */}
        {activeTab === 'scanner' && (
          <div className="animate-reveal">
            {/* Upload Area */}
            <section className={`mb-8 flex items-center justify-between p-6 rounded-3xl bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 shadow-sm transition-all ${results.length === 0 ? 'flex-col gap-6 text-center py-20 border-dashed border-2' : ''}`}>
              <div className={results.length === 0 ? 'max-w-2xl' : ''}>
                <h2 className="text-2xl font-black tracking-tight mb-1">{results.length === 0 ? 'Security Scanning Intake' : 'Local Scan Execution'}</h2>
                <p className="text-slate-500 dark:text-zinc-400 text-sm leading-relaxed">{results.length === 0 ? 'Initiate a local security audit without transmitting code to server endpoints. Drag files directly onto the browser window.' : `Security scan complete for ${files.length} active workspace files.`}</p>
              </div>
              <div className="flex flex-col items-center gap-2">
                <div className="flex gap-3">
                  <button onClick={() => fileInputRef.current.click()} className="px-5 py-2.5 rounded-2xl border border-slate-300 dark:border-zinc-700 font-bold text-xs hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all btn-press shadow-sm cursor-pointer">Select Files</button>
                  <button onClick={() => folderInputRef.current.click()} className="px-5 py-2.5 rounded-2xl bg-red-600 text-white font-bold text-xs hover:bg-red-700 transition-all btn-press shadow-lg shadow-red-500/20 cursor-pointer">Analyze Project Folder</button>
                  {results.length > 0 && (
                    <button onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); setSelectedIssueIdx(null); setLargeProjectWarning(false); addActivityLog("Scanner session cleared by user request."); }} className="p-2.5 text-red-600 hover:bg-red-50 dark:hover:bg-zinc-800 rounded-2xl transition-all btn-press cursor-pointer" title="Reset Session">
                      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                    </button>
                  )}
                </div>
                {largeProjectWarning && (
                  <p className="text-[9px] font-black text-amber-600 dark:text-amber-500 uppercase tracking-widest animate-pulse">Warning: Project size exceeds 50 files limit.</p>
                )}
              </div>
            </section>

            {results.length > 0 && (
              <>
                {/* Stats Row & Report 1: Project Security Score Report & Report 4: Vulnerability Scan Details */}
                <section className="mb-8 grid grid-cols-2 lg:grid-cols-4 gap-4">
                  
                  {/* Security Score gauge */}
                  <div className="bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex items-center gap-4 transition-all hover:shadow-md animate-reveal">
                    <div className="relative flex items-center justify-center">
                      <svg className="w-14 h-14 transform -rotate-90">
                        <circle cx="28" cy="28" r="24" className="stroke-slate-100 dark:stroke-zinc-800 fill-none" strokeWidth="4" />
                        <circle cx="28" cy="28" r="24" 
                          className="fill-none" 
                          strokeWidth="4" 
                          strokeDasharray={150.8}
                          strokeDashoffset={150.8 - (150.8 * stats.securityScore) / 100}
                          strokeLinecap="round"
                          stroke={stats.securityScore > 80 ? '#10B981' : stats.securityScore >= 50 ? '#F59E0B' : '#EF4444'} 
                        />
                      </svg>
                      <span className="absolute text-[11px] font-black tracking-tighter">
                        {stats.securityScore.toFixed(0)}%
                      </span>
                    </div>
                    <div className="flex flex-col">
                      <div className="flex items-center gap-1">
                        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Security Score</span>
                        <div className="group relative cursor-pointer">
                          <span className="text-[10px] text-slate-400">ℹ️</span>
                          <div className="absolute left-0 bottom-full mb-2 hidden group-hover:block w-64 bg-slate-900 text-white text-[10px] p-3 rounded-xl shadow-xl leading-normal z-50">
                            <p className="font-bold mb-1">AU-ABC CVSS-inspired Penalty Model:</p>
                            <p>Score = max(0, 100 - sum(cvssBaseScore))</p>
                            <div className="grid grid-cols-2 mt-1 border-t border-slate-800 pt-1">
                              <span>CRITICAL: 20 pts</span>
                              <span>HIGH: 10 pts</span>
                              <span>MEDIUM: 5 pts</span>
                              <span>LOW: 1 pt</span>
                            </div>
                            <p className="mt-1 text-slate-400">Marking False Positives restores score metrics in real-time.</p>
                          </div>
                        </div>
                      </div>
                      <span className={`text-lg font-black ${stats.securityScore > 80 ? 'text-green-500' : stats.securityScore >= 50 ? 'text-orange-500' : 'text-red-500'}`}>
                        {stats.securityScore > 80 ? 'Compliant' : stats.securityScore >= 50 ? 'Warning' : 'Vulnerable'}
                      </span>
                    </div>
                  </div>

                  {/* Scanned Files metrics */}
                  <div className="bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex items-center gap-4 transition-all hover:shadow-md animate-reveal">
                    <div className="w-10 h-10 rounded-2xl bg-indigo-50 dark:bg-indigo-900/10 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5l5 5v11a2 2 0 01-2 2z"></path></svg>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Workspace Size</span>
                      <span className="text-xl font-black">{files.length} Files</span>
                    </div>
                  </div>

                  {/* Total Vulnerabilities metrics */}
                  <div className="bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex items-center gap-4 transition-all hover:shadow-md animate-reveal">
                    <div className="w-10 h-10 rounded-2xl bg-red-50 dark:bg-red-950/10 text-red-600 dark:text-red-400 flex items-center justify-center">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Total / Active</span>
                      <span className="text-xl font-black">{stats.totalIssues} / {stats.activeIssuesCount}</span>
                    </div>
                  </div>

                  {/* Critical Issues stats */}
                  <div className="bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex items-center gap-4 transition-all hover:shadow-md animate-reveal">
                    <div className="w-10 h-10 rounded-2xl bg-red-600/10 text-red-600 flex items-center justify-center">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2zm10-11V7a4 4 0 0 0-8 0v4h8z"></path></svg>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Critical Breach</span>
                      <span className="text-xl font-black text-red-600">{stats.criticalIssues} High-Risk</span>
                    </div>
                  </div>

                </section>

                {/* Report 5: Severity Classification Breakdown */}
                <section className="mb-8 grid grid-cols-1 md:grid-cols-4 gap-4 animate-reveal">
                  {[
                    { label: 'CRITICAL', count: stats.criticalIssues, weight: '20.0 pts', color: 'border-red-600 bg-red-500/5 text-red-600', vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
                    { label: 'HIGH', count: stats.highIssues, weight: '10.0 pts', color: 'border-orange-500 bg-orange-500/5 text-orange-600', vector: 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
                    { label: 'MEDIUM', count: stats.mediumIssues, weight: '5.0 pts', color: 'border-amber-500 bg-amber-500/5 text-amber-600', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
                    { label: 'LOW', count: stats.lowIssues, weight: '1.0 pt', color: 'border-slate-500 bg-slate-500/5 text-slate-600', vector: 'AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N' }
                  ].map((sev, idx) => (
                    <div key={idx} className={`p-4 rounded-2xl border ${sev.color.split(' ')[0]} ${sev.color.split(' ')[1]} flex flex-col justify-between shadow-sm`}>
                      <div className="flex justify-between items-start">
                        <span className="text-xs font-black uppercase tracking-wider">{sev.label}</span>
                        <span className="text-[9px] font-bold px-2 py-0.5 bg-white dark:bg-zinc-800 border border-slate-200/50 dark:border-zinc-700 rounded-md text-slate-500">{sev.weight} penalty</span>
                      </div>
                      <div className="mt-3">
                        <span className="text-2xl font-black block">{sev.count} active</span>
                        <span className="text-[8px] font-mono tracking-tighter text-slate-400 block truncate mt-1">Vector: {sev.vector}</span>
                      </div>
                    </div>
                  ))}
                </section>

                {/* Report 2: OWASP Category Report & Report 6: File-Level Analysis Matrix */}
                <section className="mb-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* OWASP Compliance Dashboard (Phase 5) */}
                  <div className="bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex flex-col h-[400px]">
                    <div className="mb-4 flex items-center justify-between border-b border-slate-100 dark:border-zinc-800 pb-3">
                      <div>
                        <h3 className="text-sm font-black uppercase tracking-wide">OWASP Compliance Profile</h3>
                        <span className="text-[9px] text-slate-400 font-bold">{compliantCategoriesCount} of 9 Categories Compliant</span>
                      </div>
                      <span className="text-[9px] font-bold px-2 py-0.5 bg-slate-100 dark:bg-zinc-800 text-slate-500 rounded-lg">Category Report</span>
                    </div>
                    <div className="flex-1 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin">
                      {owaspCategories.map((cat, idx) => {
                        const catCode = cat.name.split(':')[0];
                        const isSelected = owaspFilter === catCode;
                        const isCompliant = cat.count === 0;

                        return (
                          <button
                            key={idx}
                            onClick={() => setOwaspFilter(isSelected ? 'ALL' : catCode)}
                            className={`w-full flex flex-col text-left p-2 rounded-xl border transition-all cursor-pointer btn-press ${isSelected ? 'bg-red-500/5 border-red-500/50 shadow-sm' : 'bg-transparent border-transparent hover:bg-slate-50 dark:hover:bg-zinc-800/30'}`}
                          >
                            <div className="flex justify-between items-center text-xs font-medium w-full">
                              <span className={`truncate font-bold ${isSelected ? 'text-red-600 dark:text-red-400' : 'text-slate-700 dark:text-zinc-300'}`} title={cat.name}>
                                {cat.name}
                              </span>
                              <div className="flex gap-1.5 items-center shrink-0">
                                <span className={`text-[8px] font-black uppercase px-1 py-0.5 rounded ${isCompliant ? 'bg-green-500/10 text-green-600' : 'bg-red-500/10 text-red-600'}`}>
                                  {isCompliant ? 'COMPLIANT' : 'EXPOSED'}
                                </span>
                                <span className={`text-[8px] font-black px-1.5 py-0.5 rounded ${cat.count > 0 ? 'bg-red-600 text-white' : 'bg-slate-100 dark:bg-zinc-800 text-slate-400'}`}>
                                  {cat.count}
                                </span>
                              </div>
                            </div>
                            <div className="w-full h-1.5 bg-slate-100 dark:bg-zinc-800 rounded-full overflow-hidden mt-1.5">
                              <div 
                                className={`h-full rounded-full transition-all duration-500 ${isCompliant ? 'bg-green-500' : 'bg-red-600'}`} 
                                style={{ width: `${isCompliant ? 100 : Math.min(100, Math.max(15, (cat.count / Math.max(1, stats.totalIssues)) * 100))}%` }}
                              />
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* File-Level Analysis Matrix */}
                  <div className="lg:col-span-2 bg-white dark:bg-zinc-900 p-5 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex flex-col h-[400px]">
                    <div className="mb-4 flex items-center justify-between border-b border-slate-100 dark:border-zinc-800 pb-3">
                      <div>
                        <h3 className="text-sm font-black uppercase tracking-wide">File-Level Analysis Matrix</h3>
                        <span className="text-[9px] text-slate-400">Summary ratings calculated per workspace resource</span>
                      </div>
                      <span className="text-[9px] font-bold px-2 py-0.5 bg-slate-100 dark:bg-zinc-800 text-slate-500 rounded-lg">Matrix Report</span>
                    </div>
                    <div className="flex-1 overflow-y-auto scrollbar-thin">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="text-[9px] font-black uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-zinc-800 pb-2">
                            <th className="pb-2">Resource Path</th>
                            <th className="pb-2 text-center">Status</th>
                            <th className="pb-2 text-center">Total / Active</th>
                            <th className="pb-2 text-right">Resource Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                          {fileMatrix.map((item, idx) => (
                            <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/10">
                              <td className="py-2.5 font-medium truncate max-w-[250px]" title={item.fileName}>
                                {item.fileName}
                              </td>
                              <td className="py-2.5 text-center">
                                {item.success && !item.hasError ? (
                                  <span className="text-green-500 font-bold">Passed</span>
                                ) : item.hasError ? (
                                  <span className="text-amber-500 font-bold">Warning</span>
                                ) : (
                                  <span className="text-red-500 font-bold">Failed</span>
                                )}
                              </td>
                              <td className="py-2.5 text-center font-bold">
                                {item.issuesCount} / {item.activeCount}
                              </td>
                              <td className="py-2.5 text-right font-black">
                                <span className={item.score > 80 ? 'text-green-500' : item.score >= 50 ? 'text-orange-500' : 'text-red-500'}>
                                  {item.score}%
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                </section>

                {/* Main Workspace (Report 7: Detailed Issue Findings & Report 3: Recommended Code Fix Report) */}
                <div className="flex flex-col lg:flex-row gap-6 h-[750px] animate-reveal">
                  
                  {/* Left Column: Explorer */}
                  <div className="w-full lg:w-72 flex flex-col bg-slate-100 dark:bg-zinc-900/30 rounded-3xl border border-slate-200 dark:border-zinc-800 overflow-hidden shadow-sm">
                    <div className="p-4 border-b border-slate-200 dark:border-zinc-800 flex justify-between items-center bg-white/50 dark:bg-zinc-900/50 backdrop-blur-sm">
                      <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Scanned Registry</span>
                      {isScanning && <div className="h-2 w-2 rounded-full bg-red-600 animate-ping" />}
                    </div>
                    <div className="flex-1 overflow-y-auto p-2.5 space-y-1 scrollbar-none">
                      {results.map((res, idx) => {
                        const activeCount = res.issues ? res.issues.filter(issue => {
                          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                          return !fpFlags.includes(fpKey);
                        }).length : 0;

                        return (
                          <button 
                            key={idx} 
                            onClick={() => { setSelectedFileIdx(idx); setSelectedIssueIdx(null); }}
                            className={`w-full flex items-center gap-2 px-3 py-2.5 rounded-xl transition-[background-color,color,box-shadow,border-color] duration-200 text-left group cursor-pointer btn-press border ${selectedFileIdx === idx ? 'bg-white dark:bg-zinc-800 shadow-sm border-slate-200 dark:border-zinc-700' : 'bg-transparent border-transparent hover:bg-white/60 dark:hover:bg-zinc-800/40'}`}
                          >
                            <div className={`h-2 w-2 rounded-full shrink-0 ${activeCount > 0 ? 'bg-red-500 shadow-lg shadow-red-500/50' : (!res.success || res.hasError) ? 'bg-amber-400' : 'bg-green-500'}`} />
                            <span className={`text-xs truncate flex-1 font-bold ${selectedFileIdx === idx ? 'text-slate-900 dark:text-white' : 'text-slate-500 dark:text-zinc-400 group-hover:text-slate-900 dark:group-hover:text-zinc-200'}`}>
                              {res.fileName.split('/').pop()}
                            </span>
                            {res.issues && res.issues.length > 0 && (
                              <span className={`px-1.5 py-0.5 rounded text-[8px] font-black ${selectedFileIdx === idx ? 'bg-red-500 text-white' : 'bg-slate-200 dark:bg-zinc-800 text-slate-500'}`}>
                                {activeCount} / {res.issues.length}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Right Column: Code and Remediation Inspector */}
                  <div className="flex-1 flex flex-col bg-white dark:bg-zinc-900 rounded-3xl border border-slate-200 dark:border-zinc-800 overflow-hidden shadow-sm">
                    <div className="p-4 border-b border-slate-200 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/50 backdrop-blur-sm flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-lg bg-slate-200 dark:bg-zinc-800 flex items-center justify-center">
                          <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                        </div>
                        <span className="text-xs font-black truncate max-w-[280px]" title={selectedResult?.fileName}>
                          {selectedResult ? selectedResult.fileName : 'Resource Inspector'}
                        </span>
                      </div>
                      {selectedResult && selectedResult.issues && selectedResult.issues.length > 0 && (
                        <div className="flex items-center gap-1.5 px-2.5 py-0.5 bg-red-50 dark:bg-red-900/20 text-red-600 rounded-full border border-red-100 dark:border-red-900/30">
                          <span className="relative flex h-1.5 w-1.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-red-500" />
                          </span>
                          <span className="text-[8px] font-black tracking-widest uppercase">Breaches Detected</span>
                        </div>
                      )}
                    </div>

                    <div className="flex-1 flex flex-col md:flex-row overflow-hidden divide-y md:divide-y-0 md:divide-x divide-slate-100 dark:divide-zinc-800">
                      
                      {/* Code Viewer Panel */}
                      <div className="flex-1 flex flex-col overflow-hidden">
                        <div className="p-2.5 bg-slate-50 dark:bg-zinc-950 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center text-[10px] text-slate-400 font-bold">
                          <span>SOURCE CODE STREAM</span>
                          <span>Babel Standalone Parsing</span>
                        </div>
                        <div className="flex-1 overflow-auto p-4 font-mono text-[10px] leading-relaxed bg-slate-50 dark:bg-zinc-950 text-slate-700 dark:text-zinc-300">
                          {selectedResult && selectedResult.success ? (
                            (() => {
                              const lines = selectedResult.rawCode?.split('\n') || [];
                              const activeFPIs = selectedResult.issues ? selectedResult.issues.filter(issue => {
                                const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                                return fpFlags.includes(fpKey);
                              }).map(i => i.line) : [];

                              // Filter active issues to match severity and category filter
                              const activeTargetIssues = filteredIssues.filter(issue => {
                                const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                                return !fpFlags.includes(fpKey);
                              }).map(i => i.line);

                              // Line of currently selected issue
                              const selectedIssueLine = (selectedIssueIdx !== null && selectedResult.issues) 
                                ? selectedResult.issues[selectedIssueIdx]?.line 
                                : null;

                              return lines.map((text, idx) => {
                                const num = idx + 1;
                                const isFPLine = activeFPIs.includes(num);
                                const isIssueLine = activeTargetIssues.includes(num);
                                const isSelectedLine = selectedIssueLine === num;

                                let rowStyle = "opacity-60 cursor-pointer hover:bg-slate-200/20 dark:hover:bg-zinc-800/10";
                                if (isSelectedLine) rowStyle = "line-selected-pulse text-red-600 font-bold -mx-4 px-4";
                                else if (isIssueLine) rowStyle = "bg-red-500/10 text-red-600 font-bold -mx-4 px-4 border-l-2 border-red-600/50 cursor-pointer hover:bg-red-500/15";
                                else if (isFPLine) rowStyle = "bg-green-500/5 text-green-600 -mx-4 px-4 border-l-2 border-green-500 opacity-60 cursor-pointer hover:bg-green-500/10";

                                return (
                                  <div 
                                    key={idx} 
                                    id={`code-line-${num}`}
                                    onClick={() => handleLineClick(num)}
                                    className={`flex gap-3 ${rowStyle}`}
                                  >
                                    <span className="w-5 text-right select-none text-slate-400 font-bold">{num}</span>
                                    <code className="whitespace-pre">{text || ' '}</code>
                                  </div>
                                );
                              });
                            })()
                          ) : selectedResult ? (
                            <div className="h-full flex items-center justify-center text-red-500 font-bold text-center">
                              Resource parsing failed. Check for syntax exceptions.
                            </div>
                          ) : (
                            <div className="h-full flex flex-col items-center justify-center opacity-30 text-center py-20">
                              <svg className="w-10 h-10 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                              <p className="text-[10px] font-black uppercase tracking-wider">No resource selected</p>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Findings & Remediation Inspector (Phase 2 & 5) */}
                      <div className="w-full md:w-96 flex flex-col overflow-hidden bg-white dark:bg-zinc-900">
                        <div className="p-2.5 border-b border-slate-100 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/50 flex justify-between items-center text-[10px] text-slate-400 font-bold">
                          <span>ANALYSIS INTERACTIVE INVENTORY</span>
                          {fixesAvailableCount > 0 && (
                            <span className="px-1.5 py-0.5 bg-green-500/10 text-green-600 rounded-md text-[8px] font-black">
                              {fixesAvailableCount} fixes available
                            </span>
                          )}
                        </div>

                        {/* Severity Pill Filter Bar */}
                        <div className="px-4 py-2 bg-slate-50/50 dark:bg-zinc-900/30 border-b border-slate-100 dark:border-zinc-800 flex flex-wrap gap-1.5 items-center">
                          <span className="text-[9px] font-black uppercase tracking-widest text-slate-400 mr-1">Severity:</span>
                          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
                            const count = selectedResult?.issues 
                              ? selectedResult.issues.filter(i => {
                                  const matchesSev = sev === 'ALL' || i.severity === sev;
                                  const matchesOwasp = owaspFilter === 'ALL' || (() => {
                                    let cat = 'A1';
                                    if (i.id.startsWith('OWASP-A1')) cat = 'A1';
                                    else if (i.id.startsWith('OWASP-A2')) cat = 'A2';
                                    else if (i.id.startsWith('OWASP-A3')) cat = 'A3';
                                    else if (i.id.startsWith('OWASP-A5')) cat = 'A5';
                                    else if (i.id.startsWith('OWASP-A6')) cat = 'A6';
                                    else if (i.id.startsWith('OWASP-A7')) cat = 'A7';
                                    else if (i.id.startsWith('OWASP-A8')) cat = 'A8';
                                    else if (i.id.startsWith('OWASP-A9')) cat = 'A9';
                                    else if (i.id.startsWith('OWASP-A10')) cat = 'A10';
                                    return cat === owaspFilter;
                                  })();
                                  return matchesSev && matchesOwasp;
                                }).length
                              : 0;

                            return (
                              <button
                                key={sev}
                                onClick={() => setSeverityFilter(sev)}
                                className={`px-2 py-0.5 rounded-lg text-[9px] font-black cursor-pointer transition-all btn-press ${severityFilter === sev ? 'bg-red-600 text-white shadow-sm shadow-red-500/20' : 'bg-slate-100 dark:bg-zinc-800 text-slate-500 hover:text-slate-900 dark:hover:text-zinc-200'}`}
                              >
                                {sev} ({count})
                              </button>
                            );
                          })}
                        </div>

                        {/* OWASP Filter Alert */}
                        {owaspFilter !== 'ALL' && (
                          <div className="px-4 py-1.5 bg-red-500/5 dark:bg-zinc-950/20 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center text-[9px] font-bold text-red-600">
                            <span>Filtering by category: {owaspCategories.find(c => c.name.startsWith(owaspFilter))?.name}</span>
                            <button 
                              onClick={() => setOwaspFilter('ALL')} 
                              className="px-1.5 py-0.5 rounded bg-red-600/10 hover:bg-red-600/20 font-black cursor-pointer text-[8px]"
                            >
                              Reset
                            </button>
                          </div>
                        )}
                        
                        <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
                          {selectedResult && filteredIssues && filteredIssues.length > 0 ? (
                            filteredIssues.map((issue) => {
                              const originalIdx = selectedResult.issues.indexOf(issue);
                              const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                              const isFP = fpFlags.includes(fpKey);
                              const isSelected = selectedIssueIdx === originalIdx;

                              return (
                                <div 
                                  key={originalIdx} 
                                  className={`p-3.5 rounded-2xl border transition-all duration-200 ${isFP ? 'border-green-200/50 bg-green-500/5 opacity-70' : isSelected ? 'border-red-600 bg-red-500/5 shadow-sm' : 'border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-slate-300 dark:hover:border-zinc-700'}`}
                                >
                                  <div className="flex justify-between items-start gap-1">
                                    <div className="flex flex-wrap gap-1 items-center">
                                      <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded ${isFP ? 'bg-green-600 text-white' : issue.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-orange-100 text-orange-700 dark:bg-orange-950/40 dark:text-zinc-400'}`}>
                                        {isFP ? 'FALSE POSITIVE' : issue.severity}
                                      </span>
                                      <span className="text-[8px] font-mono tracking-tighter text-slate-400">{issue.id}</span>
                                      <span className={`text-[8px] font-black px-1.5 py-0.5 rounded ${issue.confidence === 'HIGH' ? 'bg-emerald-600/10 text-emerald-600' : issue.confidence === 'MEDIUM' ? 'bg-amber-600/10 text-amber-600' : 'bg-slate-600/10 text-slate-600'}`}>
                                        {issue.confidence} Conf.
                                      </span>
                                    </div>
                                    <span className="text-[9px] font-black text-slate-400 whitespace-nowrap bg-slate-100 dark:bg-zinc-800 px-2 py-0.5 rounded-full">LINE {issue.line}</span>
                                  </div>

                                  <h4 className={`text-xs font-black mt-2 leading-tight ${isFP ? 'text-green-700 dark:text-green-400' : 'text-slate-900 dark:text-white'}`}>{issue.message}</h4>
                                  <p className="text-[10px] text-slate-500 mt-1 leading-normal">{issue.suggestion}</p>

                                  {/* Custom Annotation Trigger Input */}
                                  {!isFP && isSelected && (
                                    <div className="mt-3 pt-3 border-t border-red-600/10 space-y-2 animate-in fade-in slide-in-from-top-1 duration-150">
                                      <label className="text-[8px] font-black uppercase tracking-wider text-slate-400 block">Developer Override Justification:</label>
                                      <input 
                                        type="text" 
                                        placeholder="Enter false positive rationale context..." 
                                        id={`justification_${originalIdx}`}
                                        className="w-full text-[10px] px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-black text-slate-700 dark:text-zinc-300 focus:outline-none focus:border-red-500" 
                                      />
                                    </div>
                                  )}

                                  <div className="mt-3 flex justify-between gap-2 border-t border-slate-100 dark:border-zinc-800 pt-2.5">
                                    <button 
                                      onClick={() => setSelectedIssueIdx(isSelected ? null : originalIdx)}
                                      className="text-[9px] font-bold text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                                    >
                                      {isSelected ? 'Hide Remediation' : 'Remediation Guide'}
                                    </button>
                                    
                                    <button 
                                      onClick={() => {
                                        if (isFP) {
                                          toggleFalsePositive(selectedResult.fileName, issue);
                                        } else {
                                          const inputEl = document.getElementById(`justification_${originalIdx}`);
                                          const justification = inputEl ? inputEl.value : "";
                                          toggleFalsePositive(selectedResult.fileName, issue, justification);
                                        }
                                      }}
                                      className={`text-[9px] font-bold cursor-pointer ${isFP ? 'text-slate-600 dark:text-slate-400 hover:underline' : 'text-green-600 hover:underline'}`}
                                    >
                                      {isFP ? 'Restore to Audit' : isSelected ? 'Flag False Positive' : 'Mark FP'}
                                    </button>
                                  </div>

                                  {/* Remediation Guide (Report 3 & Copy Fix Button) */}
                                  {isSelected && codeFixGuide[issue.id] && (
                                    <div className="mt-3 pt-3 border-t border-slate-100 dark:border-zinc-800 space-y-2.5 animate-reveal text-[9px]">
                                      <div className="p-2.5 rounded-lg bg-red-600/5 border border-red-500/10 font-mono">
                                        <span className="text-[8px] font-black uppercase tracking-wider text-red-600 block mb-1">Vulnerable Pattern</span>
                                        <code className="text-red-500 block break-words whitespace-pre-wrap">{codeFixGuide[issue.id].bad}</code>
                                      </div>
                                      
                                      <div className="p-2.5 rounded-lg bg-green-500/5 border border-green-500/10 font-mono relative group">
                                        <div className="flex justify-between items-center mb-1">
                                          <span className="text-[8px] font-black uppercase tracking-wider text-green-600 block">Secure Remediation</span>
                                          <button 
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              navigator.clipboard.writeText(codeFixGuide[issue.id].good);
                                              addActivityLog(`Copied secure code fix for rule ${issue.id} to clipboard.`);
                                              const btn = e.currentTarget;
                                              const originalText = btn.innerHTML;
                                              btn.innerHTML = 'Copied!';
                                              setTimeout(() => btn.innerHTML = originalText, 1500);
                                            }}
                                            className="text-[8px] font-black text-green-600 hover:text-green-700 bg-green-500/10 hover:bg-green-500/20 px-2 py-0.5 rounded cursor-pointer transition-all active:scale-95 shrink-0"
                                          >
                                            Copy Fix
                                          </button>
                                        </div>
                                        <code className="text-green-500 block break-words whitespace-pre-wrap">{codeFixGuide[issue.id].good}</code>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })
                          ) : (
                            <div className="h-full flex items-center justify-center opacity-30 text-center py-20 text-xs font-bold uppercase tracking-widest">
                              No findings recorded.
                            </div>
                          )}
                        </div>
                      </div>

                    </div>
                  </div>

                </div>
              </>
            )}

            {results.length === 0 && (
              <div className="flex flex-col items-center justify-center h-80 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-3xl opacity-30">
                <svg className="w-12 h-12 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
                <p className="text-xs font-bold uppercase tracking-widest">Waiting for security scan execution</p>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Scan History (Report 8: Historical Comparison Analysis) */}
        {activeTab === 'history' && (
          <div className="space-y-6 animate-reveal">
            
            <section className="bg-white dark:bg-zinc-900 p-6 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm">
              <div className="mb-4">
                <h2 className="text-xl font-black uppercase tracking-tight">Historical Comparison Analysis</h2>
                <p className="text-slate-500 dark:text-zinc-400 text-xs mt-1">Perform scientific delta audits between scanning sessions to monitor mitigation trends.</p>
              </div>

              {scanHistory.length >= 2 ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end bg-slate-50 dark:bg-zinc-950 p-4 rounded-2xl border border-slate-200/50 dark:border-zinc-800">
                  <div className="space-y-1">
                    <label className="text-[9px] font-black uppercase tracking-wider text-slate-400 block">Baseline Scan (A):</label>
                    <select 
                      value={compareScanA} 
                      onChange={(e) => setCompareScanA(e.target.value)}
                      className="w-full text-xs p-2 rounded-xl border border-slate-300 dark:border-zinc-700 bg-white dark:bg-zinc-900"
                    >
                      <option value="">Select baseline scan...</option>
                      {scanHistory.map(s => (
                        <option key={s.id} value={s.id}>{s.projectName} ({s.timestamp}) - Score: {s.stats.securityScore}%</option>
                      ))}
                    </select>
                  </div>
                  
                  <div className="space-y-1">
                    <label className="text-[9px] font-black uppercase tracking-wider text-slate-400 block">Comparison Scan (B):</label>
                    <select 
                      value={compareScanB} 
                      onChange={(e) => setCompareScanB(e.target.value)}
                      className="w-full text-xs p-2 rounded-xl border border-slate-300 dark:border-zinc-700 bg-white dark:bg-zinc-900"
                    >
                      <option value="">Select comparison target...</option>
                      {scanHistory.map(s => (
                        <option key={s.id} value={s.id}>{s.projectName} ({s.timestamp}) - Score: {s.stats.securityScore}%</option>
                      ))}
                    </select>
                  </div>

                  <button 
                    onClick={handleCompare}
                    className="w-full bg-slate-900 dark:bg-zinc-100 text-white dark:text-zinc-900 py-2 rounded-xl text-xs font-bold hover:opacity-90 transition-all btn-press cursor-pointer"
                  >
                    Compare Audits
                  </button>
                </div>
              ) : (
                <p className="text-slate-400 text-xs italic">A minimum of two recorded scanning sessions is required to run comparative analyses.</p>
              )}

              {/* Comparison Results Output */}
              {comparisonResults && (
                <div className="mt-6 border-t border-slate-100 dark:border-zinc-800 pt-6 animate-reveal">
                  <h3 className="text-xs font-black uppercase tracking-widest text-slate-400 mb-3">Mitigation Delta Details</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    <div className="space-y-4">
                      <div className="p-4 bg-slate-50 dark:bg-zinc-950 border border-slate-200/50 dark:border-zinc-800 rounded-2xl">
                        <span className="text-[9px] font-bold uppercase text-slate-400">Security Rating Progression</span>
                        <div className="flex items-baseline gap-4 mt-2">
                          <span className="text-3xl font-black">{comparisonResults.scanA.stats.securityScore}%</span>
                          <span className="text-slate-400 text-xs">➡️</span>
                          <span className="text-3xl font-black">{comparisonResults.scanB.stats.securityScore}%</span>
                          <span className={`text-xs font-black ${comparisonResults.scoreDelta >= 0 ? 'text-green-500' : 'text-red-500'}`}>
                            ({comparisonResults.scoreDelta >= 0 ? `+${comparisonResults.scoreDelta}` : comparisonResults.scoreDelta}%)
                          </span>
                        </div>
                      </div>

                      <div className="p-4 bg-slate-50 dark:bg-zinc-950 border border-slate-200/50 dark:border-zinc-800 rounded-2xl">
                        <span className="text-[9px] font-bold uppercase text-slate-400">Active Vulnerability Delta</span>
                        <div className="flex items-baseline gap-4 mt-2">
                          <span className="text-2xl font-black">{comparisonResults.scanA.stats.activeIssuesCount}</span>
                          <span className="text-slate-400 text-xs">➡️</span>
                          <span className="text-2xl font-black">{comparisonResults.scanB.stats.activeIssuesCount}</span>
                          <span className={`text-xs font-black ${comparisonResults.issuesDelta <= 0 ? 'text-green-500' : 'text-red-500'}`}>
                            ({comparisonResults.issuesDelta <= 0 ? `${comparisonResults.issuesDelta}` : `+${comparisonResults.issuesDelta}`})
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-slate-50 dark:bg-zinc-950 p-4 rounded-2xl border border-slate-200/50 dark:border-zinc-800 text-xs flex flex-col justify-between">
                      <div>
                        <span className="text-[9px] font-bold uppercase text-slate-400 block mb-2">Workspace Scope Changes</span>
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Baseline Files Scope:</span>
                            <span className="font-bold">{comparisonResults.scanA.filesCount} resources</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Comparison Files Scope:</span>
                            <span className="font-bold">{comparisonResults.scanB.filesCount} resources</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Baseline Breach Counts:</span>
                            <span className="font-bold">{comparisonResults.scanA.stats.totalIssues} detected</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Comparison Breach Counts:</span>
                            <span className="font-bold">{comparisonResults.scanB.stats.totalIssues} detected</span>
                          </div>
                        </div>
                      </div>
                      <p className="text-[10px] text-slate-400 leading-normal border-t border-slate-200/50 dark:border-zinc-800 pt-3 mt-3">
                        Scientific metrics reflect active mitigation efforts. Eliminating identified structural vulnerabilities directly contributes to security score compliance.
                      </p>
                    </div>

                  </div>
                </div>
              )}
            </section>

            {/* Timelines Registry */}
            <section className="bg-white dark:bg-zinc-900 p-6 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm">
              <h3 className="text-sm font-black uppercase tracking-wide border-b border-slate-100 dark:border-zinc-800 pb-3 mb-4">Historical Scanning Log Registry</h3>
              
              <div className="space-y-3">
                {scanHistory.map((historyItem, idx) => (
                  <div key={idx} className="p-4 rounded-2xl border border-slate-200 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/30 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 hover:border-slate-300 transition-all">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-black text-sm">{historyItem.projectName}</span>
                        <span className="text-[8px] font-bold text-slate-400 uppercase tracking-tight bg-slate-200/50 dark:bg-zinc-800 px-2 py-0.5 rounded">{historyItem.timestamp}</span>
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-slate-500 text-xs mt-1 font-medium">
                        <span>Scope: {historyItem.filesCount} files</span>
                        <span>Total Issues: {historyItem.stats.totalIssues}</span>
                        <span>Active Unmitigated: {historyItem.stats.activeIssuesCount}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="flex flex-col text-right">
                        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Security Score</span>
                        <span className={`text-lg font-black ${historyItem.stats.securityScore > 80 ? 'text-green-500' : historyItem.stats.securityScore >= 50 ? 'text-orange-500' : 'text-red-500'}`}>
                          {historyItem.stats.securityScore}%
                        </span>
                      </div>
                      
                      <button 
                        onClick={() => {
                          setResults(historyItem.results);
                          setFiles(new Array(historyItem.filesCount).fill({ name: "historical-resource.js" }));
                          setSelectedFileIdx(0);
                          setSelectedIssueIdx(null);
                          setActiveTab('scanner');
                          addActivityLog(`Loaded historical scan session from project "${historyItem.projectName}" into active inspector.`);
                        }}
                        className="text-xs font-bold border border-slate-200 dark:border-zinc-700 px-3.5 py-1.5 rounded-xl hover:bg-white dark:hover:bg-zinc-800 transition-all btn-press shadow-sm cursor-pointer"
                      >
                        Load to Inspector
                      </button>
                    </div>
                  </div>
                ))}

                {scanHistory.length === 0 && (
                  <p className="text-slate-400 text-xs italic text-center py-8">No historical analysis records logged in this local registry sandbox.</p>
                )}
              </div>
            </section>

          </div>
        )}

        {/* Tab 3: Developer Activity (Report 10: Developer Audit and Activity Log) */}
        {activeTab === 'activity' && (
          <div className="animate-reveal space-y-6">
            
            <section className="bg-white dark:bg-zinc-900 p-6 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex flex-col h-[600px]">
              <div className="mb-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-100 dark:border-zinc-800 pb-4">
                <div>
                  <h2 className="text-xl font-black uppercase tracking-tight">Developer Audit & Activity Log</h2>
                  <p className="text-slate-500 dark:text-zinc-400 text-xs mt-1">Chronological record of local static analysis operations secured with local signature validation tokens.</p>
                </div>
                
                <button 
                  onClick={handleClearAuditLog}
                  className="px-4 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-xl text-xs font-bold border border-red-100 transition-all btn-press cursor-pointer"
                >
                  Clear Audit Logs
                </button>
              </div>

              <div className="flex-1 overflow-y-auto pr-1 scrollbar-thin">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-[9px] font-black uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-zinc-800 pb-2">
                      <th className="pb-2">Timestamp</th>
                      <th className="pb-2">Transaction Action Description</th>
                      <th className="pb-2 text-right">Audit Verification Signature</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                    {activityLog.map((log, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/10">
                        <td className="py-3 text-slate-500 font-bold whitespace-nowrap">{log.timestamp}</td>
                        <td className="py-3 font-medium text-slate-700 dark:text-zinc-300 pr-4">{log.action}</td>
                        <td className="py-3 text-right font-mono font-bold text-red-600">{log.verificationHash || 'GEN-PENDING'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {activityLog.length === 0 && (
                  <p className="text-slate-400 text-xs italic text-center py-20">No transactions recorded in the secure audit sandbox registry.</p>
                )}
              </div>
            </section>

          </div>
        )}

        {/* Tab 4: False Positive Review (Report 9: False Positive Annotations Log) */}
        {activeTab === 'fp' && (
          <div className="animate-reveal space-y-6">
            
            <section className="bg-white dark:bg-zinc-900 p-6 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex flex-col h-[600px]">
              <div className="mb-4 border-b border-slate-100 dark:border-zinc-800 pb-4">
                <h2 className="text-xl font-black uppercase tracking-tight">False Positive Annotations Log</h2>
                <p className="text-slate-500 dark:text-zinc-400 text-xs mt-1">Annotated log of security breaches exempted from compliance calculations by authorized developers.</p>
              </div>

              <div className="flex-1 overflow-y-auto pr-1 scrollbar-thin">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-[9px] font-black uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-zinc-800 pb-2">
                      <th className="pb-2">Vulnerability Context Target</th>
                      <th className="pb-2">Rule Identification</th>
                      <th className="pb-2">Developer Rationale & Action Justification Annotation</th>
                      <th className="pb-2 text-right">MITIGATION STATUS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                    {fpFlags.map((key, idx) => {
                      const [fileName, ruleId, line, col] = key.split(':');
                      const annotation = fpAnnotations[key];

                      return (
                        <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/10">
                          <td className="py-4 pr-3">
                            <div className="font-bold text-slate-700 dark:text-zinc-300 truncate max-w-[180px]" title={fileName}>{fileName.split('/').pop()}</div>
                            <div className="text-[9px] text-slate-400 mt-0.5 font-bold">Line {line}, Column {col}</div>
                          </td>
                          <td className="py-4">
                            <span className="px-1.5 py-0.5 bg-slate-100 dark:bg-zinc-800 border border-slate-200/50 dark:border-zinc-700 rounded text-[9px] font-mono font-bold text-slate-500">{ruleId}</span>
                          </td>
                          <td className="py-4 pr-4">
                            <div className="space-y-1 max-w-md">
                              <input 
                                type="text" 
                                value={annotation?.reason || ''} 
                                onChange={(e) => updateFpAnnotation(key, e.target.value)}
                                placeholder="Enter justification override reason..."
                                className="w-full text-[10px] px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-black text-slate-700 dark:text-zinc-300 focus:outline-none"
                              />
                              <div className="text-[8px] text-slate-400 font-bold">{annotation?.timestamp ? `Saved: ${annotation.timestamp}` : 'Override justification required'}</div>
                            </div>
                          </td>
                          <td className="py-4 text-right">
                            <button 
                              onClick={() => toggleFalsePositive(fileName, { id: ruleId, line: parseInt(line), column: parseInt(col) })}
                              className="px-2.5 py-1 bg-green-500/10 hover:bg-green-500/20 text-green-600 rounded-lg text-[10px] font-bold border border-green-500/20 transition-all btn-press cursor-pointer"
                            >
                              Restore to Audit
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {fpFlags.length === 0 && (
                  <p className="text-slate-400 text-xs italic text-center py-20">No exemptions or false positive markings registered in this scanned workspace context.</p>
                )}
              </div>
            </section>

          </div>
        )}

      </main>

      <footer className="mt-20 py-12 border-t border-slate-200 dark:border-zinc-800 bg-slate-100/50 dark:bg-zinc-950/50">
        <div className="container mx-auto px-4">
           <div className="flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-slate-900 dark:bg-zinc-200 flex items-center justify-center text-white dark:text-zinc-900 font-bold text-xs shadow-lg">JS</div>
                <div className="flex flex-col text-left">
                  <span className="text-xs font-black uppercase tracking-widest leading-none">JSentinel Security Guard</span>
                  <span className="text-[9px] text-slate-500 font-bold uppercase mt-1">Local Browser Analysis • Academic Sandbox V1.0.0</span>
                </div>
              </div>
              
              <div className="flex gap-6 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <a href="#" className="hover:text-red-600 transition-colors">OWASP Core documentation</a>
                <a href="#" className="hover:text-red-600 transition-colors">Local Sandbox Privacy Policy</a>
              </div>

              <p className="text-[8px] text-slate-400 font-black uppercase tracking-widest">Client-Side Engine • Arellano University Capstone Project</p>
           </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
