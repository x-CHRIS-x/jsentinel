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
import { getGuidance, GUIDANCE_DISCLAIMER } from './data/guidanceCatalog';
import './App.css';

// Safely parse fpKey with full support for Windows drive letters and colons in file paths
const parseFpKey = (key) => {
  if (!key) return { fileName: '', ruleId: '', line: '', col: '' };
  const lastColon = key.lastIndexOf(':');
  if (lastColon === -1) return { fileName: key, ruleId: '', line: '', col: '' };
  const col = key.substring(lastColon + 1);
  const remainder1 = key.substring(0, lastColon);
  const secondLastColon = remainder1.lastIndexOf(':');
  if (secondLastColon === -1) return { fileName: remainder1, ruleId: '', line: col, col: '' };
  const line = remainder1.substring(secondLastColon + 1);
  const remainder2 = remainder1.substring(0, secondLastColon);
  const thirdLastColon = remainder2.lastIndexOf(':');
  if (thirdLastColon === -1) return { fileName: remainder2, ruleId: line, line: col, col: '' };
  const ruleId = remainder2.substring(thirdLastColon + 1);
  const fileName = remainder2.substring(0, thirdLastColon);
  return { fileName, ruleId, line, col };
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
      rawCode: res.rawCode || '',
      issues: res.issues || []
    }))
  };
};

function App() {
  // Navigation tabs: 'scanner', 'history', 'activity', 'fp'
  const [activeTab, setActiveTab] = useState('scanner');
  
  // Scanned Files / Results
  const [results, setResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [selectedFileIdx, setSelectedFileIdx] = useState(null);
  const [selectedIssueIdx, setSelectedIssueIdx] = useState(null);
  const [expandedGuidanceSections, setExpandedGuidanceSections] = useState(new Set());
  const [darkMode, setDarkMode] = useState(false);
  const [largeProjectWarning, setLargeProjectWarning] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [fileSearchQuery, setFileSearchQuery] = useState('');

  const toggleGuidanceSection = (key, section) => {
    const compositeKey = `${key}:${section}`;
    setExpandedGuidanceSections(prev => {
      const next = new Set(prev);
      if (next.has(compositeKey)) {
        next.delete(compositeKey);
      } else {
        next.add(compositeKey);
      }
      return next;
    });
  };

  // Filtering states
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [owaspFilter, setOwaspFilter] = useState('ALL');

  // Local Storage Data Structures with Automatic Deduplication
  const [scanHistory, setScanHistory] = useState(() => {
    const data = localStorage.getItem('jsentinel_scan_history');
    if (!data) return [];
    try {
      const parsed = JSON.parse(data);
      const seen = new Set();
      return parsed.filter(item => {
        const uniqueKey = item.id || `${item.timestamp}_${item.projectName}_${item.stats?.securityScore}`;
        if (seen.has(uniqueKey)) return false;
        seen.add(uniqueKey);
        return true;
      });
    } catch {
      return [];
    }
  });
  
  const [activityLog, setActivityLog] = useState(() => {
    const data = localStorage.getItem('jsentinel_activity_log');
    if (!data) return [];
    try {
      const parsed = JSON.parse(data);
      const seen = new Set();
      return parsed.filter(item => {
        const uniqueKey = item.id || item.hash || `${item.timestamp}_${item.action}`;
        if (seen.has(uniqueKey)) return false;
        seen.add(uniqueKey);
        return true;
      });
    } catch {
      return [];
    }
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

  const selectedResult = selectedFileIdx !== null ? results[selectedFileIdx] : null;

  // Filtered Issues for Interactive Findings List
  const filteredIssues = useMemo(() => {
    if (!selectedResult?.issues) return [];
    return selectedResult.issues.filter(issue => {
      if (severityFilter !== 'ALL' && issue.severity !== severityFilter) {
        return false;
      }
      if (owaspFilter !== 'ALL') {
        const match = issue.id.match(/^OWASP-(A\d+)/);
        const cat = match ? match[1] : 'A01';
        if (cat !== owaspFilter) return false;
      }
      return true;
    });
  }, [selectedResult, severityFilter, owaspFilter]);

  // Guidance Available Counter
  const guidanceAvailableCount = useMemo(() => {
    if (!selectedResult || !filteredIssues) return 0;
    return filteredIssues.filter(issue => {
      const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
      const isFP = fpFlags.includes(fpKey);
      return !isFP && !!getGuidance(issue);
    }).length;
  }, [selectedResult, filteredIssues, fpFlags]);

  // Handle Line clicks in Code Viewer to highlight finding
  const handleLineClick = (lineNum) => {
    if (selectedResult?.issues) {
      // First check if any active filtered issue is on this line
      const matchedFiltered = filteredIssues.find(issue => issue.line === lineNum);
      if (matchedFiltered) {
        const issueIdx = selectedResult.issues.indexOf(matchedFiltered);
        setSelectedIssueIdx(issueIdx);
        return;
      }
      // If not in current filtered list, find the issue and reset active filters so it appears
      const issueIdx = selectedResult.issues.findIndex(issue => issue.line === lineNum);
      if (issueIdx !== -1) {
        if (severityFilter !== 'ALL' || owaspFilter !== 'ALL') {
          setSeverityFilter('ALL');
          setOwaspFilter('ALL');
        }
        setSelectedIssueIdx(issueIdx);
      }
    }
  };

  // Scroll selected line into view in code viewer and findings inspector
  useEffect(() => {
    if (selectedIssueIdx !== null && selectedResult?.issues) {
      const issue = selectedResult.issues[selectedIssueIdx];
      if (issue) {
        setTimeout(() => {
          const lineEl = document.getElementById(`code-line-${issue.line}`);
          if (lineEl) {
            lineEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
          const cardEl = document.getElementById(`finding-card-${selectedIssueIdx}`);
          if (cardEl) {
            cardEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }, 50);
      }
    }
  }, [selectedIssueIdx, selectedFileIdx, selectedResult]);

  // Log filter alterations via event handlers
  const handleSeverityFilterChange = (sev) => {
    setSeverityFilter(sev);
    if (sev !== 'ALL') {
      addActivityLog(`Applied severity filter: ${sev}`);
    }
  };

  const handleOwaspFilterChange = (cat) => {
    setOwaspFilter(cat);
    if (cat !== 'ALL') {
      addActivityLog(`Applied OWASP category filter: ${cat}`);
    }
  };

  // Recalculates stats excluding items marked as False Positives
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
      'A01': { name: 'A01:2021-Broken Access Control', count: 0, severity: 'HIGH' },
      'A02': { name: 'A02:2021-Cryptographic Failures', count: 0, severity: 'CRITICAL' },
      'A03': { name: 'A03:2021-Injection', count: 0, severity: 'HIGH' },
      'A05': { name: 'A05:2021-Security Misconfiguration', count: 0, severity: 'MEDIUM' },
      'A06': { name: 'A06:2021-Vulnerable and Outdated Components', count: 0, severity: 'MEDIUM' },
      'A07': { name: 'A07:2021-Identification and Authentication Failures', count: 0, severity: 'HIGH' },
      'A08': { name: 'A08:2021-Software and Data Integrity Failures', count: 0, severity: 'MEDIUM' },
      'A10': { name: 'A10:2021-Server-Side Request Forgery (SSRF)', count: 0, severity: 'HIGH' }
    };

    results.forEach(res => {
      if (res.issues) {
        res.issues.forEach(issue => {
          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
          if (fpFlags.includes(fpKey)) return;

          const match = issue.id.match(/^OWASP-(A\d+)/);
          const cat = match ? match[1] : 'A01';
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

  // Filtered files for explorer
  const filteredWorkspaceFiles = useMemo(() => {
    if (!fileSearchQuery.trim()) return results;
    const q = fileSearchQuery.toLowerCase();
    return results.filter(r => r.fileName.toLowerCase().includes(q));
  }, [results, fileSearchQuery]);

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
        const readBatch = () => new Promise((resolve, reject) => {
          dirReader.readEntries(resolve, reject);
        });

        const entries = [];
        let batch;
        do {
          batch = await readBatch();
          entries.push(...batch);
        } while (batch && batch.length > 0);

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
      const path = (file.webkitRelativePath || file.name).replace(/\\/g, '/');
      const isHidden = path.split('/').some(part => part.startsWith('.'));
      const isNodeModules = path.includes('node_modules');
      const isDist = path.includes('dist') || path.includes('build');
      const extension = path.split('.').pop().toLowerCase();
      const isSupported = ['js', 'jsx', 'ts', 'tsx'].includes(extension);

      return !isHidden && !isNodeModules && !isDist && isSupported;
    });

    if (fileList.length > 0 && filtered.length === 0) {
      addActivityLog("No supported JavaScript/TypeScript source files (.js, .jsx, .ts, .tsx) found in upload selection.");
      setIsScanning(false);
      return;
    }

    if (filtered.length > 50) {
      setLargeProjectWarning(true);
    }

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

    const updatedResults = [...results, ...scanResults];
    setResults(updatedResults);
    if (selectedFileIdx === null && updatedResults.length > 0) {
      setSelectedFileIdx(0);
    }

    // Extract Project Name
    let projectName = "Uploaded Files";
    const firstWithRelative = filtered.find(f => f.webkitRelativePath);
    if (firstWithRelative) {
      const normalizedRel = firstWithRelative.webkitRelativePath.replace(/\\/g, '/');
      const parts = normalizedRel.split('/');
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

    updatedResults.forEach(res => {
      if (res.issues) {
        res.issues.forEach(issue => {
          const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
          const isFP = currentFPFlags.includes(fpKey);
          if (!isFP) {
            activeCount++;
            if (issue.severity === 'CRITICAL') {
              critical++;
              penalty += 20.0;
            } else if (issue.severity === 'HIGH') {
              high++;
              penalty += 10.0;
            } else if (issue.severity === 'MEDIUM') {
              medium++;
              penalty += 5.0;
            } else if (issue.severity === 'LOW') {
              low++;
              penalty += 1.0;
            }
          }
        });
      }
    });

    const finalScore = parseFloat(Math.max(0, 100 - penalty).toFixed(1));

    const newHistoryRecord = createScanHistoryRecord(projectName, updatedResults, activeCount, critical, high, medium, low, finalScore);
    setScanHistory(prevHist => [newHistoryRecord, ...prevHist]);
    addActivityLog(`Security scan completed for project "${projectName}" containing ${filtered.length} files.`);

    setIsScanning(false);
  };

  // Toggle False Positive flag
  const toggleFalsePositive = (fileName, issue, customReason = "", exactKey = null) => {
    const fpKey = exactKey || `${fileName}:${issue.id}:${issue.line}:${issue.column}`;
    const isCurrentlyFP = fpFlags.includes(fpKey);

    const displayFileName = fileName ? fileName.replace(/\\/g, '/').split('/').pop() : 'resource';
    const displayRuleId = issue?.id || parseFpKey(fpKey).ruleId || 'security rule';
    const displayLine = issue?.line || parseFpKey(fpKey).line || 'N/A';

    if (isCurrentlyFP) {
      // Remove from FP
      setFpFlags(prev => prev.filter(k => k !== fpKey));
      setFpAnnotations(prevAnn => {
        const next = { ...prevAnn };
        delete next[fpKey];
        return next;
      });
      addActivityLog(`Restored issue ${displayRuleId} (Line ${displayLine}) in file "${displayFileName}" from False Positive list.`);
    } else {
      // Add to FP
      setFpFlags(prev => [...prev, fpKey]);
      if (customReason) {
        setFpAnnotations(prevAnn => ({
          ...prevAnn,
          [fpKey]: {
            reason: customReason,
            timestamp: getCurrentTimestamp()
          }
        }));
      }
      addActivityLog(`Flagged issue ${displayRuleId} (Line ${displayLine}) in file "${displayFileName}" as False Positive.`);
    }

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
    const { ruleId } = parseFpKey(fpKey);
    addActivityLog(`Updated False Positive justification context for marked issue: ${ruleId || fpKey}`);
  };

  // Compare scan logic
  const handleCompare = () => {
    if (!compareScanA || !compareScanB) return;
    const scanA = scanHistory.find(s => s.id === compareScanA);
    const scanB = scanHistory.find(s => s.id === compareScanB);
    if (!scanA || !scanB) return;

    const scoreA = scanA.stats?.securityScore ?? 100;
    const scoreB = scanB.stats?.securityScore ?? 100;
    const activeA = scanA.stats?.activeIssuesCount ?? scanA.stats?.totalIssues ?? 0;
    const activeB = scanB.stats?.activeIssuesCount ?? scanB.stats?.totalIssues ?? 0;

    const scoreDelta = parseFloat((scoreB - scoreA).toFixed(1));
    const issuesDelta = activeB - activeA;

    setComparisonResults({
      scanA,
      scanB,
      scoreDelta,
      issuesDelta
    });
    addActivityLog(`Executed historical comparison analysis between scan (${scanA.projectName} - ${scanA.timestamp}) and scan (${scanB.projectName} - ${scanB.timestamp})`);
  };

  // Reset scan history log
  const handleClearScanHistory = () => {
    if (window.confirm("Are you sure you want to clear all historical scan records? This action cannot be undone.")) {
      setScanHistory([]);
      localStorage.removeItem('jsentinel_scan_history');
      setComparisonResults(null);
      setCompareScanA('');
      setCompareScanB('');
      addActivityLog("Historical scan registry cleared by developer authorization request.");
    }
  };

  // Reset audit log
  const handleClearAuditLog = () => {
    if (window.confirm("Are you sure you want to clear the audit activity log? This action cannot be undone.")) {
      setActivityLog([]);
      localStorage.removeItem('jsentinel_activity_log');
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
      className="min-h-screen bg-slate-50 transition-colors duration-300 dark:bg-zinc-950 font-sans text-slate-900 dark:text-zinc-100 flex flex-col justify-between"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag Overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-[100] bg-red-600/10 backdrop-blur-[2px] border-4 border-dashed border-red-600 m-4 rounded-3xl flex items-center justify-center pointer-events-none animate-reveal">
          <div className="bg-white dark:bg-zinc-900 p-8 rounded-3xl shadow-2xl flex flex-col items-center gap-4 border border-slate-200 dark:border-zinc-800">
            <div className="w-14 h-14 bg-red-600 rounded-2xl flex items-center justify-center text-white shadow-lg shadow-red-500/30">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
            <p className="text-base font-bold text-slate-900 dark:text-zinc-100">Drop files or project folder to scan</p>
          </div>
        </div>
      )}
      
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Top Bar Header */}
      <div>
        <header className="sticky top-0 z-40 w-full glass">
          <div className="container mx-auto flex h-16 items-center justify-between px-4 max-w-7xl">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-red-600 text-white shadow-md shadow-red-500/25">
                <span className="font-bold text-sm tracking-tight">JS</span>
              </div>
              <div className="flex flex-col">
                <h1 className="text-base font-bold font-display tracking-tight leading-tight">JSentinel</h1>
                <span className="text-[10px] font-medium text-slate-400 dark:text-zinc-500">Static Security Guard</span>
              </div>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center bg-slate-100 dark:bg-zinc-900/90 p-1 rounded-xl border border-slate-200/80 dark:border-zinc-800">
              {[
                { id: 'scanner', label: 'Vulnerability Scanner' },
                { id: 'history', label: 'Scan History' },
                { id: 'activity', label: 'Developer Activity' },
                { id: 'fp', label: 'False Positives', badge: fpFlags.length > 0 ? fpFlags.length : null }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all cursor-pointer flex items-center gap-1.5 btn-press ${
                    activeTab === tab.id 
                      ? 'bg-white dark:bg-zinc-800 text-red-600 dark:text-red-400 shadow-xs font-semibold border border-slate-200/80 dark:border-zinc-700' 
                      : 'text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200'
                  }`}
                >
                  <span>{tab.label}</span>
                  {tab.badge !== null && (
                    <span className="text-[9px] px-1.5 py-0.2 bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 rounded-full font-bold">
                      {tab.badge}
                    </span>
                  )}
                </button>
              ))}
            </nav>

            {/* Right Header Actions */}
            <div className="flex items-center gap-2">
              <button 
                onClick={() => setDarkMode(!darkMode)}
                className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors text-slate-500 dark:text-zinc-400 cursor-pointer btn-press border border-slate-200/80 dark:border-zinc-800"
                title={darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
              >
                {darkMode ? (
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                ) : (
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                )}
              </button>
              
              <button 
                className="rounded-xl border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-3.5 py-1.5 text-xs font-semibold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all disabled:opacity-40 cursor-pointer disabled:cursor-not-allowed flex items-center gap-1.5 btn-press shadow-xs" 
                disabled={results.length === 0}
                onClick={() => {
                  addActivityLog(`Security report JSON export initiated for scanned files.`);
                  generateJSONReport(results, stats, owaspCategories, fpFlags);
                }}
              >
                <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                <span>Export JSON</span>
              </button>

              <button 
                className="rounded-xl bg-slate-900 dark:bg-zinc-100 px-3.5 py-1.5 text-xs font-semibold text-white dark:text-zinc-900 hover:opacity-90 transition-all disabled:opacity-40 cursor-pointer disabled:cursor-not-allowed flex items-center gap-1.5 btn-press shadow-xs" 
                disabled={results.length === 0 || isExporting}
                onClick={async () => {
                  setIsExporting(true);
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
                  <>
                    <svg className="w-3.5 h-3.5 text-red-500 dark:text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                    <span>Export PDF</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </header>

        {/* Mobile Navigation Bar */}
        <div className="md:hidden w-full bg-white dark:bg-zinc-900 border-b border-slate-200 dark:border-zinc-800 p-2 flex justify-around">
          {[
            { id: 'scanner', label: 'Scanner' },
            { id: 'history', label: 'History' },
            { id: 'activity', label: 'Activity' },
            { id: 'fp', label: 'False Positives', badge: fpFlags.length > 0 ? fpFlags.length : null }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`text-xs font-semibold px-3 py-1.5 rounded-lg cursor-pointer flex items-center gap-1.5 ${
                activeTab === tab.id 
                  ? 'bg-red-50 dark:bg-zinc-800 text-red-600 dark:text-red-400' 
                  : 'text-slate-500 dark:text-zinc-400'
              }`}
            >
              <span>{tab.label}</span>
              {tab.badge !== null && tab.badge !== undefined && (
                <span className="text-[9px] px-1.5 py-0.2 bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 rounded-full font-bold">
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>

        <main className="container mx-auto px-4 py-5 max-w-7xl">
          
          {/* ========================================================================= */}
          {/* TAB 1: VULNERABILITY SCANNER (Decluttered & Streamlined)                 */}
          {/* ========================================================================= */}
          {activeTab === 'scanner' && (
            <div className="animate-reveal space-y-4">
              
              {/* Empty / Intake State */}
              {results.length === 0 && (
                <div className="space-y-6 max-w-4xl mx-auto py-10">
                  <div className="text-center space-y-2">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 text-xs font-semibold border border-red-100 dark:border-red-900/40">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-600 animate-pulse"></span>
                      Local Static Security Analyzer
                    </div>
                    <h2 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-zinc-100">
                      Client-Side Vulnerability Scanner
                    </h2>
                    <p className="text-slate-500 dark:text-zinc-400 text-sm max-w-xl mx-auto">
                      Audit JavaScript and TypeScript code directly in your browser without transmitting source code to any external backend.
                    </p>
                  </div>

                  {/* Dropzone Container */}
                  <div 
                    onClick={() => fileInputRef.current?.click()}
                    className="p-10 rounded-3xl bg-white dark:bg-zinc-900 border-2 border-dashed border-slate-300 dark:border-zinc-700 hover:border-red-500 dark:hover:border-red-500 transition-all text-center cursor-pointer shadow-xs group flex flex-col items-center gap-4"
                  >
                    <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-zinc-800 text-red-600 flex items-center justify-center group-hover:scale-105 transition-transform shadow-xs">
                      <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                    </div>

                    <div className="space-y-1">
                      <p className="text-base font-bold text-slate-800 dark:text-zinc-200">
                        Drag and drop source files or project folders here
                      </p>
                      <p className="text-xs text-slate-400 dark:text-zinc-500">
                        Supports <span className="font-mono text-slate-600 dark:text-zinc-300">.js, .jsx, .ts, .tsx</span>
                      </p>
                    </div>

                    <div className="flex items-center gap-3 pt-2" onClick={(e) => e.stopPropagation()}>
                      <button 
                        onClick={() => fileInputRef.current?.click()} 
                        className="px-4 py-2 rounded-xl border border-slate-200 dark:border-zinc-700 text-xs font-semibold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all btn-press shadow-xs cursor-pointer"
                      >
                        Select Files
                      </button>
                      <button 
                        onClick={() => folderInputRef.current?.click()} 
                        className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold transition-all btn-press shadow-md shadow-red-500/20 cursor-pointer"
                      >
                        Upload Project Folder
                      </button>
                    </div>
                  </div>

                  {/* Highlights Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                    <div className="p-4 rounded-2xl bg-white dark:bg-zinc-900 border border-slate-200/80 dark:border-zinc-800 shadow-xs space-y-1.5">
                      <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 flex items-center justify-center text-sm font-bold">✓</div>
                      <h3 className="text-xs font-bold text-slate-800 dark:text-zinc-200">100% In-Browser AST Parsing</h3>
                      <p className="text-[11px] text-slate-500 dark:text-zinc-400 leading-relaxed">
                        Uses Babel Standalone parser locally. Zero network requests, keeping proprietary code confidential.
                      </p>
                    </div>

                    <div className="p-4 rounded-2xl bg-white dark:bg-zinc-900 border border-slate-200/80 dark:border-zinc-800 shadow-xs space-y-1.5">
                      <div className="w-8 h-8 rounded-lg bg-red-50 dark:bg-red-950/30 text-red-600 flex items-center justify-center text-sm font-bold">🛡️</div>
                      <h3 className="text-xs font-bold text-slate-800 dark:text-zinc-200">OWASP Top 10 Coverage</h3>
                      <p className="text-[11px] text-slate-500 dark:text-zinc-400 leading-relaxed">
                        Identifies Injection, XSS, SSRF, Broken Auth, Hardcoded Secrets, Prototype Pollution, and Misconfigurations.
                      </p>
                    </div>

                    <div className="p-4 rounded-2xl bg-white dark:bg-zinc-900 border border-slate-200/80 dark:border-zinc-800 shadow-xs space-y-1.5">
                      <div className="w-8 h-8 rounded-lg bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 flex items-center justify-center text-sm font-bold">⚡</div>
                      <h3 className="text-xs font-bold text-slate-800 dark:text-zinc-200">Security Remediation Guidance</h3>
                      <p className="text-[11px] text-slate-500 dark:text-zinc-400 leading-relaxed">
                        Contextual remediation guidance with risk analysis, analyzer limitations, and verification checklists.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Scanned Results State */}
              {results.length > 0 && (
                <>
                  {/* Compact High-Density Summary Toolbar */}
                  <div className="bg-white dark:bg-zinc-900 border border-slate-200/90 dark:border-zinc-800 rounded-2xl p-3 shadow-xs flex flex-wrap items-center justify-between gap-3">
                    
                    {/* Left Group: Score, File & Issue Counters */}
                    <div className="flex flex-wrap items-center gap-3 sm:gap-4">
                      
                      {/* Dominant Security Score Container with Status-Matched Tint */}
                      <div className={`flex items-center gap-3.5 px-4 py-2 sm:px-5 sm:py-2.5 rounded-2xl border shadow-xs transition-all ${
                        stats.securityScore > 80
                          ? 'bg-emerald-500/10 dark:bg-emerald-950/30 border-emerald-500/30 dark:border-emerald-800/40'
                          : stats.securityScore >= 50
                          ? 'bg-amber-500/10 dark:bg-amber-950/30 border-amber-500/30 dark:border-amber-800/40'
                          : 'bg-rose-500/10 dark:bg-rose-950/30 border-rose-500/30 dark:border-rose-800/40'
                      }`}>
                        {/* 2.5x Larger Headline Score */}
                        <span className={`text-3xl sm:text-4xl font-black font-mono tracking-tight leading-none ${
                          stats.securityScore > 80 
                            ? 'text-emerald-600 dark:text-emerald-400' 
                            : stats.securityScore >= 50 
                            ? 'text-amber-600 dark:text-amber-400' 
                            : 'text-rose-600 dark:text-rose-400'
                        }`}>
                          {stats.securityScore.toFixed(0)}%
                        </span>
                        
                        <div className="flex flex-col gap-0.5">
                          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400 dark:text-zinc-500 leading-none">Security Score</span>
                          <span className={`text-xs font-black uppercase tracking-wide leading-none mt-0.5 ${
                            stats.securityScore > 80 
                              ? 'text-emerald-600 dark:text-emerald-400' 
                              : stats.securityScore >= 50 
                              ? 'text-amber-600 dark:text-amber-400' 
                              : 'text-rose-600 dark:text-rose-400'
                          }`}>
                            {stats.securityScore > 80 ? 'Compliant' : stats.securityScore >= 50 ? 'Warning' : 'Vulnerable'}
                          </span>
                        </div>

                        {/* CVSS Tooltip */}
                        <div className="group relative cursor-pointer ml-0.5">
                          <span className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-zinc-200">ⓘ</span>
                          <div className="absolute left-0 top-full mt-2.5 hidden group-hover:block w-72 bg-slate-900/95 dark:bg-zinc-900/95 backdrop-blur-md text-white text-[10px] p-3.5 rounded-2xl border border-slate-700/80 dark:border-zinc-700 shadow-2xl leading-normal z-50 pointer-events-none">
                            <p className="font-bold text-xs mb-1 text-slate-100">CVSS-Inspired Deduction Model</p>
                            <p className="text-slate-300 font-mono text-[9px] bg-slate-800/80 dark:bg-zinc-800/80 px-2 py-1 rounded-md mb-2">Score = max(0, 100 - sum(deductions))</p>
                            <div className="grid grid-cols-2 border-t border-slate-800 dark:border-zinc-800 pt-2 text-[9px] gap-1 font-medium">
                              <span className="text-rose-400 font-semibold">• Critical: -20 pts</span>
                              <span className="text-orange-400 font-semibold">• High: -10 pts</span>
                              <span className="text-amber-400 font-semibold">• Medium: -5 pts</span>
                              <span className="text-slate-400 font-semibold">• Low: -1 pt</span>
                            </div>
                            <p className="mt-2 text-[9px] text-emerald-400 font-medium border-t border-slate-800/60 dark:border-zinc-800/60 pt-1.5">Exempting false positives restores score instantly.</p>
                          </div>
                        </div>
                      </div>

                      {/* Vertical Divider between Score and Secondary Stats */}
                      <div className="h-8 w-px bg-slate-200 dark:bg-zinc-800 hidden sm:block mx-0.5"></div>

                      {/* Secondary Stats Group: Files & Issues */}
                      <div className="flex items-center gap-2">
                        {/* Workspace Scope Pill */}
                        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-slate-50 dark:bg-zinc-950 border border-slate-200/80 dark:border-zinc-800 text-xs">
                          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Files</span>
                          <span className="font-bold text-slate-800 dark:text-zinc-200">{results.length}</span>
                        </div>

                        {/* Active Issues Counter */}
                        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-slate-50 dark:bg-zinc-950 border border-slate-200/80 dark:border-zinc-800 text-xs">
                          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Issues</span>
                          <span className="font-bold">
                            <span className={stats.activeIssuesCount > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}>
                              {stats.activeIssuesCount}
                            </span>
                            <span className="text-slate-400 font-normal"> / {stats.totalIssues}</span>
                          </span>
                        </div>

                        {/* False Positive Exemption Pill (if any) */}
                        {fpFlags.length > 0 && (
                          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200/60 dark:border-emerald-900/40 text-xs text-emerald-700 dark:text-emerald-400">
                            <span className="text-[9px] font-bold uppercase tracking-wider">Exempted</span>
                            <span className="font-bold">{fpFlags.length}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Center Group: Quick Severity Filter Pills */}
                    <div className="flex items-center gap-1 bg-slate-50 dark:bg-zinc-950 p-1 rounded-xl border border-slate-200/80 dark:border-zinc-800">
                      {[
                        { id: 'ALL', label: 'All', count: stats.activeIssuesCount },
                        { id: 'CRITICAL', label: 'Critical', count: stats.criticalIssues, color: 'text-rose-600 dark:text-rose-400' },
                        { id: 'HIGH', label: 'High', count: stats.highIssues, color: 'text-orange-600 dark:text-orange-400' },
                        { id: 'MEDIUM', label: 'Medium', count: stats.mediumIssues, color: 'text-amber-600 dark:text-amber-400' },
                        { id: 'LOW', label: 'Low', count: stats.lowIssues, color: 'text-slate-600 dark:text-zinc-400' }
                      ].map((sev) => {
                        const isSelected = severityFilter === sev.id;
                        return (
                          <button
                            key={sev.id}
                            onClick={() => handleSeverityFilterChange(sev.id)}
                            className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 btn-press ${
                              isSelected 
                                ? 'bg-white dark:bg-zinc-800 text-red-600 dark:text-red-400 shadow-xs border border-slate-200/80 dark:border-zinc-700' 
                                : 'text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-zinc-200'
                            }`}
                          >
                            <span>{sev.label}</span>
                            <span className={`text-[10px] font-mono font-bold px-1 rounded ${
                              isSelected 
                                ? 'bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400' 
                                : 'bg-slate-200/60 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400'
                            }`}>
                              {sev.count}
                            </span>
                          </button>
                        );
                      })}
                    </div>

                    {/* Right Group: OWASP Category Dropdown & Quick Actions */}
                    <div className="flex items-center gap-2">
                      <select
                        value={owaspFilter}
                        onChange={(e) => handleOwaspFilterChange(e.target.value)}
                        className={`text-xs font-semibold px-3 py-1.5 rounded-xl border transition-all cursor-pointer bg-white dark:bg-zinc-900 ${
                          owaspFilter !== 'ALL'
                            ? 'border-red-500 text-red-600 dark:text-red-400 bg-red-50/40 dark:bg-red-950/20'
                            : 'border-slate-200 dark:border-zinc-800 text-slate-600 dark:text-zinc-300 hover:border-slate-300 dark:hover:border-zinc-700'
                        }`}
                        title="Filter findings by OWASP category"
                      >
                        <option value="ALL">All Categories ({compliantCategoriesCount}/8 Compliant)</option>
                        {owaspCategories.map(cat => {
                          const catCode = cat.name.split(':')[0];
                          return (
                            <option key={catCode} value={catCode}>
                              {cat.name} ({cat.count} {cat.count === 1 ? 'issue' : 'issues'})
                            </option>
                          );
                        })}
                      </select>

                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="px-3 py-1.5 rounded-xl border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-xs font-semibold text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800 transition-all btn-press cursor-pointer flex items-center gap-1.5 shadow-xs"
                        title="Add more files to current scan"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"/></svg>
                        <span className="hidden sm:inline">Add Files</span>
                      </button>

                      <button
                        onClick={() => {
                          setResults([]);
                          setSelectedFileIdx(null);
                          setSelectedIssueIdx(null);
                          setLargeProjectWarning(false);
                          setSeverityFilter('ALL');
                          setOwaspFilter('ALL');
                          addActivityLog("Scanner session cleared by user request.");
                        }}
                        className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-zinc-800 rounded-xl transition-all btn-press cursor-pointer border border-transparent hover:border-red-100 dark:hover:border-red-900/30"
                        title="Reset workspace session"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                      </button>
                    </div>

                  </div>

                  {largeProjectWarning && (
                    <div className="p-2.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/40 text-amber-800 dark:text-amber-300 text-xs flex items-center gap-2">
                      <span>⚠️</span>
                      <span className="font-semibold">Large Workspace Notice:</span>
                      <span>Scanning over 50 files may impact browser performance during concurrent rule transforms.</span>
                    </div>
                  )}

                  {/* Primary IDE Inspector Workspace (Zero Vertical Scrolling Needed) */}
                  <div className="flex flex-col lg:flex-row gap-4 h-auto lg:h-[calc(100vh-210px)] lg:min-h-[640px]">
                    
                    {/* Left Column: File Explorer */}
                    <div className="w-full lg:w-72 flex flex-col bg-white dark:bg-zinc-900 rounded-2xl border border-slate-200/90 dark:border-zinc-800 overflow-hidden shadow-xs shrink-0 max-lg:h-64">
                      <div className="p-3 border-b border-slate-200/80 dark:border-zinc-800 flex justify-between items-center bg-slate-50/50 dark:bg-zinc-900/50">
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Workspace Files</span>
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 bg-slate-200/60 dark:bg-zinc-800 rounded-md text-slate-500">
                            {results.length}
                          </span>
                        </div>
                        {isScanning && <div className="h-2 w-2 rounded-full bg-red-600 animate-ping" />}
                      </div>

                      {/* File Search Filter */}
                      {results.length > 5 && (
                        <div className="p-2 border-b border-slate-100 dark:border-zinc-800/80 bg-slate-50/30 dark:bg-zinc-950/30">
                          <input
                            type="text"
                            placeholder="Filter files..."
                            value={fileSearchQuery}
                            onChange={(e) => setFileSearchQuery(e.target.value)}
                            className="w-full text-xs px-2.5 py-1 rounded-lg border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-slate-700 dark:text-zinc-300 focus:outline-none focus:border-red-500"
                          />
                        </div>
                      )}

                      {/* File List */}
                      <div className="flex-1 overflow-y-auto p-2 space-y-1 scrollbar-thin">
                        {filteredWorkspaceFiles.map((res) => {
                          const originalIdx = results.indexOf(res);
                          const activeCount = res.issues ? res.issues.filter(issue => {
                            const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                            return !fpFlags.includes(fpKey);
                          }).length : 0;

                          const isSelected = selectedFileIdx === originalIdx;

                          return (
                            <button 
                              key={originalIdx} 
                              onClick={() => { setSelectedFileIdx(originalIdx); setSelectedIssueIdx(null); }}
                              className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-xl transition-all text-left cursor-pointer btn-press border ${
                                isSelected 
                                  ? 'bg-red-50/60 dark:bg-zinc-800/90 shadow-xs border-red-200 dark:border-zinc-700' 
                                  : 'bg-transparent border-transparent hover:bg-slate-100/70 dark:hover:bg-zinc-800/40'
                              }`}
                            >
                              <div className={`h-2 w-2 rounded-full shrink-0 ${
                                activeCount > 0 
                                  ? 'bg-red-500 shadow-sm shadow-red-500/50' 
                                  : (!res.success || res.hasError) 
                                  ? 'bg-amber-400' 
                                  : 'bg-emerald-500'
                              }`} />
                              
                              <span className={`text-xs truncate flex-1 font-semibold ${
                                isSelected 
                                  ? 'text-red-700 dark:text-red-400' 
                                  : 'text-slate-600 dark:text-zinc-300'
                              }`} title={res.fileName}>
                                {res.fileName.replace(/\\/g, '/').split('/').pop()}
                              </span>

                              {res.issues && res.issues.length > 0 && (
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                                  isSelected 
                                    ? 'bg-red-500 text-white' 
                                    : activeCount > 0
                                    ? 'bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400'
                                    : 'bg-slate-100 dark:bg-zinc-800 text-slate-400'
                                }`}>
                                  {activeCount}/{res.issues.length}
                                </span>
                              )}
                            </button>
                          );
                        })}

                        {filteredWorkspaceFiles.length === 0 && (
                          <p className="text-slate-400 text-xs italic text-center py-6">No matching files</p>
                        )}
                      </div>
                    </div>

                    {/* Middle Column: Source Code Viewer */}
                    <div className="flex-1 min-w-0 flex flex-col bg-white dark:bg-zinc-900 rounded-2xl border border-slate-200/90 dark:border-zinc-800 overflow-hidden shadow-xs max-lg:min-h-[420px]">
                      
                      {/* Code Viewer Header */}
                      <div className="p-3 border-b border-slate-200/80 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/50 flex items-center justify-between">
                        <div className="flex items-center gap-2 truncate">
                          <div className="w-6 h-6 rounded-lg bg-slate-200 dark:bg-zinc-800 flex items-center justify-center shrink-0">
                            <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                          </div>
                          <span className="text-xs font-bold truncate text-slate-800 dark:text-zinc-200" title={selectedResult?.fileName}>
                            {selectedResult ? selectedResult.fileName : 'Source Code Viewer'}
                          </span>
                        </div>

                        {selectedResult && (
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="text-[10px] font-mono text-slate-400">
                              {selectedResult.rawCode ? `${selectedResult.rawCode.split('\n').length} lines` : ''}
                            </span>
                            <span className="text-[9px] font-bold px-2 py-0.5 bg-slate-100 dark:bg-zinc-800 text-slate-500 rounded-md">
                              Babel Standalone
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Code Viewer Body */}
                      <div className="flex-1 overflow-auto p-4 font-mono text-xs leading-relaxed bg-slate-900 text-slate-100 dark:bg-zinc-950 dark:text-zinc-200 scrollbar-thin">
                        {selectedResult && selectedResult.success ? (
                          selectedResult.rawCode ? (
                            (() => {
                              const lines = selectedResult.rawCode.split('\n');
                              const activeFPIs = selectedResult.issues ? selectedResult.issues.filter(issue => {
                                const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                                return fpFlags.includes(fpKey);
                              }).map(i => i.line) : [];

                              const activeTargetIssues = filteredIssues.filter(issue => {
                                const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                                return !fpFlags.includes(fpKey);
                              }).map(i => i.line);

                              const selectedIssueLine = (selectedIssueIdx !== null && selectedResult.issues) 
                                ? selectedResult.issues[selectedIssueIdx]?.line 
                                : null;

                              return lines.map((text, idx) => {
                                const num = idx + 1;
                                const isFPLine = activeFPIs.includes(num);
                                const isIssueLine = activeTargetIssues.includes(num);
                                const isSelectedLine = selectedIssueLine === num;

                                let rowStyle = "opacity-75 hover:bg-slate-800/50 cursor-pointer";
                                if (isSelectedLine) rowStyle = "line-selected-pulse text-red-400 font-bold -mx-4 px-4 bg-red-950/40";
                                else if (isIssueLine) rowStyle = "bg-red-950/30 text-red-400 font-semibold -mx-4 px-4 border-l-2 border-red-500 cursor-pointer hover:bg-red-950/40";
                                else if (isFPLine) rowStyle = "bg-emerald-950/20 text-emerald-400 -mx-4 px-4 border-l-2 border-emerald-500 opacity-80 cursor-pointer hover:bg-emerald-950/30";

                                return (
                                  <div 
                                    key={idx} 
                                    id={`code-line-${num}`}
                                    onClick={() => handleLineClick(num)}
                                    className={`flex gap-3 py-0.5 ${rowStyle}`}
                                  >
                                    <span className="w-8 text-right select-none text-slate-600 dark:text-zinc-600 font-mono text-[11px] shrink-0">{num}</span>
                                    <code className="whitespace-pre overflow-x-visible">{text || ' '}</code>
                                  </div>
                                );
                              });
                            })()
                          ) : (
                            <div className="h-full flex flex-col items-center justify-center text-slate-400 text-center py-16 px-4">
                              <div className="text-3xl mb-2">📄</div>
                              <p className="text-xs font-bold text-slate-300">Archived Historical Record</p>
                              <p className="text-[11px] text-slate-500 mt-1 max-w-xs leading-relaxed">Source code text is not cached in local storage for archived sessions. Review identified breach records and remediation guides in the findings panel.</p>
                            </div>
                          )
                        ) : selectedResult ? (
                          <div className="h-full flex items-center justify-center text-red-400 font-medium text-center">
                            Resource parsing failed. Check for syntax exceptions.
                          </div>
                        ) : (
                          <div className="h-full flex flex-col items-center justify-center opacity-40 text-center py-20">
                            <p className="text-xs font-semibold uppercase tracking-wider">No resource selected</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Right Column: Findings & Remediation Inspector */}
                    <div className="w-full lg:w-[400px] flex flex-col bg-white dark:bg-zinc-900 rounded-2xl border border-slate-200/90 dark:border-zinc-800 overflow-hidden shadow-xs shrink-0 max-lg:h-[500px]">
                      
                      {/* Findings Header */}
                      <div className="p-3 border-b border-slate-200/80 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/50 flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Findings & Guidance</span>
                          <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 bg-slate-200/60 dark:bg-zinc-800 rounded-md text-slate-500">
                            {filteredIssues.length}
                          </span>
                        </div>
                        {guidanceAvailableCount > 0 && (
                          <span className="px-2 py-0.5 bg-indigo-50 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400 rounded-lg text-[10px] font-semibold border border-indigo-200/60 dark:border-indigo-900/40">
                            {guidanceAvailableCount} guidance available
                          </span>
                        )}
                      </div>

                      {/* Active Filter Notice (if severity or OWASP filtered) */}
                      {(severityFilter !== 'ALL' || owaspFilter !== 'ALL') && (
                        <div className="px-3 py-1.5 bg-red-50/50 dark:bg-zinc-950/50 border-b border-slate-100 dark:border-zinc-800 flex justify-between items-center text-[10px] text-red-600 dark:text-red-400 font-semibold">
                          <span className="truncate">
                            Filtered: {severityFilter !== 'ALL' ? severityFilter : ''} {owaspFilter !== 'ALL' ? `• ${owaspFilter}` : ''}
                          </span>
                          <button 
                            onClick={() => { setSeverityFilter('ALL'); setOwaspFilter('ALL'); }}
                            className="text-[9px] font-bold underline hover:opacity-80 cursor-pointer shrink-0 ml-2"
                          >
                            Reset
                          </button>
                        </div>
                      )}

                      {/* Findings List */}
                      <div className="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin">
                        {selectedResult && filteredIssues && filteredIssues.length > 0 ? (
                          filteredIssues.map((issue) => {
                            const originalIdx = selectedResult.issues.indexOf(issue);
                            const fpKey = `${selectedResult.fileName}:${issue.id}:${issue.line}:${issue.column}`;
                            const isFP = fpFlags.includes(fpKey);
                            const isSelected = selectedIssueIdx === originalIdx;

                            return (
                              <div 
                                key={originalIdx} 
                                id={`finding-card-${originalIdx}`}
                                className={`p-3.5 rounded-xl border transition-all ${
                                  isFP 
                                    ? 'border-emerald-200 dark:border-emerald-900/40 bg-emerald-50/20 dark:bg-emerald-950/10 opacity-75' 
                                    : isSelected 
                                    ? 'border-red-500 bg-red-50/30 dark:bg-red-950/20 shadow-xs' 
                                    : 'border-slate-200/80 dark:border-zinc-800 bg-slate-50/40 dark:bg-zinc-900/60 hover:border-slate-300 dark:hover:border-zinc-700'
                                }`}
                              >
                                <div className="flex justify-between items-start gap-1.5">
                                  <div className="flex flex-wrap gap-1.5 items-center">
                                    <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                                      isFP 
                                        ? 'bg-emerald-600 text-white' 
                                        : issue.severity === 'CRITICAL' 
                                        ? 'bg-red-600 text-white' 
                                        : issue.severity === 'HIGH'
                                        ? 'bg-orange-500 text-white'
                                        : issue.severity === 'MEDIUM'
                                        ? 'bg-amber-500 text-white'
                                        : 'bg-zinc-500 text-white'
                                    }`}>
                                      {isFP ? 'Exempted' : issue.severity}
                                    </span>
                                    <span className="text-[10px] font-mono font-normal text-zinc-400 dark:text-zinc-500">{issue.id}</span>
                                  </div>
                                  <span className="text-[10px] font-mono font-normal text-zinc-400 dark:text-zinc-500 bg-zinc-100 dark:bg-zinc-800/80 px-2 py-0.5 rounded-md border border-zinc-200/60 dark:border-zinc-800">
                                    Line {issue.line}
                                  </span>
                                </div>

                                <h4 className={`text-sm font-bold mt-2 leading-snug tracking-tight ${
                                  isFP ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-900 dark:text-zinc-100'
                                }`}>
                                  {issue.message}
                                </h4>
                                
                                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 leading-relaxed">
                                  {issue.suggestion}
                                </p>

                                {/* Justification Context Input (when selected for FP) */}
                                {!isFP && isSelected && (
                                  <div className="mt-2.5 pt-2.5 border-t border-red-200/50 dark:border-red-900/30 space-y-1.5 animate-reveal">
                                    <label className="text-[9px] font-bold uppercase tracking-wider text-slate-400 block">Developer Override Justification:</label>
                                    <input 
                                      type="text" 
                                      placeholder="Reason for exemption (e.g. validated test stub)..." 
                                      id={`justification_${originalIdx}`}
                                      className="w-full text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 text-slate-700 dark:text-zinc-300 focus:outline-none focus:border-red-500" 
                                    />
                                  </div>
                                )}

                                {/* Action Buttons Row */}
                                <div className="mt-3 flex justify-between items-center gap-2 border-t border-slate-100 dark:border-zinc-800 pt-2 text-[10px]">
                                  <button 
                                    onClick={() => setSelectedIssueIdx(isSelected ? null : originalIdx)}
                                    className="font-bold text-indigo-600 dark:text-indigo-400 hover:underline cursor-pointer flex items-center gap-1"
                                  >
                                    <span>{isSelected ? 'Hide Guidance' : 'View Guidance'}</span>
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
                                    className={`font-semibold cursor-pointer ${
                                      isFP 
                                        ? 'text-slate-500 hover:text-slate-800 dark:hover:text-zinc-200' 
                                        : 'text-emerald-600 dark:text-emerald-400 hover:underline'
                                    }`}
                                  >
                                    {isFP ? 'Restore to Audit' : isSelected ? 'Confirm False Positive' : 'Mark as FP'}
                                  </button>
                                </div>

                                {/* Action-First Compact Guidance Panel */}
                                {isSelected && (() => {
                                  const guidance = getGuidance(issue);
                                  const detectedLine = issue.sourceLine || (selectedResult?.rawCode ? selectedResult.rawCode.split('\n')[issue.line - 1] : null);
                                  const isFlaggedExpanded = expandedGuidanceSections.has(`${fpKey}:flagged`);
                                  const isApproachExpanded = expandedGuidanceSections.has(`${fpKey}:approach`);
                                  const isTestExpanded = expandedGuidanceSections.has(`${fpKey}:test`);
                                  const isExampleExpanded = expandedGuidanceSections.has(`${fpKey}:example`);

                                  return (
                                    <div className="mt-3 pt-3 border-t border-slate-200 dark:border-zinc-800 space-y-2.5 animate-reveal text-left">
                                      {/* 1. Detected code */}
                                      <div className="space-y-1">
                                        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400 dark:text-zinc-500 block">
                                          Detected code (Line {issue.line})
                                        </span>
                                        {detectedLine !== null && detectedLine !== undefined ? (() => {
                                          const trimmed = (detectedLine || '').trim() || `Line ${issue.line}`;
                                          const displayCode = trimmed.length > 280 ? (trimmed.slice(0, 280) + '... (truncated)') : trimmed;
                                          return (
                                            <div className="p-2 rounded-lg bg-slate-900 text-slate-100 dark:bg-zinc-950 font-mono text-[10px] overflow-x-auto border border-slate-700/50 dark:border-zinc-800">
                                              <code className="whitespace-pre-wrap break-all">{displayCode}</code>
                                            </div>
                                          );
                                        })() : (
                                          <div className="p-2 rounded-lg bg-slate-100 dark:bg-zinc-800/60 text-slate-500 dark:text-zinc-400 font-mono text-[10px] italic border border-slate-200 dark:border-zinc-700">
                                            Source code line is unavailable for this archived scan record.
                                          </div>
                                        )}
                                      </div>

                                      {/* 2. Suggested next step (Visual Priority) & 3. Context indicator */}
                                      <div className="p-2.5 rounded-lg bg-indigo-50/70 dark:bg-indigo-950/30 border border-indigo-200/70 dark:border-indigo-900/40 space-y-1.5">
                                        <div className="flex items-center justify-between gap-1.5 flex-wrap">
                                          <span className="text-[9px] font-bold uppercase tracking-wider text-indigo-700 dark:text-indigo-400 block">
                                            Suggested next step
                                          </span>
                                          <div className="flex items-center gap-1.5 flex-wrap">
                                            {guidance.scope && (
                                              <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                                                {guidance.scope === 'browser' ? 'Browser Scope' : guidance.scope === 'server' ? 'Server Scope' : 'Cross-Boundary Scope'}
                                              </span>
                                            )}
                                            {guidance.scope === 'cross-boundary' && (
                                              <span className="text-[8px] font-medium px-1.5 py-0.5 rounded bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400 border border-slate-200/60 dark:border-zinc-700/60">
                                                Requires project context
                                              </span>
                                            )}
                                          </div>
                                        </div>
                                        <p className="text-[11.5px] font-bold text-slate-900 dark:text-zinc-100 leading-snug">
                                          {guidance.shortAction || guidance.recommendedAction}
                                        </p>
                                      </div>

                                      {/* 4. Compact detail actions (Progressive Disclosure) */}
                                      <div className="space-y-1 pt-0.5">
                                        {/* Action 1: Why this was flagged */}
                                        <div className="rounded-lg border border-slate-200/70 dark:border-zinc-800/80 overflow-hidden bg-slate-50/50 dark:bg-zinc-900/30">
                                          <button
                                            type="button"
                                            onClick={() => toggleGuidanceSection(fpKey, 'flagged')}
                                            aria-expanded={isFlaggedExpanded}
                                            aria-controls={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-flagged`}
                                            className="w-full flex items-center justify-between px-3 py-1.5 text-left hover:bg-slate-100/70 dark:hover:bg-zinc-800/50 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-500 transition-colors cursor-pointer"
                                          >
                                            <span className="text-[10.5px] font-semibold text-slate-700 dark:text-zinc-300">
                                              Why this was flagged
                                            </span>
                                            <span className="text-[10px] text-slate-400 dark:text-zinc-500 font-mono">
                                              {isFlaggedExpanded ? '▴' : '▾'}
                                            </span>
                                          </button>
                                          {isFlaggedExpanded && (
                                            <div id={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-flagged`} className="px-3 pb-2.5 pt-1 border-t border-slate-200/50 dark:border-zinc-800/50 text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed animate-reveal">
                                              <p>{guidance.risk}</p>
                                            </div>
                                          )}
                                        </div>

                                        {/* Action 2: Choose an approach */}
                                        <div className="rounded-lg border border-slate-200/70 dark:border-zinc-800/80 overflow-hidden bg-slate-50/50 dark:bg-zinc-900/30">
                                          <button
                                            type="button"
                                            onClick={() => toggleGuidanceSection(fpKey, 'approach')}
                                            aria-expanded={isApproachExpanded}
                                            aria-controls={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-approach`}
                                            className="w-full flex items-center justify-between px-3 py-1.5 text-left hover:bg-slate-100/70 dark:hover:bg-zinc-800/50 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-500 transition-colors cursor-pointer"
                                          >
                                            <span className="text-[10.5px] font-semibold text-slate-700 dark:text-zinc-300">
                                              Choose an approach
                                            </span>
                                            <span className="text-[10px] text-slate-400 dark:text-zinc-500 font-mono">
                                              {isApproachExpanded ? '▴' : '▾'}
                                            </span>
                                          </button>
                                          {isApproachExpanded && (
                                            <div id={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-approach`} className="px-3 pb-2.5 pt-1 border-t border-slate-200/50 dark:border-zinc-800/50 space-y-1.5 animate-reveal">
                                              <ul className="space-y-1.5 text-[10.5px] text-slate-700 dark:text-zinc-300">
                                                {guidance.approaches && guidance.approaches.map((appr, idx) => {
                                                  if (typeof appr === 'string') {
                                                    const colonIdx = appr.indexOf(':');
                                                    if (colonIdx !== -1) {
                                                      const title = appr.slice(0, colonIdx);
                                                      const desc = appr.slice(colonIdx + 1).trim();
                                                      return (
                                                        <li key={idx} className="flex items-start gap-1.5 leading-relaxed">
                                                          <span className="text-indigo-500 dark:text-indigo-400 font-bold shrink-0">•</span>
                                                          <span>
                                                            <strong className="text-slate-900 dark:text-zinc-100">{title}:</strong> {desc}
                                                          </span>
                                                        </li>
                                                      );
                                                    }
                                                    return (
                                                      <li key={idx} className="flex items-start gap-1.5 leading-relaxed">
                                                        <span className="text-indigo-500 dark:text-indigo-400 font-bold shrink-0">•</span>
                                                        <span>{appr}</span>
                                                      </li>
                                                    );
                                                  }
                                                  if (typeof appr === 'object' && appr !== null) {
                                                    return (
                                                      <li key={idx} className="flex items-start gap-1.5 leading-relaxed">
                                                        <span className="text-indigo-500 dark:text-indigo-400 font-bold shrink-0">•</span>
                                                        <span>
                                                          <strong className="text-slate-900 dark:text-zinc-100">{appr.title}:</strong> {appr.description}
                                                        </span>
                                                      </li>
                                                    );
                                                  }
                                                  return null;
                                                })}
                                              </ul>
                                            </div>
                                          )}
                                        </div>

                                        {/* Action 3: How to test */}
                                        <div className="rounded-lg border border-slate-200/70 dark:border-zinc-800/80 overflow-hidden bg-slate-50/50 dark:bg-zinc-900/30">
                                          <button
                                            type="button"
                                            onClick={() => toggleGuidanceSection(fpKey, 'test')}
                                            aria-expanded={isTestExpanded}
                                            aria-controls={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-test`}
                                            className="w-full flex items-center justify-between px-3 py-1.5 text-left hover:bg-slate-100/70 dark:hover:bg-zinc-800/50 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-500 transition-colors cursor-pointer"
                                          >
                                            <span className="text-[10.5px] font-semibold text-slate-700 dark:text-zinc-300">
                                              How to test
                                            </span>
                                            <span className="text-[10px] text-slate-400 dark:text-zinc-500 font-mono">
                                              {isTestExpanded ? '▴' : '▾'}
                                            </span>
                                          </button>
                                          {isTestExpanded && (
                                            <div id={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-test`} className="px-3 pb-2.5 pt-1 border-t border-slate-200/50 dark:border-zinc-800/50 space-y-1.5 animate-reveal">
                                              <ul className="space-y-1 text-[10.5px] text-slate-700 dark:text-zinc-300">
                                                {guidance.verifySteps && guidance.verifySteps.map((step, idx) => (
                                                  <li key={idx} className="flex items-start gap-1.5 leading-relaxed">
                                                    <span className="text-emerald-500 dark:text-emerald-400 font-bold shrink-0">✓</span>
                                                    <span>{step}</span>
                                                  </li>
                                                ))}
                                              </ul>
                                            </div>
                                          )}
                                        </div>

                                        {/* Action 4: Example structure */}
                                        <div className="rounded-lg border border-slate-200/70 dark:border-zinc-800/80 overflow-hidden bg-slate-50/50 dark:bg-zinc-900/30">
                                          <button
                                            type="button"
                                            onClick={() => toggleGuidanceSection(fpKey, 'example')}
                                            aria-expanded={isExampleExpanded}
                                            aria-controls={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-example`}
                                            className="w-full flex items-center justify-between px-3 py-1.5 text-left hover:bg-slate-100/70 dark:hover:bg-zinc-800/50 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-500 transition-colors cursor-pointer"
                                          >
                                            <span className="text-[10.5px] font-semibold text-slate-700 dark:text-zinc-300">
                                              Example structure
                                            </span>
                                            <span className="text-[10px] text-slate-400 dark:text-zinc-500 font-mono">
                                              {isExampleExpanded ? '▴' : '▾'}
                                            </span>
                                          </button>
                                          {isExampleExpanded && (
                                            <div id={`guidance-panel-${fpKey.replace(/[^a-zA-Z0-9_-]/g, '_')}-example`} className="px-3 pb-2.5 pt-2 border-t border-slate-200/50 dark:border-zinc-800/50 space-y-2 animate-reveal">
                                              {/* Why there isn't one exact fix (plain language, non-blocker) */}
                                              <div className="p-2.5 rounded-lg bg-slate-100/80 dark:bg-zinc-800/50 border border-slate-200/70 dark:border-zinc-700/50 space-y-1">
                                                <span className="text-[9px] font-bold uppercase tracking-wider text-slate-700 dark:text-zinc-300 flex items-center gap-1.5">
                                                  <svg className="w-3 h-3 text-indigo-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                                                    <circle cx="12" cy="12" r="10" />
                                                    <line x1="12" y1="16" x2="12" y2="12" />
                                                    <line x1="12" y1="8" x2="12.01" y2="8" />
                                                  </svg>
                                                  Why there isn't one exact fix
                                                </span>
                                                <p className="text-[10.5px] text-slate-600 dark:text-zinc-300 leading-relaxed">
                                                  {guidance.cannotInfer}
                                                </p>
                                              </div>

                                              {/* Illustrative pattern */}
                                              {(() => {
                                                const patternContent = guidance.illustrativePattern || '// Conceptual pattern: consult architectural guidelines and project security standards for safe implementation.';
                                                return (
                                                  <div className="space-y-1">
                                                    <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-zinc-400 block">
                                                      Illustrative pattern: adapt this to your project
                                                    </span>
                                                    <div className="p-2 rounded-lg bg-slate-900 text-slate-100 dark:bg-zinc-950 font-mono text-[10px] overflow-x-auto border border-slate-700/50 dark:border-zinc-800">
                                                      <code className="whitespace-pre-wrap break-all">{patternContent}</code>
                                                    </div>
                                                  </div>
                                                );
                                              })()}

                                              {/* Educational Disclaimer */}
                                              <div className="p-2 rounded-lg bg-indigo-50/60 dark:bg-indigo-950/30 border border-indigo-100/80 dark:border-indigo-900/40 text-[9px] text-indigo-700 dark:text-indigo-300 italic leading-snug">
                                                {GUIDANCE_DISCLAIMER}
                                              </div>
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  );
                                })()}
                              </div>
                            );
                          })
                        ) : (
                          <div className="h-full flex items-center justify-center opacity-40 text-center py-16 text-xs font-semibold">
                            No findings match selected filters
                          </div>
                        )}
                      </div>
                    </div>

                  </div>
                </>
              )}

            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 2: SCAN HISTORY (Historical Comparison Analysis)                     */}
          {/* ========================================================================= */}
          {activeTab === 'history' && (
            <div className="space-y-6 animate-reveal">
              
              {/* Comparison Section */}
              <section className="bg-white dark:bg-zinc-900 p-6 rounded-2xl border border-slate-200/90 dark:border-zinc-800 shadow-xs space-y-4">
                <div>
                  <h2 className="text-lg font-bold tracking-tight text-slate-900 dark:text-zinc-100">Historical Comparison Analysis</h2>
                  <p className="text-slate-500 dark:text-zinc-400 text-xs mt-0.5">Perform delta audits between scanning sessions to monitor mitigation trends.</p>
                </div>

                {scanHistory.length >= 2 ? (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end bg-slate-50 dark:bg-zinc-950 p-4 rounded-xl border border-slate-200/80 dark:border-zinc-800">
                    <div className="space-y-1">
                      <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Baseline Scan (A):</label>
                      <select 
                        value={compareScanA} 
                        onChange={(e) => setCompareScanA(e.target.value)}
                        className="w-full text-xs p-2 rounded-lg border border-slate-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-slate-700 dark:text-zinc-300"
                      >
                        <option value="">Select baseline scan...</option>
                        {scanHistory.map(s => (
                          <option key={s.id} value={s.id}>{s.projectName} ({s.timestamp}) - Score: {s.stats.securityScore}%</option>
                        ))}
                      </select>
                    </div>
                    
                    <div className="space-y-1">
                      <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Comparison Scan (B):</label>
                      <select 
                        value={compareScanB} 
                        onChange={(e) => setCompareScanB(e.target.value)}
                        className="w-full text-xs p-2 rounded-lg border border-slate-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-slate-700 dark:text-zinc-300"
                      >
                        <option value="">Select comparison target...</option>
                        {scanHistory.map(s => (
                          <option key={s.id} value={s.id}>{s.projectName} ({s.timestamp}) - Score: {s.stats.securityScore}%</option>
                        ))}
                      </select>
                    </div>

                    <button 
                      onClick={handleCompare}
                      className="w-full bg-slate-900 dark:bg-zinc-100 text-white dark:text-zinc-900 py-2 rounded-lg text-xs font-semibold hover:opacity-90 transition-all btn-press cursor-pointer"
                    >
                      Compare Audits
                    </button>
                  </div>
                ) : (
                  <p className="text-slate-400 text-xs italic">A minimum of two recorded scanning sessions is required to run comparative analyses.</p>
                )}

                {/* Comparison Results */}
                {comparisonResults && (
                  <div className="mt-4 border-t border-slate-100 dark:border-zinc-800 pt-4 animate-reveal">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Mitigation Delta Details</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      
                      <div className="space-y-3">
                        <div className="p-4 bg-slate-50 dark:bg-zinc-950 border border-slate-200/80 dark:border-zinc-800 rounded-xl">
                          <span className="text-[10px] font-bold uppercase text-slate-400">Security Rating Progression</span>
                          <div className="flex items-baseline gap-3 mt-1.5">
                            <span className="text-2xl font-bold font-mono">{comparisonResults.scanA.stats.securityScore}%</span>
                            <span className="text-slate-400 text-xs">→</span>
                            <span className="text-2xl font-bold font-mono">{comparisonResults.scanB.stats.securityScore}%</span>
                            <span className={`text-xs font-bold font-mono ${comparisonResults.scoreDelta >= 0 ? 'text-emerald-600' : 'text-rose-600'}`}>
                              ({comparisonResults.scoreDelta >= 0 ? `+${comparisonResults.scoreDelta}` : comparisonResults.scoreDelta}%)
                            </span>
                          </div>
                        </div>

                        <div className="p-4 bg-slate-50 dark:bg-zinc-950 border border-slate-200/80 dark:border-zinc-800 rounded-xl">
                          <span className="text-[10px] font-bold uppercase text-slate-400">Active Vulnerability Delta</span>
                          <div className="flex items-baseline gap-3 mt-1.5">
                            <span className="text-xl font-bold font-mono">{comparisonResults.scanA.stats.activeIssuesCount}</span>
                            <span className="text-slate-400 text-xs">→</span>
                            <span className="text-xl font-bold font-mono">{comparisonResults.scanB.stats.activeIssuesCount}</span>
                            <span className={`text-xs font-bold font-mono ${comparisonResults.issuesDelta <= 0 ? 'text-emerald-600' : 'text-rose-600'}`}>
                              ({comparisonResults.issuesDelta <= 0 ? `${comparisonResults.issuesDelta}` : `+${comparisonResults.issuesDelta}`})
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="bg-slate-50 dark:bg-zinc-950 p-4 rounded-xl border border-slate-200/80 dark:border-zinc-800 text-xs flex flex-col justify-between">
                        <div>
                          <span className="text-[10px] font-bold uppercase text-slate-400 block mb-2">Workspace Scope Changes</span>
                          <div className="space-y-1.5">
                            <div className="flex justify-between">
                              <span className="text-slate-500">Baseline Files Scope:</span>
                              <span className="font-semibold">{comparisonResults.scanA.filesCount} resources</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500">Comparison Files Scope:</span>
                              <span className="font-semibold">{comparisonResults.scanB.filesCount} resources</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500">Baseline Breach Counts:</span>
                              <span className="font-semibold">{comparisonResults.scanA.stats.totalIssues} detected</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-500">Comparison Breach Counts:</span>
                              <span className="font-semibold">{comparisonResults.scanB.stats.totalIssues} detected</span>
                            </div>
                          </div>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed border-t border-slate-200/80 dark:border-zinc-800 pt-2 mt-2">
                          Eliminating identified structural vulnerabilities directly contributes to security score compliance.
                        </p>
                      </div>

                    </div>
                  </div>
                )}
              </section>

              {/* Scanning Log Registry */}
              <section className="bg-white dark:bg-zinc-900 p-6 rounded-2xl border border-slate-200/90 dark:border-zinc-800 shadow-xs space-y-3">
                <div className="flex justify-between items-center border-b border-slate-100 dark:border-zinc-800 pb-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Historical Scanning Log Registry</h3>
                  {scanHistory.length > 0 && (
                    <button 
                      onClick={handleClearScanHistory}
                      className="px-3 py-1 bg-red-50 hover:bg-red-100 text-red-600 dark:bg-red-950/40 dark:hover:bg-red-950/60 dark:text-red-400 rounded-lg text-xs font-semibold border border-red-100 dark:border-red-900/30 transition-all btn-press cursor-pointer"
                    >
                      Clear Scan History
                    </button>
                  )}
                </div>
                
                <div className="space-y-2.5">
                  {scanHistory.map((historyItem, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl border border-slate-200/80 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-950/40 flex flex-col md:flex-row justify-between items-start md:items-center gap-3 hover:border-slate-300 dark:hover:border-zinc-700 transition-all">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-slate-800 dark:text-zinc-200">{historyItem.projectName}</span>
                          <span className="text-[9px] font-mono text-slate-400 bg-slate-200/60 dark:bg-zinc-800 px-2 py-0.5 rounded">{historyItem.timestamp}</span>
                        </div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-slate-500 text-xs mt-1 font-medium">
                          <span>Scope: {historyItem.filesCount} files</span>
                          <span>Total Issues: {historyItem.stats.totalIssues}</span>
                          <span>Active Unmitigated: {historyItem.stats.activeIssuesCount}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="flex flex-col text-right">
                          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Score</span>
                          <span className={`text-base font-bold font-mono ${historyItem.stats.securityScore > 80 ? 'text-emerald-600' : historyItem.stats.securityScore >= 50 ? 'text-amber-600' : 'text-rose-600'}`}>
                            {historyItem.stats.securityScore}%
                          </span>
                        </div>
                        
                        <button 
                          onClick={() => {
                            setResults(historyItem.results || []);
                            setSelectedFileIdx(historyItem.results && historyItem.results.length > 0 ? 0 : null);
                            setSelectedIssueIdx(null);
                            setActiveTab('scanner');
                            addActivityLog(`Loaded historical scan session from project "${historyItem.projectName}" into active scanner.`);
                          }}
                          className="text-xs font-semibold border border-slate-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-3 py-1.5 rounded-lg hover:bg-slate-50 dark:hover:bg-zinc-700 transition-all btn-press shadow-xs cursor-pointer"
                        >
                          Load Scan
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

          {/* ========================================================================= */}
          {/* TAB 3: DEVELOPER ACTIVITY (Audit Log)                                    */}
          {/* ========================================================================= */}
          {activeTab === 'activity' && (
            <div className="animate-reveal space-y-6">
              
              <section className="bg-white dark:bg-zinc-900 p-6 rounded-2xl border border-slate-200/90 dark:border-zinc-800 shadow-xs flex flex-col h-[600px]">
                <div className="mb-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-3 border-b border-slate-100 dark:border-zinc-800 pb-3">
                  <div>
                    <h2 className="text-lg font-bold tracking-tight text-slate-900 dark:text-zinc-100">Developer Audit & Activity Log</h2>
                    <p className="text-slate-500 dark:text-zinc-400 text-xs mt-0.5">Chronological record of local static analysis operations secured with local validation hashes.</p>
                  </div>
                  
                  <button 
                    onClick={handleClearAuditLog}
                    className="px-3 py-1.5 bg-red-50 hover:bg-red-100 text-red-600 dark:bg-red-950/40 dark:hover:bg-red-950/60 dark:text-red-400 rounded-lg text-xs font-semibold border border-red-100 dark:border-red-900/30 transition-all btn-press cursor-pointer"
                  >
                    Clear Audit Logs
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto pr-1 scrollbar-thin">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-zinc-800 pb-2">
                        <th className="pb-2">Timestamp</th>
                        <th className="pb-2">Transaction Action Description</th>
                        <th className="pb-2 text-right">Verification Signature</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                      {activityLog.map((log, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/20">
                          <td className="py-2.5 text-slate-500 font-mono font-medium whitespace-nowrap">{log.timestamp}</td>
                          <td className="py-2.5 font-medium text-slate-700 dark:text-zinc-300 pr-4">{log.action}</td>
                          <td className="py-2.5 text-right font-mono font-bold text-red-600 dark:text-red-400">{log.verificationHash || 'GEN-PENDING'}</td>
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

          {/* ========================================================================= */}
          {/* TAB 4: FALSE POSITIVES (Exemption Review)                                 */}
          {/* ========================================================================= */}
          {activeTab === 'fp' && (
            <div className="animate-reveal space-y-6">
              
              <section className="bg-white dark:bg-zinc-900 p-6 rounded-2xl border border-slate-200/90 dark:border-zinc-800 shadow-xs flex flex-col h-[600px]">
                <div className="mb-4 border-b border-slate-100 dark:border-zinc-800 pb-3 flex justify-between items-center">
                  <div>
                    <h2 className="text-lg font-bold tracking-tight text-slate-900 dark:text-zinc-100">False Positive Annotations Log</h2>
                    <p className="text-slate-500 dark:text-zinc-400 text-xs mt-0.5">Annotated log of security breaches exempted from compliance calculations by authorized developers.</p>
                  </div>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 rounded-md border border-emerald-200/60 dark:border-emerald-900/40">
                    {fpFlags.length} Exempted
                  </span>
                </div>

                <div className="flex-1 overflow-y-auto pr-1 scrollbar-thin">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-zinc-800 pb-2">
                        <th className="pb-2">Vulnerability Target</th>
                        <th className="pb-2">Rule ID</th>
                        <th className="pb-2">Developer Override Justification Rationale</th>
                        <th className="pb-2 text-right">Status & Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-zinc-800">
                      {fpFlags.map((key, idx) => {
                        const { fileName, ruleId, line, col } = parseFpKey(key);
                        const annotation = fpAnnotations[key];
                        const shortName = fileName.replace(/\\/g, '/').split('/').pop();

                        return (
                          <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-zinc-800/20">
                            <td className="py-3 pr-3">
                              <div className="font-semibold text-slate-700 dark:text-zinc-300 truncate max-w-[180px]" title={fileName}>{shortName || fileName}</div>
                              <div className="text-[10px] font-mono text-slate-400 mt-0.5">Line {line || 'N/A'}, Col {col || 'N/A'}</div>
                            </td>
                            <td className="py-3">
                              <span className="px-2 py-0.5 bg-slate-100 dark:bg-zinc-800 border border-slate-200/60 dark:border-zinc-700 rounded text-[10px] font-mono font-semibold text-slate-600 dark:text-zinc-300">{ruleId}</span>
                            </td>
                            <td className="py-3 pr-4">
                              <div className="space-y-1 max-w-md">
                                <input 
                                  type="text" 
                                  value={annotation?.reason || ''} 
                                  onChange={(e) => updateFpAnnotation(key, e.target.value)}
                                  placeholder="Enter justification override reason..."
                                  className="w-full text-xs px-2.5 py-1 rounded-lg border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 text-slate-700 dark:text-zinc-300 focus:outline-none focus:border-red-500"
                                />
                                <div className="text-[9px] text-slate-400 font-mono">{annotation?.timestamp ? `Saved: ${annotation.timestamp}` : 'Override justification required'}</div>
                              </div>
                            </td>
                            <td className="py-3 text-right">
                              <button 
                                onClick={() => toggleFalsePositive(fileName, { id: ruleId, line, column: col }, '', key)}
                                className="px-2.5 py-1 bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950/40 dark:hover:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 rounded-lg text-[11px] font-semibold border border-emerald-200/60 dark:border-emerald-900/40 transition-all btn-press cursor-pointer"
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
      </div>

      {/* Footer */}
      <footer className="mt-12 py-6 border-t border-slate-200 dark:border-zinc-800 bg-white/60 dark:bg-zinc-950/60 text-slate-500 dark:text-zinc-400 text-xs">
        <div className="container mx-auto px-4 max-w-7xl">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="h-6 w-6 rounded-lg bg-red-600 flex items-center justify-center text-white font-bold text-[10px]">JS</div>
              <span className="font-semibold text-slate-700 dark:text-zinc-300">JSentinel Static Security Guard</span>
              <span className="text-slate-400 text-[10px]">• Client-Side Engine v1.0.0</span>
            </div>
            
            <div className="flex items-center gap-4 text-[11px] text-slate-400">
              <span className="hover:text-slate-600 dark:hover:text-zinc-300 cursor-pointer">OWASP Core Documentation</span>
              <span>•</span>
              <span className="hover:text-slate-600 dark:hover:text-zinc-300 cursor-pointer">Local Privacy Sandbox</span>
              <span>•</span>
              <span className="text-slate-400">Arellano University Capstone Project</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
