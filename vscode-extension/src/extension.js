/**
 * JSentinel VS Code Extension: Main Entry Point
 * 
 * JSENTINEL: A Client-Side Static Analysis System for Detecting JavaScript
 * Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm
 */

const vscode = require('vscode');
const { scanCode } = require('./scanner/scannerEngine');
const { allRules } = require('./scanner/rules');
const { createDiagnostics } = require('./diagnosticsProvider');
const { createHoverProvider } = require('./hoverProvider');
const { JSentinelSidebarProvider } = require('./sidebarProvider');

// Diagnostics collection for tracking issues across files in the problems pane
let diagnosticCollection;

// Shared issues map for hover provider, keyed by file URI string
const issuesMap = new Map();

// Shared in-memory scan state for the Webview Dashboard
// uriString -> { fileName, relativePath, issues, success, hasError, error }
const scannedFiles = {};

// Sidebar provider instance
let sidebarProvider;

/**
 * Calculates security stats and score based on scanned files and active false positives
 */
const calculateStats = (scannedFiles, fpFlags) => {
  let totalIssues = 0;
  let activeIssuesCount = 0;
  let criticalIssues = 0;
  let highIssues = 0;
  let mediumIssues = 0;
  let lowIssues = 0;
  let penalty = 0.0;

  Object.values(scannedFiles).forEach(fileData => {
    if (fileData.issues) {
      fileData.issues.forEach(issue => {
        totalIssues++;
        const fpKey = `${fileData.fileName}:${issue.id}:${issue.line}:${issue.column}`;
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
    securityScore,
    filesScanned: Object.keys(scannedFiles).length
  };
};

/**
 * Pushes the updated extension state to the Sidebar Webview
 */
const updateSidebarState = (context) => {
  if (!sidebarProvider) return;
  const fpFlags = context.workspaceState.get('jsentinel_fpFlags', []);
  const stats = calculateStats(scannedFiles, fpFlags);
  sidebarProvider.updateState(scannedFiles, fpFlags, stats);
};

/**
 * Scans a single document and updates its diagnostics.
 * @param {vscode.TextDocument} document
 * @param {vscode.ExtensionContext} context
 */
const scanDocument = (document, context) => {
  // Only scan supported file types (by language ID or file extension fallback)
  const supportedLanguages = ['javascript', 'javascriptreact', 'typescript', 'typescriptreact'];
  const fileNameLower = document.fileName.toLowerCase();
  const hasSupportedExtension = 
    fileNameLower.endsWith('.js') || 
    fileNameLower.endsWith('.jsx') || 
    fileNameLower.endsWith('.ts') || 
    fileNameLower.endsWith('.tsx');

  if (!supportedLanguages.includes(document.languageId) && !hasSupportedExtension) {
    return;
  }

  const code = document.getText();
  const fileName = document.fileName;
  const uriStr = document.uri.toString();

  // Get severity filter and false positives
  const config = vscode.workspace.getConfiguration('jsentinel');
  const severityFilter = config.get('severityFilter', 'ALL');
  const fpFlags = context.workspaceState.get('jsentinel_fpFlags', []);

  try {
    const result = scanCode(code, fileName, allRules);

    if (result.success) {
      // Store issues in global scannedFiles state
      scannedFiles[uriStr] = {
        fileName,
        relativePath: vscode.workspace.asRelativePath(document.uri),
        issues: result.issues,
        success: true,
        hasError: result.hasError
      };

      issuesMap.set(uriStr, result.issues);

      // Create diagnostics with false positive filtering
      const diagnostics = createDiagnostics(document, result.issues, severityFilter, fpFlags);
      diagnosticCollection.set(document.uri, diagnostics);

      // Show status bar summary
      const criticalCount = result.issues.filter(i => i.severity === 'CRITICAL').length;
      const highCount = result.issues.filter(i => i.severity === 'HIGH').length;
      const totalActive = result.issues.length;

      if (criticalCount > 0) {
        vscode.window.setStatusBarMessage(
          `$(shield) JSentinel: ${totalActive} issues found (${criticalCount} critical, ${highCount} high)`,
          5000
        );
      } else if (totalActive > 0) {
        vscode.window.setStatusBarMessage(
          `$(shield) JSentinel: ${totalActive} issues found`,
          5000
        );
      }
    } else {
      // Parse error
      scannedFiles[uriStr] = {
        fileName,
        relativePath: vscode.workspace.asRelativePath(document.uri),
        issues: [],
        success: false,
        hasError: true,
        error: result.error
      };

      issuesMap.delete(uriStr);
      diagnosticCollection.set(document.uri, []);
      if (result.error) {
        vscode.window.setStatusBarMessage(`$(warning) JSentinel: Parse error in ${fileName}`, 5000);
      }
    }
  } catch (error) {
    console.error('JSentinel scan error:', error);
    vscode.window.setStatusBarMessage(`$(error) JSentinel: Scan failed: ${error.message}`, 5000);
  }

  updateSidebarState(context);
};

/**
 * Scans all supported files in the workspace.
 * @param {vscode.ExtensionContext} context
 */
const scanWorkspace = async (context) => {
  const files = await vscode.workspace.findFiles(
    '**/*.{js,jsx,ts,tsx}',
    '{**/node_modules/**,**/dist/**,**/build/**,**/.git/**}'
  );

  if (files.length === 0) {
    vscode.window.showInformationMessage('JSentinel: No JavaScript/TypeScript files found in workspace.');
    return;
  }

  // Clear stale scannedFiles
  Object.keys(scannedFiles).forEach(key => delete scannedFiles[key]);
  issuesMap.clear();

  // Show progress
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'JSentinel: Scanning workspace for vulnerabilities...',
      cancellable: true
    },
    async (progress, token) => {
      let totalIssues = 0;
      let scannedCount = 0;

      for (const fileUri of files) {
        if (token.isCancellationRequested) {
          vscode.window.showInformationMessage('JSentinel: Workspace scan cancelled.');
          return;
        }

        try {
          const document = await vscode.workspace.openTextDocument(fileUri);
          scanDocument(document, context);

          const diags = diagnosticCollection.get(fileUri);
          if (diags) {
            totalIssues += diags.length;
          }
        } catch (err) {
          console.warn(`JSentinel: Could not scan ${fileUri.fsPath}:`, err.message);
        }

        scannedCount++;
        progress.report({
          increment: (100 / files.length),
          message: `${scannedCount}/${files.length} files scanned...`
        });
      }

      vscode.window.showInformationMessage(
        `JSentinel: Workspace scan complete. ${scannedCount} files scanned, ${totalIssues} issues found.`
      );
    }
  );
};

/**
 * Exports a Markdown security report to the workspace root
 * @param {vscode.ExtensionContext} context
 */
const exportReport = async (context) => {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage('JSentinel: No workspace folder open to export report.');
    return;
  }

  const rootPath = workspaceFolders[0].uri;
  const reportUri = vscode.Uri.joinPath(rootPath, 'jsentinel_report.md');

  const fpFlags = context.workspaceState.get('jsentinel_fpFlags', []);
  const stats = calculateStats(scannedFiles, fpFlags);

  let mdContent = `# JSentinel Security Scan Report\n\n`;
  mdContent += `*Generated by JSentinel Static Analysis on ${new Date().toLocaleString()}*\n\n`;

  mdContent += `## 📊 Security Metrics\n\n`;
  
  let scoreText = 'Vulnerable';
  if (stats.securityScore > 80) scoreText = 'Compliant';
  else if (stats.securityScore >= 50) scoreText = 'Warning';

  mdContent += `- **Security Score:** \`${stats.securityScore}%\` (${scoreText})\n`;
  mdContent += `- **Files Scanned:** ${stats.filesScanned}\n`;
  mdContent += `- **Active Vulnerabilities:** ${stats.activeIssuesCount}\n`;
  mdContent += `- **Ignored False Positives:** ${fpFlags.length}\n\n`;

  mdContent += `### Severity Breakdown\n\n`;
  mdContent += `| Severity | Count |\n`;
  mdContent += `| :--- | :--- |\n`;
  mdContent += `| 🔴 CRITICAL | ${stats.criticalIssues} |\n`;
  mdContent += `| 🟠 HIGH | ${stats.highIssues} |\n`;
  mdContent += `| 🟡 MEDIUM | ${stats.mediumIssues} |\n`;
  mdContent += `| 🔵 LOW | ${stats.lowIssues} |\n\n`;

  mdContent += `## 🛡️ Detailed Findings\n\n`;

  let hasActiveIssues = false;

  Object.entries(scannedFiles).forEach(([uriStr, fileData]) => {
    const activeIssues = (fileData.issues || []).filter(issue => {
      const fpKey = `${fileData.fileName}:${issue.id}:${issue.line}:${issue.column}`;
      return !fpFlags.includes(fpKey);
    });

    if (activeIssues.length > 0) {
      hasActiveIssues = true;
      mdContent += `### 📄 File: \`${fileData.relativePath}\`\n\n`;
      mdContent += `| Line | Severity | Rule ID | Message | Suggestion | Confidence |\n`;
      mdContent += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
      
      activeIssues.forEach(issue => {
        mdContent += `| L${issue.line} | **${issue.severity}** | \`${issue.id}\` | ${issue.message} | ${issue.suggestion || 'Verify manually.'} | ${issue.confidence || 'MEDIUM'} |\n`;
      });
      mdContent += `\n`;
    }
  });

  if (!hasActiveIssues) {
    mdContent += `*No active security vulnerabilities detected! Great job! 🎉*\n\n`;
  }

  const ignoredIssues = [];
  Object.entries(scannedFiles).forEach(([uriStr, fileData]) => {
    (fileData.issues || []).forEach(issue => {
      const fpKey = `${fileData.fileName}:${issue.id}:${issue.line}:${issue.column}`;
      if (fpFlags.includes(fpKey)) {
        ignoredIssues.push({ file: fileData.relativePath, ...issue });
      }
    });
  });

  if (ignoredIssues.length > 0) {
    mdContent += `## 🏳️ Excluded False Positives\n\n`;
    mdContent += `The following issues were flagged by scanner but manually marked as False Positives:\n\n`;
    mdContent += `| File | Line | Rule ID | Message |\n`;
    mdContent += `| :--- | :--- | :--- | :--- |\n`;
    ignoredIssues.forEach(issue => {
      mdContent += `| \`${issue.file}\` | L${issue.line} | \`${issue.id}\` | ${issue.message} |\n`;
    });
    mdContent += `\n`;
  }

  try {
    const writeData = Buffer.from(mdContent, 'utf8');
    await vscode.workspace.fs.writeFile(reportUri, writeData);
    
    // Open markdown report in preview/editor
    const doc = await vscode.workspace.openTextDocument(reportUri);
    await vscode.window.showTextDocument(doc);
    
    vscode.window.showInformationMessage(`JSentinel: Security report exported to ${vscode.workspace.asRelativePath(reportUri)}`);
  } catch (err) {
    vscode.window.showErrorMessage(`JSentinel: Failed to export report: ${err.message}`);
  }
};

/**
 * Extension activation, called when the extension is first loaded.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log('JSentinel Security Scanner activated.');

  // Create diagnostics collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('jsentinel');
  context.subscriptions.push(diagnosticCollection);

  // Initialize Sidebar Provider
  sidebarProvider = new JSentinelSidebarProvider(context);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('jsentinel.sidebar', sidebarProvider)
  );

  // Register commands
  const scanActiveFileCmd = vscode.commands.registerCommand('jsentinel.scanActiveFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('JSentinel: No active file to scan.');
      return;
    }
    scanDocument(editor.document, context);
  });

  const scanWorkspaceCmd = vscode.commands.registerCommand('jsentinel.scanWorkspace', () => {
    scanWorkspace(context);
  });

  const clearDiagnosticsCmd = vscode.commands.registerCommand('jsentinel.clearDiagnostics', () => {
    diagnosticCollection.clear();
    issuesMap.clear();
    Object.keys(scannedFiles).forEach(key => delete scannedFiles[key]);
    updateSidebarState(context);
    vscode.window.setStatusBarMessage('$(shield) JSentinel: Diagnostics cleared', 3000);
  });

  context.subscriptions.push(scanActiveFileCmd, scanWorkspaceCmd, clearDiagnosticsCmd);

  // Set up Sidebar Callbacks
  sidebarProvider.setToggleFpCallback(async (fpKey) => {
    const fpFlags = context.workspaceState.get('jsentinel_fpFlags', []);
    const index = fpFlags.indexOf(fpKey);
    
    if (index >= 0) {
      fpFlags.splice(index, 1);
    } else {
      fpFlags.push(fpKey);
    }
    
    await context.workspaceState.update('jsentinel_fpFlags', fpFlags);
    
    // Refresh diagnostics for all currently scanned files
    const config = vscode.workspace.getConfiguration('jsentinel');
    const severityFilter = config.get('severityFilter', 'ALL');

    for (const [uriStr, fileData] of Object.entries(scannedFiles)) {
      const uri = vscode.Uri.parse(uriStr);
      try {
        const document = await vscode.workspace.openTextDocument(uri);
        const diagnostics = createDiagnostics(document, fileData.issues, severityFilter, fpFlags);
        diagnosticCollection.set(uri, diagnostics);
      } catch (err) {
        console.error(`JSentinel: Failed to update diagnostics for ${uriStr}:`, err);
      }
    }

    updateSidebarState(context);
  });

  sidebarProvider.setExportReportCallback(() => {
    exportReport(context);
  });

  // Register hover provider for rich hover cards on flagged lines
  const supportedSelectors = [
    { language: 'javascript' },
    { language: 'javascriptreact' },
    { language: 'typescript' },
    { language: 'typescriptreact' }
  ];
  const hoverProvider = vscode.languages.registerHoverProvider(
    supportedSelectors,
    createHoverProvider(issuesMap, () => context.workspaceState.get('jsentinel_fpFlags', []))
  );
  context.subscriptions.push(hoverProvider);

  // Auto-scan on save
  const onSaveListener = vscode.workspace.onDidSaveTextDocument((document) => {
    const config = vscode.workspace.getConfiguration('jsentinel');
    if (config.get('scanOnSave', true)) {
      scanDocument(document, context);
    }
  });
  context.subscriptions.push(onSaveListener);

  // Auto-scan on open (if enabled)
  const onOpenListener = vscode.workspace.onDidOpenTextDocument((document) => {
    const config = vscode.workspace.getConfiguration('jsentinel');
    if (config.get('scanOnOpen', false)) {
      scanDocument(document, context);
    }
  });
  context.subscriptions.push(onOpenListener);

  // Scan currently active file on activation immediately
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document, context);
  }
}

/**
 * Extension deactivation, called when the extension is unloaded.
 */
function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}

module.exports = { activate, deactivate };
