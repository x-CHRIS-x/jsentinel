/**
 * JSentinel VS Code Extension — Main Entry Point
 * 
 * JSENTINEL: A Client-Side Static Analysis System for Detecting JavaScript
 * Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm
 * 
 * This extension brings JSentinel's browser-based security scanner directly
 * into VS Code / Antigravity IDE. It analyzes JavaScript and TypeScript files
 * for OWASP Top 10 vulnerabilities using the same AST traversal engine as the
 * web application, with results displayed as native VS Code diagnostics.
 * 
 * Features:
 *   - Scan active file for security vulnerabilities
 *   - Scan entire workspace
 *   - Automatic scan-on-save
 *   - Configurable severity filtering
 *   - Results in Problems panel with inline squiggly underlines
 */

const vscode = require('vscode');
const { scanCode } = require('./scanner/scannerEngine');
const { allRules } = require('./scanner/rules');
const { createDiagnostics } = require('./diagnosticsProvider');

// Diagnostics collection for tracking issues across files
let diagnosticCollection;

/**
 * Scans a single document and updates its diagnostics.
 * @param {vscode.TextDocument} document
 */
const scanDocument = (document) => {
  // Only scan supported file types
  const supportedLanguages = ['javascript', 'javascriptreact', 'typescript', 'typescriptreact'];
  if (!supportedLanguages.includes(document.languageId)) {
    return;
  }

  const code = document.getText();
  const fileName = document.fileName;

  // Get severity filter from configuration
  const config = vscode.workspace.getConfiguration('jsentinel');
  const severityFilter = config.get('severityFilter', 'ALL');

  try {
    const result = scanCode(code, fileName, allRules);

    if (result.success && result.issues.length > 0) {
      const diagnostics = createDiagnostics(document, result.issues, severityFilter);
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
    } else if (result.success) {
      // Clean file — clear any previous diagnostics
      diagnosticCollection.set(document.uri, []);
      vscode.window.setStatusBarMessage('$(shield) JSentinel: No vulnerabilities detected', 3000);
    } else {
      // Parse error
      diagnosticCollection.set(document.uri, []);
      if (result.error) {
        vscode.window.setStatusBarMessage(`$(warning) JSentinel: Parse error in ${fileName}`, 5000);
      }
    }
  } catch (error) {
    console.error('JSentinel scan error:', error);
    vscode.window.setStatusBarMessage(`$(error) JSentinel: Scan failed — ${error.message}`, 5000);
  }
};

/**
 * Scans all supported files in the workspace.
 */
const scanWorkspace = async () => {
  const files = await vscode.workspace.findFiles(
    '**/*.{js,jsx,ts,tsx}',
    '{**/node_modules/**,**/dist/**,**/build/**,**/.git/**}'
  );

  if (files.length === 0) {
    vscode.window.showInformationMessage('JSentinel: No JavaScript/TypeScript files found in workspace.');
    return;
  }

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
          scanDocument(document);

          const diags = diagnosticCollection.get(fileUri);
          if (diags) {
            totalIssues += diags.length;
          }
        } catch (err) {
          // Skip files that can't be opened
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
 * Extension activation — called when the extension is first loaded.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log('JSentinel Security Scanner activated.');

  // Create diagnostics collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('jsentinel');
  context.subscriptions.push(diagnosticCollection);

  // Register commands
  const scanActiveFileCmd = vscode.commands.registerCommand('jsentinel.scanActiveFile', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('JSentinel: No active file to scan.');
      return;
    }
    scanDocument(editor.document);
  });

  const scanWorkspaceCmd = vscode.commands.registerCommand('jsentinel.scanWorkspace', () => {
    scanWorkspace();
  });

  const clearDiagnosticsCmd = vscode.commands.registerCommand('jsentinel.clearDiagnostics', () => {
    diagnosticCollection.clear();
    vscode.window.setStatusBarMessage('$(shield) JSentinel: Diagnostics cleared', 3000);
  });

  context.subscriptions.push(scanActiveFileCmd, scanWorkspaceCmd, clearDiagnosticsCmd);

  // Auto-scan on save
  const onSaveListener = vscode.workspace.onDidSaveTextDocument((document) => {
    const config = vscode.workspace.getConfiguration('jsentinel');
    if (config.get('scanOnSave', true)) {
      scanDocument(document);
    }
  });
  context.subscriptions.push(onSaveListener);

  // Auto-scan on open (if enabled)
  const onOpenListener = vscode.workspace.onDidOpenTextDocument((document) => {
    const config = vscode.workspace.getConfiguration('jsentinel');
    if (config.get('scanOnOpen', false)) {
      scanDocument(document);
    }
  });
  context.subscriptions.push(onOpenListener);

  // Clear diagnostics when a file is closed
  const onCloseListener = vscode.workspace.onDidCloseTextDocument((document) => {
    diagnosticCollection.delete(document.uri);
  });
  context.subscriptions.push(onCloseListener);

  // Scan currently active file on activation
  if (vscode.window.activeTextEditor) {
    const config = vscode.workspace.getConfiguration('jsentinel');
    if (config.get('scanOnOpen', false)) {
      scanDocument(vscode.window.activeTextEditor.document);
    }
  }
}

/**
 * Extension deactivation — called when the extension is unloaded.
 */
function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}

module.exports = { activate, deactivate };
