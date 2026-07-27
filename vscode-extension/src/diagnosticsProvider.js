/**
 * JSentinel Diagnostics Provider
 * 
 * Maps scanner issues to VS Code Diagnostic objects for display in the
 * Problems panel and as inline squiggly underlines in the editor.
 */

const vscode = require('vscode');

/**
 * Severity mapping from JSentinel severity levels to VS Code DiagnosticSeverity.
 * CRITICAL and HIGH → Error (red squiggly)
 * MEDIUM → Warning (yellow squiggly)
 * LOW → Information (blue squiggly)
 */
const mapSeverity = (severity) => {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM':
      return vscode.DiagnosticSeverity.Warning;
    case 'LOW':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
};

/**
 * Converts scanner issues into VS Code Diagnostics for a given document.
 * 
 * @param {vscode.TextDocument} document - The VS Code document.
 * @param {Array} issues - Array of scanner issue objects.
 * @param {string} severityFilter - Minimum severity to report ('ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
 * @returns {vscode.Diagnostic[]} - Array of VS Code Diagnostic objects.
 */
const createDiagnostics = (document, issues, severityFilter = 'ALL', fpFlags = []) => {
  const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
  const filterLevel = severityOrder[severityFilter] || 0;

  return issues
    .filter(issue => {
      // Filter out false positives
      const fpKey = `${document.fileName}:${issue.id}:${issue.line}:${issue.column}`;
      if (fpFlags.includes(fpKey)) return false;

      if (severityFilter === 'ALL') return true;
      return (severityOrder[issue.severity] || 0) >= filterLevel;
    })
    .map(issue => {
      // Convert 1-indexed line numbers to 0-indexed for VS Code
      const line = typeof issue.line === 'number' ? Math.max(0, issue.line - 1) : 0;
      const column = typeof issue.column === 'number' ? issue.column : 0;

      // Create a range that highlights the entire line for visibility
      const lineText = document.lineAt(Math.min(line, document.lineCount - 1)).text;
      const startCol = lineText.search(/\S/); // First non-whitespace character
      const range = new vscode.Range(
        new vscode.Position(line, startCol >= 0 ? startCol : 0),
        new vscode.Position(line, lineText.length)
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        `[${issue.id}] ${issue.message}`,
        mapSeverity(issue.severity)
      );

      diagnostic.source = 'JSentinel';
      diagnostic.code = {
        value: issue.id,
        target: vscode.Uri.parse('https://owasp.org/Top10/')
      };

      return diagnostic;
    });
};

module.exports = { createDiagnostics };
