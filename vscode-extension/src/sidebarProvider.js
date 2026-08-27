const vscode = require('vscode');
const { getGuidance: _getGuidance, getAllGuidance, GUIDANCE_DISCLAIMER } = require('./data/guidanceCatalog');

/**
 * OWASP Categories Metadata
 */
const OWASP_CATEGORIES = {
  'A01': 'Broken Access Control',
  'A02': 'Cryptographic Failures',
  'A03': 'Injection',
  'A05': 'Security Misconfiguration',
  'A06': 'Vulnerable and Outdated Components',
  'A07': 'Identification and Authentication Failures',
  'A08': 'Software and Data Integrity Failures',
  'A10': 'Server-Side Request Forgery (SSRF)'
};

class JSentinelSidebarProvider {
  constructor(context) {
    this._context = context;
    this._view = undefined;
    this._state = {
      scannedFiles: {}, // uriString -> { fileName, relativePath, issues, success, hasError, error }
      fpFlags: [],      // array of false positive keys
      stats: {
        totalIssues: 0,
        activeIssuesCount: 0,
        criticalIssues: 0,
        highIssues: 0,
        mediumIssues: 0,
        lowIssues: 0,
        securityScore: 100,
        filesScanned: 0
      },
      isScanning: false,
      scanProgress: null
    };
    this._toggleFpCallback = null;
    this._exportReportCallback = null;
  }

  setToggleFpCallback(callback) {
    this._toggleFpCallback = callback;
  }

  setExportReportCallback(callback) {
    this._exportReportCallback = callback;
  }

  setScanning(isScanning, scanProgress = null) {
    this._state.isScanning = isScanning;
    if (scanProgress !== null) {
      this._state.scanProgress = scanProgress;
    }
    if (this._view) {
      this._view.webview.postMessage({
        type: 'scanProgress',
        isScanning: this._state.isScanning,
        scanProgress: this._state.scanProgress
      });
    }
  }

  resolveWebviewView(webviewView, _context, _token) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._context.extensionUri]
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    // Set up message listener
    webviewView.webview.onDidReceiveMessage(async (data) => {
      switch (data.type) {
        case 'scanActive':
          vscode.commands.executeCommand('jsentinel.scanActiveFile');
          break;
        case 'scanWorkspace':
          vscode.commands.executeCommand('jsentinel.scanWorkspace');
          break;
        case 'clearResults':
          vscode.commands.executeCommand('jsentinel.clearDiagnostics');
          break;
        case 'revealIssue':
          this._revealIssue(data.fileUri, data.line, data.column);
          break;
        case 'toggleFalsePositive':
          if (this._toggleFpCallback) {
            this._toggleFpCallback(data.fpKey);
          }
          break;
        case 'exportReport':
          if (this._exportReportCallback) {
            this._exportReportCallback();
          }
          break;
        case 'requestState':
          this.updateWebview();
          break;
      }
    });

    // Send initial state
    this.updateWebview();
  }

  /**
   * Updates the shared state and sends it to the webview
   */
  updateState(scannedFiles, fpFlags, stats) {
    this._state = {
      ...this._state,
      scannedFiles,
      fpFlags,
      stats
    };
    this.updateWebview();
  }

  updateWebview() {
    if (this._view) {
      this._view.webview.postMessage({
        type: 'updateState',
        state: this._state
      });
    }
  }

  async _revealIssue(fileUriStr, line, column) {
    try {
      if (!fileUriStr) return;
      let uri;
      if (fileUriStr.startsWith('file:') || fileUriStr.startsWith('vscode-')) {
        uri = vscode.Uri.parse(fileUriStr);
      } else {
        uri = vscode.Uri.file(fileUriStr);
      }

      const document = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(document, { preview: false });
      
      const lineCount = document.lineCount;
      if (lineCount === 0) return;

      const parsedLine = parseInt(line, 10);
      const parsedCol = parseInt(column, 10);
      const validLine = !Number.isNaN(parsedLine) ? parsedLine : 1;
      const validCol = !Number.isNaN(parsedCol) ? parsedCol : 0;

      const zeroLine = Math.max(0, Math.min(validLine - 1, lineCount - 1));
      const lineText = document.lineAt(zeroLine).text;
      const zeroCol = Math.max(0, Math.min(validCol, lineText.length));
      const endCol = lineText.length === 0 ? 0 : Math.max(zeroCol, lineText.length);

      const startPos = new vscode.Position(zeroLine, zeroCol);
      const endPos = new vscode.Position(zeroLine, endCol);
      const range = new vscode.Range(startPos, endPos);

      editor.selection = new vscode.Selection(startPos, endPos);
      editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    } catch (err) {
      vscode.window.showErrorMessage(`JSentinel: Failed to open file: ${err.message}`);
    }
  }

  _getHtmlForWebview(_webview) {
    const guidanceCatalogJson = JSON.stringify(getAllGuidance()).replace(/</g, '\\u003c');
    const disclaimerJson = JSON.stringify(GUIDANCE_DISCLAIMER).replace(/</g, '\\u003c');
    const owaspJson = JSON.stringify(OWASP_CATEGORIES).replace(/</g, '\\u003c');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JSentinel Dashboard</title>
  <style>
    :root {
      --js-primary: var(--vscode-button-background, #dc2626);
      --js-primary-hover: var(--vscode-button-hoverBackground, #b91c1c);
      --js-critical: #ef4444;
      --js-critical-bg: rgba(239, 68, 68, 0.14);
      --js-critical-border: rgba(239, 68, 68, 0.35);
      --js-high: #f97316;
      --js-high-bg: rgba(249, 115, 22, 0.14);
      --js-high-border: rgba(249, 115, 22, 0.35);
      --js-medium: #eab308;
      --js-medium-bg: rgba(234, 179, 8, 0.14);
      --js-medium-border: rgba(234, 179, 8, 0.35);
      --js-low: #3b82f6;
      --js-low-bg: rgba(59, 130, 246, 0.14);
      --js-low-border: rgba(59, 130, 246, 0.35);
      --js-success: #10b981;
      --js-success-bg: rgba(16, 185, 129, 0.14);
      --js-success-border: rgba(16, 185, 129, 0.35);
      --card-bg: var(--vscode-editorWidget-background, rgba(128, 128, 128, 0.06));
      --card-border: var(--vscode-editorWidget-border, rgba(128, 128, 128, 0.18));
      --card-hover-bg: rgba(128, 128, 128, 0.12);
      --surface-tint: rgba(128, 128, 128, 0.05);
      --font-mono: var(--vscode-editor-font-family, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    }

    body.vscode-light {
      --card-bg: rgba(0, 0, 0, 0.03);
      --card-border: rgba(0, 0, 0, 0.12);
      --card-hover-bg: rgba(0, 0, 0, 0.07);
      --surface-tint: rgba(0, 0, 0, 0.02);
      --js-critical: #dc2626;
      --js-high: #ea580c;
      --js-medium: #ca8a04;
      --js-low: #2563eb;
      --js-success: #059669;
    }

    body.vscode-high-contrast, body.vscode-high-contrast-light {
      --card-bg: var(--vscode-sideBar-background);
      --card-border: var(--vscode-contrastBorder, #ffffff);
      --card-hover-bg: var(--vscode-list-hoverBackground, #333333);
      --js-critical-border: var(--vscode-contrastBorder, #ff4444);
      --js-high-border: var(--vscode-contrastBorder, #ff9900);
      --js-medium-border: var(--vscode-contrastBorder, #ffff00);
      --js-low-border: var(--vscode-contrastBorder, #00ffff);
      --js-success-border: var(--vscode-contrastBorder, #00ff00);
    }

    * {
      box-sizing: border-box;
    }

    body {
      background-color: var(--vscode-sideBar-background);
      color: var(--vscode-foreground);
      font-family: var(--vscode-font-family), -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 8px;
      font-size: 12px;
      line-height: 1.4;
      overflow-x: hidden;
      word-wrap: break-word;
    }
    
    /* Scrollbars */
    ::-webkit-scrollbar {
      width: 5px;
      height: 5px;
    }
    ::-webkit-scrollbar-track {
      background: transparent;
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(128, 128, 128, 0.25);
      border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(128, 128, 128, 0.45);
    }

    /* Container fluid */
    .app-wrapper {
      display: flex;
      flex-direction: column;
      gap: 8px;
      width: 100%;
      min-width: 0;
    }

    /* Header Gauge & Health Dashboard */
    .dashboard-header {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      position: relative;
      overflow: hidden;
    }
    .score-wrapper {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
      flex: 1;
    }
    .gauge-container {
      position: relative;
      width: 44px;
      height: 44px;
      flex-shrink: 0;
    }
    .circular-chart {
      display: block;
      width: 44px;
      height: 44px;
    }
    .circle-bg {
      fill: none;
      stroke: var(--card-border);
      stroke-width: 3.2;
    }
    .circle {
      fill: none;
      stroke-width: 3.2;
      stroke-linecap: round;
      stroke-dasharray: 0, 100;
      transition: stroke-dasharray 0.5s ease, stroke 0.3s ease;
    }
    .gauge-center-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 10.5px;
      font-weight: 800;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      color: var(--vscode-foreground);
      text-align: center;
      line-height: 1;
      pointer-events: none;
    }
    .score-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
      flex: 1;
    }
    .score-label-row {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .score-title {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--vscode-descriptionForeground);
    }
    .score-status-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      padding: 1.5px 6px;
      border-radius: 4px;
      width: fit-content;
      transition: background-color 0.3s, color 0.3s, border 0.3s;
    }
    .score-status-badge.compliant {
      color: var(--js-success);
      background: var(--js-success-bg);
      border: 1px solid var(--js-success-border);
    }
    .score-status-badge.warning {
      color: var(--js-medium);
      background: var(--js-medium-bg);
      border: 1px solid var(--js-medium-border);
    }
    .score-status-badge.vulnerable {
      color: var(--js-critical);
      background: var(--js-critical-bg);
      border: 1px solid var(--js-critical-border);
    }
    .score-subtitle {
      font-size: 9.5px;
      color: var(--vscode-descriptionForeground);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-variant-numeric: tabular-nums;
    }

    /* Active Scan Progress Banner */
    .scan-progress-banner {
      background: var(--card-bg);
      border: 1px solid var(--vscode-focusBorder, var(--js-low));
      border-radius: 6px;
      padding: 7px 9px;
      display: flex;
      flex-direction: column;
      gap: 5px;
      animation: pulseBorder 1.5s infinite ease-in-out;
    }
    @keyframes pulseBorder {
      0%, 100% { border-color: rgba(59, 130, 246, 0.4); }
      50% { border-color: rgba(59, 130, 246, 0.9); box-shadow: 0 0 6px rgba(59, 130, 246, 0.25); }
    }
    .scan-progress-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      font-size: 10px;
      font-weight: 700;
    }
    .scan-progress-title {
      display: flex;
      align-items: center;
      gap: 5px;
      color: var(--vscode-foreground);
      min-width: 0;
      overflow: hidden;
    }
    #scan-progress-text {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .scan-spinner {
      display: inline-block;
      width: 10px;
      height: 10px;
      border: 2px solid rgba(59, 130, 246, 0.2);
      border-top-color: #3b82f6;
      border-radius: 50%;
      flex-shrink: 0;
      animation: spin 0.7s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .scan-progress-bar-bg {
      width: 100%;
      height: 4px;
      background: rgba(128, 128, 128, 0.2);
      border-radius: 2px;
      overflow: hidden;
    }
    .scan-progress-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      border-radius: 2px;
      transition: width 0.2s ease;
    }

    /* Actions Grid */
    .btn-group {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    .btn-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 5px;
    }
    button.action-btn {
      background-color: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: 1px solid transparent;
      padding: 5px 6px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      font-family: inherit;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      transition: all 0.15s ease;
      white-space: nowrap;
      min-width: 0;
      outline: none;
    }
    button.action-btn:hover {
      background-color: var(--vscode-button-hoverBackground);
    }
    button.action-btn:active {
      transform: translateY(1px);
    }
    button.action-btn:focus-visible {
      border-color: var(--vscode-focusBorder);
      outline: 1px solid var(--vscode-focusBorder);
    }
    button.secondary-btn {
      background-color: var(--vscode-button-secondaryBackground, var(--surface-tint));
      color: var(--vscode-button-secondaryForeground, var(--vscode-foreground));
      border: 1px solid var(--card-border);
    }
    button.secondary-btn:hover {
      background-color: var(--vscode-button-secondaryHoverBackground, var(--card-hover-bg));
    }
    button.danger-btn {
      background-color: transparent;
      color: var(--vscode-descriptionForeground);
      border: 1px solid var(--card-border);
    }
    button.danger-btn:hover {
      color: var(--js-critical);
      border-color: var(--js-critical-border);
      background-color: var(--js-critical-bg);
    }

    /* Interactive Severity Filter Cards */
    .severity-filter-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 3px;
    }
    .severity-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 4px;
      padding: 4px 1px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
      min-width: 0;
      outline: none;
    }
    .severity-card:hover {
      background: var(--card-hover-bg);
      border-color: rgba(128, 128, 128, 0.35);
    }
    .severity-card:focus-visible {
      border-color: var(--vscode-focusBorder, #3b82f6);
      outline: 1px solid var(--vscode-focusBorder, #3b82f6);
    }
    .severity-card.active {
      background: var(--surface-tint);
      border-color: var(--vscode-focusBorder, #3b82f6);
      box-shadow: 0 0 0 1px var(--vscode-focusBorder, #3b82f6);
    }
    .severity-card.active.all { border-color: var(--vscode-foreground); }
    .severity-card.active.critical { border-color: var(--js-critical); background: var(--js-critical-bg); }
    .severity-card.active.high { border-color: var(--js-high); background: var(--js-high-bg); }
    .severity-card.active.medium { border-color: var(--js-medium); background: var(--js-medium-bg); }
    .severity-card.active.low { border-color: var(--js-low); background: var(--js-low-bg); }

    .sev-val {
      font-size: 11px;
      font-weight: 800;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      line-height: 1.1;
    }
    .severity-card.critical .sev-val { color: var(--js-critical); }
    .severity-card.high .sev-val { color: var(--js-high); }
    .severity-card.medium .sev-val { color: var(--js-medium); }
    .severity-card.low .sev-val { color: var(--js-low); }
    .severity-card.all .sev-val { color: var(--vscode-foreground); }

    .sev-lbl {
      font-size: 7.5px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--vscode-descriptionForeground);
      margin-top: 1px;
      letter-spacing: 0.2px;
    }

    /* Search & Filter Toolbar */
    .filter-toolbar {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    .search-box {
      position: relative;
      width: 100%;
    }
    .search-input {
      width: 100%;
      background-color: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, var(--card-border));
      border-radius: 4px;
      padding: 4px 22px 4px 22px;
      font-size: 11px;
      font-family: inherit;
      outline: none;
      transition: border-color 0.15s;
    }
    .search-input:focus {
      border-color: var(--vscode-focusBorder);
    }
    .search-icon {
      position: absolute;
      left: 6px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 10px;
      color: var(--vscode-input-placeholderForeground, var(--vscode-descriptionForeground));
      pointer-events: none;
    }
    .search-clear-btn {
      position: absolute;
      right: 4px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      font-size: 11px;
      padding: 1px 4px;
      border-radius: 3px;
      display: none;
    }
    .search-clear-btn:hover {
      color: var(--vscode-foreground);
    }
    .category-select {
      width: 100%;
      background-color: var(--vscode-dropdown-background, var(--vscode-input-background));
      color: var(--vscode-dropdown-foreground, var(--vscode-input-foreground));
      border: 1px solid var(--vscode-dropdown-border, var(--card-border));
      border-radius: 4px;
      padding: 4px 5px;
      font-size: 11px;
      font-family: inherit;
      outline: none;
      cursor: pointer;
    }
    .category-select:focus {
      border-color: var(--vscode-focusBorder);
    }

    /* Active Filter Status Ribbon */
    .filter-status-ribbon {
      background: var(--surface-tint);
      border: 1px dashed var(--card-border);
      border-radius: 4px;
      padding: 3px 6px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 9.5px;
      color: var(--vscode-descriptionForeground);
    }
    .filter-reset-link {
      color: var(--vscode-textLink-foreground);
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      outline: none;
    }
    .filter-reset-link:hover {
      text-decoration: underline;
    }
    .filter-reset-link:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, #3b82f6);
      outline-offset: 2px;
      border-radius: 2px;
    }

    /* Tabs */
    .tabs-container {
      display: flex;
      border-bottom: 1px solid var(--card-border);
      gap: 2px;
    }
    .tab-btn {
      flex: 1;
      background: none;
      border: none;
      color: var(--vscode-descriptionForeground);
      padding: 5px 3px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      font-family: inherit;
      text-align: center;
      outline: none;
      border-bottom: 2px solid transparent;
      transition: color 0.15s, border-bottom 0.15s;
      white-space: nowrap;
    }
    .tab-btn:hover {
      color: var(--vscode-foreground);
    }
    .tab-btn:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, #3b82f6);
      outline-offset: -1px;
    }
    .tab-btn.active {
      color: var(--vscode-foreground);
      border-bottom: 2px solid var(--vscode-button-background, #dc2626);
    }
    .tab-count-badge {
      display: inline-block;
      padding: 0.5px 4px;
      font-size: 8.5px;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      font-weight: 700;
      border-radius: 10px;
      background: rgba(128, 128, 128, 0.2);
      color: inherit;
      margin-left: 2px;
    }

    /* Findings List View */
    .list-view {
      display: flex;
      flex-direction: column;
      gap: 7px;
      width: 100%;
      min-width: 0;
    }
    .file-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 5px;
      overflow: hidden;
      width: 100%;
      min-width: 0;
    }
    .file-header {
      background: var(--surface-tint);
      padding: 5px 7px;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      border-bottom: 1px solid var(--card-border);
      user-select: none;
    }
    .file-title-group {
      display: flex;
      align-items: center;
      gap: 4px;
      min-width: 0;
      flex: 1;
      cursor: pointer;
      outline: none;
      padding: 1px 2px;
      border-radius: 3px;
    }
    .file-title-group:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, #3b82f6);
      outline-offset: 1px;
    }
    .file-path {
      color: var(--vscode-textLink-foreground);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-family: var(--font-mono);
      font-size: 10px;
    }
    .file-path:hover {
      text-decoration: underline;
    }
    .file-badge-count {
      background: rgba(128, 128, 128, 0.18);
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      font-size: 8.5px;
      font-weight: 700;
      padding: 1px 4px;
      border-radius: 6px;
      flex-shrink: 0;
    }

    /* Issue Item */
    .issue-item {
      padding: 8px 7px;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      flex-direction: column;
      gap: 4px;
      transition: background-color 0.15s;
    }
    .issue-item:last-child {
      border-bottom: none;
    }
    .issue-item:hover {
      background-color: var(--card-hover-bg);
    }
    .issue-meta-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 3px;
      flex-wrap: wrap;
    }
    .issue-pills-left {
      display: flex;
      align-items: center;
      gap: 3px;
      flex-wrap: wrap;
    }
    .issue-badge {
      font-size: 8px;
      font-weight: 800;
      padding: 1px 3.5px;
      border-radius: 3px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      line-height: 1.2;
    }
    .issue-badge.critical { background-color: var(--js-critical-bg); color: var(--js-critical); border: 1px solid var(--js-critical-border); }
    .issue-badge.high { background-color: var(--js-high-bg); color: var(--js-high); border: 1px solid var(--js-high-border); }
    .issue-badge.medium { background-color: var(--js-medium-bg); color: var(--js-medium); border: 1px solid var(--js-medium-border); }
    .issue-badge.low { background-color: var(--js-low-bg); color: var(--js-low); border: 1px solid var(--js-low-border); }

    .cvss-pill {
      font-size: 8px;
      font-weight: 700;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      background: rgba(128, 128, 128, 0.15);
      border: 1px solid var(--card-border);
      padding: 1px 3.5px;
      border-radius: 3px;
      color: var(--vscode-foreground);
      line-height: 1.2;
      cursor: help;
    }
    .rule-id-pill {
      font-size: 8px;
      font-family: var(--font-mono);
      color: var(--vscode-descriptionForeground);
    }
    .issue-loc-pill {
      font-size: 8.5px;
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
      color: var(--vscode-descriptionForeground);
      background: var(--surface-tint);
      border: 1px solid var(--card-border);
      padding: 0.5px 3.5px;
      border-radius: 3px;
      white-space: nowrap;
    }

    .issue-message {
      font-size: 10.5px;
      font-weight: 700;
      line-height: 1.35;
      color: var(--vscode-foreground);
    }
    .issue-risk-text {
      font-size: 9.5px;
      color: var(--vscode-descriptionForeground);
      line-height: 1.35;
    }

    /* Accordion Fix Section */
    .accordion-toggle {
      background: none;
      border: none;
      color: var(--vscode-textLink-foreground);
      font-size: 9.5px;
      font-weight: 700;
      font-family: inherit;
      cursor: pointer;
      padding: 0;
      display: flex;
      align-items: center;
      gap: 3px;
      width: fit-content;
      outline: none;
    }
    .accordion-toggle:hover {
      text-decoration: underline;
    }
    .accordion-toggle:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, #3b82f6);
      outline-offset: 2px;
      border-radius: 2px;
    }
    .accordion-arrow {
      display: inline-block;
      transition: transform 0.2s ease;
      font-size: 7.5px;
    }
    .accordion-arrow.expanded {
      transform: rotate(90deg);
    }

    .remediation-box {
      margin-top: 6px;
      padding: 8px;
      background: var(--surface-tint);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-size: 9.5px;
      animation: fadeIn 0.2s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-3px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .guidance-section {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .guidance-section-label {
      font-size: 8px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: var(--vscode-descriptionForeground);
    }
    .guidance-header-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 4px;
    }
    .scope-badge {
      font-size: 7.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      padding: 1px 5px;
      border-radius: 3px;
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }
    .guidance-code-box {
      border-radius: 4px;
      padding: 4px 6px;
      background: var(--vscode-editor-background, #1e1e1e);
      border: 1px solid var(--card-border);
      font-family: var(--font-mono);
      font-size: 9px;
      line-height: 1.35;
      overflow-x: auto;
    }
    .guidance-unavailable-box {
      border-radius: 4px;
      padding: 4px 6px;
      background: rgba(128, 128, 128, 0.08);
      border: 1px solid var(--card-border);
      font-family: var(--font-mono);
      font-size: 8.5px;
      font-style: italic;
      color: var(--vscode-descriptionForeground);
    }
    .guidance-code-snippet {
      white-space: pre-wrap;
      word-break: break-all;
      color: var(--vscode-editor-foreground, #d4d4d4);
    }
    .guidance-text {
      font-size: 9.5px;
      line-height: 1.4;
      color: var(--vscode-foreground);
      margin: 0;
    }
    .guidance-action-text {
      font-weight: 600;
    }
    .cannot-infer-box {
      padding: 6px;
      border-radius: 4px;
      background: rgba(234, 179, 8, 0.12);
      border: 1px solid rgba(234, 179, 8, 0.3);
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .cannot-infer-label {
      font-size: 8px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: #eab308;
      display: flex;
      align-items: center;
      gap: 3px;
    }
    .cannot-infer-text {
      font-size: 9px;
      line-height: 1.35;
      color: var(--vscode-foreground);
      margin: 0;
    }
    .guidance-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .guidance-list-item {
      display: flex;
      align-items: flex-start;
      gap: 4px;
      font-size: 9px;
      line-height: 1.35;
    }
    .guidance-bullet {
      color: #818cf8;
      font-weight: bold;
      flex-shrink: 0;
    }
    .illustrative-box {
      margin-top: 4px;
      padding: 5px 6px;
      border-radius: 4px;
      background: rgba(128, 128, 128, 0.08);
      border: 1px solid var(--card-border);
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .illustrative-label {
      font-size: 7.5px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      color: var(--vscode-descriptionForeground);
    }
    .illustrative-code {
      font-family: var(--font-mono);
      font-size: 8.5px;
      line-height: 1.3;
      white-space: pre-wrap;
      word-break: break-all;
      color: var(--vscode-editor-foreground, #d4d4d4);
    }
    .verify-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .verify-list-item {
      display: flex;
      align-items: flex-start;
      gap: 4px;
      font-size: 9px;
      line-height: 1.35;
    }
    .verify-check {
      color: var(--js-success, #10b981);
      font-weight: bold;
      flex-shrink: 0;
    }
    .disclaimer-banner {
      padding: 6px;
      border-radius: 4px;
      background: rgba(99, 102, 241, 0.08);
      border: 1px solid rgba(99, 102, 241, 0.2);
      font-size: 8.5px;
      font-style: italic;
      line-height: 1.35;
      color: var(--vscode-descriptionForeground);
    }
    .cvss-vector-footer {
      font-size: 8px;
      font-family: var(--font-mono);
      color: var(--vscode-descriptionForeground);
      border-top: 1px dashed var(--card-border);
      padding-top: 3px;
      word-break: break-all;
    }

    /* Actions Bar */
    .issue-actions-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 4px;
      margin-top: 2px;
      padding-top: 2px;
      flex-wrap: wrap;
    }
    .issue-action-btn {
      background: transparent;
      border: 1px solid var(--card-border);
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      padding: 2px 5px;
      font-size: 9px;
      font-weight: 600;
      font-family: inherit;
      border-radius: 3px;
      display: inline-flex;
      align-items: center;
      gap: 3px;
      transition: all 0.15s;
      outline: none;
    }
    .issue-action-btn:hover {
      background: var(--card-hover-bg);
      border-color: rgba(128, 128, 128, 0.4);
      color: var(--vscode-foreground);
    }
    .issue-action-btn:focus-visible {
      border-color: var(--vscode-focusBorder);
      outline: 1px solid var(--vscode-focusBorder);
    }
    .issue-action-btn.fp-btn:hover {
      color: var(--js-medium);
      border-color: var(--js-medium-border);
    }
    .issue-action-btn.restore-btn:hover {
      color: var(--js-success);
      border-color: var(--js-success-border);
    }

    /* Empty States */
    .empty-state {
      padding: 20px 10px;
      text-align: center;
      color: var(--vscode-descriptionForeground);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 5px;
      background: var(--card-bg);
      border-radius: 6px;
      border: 1px dashed var(--card-border);
    }
    .empty-icon {
      font-size: 24px;
      line-height: 1;
    }
    .empty-title {
      font-weight: 800;
      font-size: 12px;
      color: var(--vscode-foreground);
    }
    .empty-desc {
      font-size: 10px;
      line-height: 1.4;
      max-width: 200px;
    }

    .hidden {
      display: none !important;
    }

    /* Narrow sidebar responsive adjustments (< 250px) */
    @media (max-width: 250px) {
      body {
        padding: 5px;
      }
      .dashboard-header {
        padding: 6px;
        gap: 6px;
      }
      .gauge-container, .circular-chart {
        width: 38px;
        height: 38px;
      }
      .gauge-center-text {
        font-size: 9.5px;
      }
      .btn-row {
        grid-template-columns: 1fr;
        gap: 4px;
      }
      .severity-filter-grid {
        gap: 2px;
      }
      .sev-val {
        font-size: 10px;
      }
      .sev-lbl {
        font-size: 7px;
      }
      .issue-actions-row {
        flex-direction: column;
        align-items: stretch;
      }
      .issue-action-btn {
        justify-content: center;
      }
    }
  </style>
</head>
<body>
  <div class="app-wrapper">
    
    <!-- 1. Header Security Score Gauge & Health -->
    <div class="dashboard-header" role="region" aria-label="Security Health Score">
      <div class="score-wrapper">
        <div class="gauge-container" role="img" id="gauge-container" aria-label="Security score: 100%">
          <svg viewBox="0 0 36 36" class="circular-chart" aria-hidden="true">
            <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
            <path id="score-circle" class="circle" stroke="var(--js-success)" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          </svg>
          <div id="score-text" class="gauge-center-text" aria-hidden="true">100%</div>
        </div>
        <div class="score-info">
          <div class="score-label-row">
            <span class="score-title">Security Score</span>
          </div>
          <span id="score-status-badge" class="score-status-badge compliant">Compliant</span>
          <span id="score-subtitle" class="score-subtitle">0 files scanned • 0 issues</span>
        </div>
      </div>
    </div>

    <!-- 2. Active Scan Progress Banner -->
    <div id="scan-progress-banner" class="scan-progress-banner hidden" role="status" aria-live="polite">
      <div class="scan-progress-header">
        <div class="scan-progress-title">
          <span class="scan-spinner" aria-hidden="true"></span>
          <span id="scan-progress-text">Scanning workspace for vulnerabilities...</span>
        </div>
        <span id="scan-progress-count" style="color: var(--vscode-descriptionForeground); font-variant-numeric: tabular-nums;">0%</span>
      </div>
      <div class="scan-progress-bar-bg" role="progressbar" id="scan-progress-bar-container" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
        <div id="scan-progress-bar" class="scan-progress-bar-fill"></div>
      </div>
    </div>

    <!-- 3. Primary Actions -->
    <div class="btn-group">
      <div class="btn-row">
        <button class="action-btn" id="scan-workspace-btn" title="Scan entire workspace">🛡️ Workspace</button>
        <button class="action-btn secondary-btn" id="scan-active-btn" title="Scan currently open file">📄 Active File</button>
      </div>
      <div class="btn-row">
        <button class="action-btn secondary-btn" id="export-report-btn" title="Export Academic PDF Security Report">📊 Export PDF</button>
        <button class="action-btn danger-btn" id="clear-results-btn" title="Clear all diagnostics">🗑️ Clear</button>
      </div>
    </div>

    <!-- 4. Interactive Severity Filter Cards -->
    <div class="severity-filter-grid" role="group" aria-label="Severity Filter">
      <div class="severity-card all active" id="sev-filter-all" data-sev="ALL" role="button" tabindex="0" aria-pressed="true" title="Show all severity levels">
        <span id="stat-all" class="sev-val">0</span>
        <span class="sev-lbl">All</span>
      </div>
      <div class="severity-card critical" id="sev-filter-critical" data-sev="CRITICAL" role="button" tabindex="0" aria-pressed="false" title="Filter Critical vulnerabilities (-20 pts)">
        <span id="stat-critical" class="sev-val">0</span>
        <span class="sev-lbl">Crit</span>
      </div>
      <div class="severity-card high" id="sev-filter-high" data-sev="HIGH" role="button" tabindex="0" aria-pressed="false" title="Filter High vulnerabilities (-10 pts)">
        <span id="stat-high" class="sev-val">0</span>
        <span class="sev-lbl">High</span>
      </div>
      <div class="severity-card medium" id="sev-filter-medium" data-sev="MEDIUM" role="button" tabindex="0" aria-pressed="false" title="Filter Medium vulnerabilities (-5 pts)">
        <span id="stat-medium" class="sev-val">0</span>
        <span class="sev-lbl">Med</span>
      </div>
      <div class="severity-card low" id="sev-filter-low" data-sev="LOW" role="button" tabindex="0" aria-pressed="false" title="Filter Low vulnerabilities (-1 pt)">
        <span id="stat-low" class="sev-val">0</span>
        <span class="sev-lbl">Low</span>
      </div>
    </div>

    <!-- 5. Search Bar & OWASP Category Filter -->
    <div class="filter-toolbar">
      <div class="search-box">
        <span class="search-icon" aria-hidden="true">🔍</span>
        <input type="text" id="search-input" class="search-input" placeholder="Filter by rule, path, text, or line..." aria-label="Filter findings by text, rule ID, or code snippet" />
        <button id="search-clear-btn" class="search-clear-btn" title="Clear search" aria-label="Clear search input">✕</button>
      </div>
      <select id="category-select" class="category-select" title="Filter by OWASP Top 10 Category" aria-label="Filter findings by OWASP category">
        <option value="ALL">All OWASP Categories (8 categories)</option>
        <option value="A01">A01: Broken Access Control</option>
        <option value="A02">A02: Cryptographic Failures</option>
        <option value="A03">A03: Injection</option>
        <option value="A05">A05: Security Misconfiguration</option>
        <option value="A06">A06: Vulnerable and Outdated Components</option>
        <option value="A07">A07: Identification and Authentication Failures</option>
        <option value="A08">A08: Software and Data Integrity Failures</option>
        <option value="A10">A10: Server-Side Request Forgery (SSRF)</option>
      </select>
      <div id="filter-status-ribbon" class="filter-status-ribbon hidden">
        <span id="filter-status-text">Showing filtered findings</span>
        <a href="#" id="filter-reset-link" class="filter-reset-link" role="button" tabindex="0">Reset Filters</a>
      </div>
    </div>

    <!-- 6. Tabs Navigation -->
    <div class="tabs-container" role="tablist" aria-label="Finding types">
      <button class="tab-btn active" id="tab-active" role="tab" aria-selected="true" aria-controls="active-issues-list">Active Issues <span id="count-active" class="tab-count-badge">0</span></button>
      <button class="tab-btn" id="tab-fp" role="tab" aria-selected="false" aria-controls="fp-issues-list">False Positives <span id="count-fp" class="tab-count-badge">0</span></button>
    </div>

    <!-- 7. Main Finding Lists -->
    <div id="active-issues-list" class="list-view" role="tabpanel" aria-labelledby="tab-active">
      <div class="empty-state" id="empty-state-clean">
        <span class="empty-icon">🎉</span>
        <span class="empty-title">Code Guard Clean</span>
        <span class="empty-desc">No vulnerabilities detected in your project. Scan workspace or files to begin.</span>
      </div>
    </div>

    <div id="fp-issues-list" class="list-view hidden" role="tabpanel" aria-labelledby="tab-fp">
      <div class="empty-state" id="empty-state-fp">
        <span class="empty-icon">🏳️</span>
        <span class="empty-title">No False Positives</span>
        <span class="empty-desc">Vulnerabilities you mark as false positives will appear here and restore your score.</span>
      </div>
    </div>

  </div>

  <script>
    const vscode = acquireVsCodeApi();

    // Dictionaries passed from extension backend
    const guidanceCatalog = ${guidanceCatalogJson};
    const guidanceDisclaimer = ${disclaimerJson};
    const owaspCategories = ${owaspJson};

    function getGuidanceForIssue(issue) {
      const key = (issue && (issue.guidanceId || issue.id)) || '';
      if (key && Object.prototype.hasOwnProperty.call(guidanceCatalog, key)) return guidanceCatalog[key];
      if (issue && issue.id && Object.prototype.hasOwnProperty.call(guidanceCatalog, issue.id)) return guidanceCatalog[issue.id];
      return {
        guidanceId: issue ? (issue.guidanceId || issue.id || 'UNKNOWN') : 'UNKNOWN',
        ruleId: issue ? (issue.id || 'UNKNOWN') : 'UNKNOWN',
        title: 'Security Review Recommendation',
        category: 'General Security Practice',
        recommendedAction: 'Review the flagged code against project security requirements.',
        shortAction: 'Review the flagged code against project security requirements.',
        risk: 'Static analysis flagged an unclassified code pattern that may warrant security review.',
        cannotInfer: 'JSentinel cannot determine application intent, runtime context, or environmental security controls.',
        scope: 'cross-boundary',
        approaches: [
          'Architecture Review: Review code behavior with development and security team members to ensure safe handling.',
          'Defensive Controls: Apply least-privilege principles and input validation tailored to the application architecture.'
        ],
        verifySteps: [
          'Verify that the flagged pattern adheres to application security policies.',
          'Test edge cases and unexpected inputs in automated test suites.'
        ]
      };
    }

    // Client state
    let currentState = {
      scannedFiles: {},
      fpFlags: [],
      stats: {
        totalIssues: 0,
        activeIssuesCount: 0,
        criticalIssues: 0,
        highIssues: 0,
        mediumIssues: 0,
        lowIssues: 0,
        securityScore: 100,
        filesScanned: 0
      },
      isScanning: false,
      scanProgress: null
    };

    // Restore persisted client state if available
    const previousState = vscode.getState() || {};
    let activeTabName = previousState.activeTabName || 'active'; // 'active' | 'fp'
    let selectedSeverity = previousState.selectedSeverity || 'ALL';  // 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    let selectedCategory = previousState.selectedCategory || 'ALL';  // 'ALL' | 'A1' | 'A2' | ...
    let searchQuery = previousState.searchQuery || '';
    const expandedIssues = new Set(previousState.expandedKeys || []); // set of unique keys currently expanded

    function persistClientState() {
      vscode.setState({
        activeTabName,
        selectedSeverity,
        selectedCategory,
        searchQuery,
        expandedKeys: Array.from(expandedIssues)
      });
    }

    // DOM Elements
    const scoreCircle = document.getElementById('score-circle');
    const scoreText = document.getElementById('score-text');
    const scoreStatusBadge = document.getElementById('score-status-badge');
    const scoreSubtitle = document.getElementById('score-subtitle');

    const scanProgressBanner = document.getElementById('scan-progress-banner');
    const scanProgressText = document.getElementById('scan-progress-text');
    const scanProgressCount = document.getElementById('scan-progress-count');
    const scanProgressBar = document.getElementById('scan-progress-bar');
    const scanProgressBarContainer = document.getElementById('scan-progress-bar-container');

    const statAll = document.getElementById('stat-all');
    const statCritical = document.getElementById('stat-critical');
    const statHigh = document.getElementById('stat-high');
    const statMedium = document.getElementById('stat-medium');
    const statLow = document.getElementById('stat-low');

    const searchInput = document.getElementById('search-input');
    const searchClearBtn = document.getElementById('search-clear-btn');
    const categorySelect = document.getElementById('category-select');
    const filterStatusRibbon = document.getElementById('filter-status-ribbon');
    const filterStatusText = document.getElementById('filter-status-text');
    const filterResetLink = document.getElementById('filter-reset-link');

    const tabActive = document.getElementById('tab-active');
    const tabFp = document.getElementById('tab-fp');
    const countActive = document.getElementById('count-active');
    const countFp = document.getElementById('count-fp');
    const activeList = document.getElementById('active-issues-list');
    const fpList = document.getElementById('fp-issues-list');

    // Restore inputs from persisted state
    if (searchQuery) {
      searchInput.value = searchQuery;
      searchClearBtn.style.display = 'block';
    }
    if (selectedCategory !== 'ALL') {
      categorySelect.value = selectedCategory;
    }
    if (activeTabName === 'fp') {
      tabFp.classList.add('active');
      tabFp.setAttribute('aria-selected', 'true');
      tabActive.classList.remove('active');
      tabActive.setAttribute('aria-selected', 'false');
      fpList.classList.remove('hidden');
      activeList.classList.add('hidden');
    }

    // Severity card filter buttons
    const severityCards = document.querySelectorAll('.severity-card');
    severityCards.forEach(card => {
      const toggleHandler = () => {
        const sev = card.getAttribute('data-sev');
        if (selectedSeverity === sev && sev !== 'ALL') {
          selectedSeverity = 'ALL';
        } else {
          selectedSeverity = sev;
        }
        updateSeverityCardStyles();
        persistClientState();
        renderFindings();
      };
      card.addEventListener('click', toggleHandler);
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleHandler();
        }
      });
    });

    function updateSeverityCardStyles() {
      severityCards.forEach(card => {
        const sev = card.getAttribute('data-sev');
        const isActive = sev === selectedSeverity;
        if (isActive) {
          card.classList.add('active');
          card.setAttribute('aria-pressed', 'true');
        } else {
          card.classList.remove('active');
          card.setAttribute('aria-pressed', 'false');
        }
      });
    }
    updateSeverityCardStyles();

    // Search and Category Handlers
    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.trim().toLowerCase();
      searchClearBtn.style.display = searchQuery ? 'block' : 'none';
      persistClientState();
      renderFindings();
    });

    searchClearBtn.addEventListener('click', () => {
      searchInput.value = '';
      searchQuery = '';
      searchClearBtn.style.display = 'none';
      persistClientState();
      renderFindings();
    });

    categorySelect.addEventListener('change', (e) => {
      selectedCategory = e.target.value;
      persistClientState();
      renderFindings();
    });

    const resetFiltersHandler = (e) => {
      if (e) e.preventDefault();
      selectedSeverity = 'ALL';
      selectedCategory = 'ALL';
      categorySelect.value = 'ALL';
      searchQuery = '';
      searchInput.value = '';
      searchClearBtn.style.display = 'none';
      updateSeverityCardStyles();
      persistClientState();
      renderFindings();
    };

    filterResetLink.addEventListener('click', resetFiltersHandler);
    filterResetLink.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        resetFiltersHandler();
      }
    });

    // Tab Handlers
    tabActive.addEventListener('click', () => {
      activeTabName = 'active';
      tabActive.classList.add('active');
      tabActive.setAttribute('aria-selected', 'true');
      tabFp.classList.remove('active');
      tabFp.setAttribute('aria-selected', 'false');
      activeList.classList.remove('hidden');
      fpList.classList.add('hidden');
      persistClientState();
      renderFindings();
    });

    tabFp.addEventListener('click', () => {
      activeTabName = 'fp';
      tabFp.classList.add('active');
      tabFp.setAttribute('aria-selected', 'true');
      tabActive.classList.remove('active');
      tabActive.setAttribute('aria-selected', 'false');
      fpList.classList.remove('hidden');
      activeList.classList.add('hidden');
      persistClientState();
      renderFindings();
    });

    // Primary Action Buttons
    document.getElementById('scan-workspace-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'scanWorkspace' });
    });

    document.getElementById('scan-active-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'scanActive' });
    });

    document.getElementById('export-report-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'exportReport' });
    });

    document.getElementById('clear-results-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'clearResults' });
    });

    // Request initial state on mount
    vscode.postMessage({ type: 'requestState' });

    // Handle messages from the extension host
    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.type === 'updateState') {
        currentState = message.state || currentState;
        updateUI();
      } else if (message.type === 'scanProgress') {
        currentState.isScanning = Boolean(message.isScanning);
        currentState.scanProgress = message.scanProgress || null;
        updateScanProgress();
      }
    });

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function updateScanProgress() {
      if (currentState.isScanning) {
        scanProgressBanner.classList.remove('hidden');
        if (currentState.scanProgress) {
          const { message, current, total } = currentState.scanProgress;
          scanProgressText.textContent = message || 'Scanning workspace...';
          if (total > 0) {
            const pct = Math.min(100, Math.round((current / total) * 100));
            scanProgressCount.textContent = pct + '%';
            scanProgressBar.style.width = pct + '%';
            if (scanProgressBarContainer) scanProgressBarContainer.setAttribute('aria-valuenow', String(pct));
          } else {
            scanProgressCount.textContent = '...';
            scanProgressBar.style.width = '30%';
            if (scanProgressBarContainer) scanProgressBarContainer.setAttribute('aria-valuenow', '30');
          }
        } else {
          scanProgressText.textContent = 'Scanning files for vulnerabilities...';
          scanProgressCount.textContent = '';
          scanProgressBar.style.width = '60%';
          if (scanProgressBarContainer) scanProgressBarContainer.setAttribute('aria-valuenow', '60');
        }
      } else {
        scanProgressBanner.classList.add('hidden');
      }
    }

    function updateUI() {
      updateScanProgress();

      const stats = currentState.stats || {};
      const score = typeof stats.securityScore === 'number' && !Number.isNaN(stats.securityScore)
        ? Math.min(100, Math.max(0, Math.round(stats.securityScore)))
        : 100;

      // Score circle gauge (perimeter ~ 100 on r=15.9155)
      const strokeDash = \`\${score}, 100\`;
      scoreCircle.setAttribute('stroke-dasharray', strokeDash);
      scoreText.textContent = \`\${score}%\`;
      const gaugeContainer = document.getElementById('gauge-container');
      if (gaugeContainer) {
        gaugeContainer.setAttribute('aria-label', \`Security score: \${score}%\`);
      }

      let scoreColor = 'var(--js-critical)';
      let statusClass = 'vulnerable';
      let statusText = 'Vulnerable';

      if (score > 80) {
        scoreColor = 'var(--js-success)';
        statusClass = 'compliant';
        statusText = 'Compliant';
      } else if (score >= 50) {
        scoreColor = 'var(--js-medium)';
        statusClass = 'warning';
        statusText = 'Warning';
      }

      scoreCircle.style.stroke = scoreColor;
      scoreCircle.setAttribute('stroke', scoreColor);
      scoreStatusBadge.className = \`score-status-badge \${statusClass}\`;
      scoreStatusBadge.textContent = statusText;

      const fileCount = stats.filesScanned || Object.keys(currentState.scannedFiles || {}).length;
      const totalIssues = stats.activeIssuesCount || 0;
      scoreSubtitle.textContent = \`\${fileCount} file\${fileCount === 1 ? '' : 's'} scanned • \${totalIssues} active issue\${totalIssues === 1 ? '' : 's'}\`;

      // Update counters
      statAll.textContent = stats.activeIssuesCount || 0;
      statCritical.textContent = stats.criticalIssues || 0;
      statHigh.textContent = stats.highIssues || 0;
      statMedium.textContent = stats.mediumIssues || 0;
      statLow.textContent = stats.lowIssues || 0;

      renderFindings();
    }

    function getCategoryPrefix(ruleId) {
      if (!ruleId) return 'OTHER';
      const m = String(ruleId).match(/^OWASP-(A\\d+)/i);
      return m ? m[1].toUpperCase() : 'OTHER';
    }

    function renderFindings() {
      const scannedFiles = currentState.scannedFiles || {};
      const fpFlags = Array.isArray(currentState.fpFlags) ? currentState.fpFlags : [];

      const activeGrouped = {};
      const fpGrouped = {};
      let totalActiveCount = 0;
      let totalFpCount = 0;

      let filteredActiveCount = 0;
      let filteredFpCount = 0;

      const searchTerms = searchQuery ? searchQuery.split(/\\s+/).filter(Boolean) : [];

      // Group and classify
      Object.entries(scannedFiles).forEach(([uriStr, fileData]) => {
        if (!fileData || !Array.isArray(fileData.issues) || fileData.issues.length === 0) return;

        fileData.issues.forEach(issue => {
          if (!issue) return;
          const issueId = String(issue.id || 'UNKNOWN');
          const issueSeverity = (issue.severity || 'MEDIUM').toUpperCase();
          const issueLine = issue.line || 1;
          const issueCol = issue.column || 0;
          const fpKey = \`\${fileData.fileName || 'unknown'}:\${issueId}:\${issueLine}:\${issueCol}\`;
          const isFP = fpFlags.includes(fpKey);
          const catPrefix = getCategoryPrefix(issueId);

          if (isFP) {
            totalFpCount++;
          } else {
            totalActiveCount++;
          }

          // Apply filters
          let passes = true;
          if (selectedSeverity !== 'ALL' && issueSeverity !== selectedSeverity) {
            passes = false;
          }
          if (selectedCategory !== 'ALL' && catPrefix !== selectedCategory) {
            passes = false;
          }
          if (searchTerms.length > 0) {
            const rel = (fileData.relativePath || fileData.fileName || '').toLowerCase();
            const msg = (issue.message || '').toLowerCase();
            const id = issueId.toLowerCase();
            const catName = (owaspCategories[catPrefix] || '').toLowerCase();
            const sugg = (issue.suggestion || '').toLowerCase();
            const gRecord = getGuidanceForIssue(issue);
            const gRisk = (gRecord.risk || '').toLowerCase();
            const gAction = (gRecord.recommendedAction || gRecord.shortAction || '').toLowerCase();
            const gCannot = (gRecord.cannotInfer || '').toLowerCase();
            const gApproaches = (gRecord.approaches || []).map(a => typeof a === 'string' ? a : \`\${a.title} \${a.description}\`).join(' ').toLowerCase();
            const sev = issueSeverity.toLowerCase();
            const locStr = \`l\${issueLine}:c\${issueCol} \${issueLine}\`.toLowerCase();
            
            const combinedSearchString = \`\${rel} \${msg} \${id} \${catName} \${sugg} \${gRisk} \${gAction} \${gCannot} \${gApproaches} \${sev} \${locStr}\`;

            const queryMatch = searchTerms.every(term => combinedSearchString.includes(term));
            if (!queryMatch) {
              passes = false;
            }
          }

          if (!passes) return;

          const itemData = {
            ...issue,
            id: issueId,
            severity: issueSeverity,
            line: issueLine,
            column: issueCol,
            fpKey,
            catPrefix
          };

          if (isFP) {
            filteredFpCount++;
            if (!fpGrouped[uriStr]) {
              fpGrouped[uriStr] = {
                relativePath: fileData.relativePath || fileData.fileName || 'unknown',
                issues: []
              };
            }
            fpGrouped[uriStr].issues.push(itemData);
          } else {
            filteredActiveCount++;
            if (!activeGrouped[uriStr]) {
              activeGrouped[uriStr] = {
                relativePath: fileData.relativePath || fileData.fileName || 'unknown',
                issues: []
              };
            }
            activeGrouped[uriStr].issues.push(itemData);
          }
        });
      });

      countActive.textContent = totalActiveCount;
      countFp.textContent = totalFpCount;

      // Filter ribbon visibility
      const hasActiveFilters = selectedSeverity !== 'ALL' || selectedCategory !== 'ALL' || !!searchQuery;
      if (hasActiveFilters) {
        filterStatusRibbon.classList.remove('hidden');
        const countShowing = activeTabName === 'active' ? filteredActiveCount : filteredFpCount;
        const countTotal = activeTabName === 'active' ? totalActiveCount : totalFpCount;
        filterStatusText.textContent = \`Showing \${countShowing} of \${countTotal} finding\${countTotal === 1 ? '' : 's'}\`;
      } else {
        filterStatusRibbon.classList.add('hidden');
      }

      // Render respective list
      if (activeTabName === 'active') {
        renderGroupedView(activeGrouped, activeList, 'active', filteredActiveCount, totalActiveCount, hasActiveFilters);
      } else {
        renderGroupedView(fpGrouped, fpList, 'fp', filteredFpCount, totalFpCount, hasActiveFilters);
      }
    }

    function renderGroupedView(grouped, targetContainer, type, filteredCount, totalCount, hasActiveFilters) {
      targetContainer.innerHTML = '';

      if (totalCount === 0) {
        const emptyEl = document.createElement('div');
        emptyEl.className = 'empty-state';
        if (type === 'active') {
          emptyEl.innerHTML = \`
            <span class="empty-icon">🎉</span>
            <span class="empty-title">Code Guard Clean</span>
            <span class="empty-desc">No vulnerabilities detected in your project. Scan workspace or files to begin.</span>
          \`;
        } else {
          emptyEl.innerHTML = \`
            <span class="empty-icon">🏳️</span>
            <span class="empty-title">No False Positives</span>
            <span class="empty-desc">Vulnerabilities you exempt will appear here and restore your compliance score.</span>
          \`;
        }
        targetContainer.appendChild(emptyEl);
        return;
      }

      if (filteredCount === 0 && hasActiveFilters) {
        const emptyEl = document.createElement('div');
        emptyEl.className = 'empty-state';
        emptyEl.innerHTML = \`
          <span class="empty-icon">🔎</span>
          <span class="empty-title">No Matching Findings</span>
          <span class="empty-desc">No vulnerabilities matched your current search or category filter.</span>
        \`;
        targetContainer.appendChild(emptyEl);
        return;
      }

      Object.entries(grouped).forEach(([uriStr, fileObj]) => {
        const fileCard = document.createElement('div');
        fileCard.className = 'file-card';

        const fileHeader = document.createElement('div');
        fileHeader.className = 'file-header';

        const titleGroup = document.createElement('div');
        titleGroup.className = 'file-title-group';
        titleGroup.setAttribute('role', 'button');
        titleGroup.setAttribute('tabindex', '0');
        titleGroup.setAttribute('aria-label', \`Open \${fileObj.relativePath} in editor\`);
        titleGroup.title = 'Click to open file in editor';
        titleGroup.innerHTML = \`
          <span aria-hidden="true">📄</span>
          <span class="file-path">\${escapeHtml(fileObj.relativePath)}</span>
        \`;
        const openFileHandler = () => {
          vscode.postMessage({
            type: 'revealIssue',
            fileUri: uriStr,
            line: 1,
            column: 0
          });
        };
        titleGroup.addEventListener('click', openFileHandler);
        titleGroup.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openFileHandler();
          }
        });

        const badgeCount = document.createElement('span');
        badgeCount.className = 'file-badge-count';
        badgeCount.textContent = \`\${fileObj.issues.length} \${fileObj.issues.length === 1 ? 'issue' : 'issues'}\`;

        fileHeader.appendChild(titleGroup);
        fileHeader.appendChild(badgeCount);
        fileCard.appendChild(fileHeader);

        fileObj.issues.forEach(issue => {
          const issueItem = document.createElement('div');
          issueItem.className = 'issue-item';

          const metaRow = document.createElement('div');
          metaRow.className = 'issue-meta-row';

          const pillsLeft = document.createElement('div');
          pillsLeft.className = 'issue-pills-left';

          const sevBadge = document.createElement('span');
          sevBadge.className = \`issue-badge \${(issue.severity || 'medium').toLowerCase()}\`;
          sevBadge.textContent = issue.severity || 'MEDIUM';
          pillsLeft.appendChild(sevBadge);

          const cvssScore = issue.cvssBaseScore !== undefined ? issue.cvssBaseScore : (issue.severity === 'CRITICAL' ? '9.8' : issue.severity === 'HIGH' ? '8.8' : issue.severity === 'MEDIUM' ? '5.3' : '3.7');
          const cvssPill = document.createElement('span');
          cvssPill.className = 'cvss-pill';
          cvssPill.textContent = \`CVSS \${cvssScore}\`;
          if (issue.cvssVector) {
            cvssPill.title = issue.cvssVector;
          }
          pillsLeft.appendChild(cvssPill);

          const rulePill = document.createElement('span');
          rulePill.className = 'rule-id-pill';
          rulePill.textContent = issue.id;
          pillsLeft.appendChild(rulePill);

          const locPill = document.createElement('span');
          locPill.className = 'issue-loc-pill';
          locPill.textContent = \`L\${issue.line}:C\${issue.column}\`;

          metaRow.appendChild(pillsLeft);
          metaRow.appendChild(locPill);
          issueItem.appendChild(metaRow);

          const msgEl = document.createElement('div');
          msgEl.className = 'issue-message';
          msgEl.textContent = issue.message;
          issueItem.appendChild(msgEl);

          const guidanceRec = getGuidanceForIssue(issue);
          if (guidanceRec && guidanceRec.risk) {
            const riskEl = document.createElement('div');
            riskEl.className = 'issue-risk-text';
            riskEl.textContent = guidanceRec.risk;
            issueItem.appendChild(riskEl);
          }

          // Remediation Accordion
          const isExpanded = expandedIssues.has(issue.fpKey);
          const remediationId = 'remediation-' + issue.fpKey.replace(/[^a-zA-Z0-9_-]/g, '_');

          const accordionToggle = document.createElement('button');
          accordionToggle.className = 'accordion-toggle';
          accordionToggle.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
          accordionToggle.setAttribute('aria-controls', remediationId);
          accordionToggle.innerHTML = '<span class="accordion-arrow ' + (isExpanded ? 'expanded' : '') + '" aria-hidden="true">▶</span> <span>' + (isExpanded ? 'Hide Guidance' : '💡 Remediation Guidance') + '</span>';

          const remediationContainer = document.createElement('div');
          remediationContainer.id = remediationId;
          remediationContainer.className = 'remediation-box';
          if (!isExpanded) {
            remediationContainer.style.display = 'none';
          } else {
            renderRemediationContent(remediationContainer, issue);
          }

          accordionToggle.addEventListener('click', () => {
            if (expandedIssues.has(issue.fpKey)) {
              expandedIssues.delete(issue.fpKey);
              accordionToggle.setAttribute('aria-expanded', 'false');
              remediationContainer.style.display = 'none';
              accordionToggle.innerHTML = '<span class="accordion-arrow" aria-hidden="true">▶</span> <span>💡 Remediation Guidance</span>';
            } else {
              expandedIssues.add(issue.fpKey);
              accordionToggle.setAttribute('aria-expanded', 'true');
              renderRemediationContent(remediationContainer, issue);
              remediationContainer.style.display = 'flex';
              accordionToggle.innerHTML = '<span class="accordion-arrow expanded" aria-hidden="true">▶</span> <span>Hide Guidance</span>';
            }
            persistClientState();
          });

          issueItem.appendChild(accordionToggle);
          issueItem.appendChild(remediationContainer);

          // Actions Row
          const actionsRow = document.createElement('div');
          actionsRow.className = 'issue-actions-row';

          const revealBtn = document.createElement('button');
          revealBtn.className = 'issue-action-btn';
          revealBtn.innerHTML = '🔍 Reveal in Editor';
          revealBtn.title = 'Open file and navigate to this finding';
          revealBtn.addEventListener('click', () => {
            vscode.postMessage({
              type: 'revealIssue',
              fileUri: uriStr,
              line: issue.line,
              column: issue.column
            });
          });
          actionsRow.appendChild(revealBtn);

          const fpBtn = document.createElement('button');
          fpBtn.className = 'issue-action-btn ' + (type === 'active' ? 'fp-btn' : 'restore-btn');
          if (type === 'active') {
            fpBtn.innerHTML = '🏳️ Ignore';
            fpBtn.title = 'Mark as False Positive (restores security score)';
          } else {
            fpBtn.innerHTML = '🔄 Restore';
            fpBtn.title = 'Restore to active security audit';
          }
          fpBtn.addEventListener('click', () => {
            vscode.postMessage({
              type: 'toggleFalsePositive',
              fpKey: issue.fpKey
            });
          });
          actionsRow.appendChild(fpBtn);

          issueItem.appendChild(actionsRow);
          fileCard.appendChild(issueItem);
        });

        targetContainer.appendChild(fileCard);
      });
    }

    function renderRemediationContent(container, issue) {
      container.innerHTML = '';
      const guidance = getGuidanceForIssue(issue);
      const detectedLine = issue.sourceLine;

      // 1. Detected in your code
      const sec1 = document.createElement('div');
      sec1.className = 'guidance-section';
      const label1 = document.createElement('span');
      label1.className = 'guidance-section-label';
      label1.textContent = '1. Detected in your code (Line ' + issue.line + ')';
      sec1.appendChild(label1);

      if (detectedLine !== undefined && detectedLine !== null && detectedLine !== '') {
        const codeBox = document.createElement('div');
        codeBox.className = 'guidance-code-box';
        const codeEl = document.createElement('code');
        codeEl.className = 'guidance-code-snippet';
        codeEl.textContent = detectedLine.trim() || ('Line ' + issue.line);
        codeBox.appendChild(codeEl);
        sec1.appendChild(codeBox);
      } else {
        const unavailBox = document.createElement('div');
        unavailBox.className = 'guidance-unavailable-box';
        unavailBox.textContent = 'Source code line is unavailable for this archived scan record.';
        sec1.appendChild(unavailBox);
      }
      container.appendChild(sec1);

      // 2. Why review this
      const sec2 = document.createElement('div');
      sec2.className = 'guidance-section';
      const label2 = document.createElement('span');
      label2.className = 'guidance-section-label';
      label2.textContent = '2. Why review this';
      sec2.appendChild(label2);
      const pRisk = document.createElement('p');
      pRisk.className = 'guidance-text';
      pRisk.textContent = guidance.risk || 'Review the flagged pattern for potential security impact.';
      sec2.appendChild(pRisk);
      container.appendChild(sec2);

      // 3. Recommended action
      const sec3 = document.createElement('div');
      sec3.className = 'guidance-section';
      const actionHeader = document.createElement('div');
      actionHeader.className = 'guidance-header-row';
      const label3 = document.createElement('span');
      label3.className = 'guidance-section-label';
      label3.textContent = '3. Recommended action';
      actionHeader.appendChild(label3);

      if (guidance.scope) {
        const scopeBadge = document.createElement('span');
        scopeBadge.className = 'scope-badge';
        scopeBadge.textContent = guidance.scope === 'browser' ? 'Browser Scope' : guidance.scope === 'server' ? 'Server Scope' : 'Cross-Boundary Scope';
        actionHeader.appendChild(scopeBadge);
      }
      sec3.appendChild(actionHeader);

      const pAction = document.createElement('p');
      pAction.className = 'guidance-text guidance-action-text';
      pAction.textContent = guidance.recommendedAction || guidance.shortAction || 'Review according to security best practices.';
      sec3.appendChild(pAction);
      container.appendChild(sec3);

      // 4. What JSentinel cannot determine
      const sec4 = document.createElement('div');
      sec4.className = 'cannot-infer-box';
      const label4 = document.createElement('span');
      label4.className = 'cannot-infer-label';
      label4.innerHTML = '<span>⚠️</span> 4. What JSentinel cannot determine';
      sec4.appendChild(label4);
      const pCannot = document.createElement('p');
      pCannot.className = 'cannot-infer-text';
      pCannot.textContent = guidance.cannotInfer || 'JSentinel cannot determine application intent, runtime context, or environmental controls.';
      sec4.appendChild(pCannot);
      container.appendChild(sec4);

      // 5. Possible approaches
      const sec5 = document.createElement('div');
      sec5.className = 'guidance-section';
      const label5 = document.createElement('span');
      label5.className = 'guidance-section-label';
      label5.textContent = '5. Possible approaches';
      sec5.appendChild(label5);

      if (guidance.approaches && Array.isArray(guidance.approaches) && guidance.approaches.length > 0) {
        const ul = document.createElement('ul');
        ul.className = 'guidance-list';
        guidance.approaches.forEach(appr => {
          const li = document.createElement('li');
          li.className = 'guidance-list-item';
          const bullet = document.createElement('span');
          bullet.className = 'guidance-bullet';
          bullet.textContent = '•';
          li.appendChild(bullet);

          const contentSpan = document.createElement('span');
          if (typeof appr === 'string') {
            const colonIdx = appr.indexOf(':');
            if (colonIdx !== -1) {
              const strong = document.createElement('strong');
              strong.textContent = appr.slice(0, colonIdx) + ': ';
              contentSpan.appendChild(strong);
              contentSpan.appendChild(document.createTextNode(appr.slice(colonIdx + 1).trim()));
            } else {
              contentSpan.textContent = appr;
            }
          } else if (typeof appr === 'object' && appr !== null) {
            const strong = document.createElement('strong');
            strong.textContent = (appr.title || '') + ': ';
            contentSpan.appendChild(strong);
            contentSpan.appendChild(document.createTextNode(appr.description || ''));
          }
          li.appendChild(contentSpan);
          ul.appendChild(li);
        });
        sec5.appendChild(ul);
      }

      if (guidance.illustrativePattern) {
        const patternBox = document.createElement('div');
        patternBox.className = 'illustrative-box';
        const patternLabel = document.createElement('span');
        patternLabel.className = 'illustrative-label';
        patternLabel.textContent = 'Illustrative Pattern (Non-Prescriptive)';
        patternBox.appendChild(patternLabel);

        const patternCode = document.createElement('code');
        patternCode.className = 'illustrative-code';
        patternCode.textContent = guidance.illustrativePattern;
        patternBox.appendChild(patternCode);
        sec5.appendChild(patternBox);
      }
      container.appendChild(sec5);

      // 6. How to verify
      const sec6 = document.createElement('div');
      sec6.className = 'guidance-section';
      const label6 = document.createElement('span');
      label6.className = 'guidance-section-label';
      label6.textContent = '6. How to verify';
      sec6.appendChild(label6);

      if (guidance.verifySteps && Array.isArray(guidance.verifySteps) && guidance.verifySteps.length > 0) {
        const ulVerify = document.createElement('ul');
        ulVerify.className = 'verify-list';
        guidance.verifySteps.forEach(step => {
          const li = document.createElement('li');
          li.className = 'verify-list-item';
          const check = document.createElement('span');
          check.className = 'verify-check';
          check.textContent = '✓';
          li.appendChild(check);

          const stepText = document.createElement('span');
          stepText.textContent = step;
          li.appendChild(stepText);
          ulVerify.appendChild(li);
        });
        sec6.appendChild(ulVerify);
      }
      container.appendChild(sec6);

      // Mandatory Educational Disclaimer Banner
      const disclaimerEl = document.createElement('div');
      disclaimerEl.className = 'disclaimer-banner';
      disclaimerEl.textContent = guidanceDisclaimer;
      container.appendChild(disclaimerEl);

      if (issue.cvssVector) {
        const cvssFooter = document.createElement('div');
        cvssFooter.className = 'cvss-vector-footer';
        cvssFooter.textContent = 'Vector: ' + issue.cvssVector;
        container.appendChild(cvssFooter);
      }
    }
  </script>
</body>
</html>`;
  }
}

module.exports = { JSentinelSidebarProvider };
