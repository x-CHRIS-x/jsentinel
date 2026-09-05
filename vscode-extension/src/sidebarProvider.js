const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
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

    const htmlPath = path.join(__dirname, 'sidebar.html');
    const template = fs.readFileSync(htmlPath, 'utf8');

    return template
      .replace('__GUIDANCE_CATALOG_JSON__', guidanceCatalogJson)
      .replace('__DISCLAIMER_JSON__', disclaimerJson)
      .replace('__OWASP_JSON__', owaspJson);
  }
}

module.exports = {
  JSentinelSidebarProvider
};
