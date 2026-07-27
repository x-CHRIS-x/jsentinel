const vscode = require('vscode');

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
      }
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

  resolveWebviewView(webviewView, context, token) {
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
      const uri = vscode.Uri.parse(fileUriStr);
      const document = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(document);
      
      const zeroLine = Math.max(0, line - 1);
      const zeroCol = Math.max(0, column);
      const position = new vscode.Position(zeroLine, zeroCol);
      editor.selection = new vscode.Selection(position, position);
      editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
    } catch (err) {
      vscode.window.showErrorMessage(`JSentinel: Failed to open file: ${err.message}`);
    }
  }

  _getHtmlForWebview(webview) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JSentinel Dashboard</title>
  <style>
    body {
      background-color: var(--vscode-sideBar-background);
      color: var(--vscode-foreground);
      font-family: var(--vscode-font-family), -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 12px;
      box-sizing: border-box;
      font-size: 12px;
    }
    
    /* Scrollbar Styling */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: transparent;
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(255, 255, 255, 0.2);
    }

    /* Header Dashboard Gauge */
    .dashboard-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
      background: rgba(255, 255, 255, 0.02);
      padding: 10px;
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .score-wrapper {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .score-info {
      display: flex;
      flex-direction: column;
    }
    .score-title {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--vscode-descriptionForeground);
    }
    .score-status {
      font-size: 13px;
      font-weight: 800;
      margin-top: 2px;
    }
    .circular-chart {
      display: block;
      max-width: 52px;
      max-height: 52px;
    }
    .circle-bg {
      fill: none;
      stroke: rgba(255, 255, 255, 0.06);
      stroke-width: 2.8;
    }
    .circle {
      fill: none;
      stroke-width: 2.8;
      stroke-linecap: round;
      transition: stroke-dasharray 0.3s ease, stroke 0.3s ease;
    }
    .percentage {
      font-family: sans-serif;
      font-weight: 800;
      font-size: 8.5px;
      text-anchor: middle;
    }

    /* Tabs */
    .tabs-container {
      display: flex;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      margin-bottom: 12px;
    }
    .tab-btn {
      flex: 1;
      background: none;
      border: none;
      color: var(--vscode-descriptionForeground);
      padding: 6px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      text-align: center;
      outline: none;
      border-bottom: 2px solid transparent;
      transition: color 0.2s, border-bottom 0.2s;
    }
    .tab-btn:hover {
      color: var(--vscode-foreground);
    }
    .tab-btn.active {
      color: var(--vscode-foreground);
      border-bottom: 2px solid var(--vscode-button-background);
    }

    /* Actions Grid */
    .btn-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      margin-bottom: 12px;
    }
    .btn-full {
      grid-column: span 2;
    }
    button.action-btn {
      background-color: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 6px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      transition: background-color 0.2s;
    }
    button.action-btn:hover {
      background-color: var(--vscode-button-hoverBackground);
    }
    button.secondary-btn {
      background-color: rgba(255, 255, 255, 0.04);
      color: var(--vscode-foreground);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }
    button.secondary-btn:hover {
      background-color: rgba(255, 255, 255, 0.08);
    }

    /* Stats Grid */
    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 4px;
      margin-bottom: 12px;
    }
    .stat-card {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 5px 3px;
      background: rgba(255, 255, 255, 0.01);
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.04);
      text-align: center;
    }
    .stat-val {
      font-size: 12px;
      font-weight: 700;
    }
    .stat-card.critical .stat-val { color: #ef4444; }
    .stat-card.high .stat-val { color: #f97316; }
    .stat-card.medium .stat-val { color: #eab308; }
    .stat-card.low .stat-val { color: #3b82f6; }
    .stat-lbl {
      font-size: 8px;
      color: var(--vscode-descriptionForeground);
      text-transform: uppercase;
      margin-top: 1px;
    }

    /* List Content */
    .list-view {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .file-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 5px;
      overflow: hidden;
    }
    .file-header {
      background: rgba(255, 255, 255, 0.04);
      padding: 5px 8px;
      font-size: 10.5px;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      word-break: break-all;
    }
    .file-path {
      color: var(--vscode-textLink-foreground);
      cursor: pointer;
    }
    .file-path:hover {
      text-decoration: underline;
    }
    .file-issues-count {
      background: rgba(255, 255, 255, 0.08);
      padding: 1px 5px;
      border-radius: 8px;
      font-size: 9px;
      flex-shrink: 0;
    }
    .issue-item {
      padding: 7px 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .issue-item:last-child {
      border-bottom: none;
    }
    .issue-meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
    }
    .issue-badge {
      font-size: 7.5px;
      font-weight: 800;
      padding: 0.5px 3.5px;
      border-radius: 2.5px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .issue-badge.critical { background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .issue-badge.high { background-color: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .issue-badge.medium { background-color: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
    .issue-badge.low { background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    
    .issue-loc {
      font-size: 9px;
      color: var(--vscode-descriptionForeground);
      font-family: var(--vscode-editor-font-family, monospace);
    }
    .issue-msg {
      font-size: 11px;
      line-height: 1.35;
      color: var(--vscode-foreground);
    }
    .issue-actions {
      display: flex;
      gap: 6px;
      margin-top: 3px;
    }
    .btn-icon {
      background: none;
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--vscode-descriptionForeground);
      cursor: pointer;
      padding: 2px 5px;
      font-size: 9px;
      border-radius: 3px;
      display: inline-flex;
      align-items: center;
      gap: 2px;
      transition: all 0.2s;
    }
    .btn-icon:hover {
      background: rgba(255, 255, 255, 0.06);
      border-color: rgba(255, 255, 255, 0.18);
      color: var(--vscode-foreground);
    }

    /* Empty states */
    .empty-state {
      padding: 20px 10px;
      text-align: center;
      color: var(--vscode-descriptionForeground);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.01);
      border-radius: 5px;
      border: 1px dashed rgba(255, 255, 255, 0.05);
    }
    .empty-icon {
      font-size: 24px;
    }
    .empty-title {
      font-weight: 700;
      color: var(--vscode-foreground);
    }

    .hidden {
      display: none !important;
    }
  </style>
</head>
<body>
  <!-- Header Score Gauge -->
  <div class="dashboard-header">
    <div class="score-wrapper">
      <svg width="40" height="40" viewBox="0 0 36 36" class="circular-chart">
        <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
        <path id="score-circle" class="circle" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
        <text id="score-text" x="18" y="21" class="percentage" fill="currentColor">100%</text>
      </svg>
      <div class="score-info">
        <span class="score-title">Security Score</span>
        <span id="score-status-text" class="score-status" style="color: #10b981;">Compliant</span>
      </div>
    </div>
  </div>

  <!-- Primary Action Controls -->
  <div class="btn-row">
    <button class="action-btn" id="scan-workspace-btn">🛡️ Scan Workspace</button>
    <button class="action-btn secondary-btn" id="scan-active-btn">📄 Scan Active File</button>
    <button class="action-btn secondary-btn btn-full" id="export-report-btn">📊 Export Security Report</button>
  </div>

  <!-- Breakdown Stats -->
  <div class="stats-row">
    <div class="stat-card critical">
      <span id="stat-critical" class="stat-val">0</span>
      <span class="stat-lbl">Crit</span>
    </div>
    <div class="stat-card high">
      <span id="stat-high" class="stat-val">0</span>
      <span class="stat-lbl">High</span>
    </div>
    <div class="stat-card medium">
      <span id="stat-medium" class="stat-val">0</span>
      <span class="stat-lbl">Med</span>
    </div>
    <div class="stat-card low">
      <span id="stat-low" class="stat-val">0</span>
      <span class="stat-lbl">Low</span>
    </div>
  </div>

  <!-- Tabs Navigation -->
  <div class="tabs-container">
    <button class="tab-btn active" id="tab-active">Active Issues (<span id="count-active">0</span>)</button>
    <button class="tab-btn" id="tab-fp">False Positives (<span id="count-fp">0</span>)</button>
  </div>

  <!-- Main Lists -->
  <div id="active-issues-list" class="list-view">
    <div class="empty-state">
      <span class="empty-icon">🎉</span>
      <span class="empty-title">Code Guard Clean</span>
      <span>No vulnerabilities detected in your project. Scan workspace or files to begin.</span>
    </div>
  </div>

  <div id="fp-issues-list" class="list-view hidden">
    <div class="empty-state">
      <span class="empty-icon">🏳️</span>
      <span class="empty-title">No False Positives</span>
      <span>Vulnerabilities you mark as false positives will appear here.</span>
    </div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();

    // Tab toggling
    const tabActive = document.getElementById('tab-active');
    const tabFp = document.getElementById('tab-fp');
    const activeList = document.getElementById('active-issues-list');
    const fpList = document.getElementById('fp-issues-list');

    tabActive.addEventListener('click', () => {
      tabActive.classList.add('active');
      tabFp.classList.remove('active');
      activeList.classList.remove('hidden');
      fpList.classList.add('hidden');
    });

    tabFp.addEventListener('click', () => {
      tabFp.classList.add('active');
      tabActive.classList.remove('active');
      fpList.classList.remove('hidden');
      activeList.classList.add('hidden');
    });

    // Button actions
    document.getElementById('scan-workspace-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'scanWorkspace' });
    });

    document.getElementById('scan-active-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'scanActive' });
    });

    document.getElementById('export-report-btn').addEventListener('click', () => {
      vscode.postMessage({ type: 'exportReport' });
    });

    // Request initial state on load
    vscode.postMessage({ type: 'requestState' });

    // Handle messages from the extension
    window.addEventListener('message', event => {
      const message = event.data;
      if (message.type === 'updateState') {
        renderState(message.state);
      }
    });

    function getRelativePath(uriStr, scannedFiles) {
      if (scannedFiles[uriStr]) {
        return scannedFiles[uriStr].relativePath || scannedFiles[uriStr].fileName;
      }
      return uriStr;
    }

    function renderState(state) {
      const { scannedFiles, fpFlags, stats } = state;

      // Update score gauge
      const score = Math.round(stats.securityScore);
      const scoreCircle = document.getElementById('score-circle');
      const scoreText = document.getElementById('score-text');
      const scoreStatusText = document.getElementById('score-status-text');

      // Formula for circle stroke offset
      // circle perimeter = 2 * pi * radius (15.9155) = ~100
      const strokeDash = \`\${score}, 100\`;
      scoreCircle.setAttribute('stroke-dasharray', strokeDash);
      scoreText.textContent = \`\${score}%\`;

      let scoreColor = '#ef4444'; // Red
      let statusStr = 'Vulnerable';
      if (score > 80) {
        scoreColor = '#10b981'; // Green
        statusStr = 'Compliant';
      } else if (score >= 50) {
        scoreColor = '#f59e0b'; // Amber
        statusStr = 'Warning';
      }
      
      scoreCircle.setAttribute('stroke', scoreColor);
      scoreText.setAttribute('fill', scoreColor);
      scoreStatusText.textContent = statusStr;
      scoreStatusText.style.color = scoreColor;

      // Update counters
      document.getElementById('stat-critical').textContent = stats.criticalIssues;
      document.getElementById('stat-high').textContent = stats.highIssues;
      document.getElementById('stat-medium').textContent = stats.mediumIssues;
      document.getElementById('stat-low').textContent = stats.lowIssues;

      // Classify active issues and false positives
      const activeGrouped = {};
      const fpGrouped = {};
      let activeCount = 0;
      let fpCount = 0;

      Object.entries(scannedFiles).forEach(([uriStr, fileData]) => {
        if (!fileData.issues) return;

        fileData.issues.forEach(issue => {
          const fpKey = \`\${fileData.fileName}:\${issue.id}:\${issue.line}:\${issue.column}\`;
          const isFP = fpFlags.includes(fpKey);

          if (isFP) {
            if (!fpGrouped[uriStr]) {
              fpGrouped[uriStr] = {
                relativePath: fileData.relativePath || fileData.fileName,
                issues: []
              };
            }
            fpGrouped[uriStr].issues.push({ ...issue, fpKey });
            fpCount++;
          } else {
            if (!activeGrouped[uriStr]) {
              activeGrouped[uriStr] = {
                relativePath: fileData.relativePath || fileData.fileName,
                issues: []
              };
            }
            activeGrouped[uriStr].issues.push({ ...issue, fpKey });
            activeCount++;
          }
        });
      });

      document.getElementById('count-active').textContent = activeCount;
      document.getElementById('count-fp').textContent = fpCount;

      // Render Active Issues
      renderGroupedList(activeGrouped, activeList, 'active', activeCount);
      
      // Render False Positives
      renderGroupedList(fpGrouped, fpList, 'fp', fpCount);
    }

    function renderGroupedList(grouped, targetContainer, type, totalCount) {
      // Clear current list content
      const emptyState = targetContainer.querySelector('.empty-state');
      targetContainer.innerHTML = '';
      if (emptyState) {
        targetContainer.appendChild(emptyState);
      }

      if (totalCount === 0) {
        if (emptyState) emptyState.classList.remove('hidden');
        return;
      }

      if (emptyState) emptyState.classList.add('hidden');

      Object.entries(grouped).forEach(([uriStr, data]) => {
        const fileCard = document.createElement('div');
        fileCard.className = 'file-card';

        const fileHeader = document.createElement('div');
        fileHeader.className = 'file-header';
        
        const fileTitle = document.createElement('span');
        fileTitle.className = 'file-path';
        fileTitle.textContent = data.relativePath;
        fileTitle.title = 'Click to open file';
        
        // Clicking header reveals the file at line 1
        fileTitle.addEventListener('click', () => {
          vscode.postMessage({
            type: 'revealIssue',
            fileUri: uriStr,
            line: 1,
            column: 0
          });
        });

        const issuesCount = document.createElement('span');
        issuesCount.className = 'file-issues-count';
        issuesCount.textContent = \`\${data.issues.length} issue\${data.issues.length > 1 ? 's' : ''}\`;

        fileHeader.appendChild(fileTitle);
        fileHeader.appendChild(issuesCount);
        fileCard.appendChild(fileHeader);

        data.issues.forEach(issue => {
          const issueItem = document.createElement('div');
          issueItem.className = 'issue-item';

          const issueMeta = document.createElement('div');
          issueMeta.className = 'issue-meta';

          const badge = document.createElement('span');
          badge.className = \`issue-badge \${issue.severity.toLowerCase()}\`;
          badge.textContent = issue.severity;

          const location = document.createElement('span');
          location.className = 'issue-loc';
          location.textContent = \`L\${issue.line}:C\${issue.column} [\${issue.id}]\`;

          issueMeta.appendChild(badge);
          issueMeta.appendChild(location);
          issueItem.appendChild(issueMeta);

          const msg = document.createElement('div');
          msg.className = 'issue-msg';
          msg.textContent = issue.message;
          issueItem.appendChild(msg);

          const actions = document.createElement('div');
          actions.className = 'issue-actions';

          const revealBtn = document.createElement('button');
          revealBtn.className = 'btn-icon';
          revealBtn.innerHTML = '🔍 Reveal';
          revealBtn.addEventListener('click', () => {
            vscode.postMessage({
              type: 'revealIssue',
              fileUri: uriStr,
              line: issue.line,
              column: issue.column
            });
          });
          actions.appendChild(revealBtn);

          const fpBtn = document.createElement('button');
          fpBtn.className = 'btn-icon';
          if (type === 'active') {
            fpBtn.innerHTML = '🏳️ Ignore';
            fpBtn.title = 'Mark as False Positive';
          } else {
            fpBtn.innerHTML = '🔄 Restore';
            fpBtn.title = 'Mark as Active Vulnerability';
          }
          fpBtn.addEventListener('click', () => {
            vscode.postMessage({
              type: 'toggleFalsePositive',
              fpKey: issue.fpKey
            });
          });
          actions.appendChild(fpBtn);

          issueItem.appendChild(actions);
          fileCard.appendChild(issueItem);
        });

        targetContainer.appendChild(fileCard);
      });
    }
  </script>
</body>
</html>`;
  }
}

module.exports = { JSentinelSidebarProvider };
