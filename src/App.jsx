import { useState, useRef, useMemo, useEffect } from 'react'
import { scanFile } from './utils/scannerEngine'
import { injectionRules } from './scanner/rules/injection'
import { xssRules } from './scanner/rules/xss'
import { authRules } from './scanner/rules/auth'
import { sensitiveDataRules } from './scanner/rules/sensitiveData'
import { misconfigRules } from './scanner/rules/misconfig'
import { deserializationRules } from './scanner/rules/deserialization'
import { knownVulnsRules } from './scanner/rules/knownVulns'
import { generatePDFReport } from './utils/pdfGenerator'
import './App.css'

function App() {
  const [files, setFiles] = useState([])
  const [results, setResults] = useState([])
  const [isScanning, setIsScanning] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [selectedFileIdx, setSelectedFileIdx] = useState(null)
  const [darkMode, setDarkMode] = useState(false)
  const [largeProjectWarning, setLargeProjectWarning] = useState(false)
  const [isDragging, setIsDragging] = useState(false)

  const fileInputRef = useRef(null)
  const folderInputRef = useRef(null)

  // Handle Dark Mode Class
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  const stats = useMemo(() => {
    const totalIssues = results.reduce((acc, res) => acc + (res.issues?.length || 0), 0)
    const criticalIssues = results.reduce((acc, res) => 
      acc + (res.issues?.filter(i => i.severity === 'CRITICAL').length || 0), 0)
    
    const penalty = results.reduce((acc, res) => 
      acc + (res.issues?.reduce((sum, issue) => 
        sum + (issue.cvssBaseScore || 0), 0) || 0), 0)

    const securityScore = results.length > 0 
      ? parseFloat(Math.max(0, 100 - penalty).toFixed(1)) 
      : 100

    return { totalIssues, criticalIssues, securityScore }
  }, [results])

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files)
    processFiles(uploadedFiles)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    const items = e.dataTransfer.items
    if (!items) return

    const filesToProcess = []
    
    const traverseFileTree = async (item, path = "") => {
      if (item.isFile) {
        return new Promise((resolve) => {
          item.file((file) => {
            // Reconstruct the relative path for the scanner
            Object.defineProperty(file, 'webkitRelativePath', {
              value: path + file.name,
              writable: false
            })
            filesToProcess.push(file)
            resolve()
          })
        })
      } else if (item.isDirectory) {
        const dirReader = item.createReader()
        const entries = await new Promise((resolve) => {
          dirReader.readEntries((entries) => resolve(entries))
        })
        for (const entry of entries) {
          await traverseFileTree(entry, path + item.name + "/")
        }
      }
    }

    const traversePromises = []
    for (let i = 0; i < items.length; i++) {
      const item = items[i].webkitGetAsEntry()
      if (item) {
        traversePromises.push(traverseFileTree(item))
      }
    }

    await Promise.all(traversePromises)
    processFiles(filesToProcess)
  }

  const processFiles = async (fileList) => {
    setIsScanning(true)
    setSelectedFileIdx(null)
    setLargeProjectWarning(false)

    const filtered = fileList.filter(file => {
      const path = file.webkitRelativePath || file.name
      const isHidden = path.split('/').some(part => part.startsWith('.'))
      const isNodeModules = path.includes('node_modules')
      const isDist = path.includes('dist') || path.includes('build')
      const extension = path.split('.').pop().toLowerCase()
      const isSupported = ['js', 'jsx', 'ts', 'tsx'].includes(extension)

      return !isHidden && !isNodeModules && !isDist && isSupported
    })

    if (filtered.length > 50) {
      setLargeProjectWarning(true)
    }

    setFiles(prev => [...prev, ...filtered])
    const scanResults = []
    const allRules = [
      ...injectionRules, ...xssRules, ...authRules,
      ...sensitiveDataRules, ...misconfigRules,
      ...deserializationRules, ...knownVulnsRules
    ]

    for (const file of filtered) {
      // Prevent duplicates by checking if path/name already exists in current results
      const filePath = file.webkitRelativePath || file.name
      if (results.some(r => r.fileName === filePath)) continue

      const result = await scanFile(file, allRules)
      scanResults.push(result)
    }

    setResults(prev => {
      const updated = [...prev, ...scanResults]
      // If nothing was selected before, select the first new file
      if (selectedFileIdx === null && updated.length > 0) setSelectedFileIdx(0)
      return updated
    })
    setIsScanning(false)
  }

  const selectedResult = selectedFileIdx !== null ? results[selectedFileIdx] : null

  return (
    <div 
      className="min-h-screen bg-white transition-colors duration-300 dark:bg-zinc-950 font-sans text-slate-900 dark:text-zinc-100 relative"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag Overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-[100] bg-red-600/10 backdrop-blur-[2px] border-4 border-dashed border-red-600 m-4 rounded-3xl flex items-center justify-center pointer-events-none animate-in fade-in zoom-in duration-200">
          <div className="bg-white dark:bg-zinc-900 p-8 rounded-3xl shadow-2xl flex flex-col items-center gap-4 border border-slate-200 dark:border-zinc-800">
            <div className="w-16 h-16 bg-red-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-red-500/40">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            </div>
            <p className="text-xl font-black uppercase tracking-tight">Drop files to scan</p>
          </div>
        </div>
      )}
      <input type="file" ref={fileInputRef} onChange={handleFileUpload} multiple className="hidden" accept=".js,.jsx,.ts,.tsx" />
      <input type="file" ref={folderInputRef} onChange={handleFileUpload} webkitdirectory="true" directory="true" className="hidden" />

      {/* Header */}
      <header className="sticky top-0 z-50 w-full glass">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-red-600 text-white shadow-lg shadow-red-500/20 group hover:rotate-12 transition-transform duration-500">
              <span className="font-black text-sm">JS</span>
            </div>
            <h1 className="text-xl font-display font-medium tracking-tight">
              JSentinel
            </h1>
          </div>

          <div className="flex items-center gap-3">
            {largeProjectWarning && (
              <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-amber-100/50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 text-[10px] font-black rounded-lg border border-amber-200/50 dark:border-zinc-800 animate-pulse">
                <span>⚠️ LARGE PROJECT (50+ FILES)</span>
              </div>
            )}
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors text-slate-500 dark:text-zinc-400 cursor-pointer btn-press"
              title="Toggle Theme"
            >
              {darkMode ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
            </button>
            <button 
              className="rounded-lg bg-slate-900 dark:bg-zinc-100 px-4 py-2 text-sm font-bold text-white dark:text-zinc-900 hover:opacity-90 transition-all disabled:opacity-30 cursor-pointer disabled:cursor-not-allowed flex items-center gap-2 btn-press" 
              disabled={results.length === 0 || isExporting}
              onClick={async () => {
                setIsExporting(true);
                // Give UI time to show loading state
                setTimeout(() => {
                  generatePDFReport(results, stats);
                  setIsExporting(false);
                }, 100);
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

      <main className="container mx-auto px-4 py-12 max-w-7xl">
        {/* Simplified Upload */}
        <section className={`mb-12 flex items-center justify-between p-8 rounded-3xl bg-slate-100 dark:bg-zinc-900/50 border border-slate-200 dark:border-zinc-800 shadow-refined dark:shadow-none transition-all animate-reveal ${results.length === 0 ? 'flex-col gap-8 text-center py-24 border-dashed border-2' : ''}`}>
          <div className={results.length === 0 ? 'max-w-2xl' : ''}>
            <h2 className="text-3xl font-black tracking-tight mb-2">{results.length === 0 ? 'Protocol Start' : 'Analysis Complete'}</h2>
            <p className="text-slate-500 dark:text-zinc-400 text-lg leading-relaxed">{results.length === 0 ? 'Initiate a local security audit by dropping your JavaScript project here.' : `Security scan finished for ${files.length} files. Review findings below.`}</p>
          </div>
          <div className="flex flex-col items-center gap-4">
            <div className="flex gap-4">
              <button onClick={() => fileInputRef.current.click()} className="px-6 py-3 rounded-2xl border border-slate-300 dark:border-zinc-700 font-bold text-sm hover:bg-white dark:hover:bg-zinc-800 transition-all btn-press shadow-sm cursor-pointer">Select Files</button>
              <button onClick={() => folderInputRef.current.click()} className="px-6 py-3 rounded-2xl bg-red-600 text-white font-bold text-sm hover:bg-red-700 transition-all btn-press shadow-lg shadow-red-500/20 cursor-pointer">Analyze Folder</button>
              {results.length > 0 && (
                <button onClick={() => { setResults([]); setFiles([]); setSelectedFileIdx(null); setLargeProjectWarning(false); }} className="p-3 text-red-600 hover:bg-red-50 dark:hover:bg-zinc-800 rounded-2xl transition-all btn-press cursor-pointer" title="Clear All">
                  <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                </button>
              )}
            </div>
            {largeProjectWarning && results.length === 0 && (
              <p className="text-[10px] font-black text-amber-600 dark:text-amber-500 uppercase tracking-[0.3em] animate-pulse">Warning: Project size exceeds 50 files.</p>
            )}
          </div>
        </section>

        {/* Stats Row */}
        <section className="mb-12 grid grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            { label: 'Files', value: files.length, color: 'text-indigo-600 dark:text-indigo-400', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l5 5v11a2 2 0 0 1-2 2z' },
            { label: 'Issues', value: stats.totalIssues, color: stats.totalIssues > 0 ? 'text-red-600' : 'text-slate-900 dark:text-white', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
            { label: 'Critical', value: stats.criticalIssues, color: stats.criticalIssues > 0 ? 'text-red-500' : 'text-slate-900 dark:text-white', icon: 'M12 15v2m-6 4h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2zm10-11V7a4 4 0 0 0-8 0v4h8z' },
            { label: 'Score', value: `${stats.securityScore.toFixed(1)}%`, color: stats.securityScore > 80 ? 'text-green-500' : 'text-orange-500', 
              icon: stats.securityScore === 100 ? 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' : 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' }
          ].map((s, i) => (
            <div key={i} className="bg-white dark:bg-zinc-900 p-6 rounded-3xl border border-slate-200 dark:border-zinc-800 shadow-sm flex items-center gap-5 transition-all hover:shadow-md hover:-translate-y-1 animate-reveal" style={{ animationDelay: `${(i+2)*100}ms` }}>
              <div className={`w-12 h-12 rounded-2xl flex items-center justify-center ${s.color.split(' ')[0].replace('text-', 'bg-')}/10 ${s.color}`}>
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d={s.icon}></path></svg>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-400 mb-0.5">{s.label}</span>
                <span className={`text-2xl font-black ${s.color}`}>{s.value}</span>
              </div>
            </div>
          ))}
        </section>

        {/* Main Workspace */}
        <div className="flex flex-col lg:flex-row gap-8 h-[750px] animate-reveal delay-400">
          {/* File Browser */}
          <div className="w-full lg:w-80 flex flex-col bg-slate-100 dark:bg-zinc-900/30 rounded-3xl border border-slate-200 dark:border-zinc-800 overflow-hidden shadow-sm">
            <div className="p-5 border-b border-slate-200 dark:border-zinc-800 flex justify-between items-center bg-white/50 dark:bg-zinc-900/50 backdrop-blur-sm">
              <span className="text-xs font-bold uppercase tracking-widest text-slate-500">Source Explorer</span>
              {isScanning && <div className="h-2 w-2 rounded-full bg-red-600 animate-ping"></div>}
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-1.5 scrollbar-none">
              {results.map((res, idx) => (
                <button 
                  key={idx} 
                  onClick={() => setSelectedFileIdx(idx)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-[background-color,color,box-shadow,border-color] duration-200 text-left group cursor-pointer btn-press border ${selectedFileIdx === idx ? 'bg-white dark:bg-zinc-800 shadow-sm border-slate-200 dark:border-zinc-700' : 'bg-transparent border-transparent hover:bg-white/60 dark:hover:bg-zinc-800/40'}`}
                >
                  <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${res.issues.length > 0 ? 'bg-red-500 shadow-lg shadow-red-500/50' : (!res.success || res.hasError) ? 'bg-amber-400' : 'bg-green-500'}`}></div>
                  <span className={`text-sm truncate flex-1 font-medium ${selectedFileIdx === idx ? 'text-slate-900 dark:text-white' : 'text-slate-500 dark:text-zinc-400 group-hover:text-slate-900 dark:group-hover:text-zinc-200'}`}>
                    {res.fileName.split('/').pop()}
                  </span>
                  {res.issues.length > 0 && (
                    <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${selectedFileIdx === idx ? 'bg-red-500 text-white' : 'bg-slate-200 dark:bg-zinc-800 text-slate-500'}`}>
                      {res.issues.length}
                    </span>
                  )}
                </button>
              ))}
              {results.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full opacity-30 py-20">
                  <svg className="w-12 h-12 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
                  <p className="text-xs font-bold uppercase tracking-tighter">Waiting for intake</p>
                </div>
              )}
            </div>
          </div>

          {/* Code & Issue Viewer */}
          <div className="flex-1 flex flex-col bg-white dark:bg-zinc-900 rounded-3xl border border-slate-200 dark:border-zinc-800 overflow-hidden shadow-sm">
            <div className="p-5 border-b border-slate-200 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-900/50 backdrop-blur-sm flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-slate-200 dark:bg-zinc-800 flex items-center justify-center">
                  <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                </div>
                <span className="text-sm font-bold truncate max-w-[300px]">{selectedResult?.fileName || 'Secure Inspector'}</span>
              </div>
              {selectedResult && selectedResult.issues.length > 0 && (
                <div className="flex items-center gap-2 px-3 py-1 bg-red-50 dark:bg-red-900/20 text-red-600 rounded-full border border-red-100 dark:border-red-900/30">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                  </span>
                  <span className="text-[10px] font-black tracking-widest uppercase">Breach Points Detected</span>
                </div>
              )}
            </div>

            <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-200 dark:scrollbar-thumb-zinc-700">
              {!selectedResult ? (
                <div className="h-full flex flex-col items-center justify-center p-20 text-center">
                  <div className="w-24 h-24 bg-slate-50 dark:bg-zinc-800/50 rounded-3xl flex items-center justify-center mb-6 shadow-inner">
                    <svg className="w-10 h-10 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                  </div>
                  <h3 className="font-black text-2xl tracking-tight mb-2 uppercase">Ready for Inspection</h3>
                  <p className="text-slate-400 dark:text-zinc-500 max-w-sm mx-auto leading-relaxed">Select a scanned resource from the registry to perform deep structural analysis.</p>
                </div>
              ) : !selectedResult.success ? (
                <div className="h-full flex flex-col items-center justify-center text-amber-500 p-10 text-center">
                  <div className="w-20 h-20 bg-amber-50 dark:bg-amber-900/20 rounded-full flex items-center justify-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </div>
                  <h3 className="text-xl font-black uppercase tracking-tight text-slate-800 dark:text-zinc-100">Parse Error</h3>
                  <p className="text-sm text-slate-500 mt-1 max-w-sm mx-auto">{selectedResult.error || "This file could not be parsed. It may contain syntax errors or non-standard syntax that prevents a full scan."}</p>
                </div>
              ) : selectedResult.issues.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-green-500">
                  <div className="w-20 h-20 bg-green-50 dark:bg-green-900/20 rounded-full flex items-center justify-center mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  </div>
                  <h3 className="text-xl font-black">Clean File</h3>
                  <p className="text-sm text-slate-400 mt-1 font-medium">No known security patterns detected in this file.</p>
                  {selectedResult.hasError && <p className="text-[10px] text-amber-500 font-bold uppercase mt-4 px-2 py-1 bg-amber-50 dark:bg-amber-900/20 rounded-lg">Partial Scan: Some rules failed to execute</p>}
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-zinc-800">
                  {selectedResult.hasError && (
                    <div className="bg-amber-50 dark:bg-amber-900/10 p-3 flex items-center gap-3 border-b border-amber-100 dark:border-zinc-800">
                       <span className="text-amber-500 text-lg">⚠️</span>
                       <p className="text-[11px] font-bold text-amber-700 dark:text-amber-400 uppercase tracking-wider">Partial scan completed. Some rules encountered errors while processing this file.</p>
                    </div>
                  )}
                  {[...selectedResult.issues]
                    .sort((a, b) => {
                      const priority = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
                      return (priority[a.severity] ?? 99) - (priority[b.severity] ?? 99);
                    })
                    .map((issue, i) => (
                    <div key={i} className="p-6 transition-colors hover:bg-slate-100/50 dark:hover:bg-zinc-800/20 cursor-pointer">
                      <div className="flex items-start justify-between mb-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                             <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${issue.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-zinc-400'}`}>
                              {issue.severity}
                            </span>
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">{issue.id}</span>
                          </div>
                          <h4 className="font-black text-slate-900 dark:text-white text-lg leading-tight">{issue.message}</h4>
                        </div>
                        <div className="text-xs font-black text-slate-400 whitespace-nowrap bg-slate-100 dark:bg-zinc-800 px-3 py-1 rounded-full">LINE {issue.line}</div>
                      </div>

                      <p className="text-sm text-slate-600 dark:text-zinc-400 mb-6 font-medium leading-relaxed">
                        {issue.suggestion}
                      </p>

                      <div className="bg-slate-50 dark:bg-black rounded-xl overflow-hidden border border-slate-200 dark:border-zinc-800 shadow-xl">
                        <div className="px-4 py-2 bg-slate-200/50 dark:bg-zinc-900/50 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-1.5">
                           <div className="w-2 h-2 rounded-full bg-red-400/50"></div>
                           <div className="w-2 h-2 rounded-full bg-orange-400/50"></div>
                           <div className="w-2 h-2 rounded-full bg-green-400/50"></div>
                        </div>
                        <div className="p-4 font-mono text-[11px] leading-relaxed overflow-x-auto text-slate-700 dark:text-zinc-300">
                          {(() => {
                            const lines = selectedResult.rawCode?.split('\n') || [];
                            const target = typeof issue.line === 'number' ? issue.line - 1 : -1;
                            const start = Math.max(0, target - 1);
                            const end = Math.min(lines.length - 1, target + 1);

                            return lines.slice(start, end + 1).map((text, idx) => {
                              const num = start + idx + 1;
                              const isTarget = num === issue.line;
                              return (
                                <div key={idx} className={`flex gap-4 ${isTarget ? 'text-red-600 bg-red-500/10 -mx-4 px-4 font-bold' : 'opacity-60'}`}>
                                  <span className="w-6 text-right select-none text-slate-400">{num}</span>
                                  <code className="whitespace-pre">{text || ' '}</code>
                                </div>
                              );
                            });
                          })()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      <footer className="mt-32 py-16 border-t border-slate-200 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-950/50">
        <div className="container mx-auto px-4">
           <div className="flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-slate-900 dark:bg-zinc-200 flex items-center justify-center text-white dark:text-zinc-900 font-bold text-xs shadow-lg">JS</div>
                <div className="flex flex-col">
                  <span className="text-sm font-black uppercase tracking-widest">JSentinel Protocol</span>
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-tighter">V1.0.0-Beta • System Active</span>
                </div>
              </div>
              
              <div className="flex gap-8 text-[10px] font-bold uppercase tracking-widest text-slate-400">
                <a href="#" className="hover:text-red-600 transition-colors">Security documentation</a>
                <a href="#" className="hover:text-red-600 transition-colors">Privacy policy</a>
                <a href="#" className="hover:text-red-600 transition-colors">Report vulnerability</a>
              </div>

              <p className="text-[10px] text-slate-500 font-medium uppercase tracking-widest">Local-first browser analysis • 2026</p>
           </div>
        </div>
      </footer>
    </div>
  )
}

export default App
