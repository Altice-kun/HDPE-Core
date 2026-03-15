const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close:    () => ipcRenderer.send('window-close'),

  // Scan
  getSystemInfo:    ()    => ipcRenderer.invoke('get-system-info'),
  scanInstalledApps:()    => ipcRenderer.invoke('scan-installed-apps'),
  scanDrivers:      ()    => ipcRenderer.invoke('scan-drivers'),
  scanDirectory:    (p)   => ipcRenderer.invoke('scan-directory', p),
  scanZip:          (p)   => ipcRenderer.invoke('scan-zip', p),

  // Compatibility checks
  searchCompatibility:    (name)        => ipcRenderer.invoke('search-compatibility', name),
  checkGithubRelease:     (opts)        => ipcRenderer.invoke('check-github-release', opts),
  checkKnownIncompatible: (name)        => ipcRenderer.invoke('check-known-incompatible', name),
  aiDeepCheck:            (name, ver)   => ipcRenderer.invoke('ai-deep-check', { appName: name, version: ver }),

  // Progress events from main process during long scans
  onScanProgress: (cb) => ipcRenderer.on('scan-progress', (_e, msg) => cb(msg)),
  offScanProgress:()   => ipcRenderer.removeAllListeners('scan-progress'),

  // Dialogs
  openDirectoryDialog: () => ipcRenderer.invoke('open-directory-dialog'),
  openFileDialog:      () => ipcRenderer.invoke('open-file-dialog'),

  // Export
  exportResults:    (d) => ipcRenderer.invoke('export-results',     d),
  exportHtmlReport: (d) => ipcRenderer.invoke('export-html-report', d),
  exportPdfReport:  (d) => ipcRenderer.invoke('export-pdf-report',  d),

  // External
  openUrl: (url) => ipcRenderer.invoke('open-url', url),
});
