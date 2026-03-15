'use strict';
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs   = require('fs');
const os   = require('os');
const https = require('https');
// NON-BLOCKING: use spawn (async) instead of execSync (blocks UI)
const { spawn } = require('child_process');

let mainWindow;

// ─── Window ────────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400, height: 900, minWidth: 1080, minHeight: 680,
    frame: false, backgroundColor: '#06060c',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'Windows Upgrade Requirements Scanner'
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

ipcMain.on('window-minimize', () => mainWindow.minimize());
ipcMain.on('window-maximize', () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('window-close',   () => mainWindow.close());

// ─── Async PowerShell runner (NON-BLOCKING) ────────────────────────────────
// Runs PS in a child process; yields to event loop throughout.
// Sends optional progress events back via IPC during long scans.
function runPS(script, { timeout = 30000, maxMB = 25, progressEvent, progressMsg } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalLen = 0;
    const maxBytes = maxMB * 1024 * 1024;

    const child = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script
    ], { windowsHide: true });

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('PowerShell timeout'));
    }, timeout);

    if (progressEvent && mainWindow) {
      // send a "still working" ping every 2 s so the UI can show activity
      const pingInterval = setInterval(() => {
        if (!mainWindow.isDestroyed())
          mainWindow.webContents.send(progressEvent, progressMsg || 'スキャン中...');
      }, 2000);
      child.once('close', () => clearInterval(pingInterval));
    }

    child.stdout.on('data', chunk => {
      totalLen += chunk.length;
      if (totalLen > maxBytes) { child.kill(); reject(new Error('Output too large')); return; }
      chunks.push(chunk);
    });
    child.stderr.on('data', () => {}); // swallow PS warnings

    child.once('close', code => {
      clearTimeout(timer);
      const out = Buffer.concat(chunks).toString('utf8').trim();
      resolve(out);
    });
    child.once('error', err => { clearTimeout(timer); reject(err); });
  });
}

// ─── HTTP helper ──────────────────────────────────────────────────────────
function httpsGet(url, extraHeaders = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'GET',
      headers: {
        'User-Agent': 'WURS/2.1 (Windows NT 10.0; Win64; x64) CompatibilityScanner',
        Accept: 'application/json,text/html,*/*',
        ...extraHeaders
      },
      timeout: timeoutMs
    }, res => {
      let d = '';
      res.on('data', c => { if (d.length < 800000) d += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ─── System Info ──────────────────────────────────────────────────────────
ipcMain.handle('get-system-info', async () => {
  const info = {
    platform: process.platform, arch: process.arch,
    osVersion: os.release(),
    cpuModel: os.cpus()[0]?.model || 'Unknown',
    cpuCores: os.cpus().length,
    totalMemGB: (os.totalmem()  / 1073741824).toFixed(1),
    freeMemGB:  (os.freemem()   / 1073741824).toFixed(1),
    hostname: os.hostname(), username: os.userInfo().username,
    uptime: Math.floor(os.uptime() / 3600) + '時間',
    scanTime: new Date().toLocaleString('ja-JP')
  };

  if (process.platform === 'win32') {
    // Run all PS queries concurrently (non-blocking)
    const [tpmR, sbR, diskTypeR, diskSzR, gpuR] = await Promise.allSettled([
      runPS('Get-WmiObject -Namespace root/cimv2/security/microsofttpm -Class Win32_Tpm | Select-Object -ExpandProperty IsEnabled_InitialValue 2>$null', { timeout: 6000 }),
      runPS('try { Confirm-SecureBootUEFI } catch { "False" }', { timeout: 6000 }),
      runPS('Get-PhysicalDisk | Select-Object -First 1 | Select-Object -ExpandProperty MediaType', { timeout: 6000 }),
      runPS('Get-WmiObject Win32_DiskDrive | Measure-Object -Property Size -Sum | Select-Object -ExpandProperty Sum', { timeout: 6000 }),
      runPS('Get-WmiObject Win32_VideoController | Select-Object -First 1 -ExpandProperty Name', { timeout: 6000 }),
    ]);

    info.tpm        = tpmR.value === 'True' ? true : tpmR.value === 'False' ? false : null;
    info.secureBoot = sbR.value  === 'True' ? true : sbR.value  === 'False' ? false : null;
    info.diskType   = diskTypeR.value || 'Unknown';
    if (diskSzR.value) info.diskGB = (parseFloat(diskSzR.value) / 1073741824).toFixed(0);
    info.gpu        = gpuR.value || 'Unknown';
    info.directx    = '12';
    info.cpuGeneration = detectCpuGen(info.cpuModel.toLowerCase());
  }
  return info;
});

function detectCpuGen(n) {
  if (n.includes('intel')) {
    const m = n.match(/i[3579]-(\d{4,5})/);
    if (m) { const v = parseInt(m[1]); const g = v >= 10000 ? Math.floor(v/1000) : Math.floor(v/100); return { vendor:'Intel', gen:g, supported:g >= 8 }; }
    if (/pentium|celeron/.test(n)) return { vendor:'Intel', gen:0, supported:false };
  }
  if (n.includes('amd') || n.includes('ryzen')) {
    const m = n.match(/ryzen\s+[3579]\s+(\d{4})/);
    if (m) { const v = parseInt(m[1]); const g = Math.floor(v/1000); return { vendor:'AMD', gen:g, supported:g >= 2 }; }
  }
  return null;
}

// ─── Installed Apps (non-blocking) ────────────────────────────────────────
ipcMain.handle('scan-installed-apps', async () => {
  if (process.platform !== 'win32') return getDemoApps();

  // Run all three registry paths concurrently
  const regPaths = [
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
  ];

  const results = await Promise.allSettled(regPaths.map(rp =>
    runPS(
      `Get-ItemProperty '${rp}\\*' | Where-Object { $_.DisplayName } | ` +
      `Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | ` +
      `ConvertTo-Json -Compress -Depth 2`,
      { timeout: 25000, maxMB: 20, progressEvent: 'scan-progress', progressMsg: 'アプリ情報収集中...' }
    )
  ));

  const apps = [];
  for (const r of results) {
    if (r.status !== 'fulfilled' || !r.value) continue;
    try {
      const list = JSON.parse(r.value);
      for (const a of (Array.isArray(list) ? list : [list])) {
        if (a.DisplayName) apps.push({
          name: a.DisplayName,
          version: a.DisplayVersion || '',
          publisher: a.Publisher || '',
          installDate: a.InstallDate || '',
          installPath: a.InstallLocation || '',
          compatibility: checkAppCompat(a.DisplayName, a.DisplayVersion || '')
        });
      }
    } catch { /* bad JSON from one path – continue */ }
  }

  const seen = new Set();
  return apps.filter(a => { if (seen.has(a.name)) return false; seen.add(a.name); return true; });
});

// ─── Compatibility databases ───────────────────────────────────────────────
const INCOMPAT = [
  [/internet explorer/i,                      'Windows 11ではIEが完全削除されました'],
  [/quicktime/i,                              'QuickTimeはWindows非推奨・脆弱性あり'],
  [/virtualbox\s+[45]\./i,                    'VirtualBox 4/5はWin11非対応 → 最新版へ更新'],
  [/daemon tools.*(?:lite [34]|pro [456])/i,  '旧DAEMON Toolsはドライバー非互換'],
  [/adobe.*cs[0-6]/i,                         'Adobe CS旧版はWin11非対応 → CCへ移行'],
  [/microsoft office 200[0-9]|office 2010/i,  'Office 2010以前はWin11サポート外'],
  [/itunes.*1[0-2]\./i,                       '旧iTunes → Microsoft Storeの新版を使用'],
  [/winpcap/i,                                'WinPcapはWin11非対応 → Npcapへ移行'],
  [/net framework 1\.|net framework 2\./i,    '.NET Framework 1.x/2.xは組込み不可'],
];
const WARN = [
  [/antivirus|internet security|kaspersky|norton|mcafee|avast|avg|bitdefender|eset/i, 'Win11対応版か公式サイトで確認してください'],
  [/nvidia.*driver|geforce.*experience/i,  'Win11用最新ドライバーへ更新を推奨'],
  [/amd.*driver|radeon.*software/i,        'Win11用AMDドライバーへ更新を推奨'],
  [/realtek|intel.*driver|audio.*driver/i, 'Win11用ドライバーへ更新を推奨'],
  [/\.net.*(?:3\.5|3\.0)/i,               '.NET 3.5はWin11で手動インストールが必要'],
  [/vmware workstation\s+1[0-4]\./i,       'VMware 14以前はWin11で要確認'],
  [/winamp/i,                              'WinampのWin11対応は非公式'],
  [/cpu-z|hwinfo|speccy|gpu-z/i,           '診断ツール — Win11用最新版に更新を推奨'],
];
function checkAppCompat(name, ver) {
  const full = `${name} ${ver}`;
  for (const [re, reason] of INCOMPAT) if (re.test(full)) return { status:'incompatible', reason };
  for (const [re, reason] of WARN)    if (re.test(name))  return { status:'warning', reason };
  return { status:'compatible', reason:'既知の問題なし' };
}
function getDemoApps() {
  return [
    { name:'Google Chrome',        version:'120.0',  publisher:'Google LLC',        compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Internet Explorer 11', version:'11.0.9', publisher:'Microsoft',          compatibility:{ status:'incompatible', reason:'Windows 11ではIEが完全削除されました' } },
    { name:'VirtualBox 5.2',       version:'5.2.44', publisher:'Oracle',             compatibility:{ status:'incompatible', reason:'VirtualBox 4/5はWin11非対応 → 最新版へ更新' } },
    { name:'Kaspersky Security',   version:'21.3',   publisher:'Kaspersky',          compatibility:{ status:'warning',      reason:'Win11対応版か公式サイトで確認してください' } },
    { name:'Visual Studio Code',   version:'1.85.1', publisher:'Microsoft',          compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Adobe Photoshop 2024', version:'25.0',   publisher:'Adobe',              compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Realtek Audio Driver', version:'6.0.92', publisher:'Realtek',            compatibility:{ status:'warning',      reason:'Win11用ドライバーへ更新を推奨' } },
    { name:'QuickTime Player',     version:'7.79',   publisher:'Apple',              compatibility:{ status:'incompatible', reason:'QuickTimeはWindows非推奨・脆弱性あり' } },
    { name:'7-Zip 23',             version:'23.01',  publisher:'Igor Pavlov',        compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'DAEMON Tools Lite 4.0',version:'4.0.0',  publisher:'DT Soft',            compatibility:{ status:'incompatible', reason:'旧DAEMON Toolsはドライバー非互換' } },
    { name:'NVIDIA GeForce Driver',version:'536.99', publisher:'NVIDIA',             compatibility:{ status:'warning',      reason:'Win11用最新ドライバーへ更新を推奨' } },
    { name:'Mozilla Firefox',      version:'121.0',  publisher:'Mozilla',            compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Microsoft Office 2010',version:'14.0.72',publisher:'Microsoft',          compatibility:{ status:'incompatible', reason:'Office 2010はサポート終了(2020年)' } },
    { name:'Blender',              version:'4.0.1',  publisher:'Blender Foundation', compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Steam',                version:'1.0',    publisher:'Valve',              compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
  ];
}

// ─── Driver Scan (non-blocking) ───────────────────────────────────────────
ipcMain.handle('scan-drivers', async () => {
  if (process.platform !== 'win32') return getDemoDrivers();
  try {
    const raw = await runPS(
      'Get-WmiObject Win32_PnPSignedDriver | ' +
      'Where-Object { $_.DeviceName -ne $null -and $_.DriverVersion -ne $null } | ' +
      'Select-Object DeviceName,DriverVersion,DriverDate,Manufacturer,DeviceClass,IsSigned | ' +
      'Sort-Object DeviceClass | ConvertTo-Json -Compress -Depth 2',
      { timeout: 45000, maxMB: 30, progressEvent: 'scan-progress', progressMsg: 'ドライバー情報収集中...' }
    );
    const list = JSON.parse(raw);
    return (Array.isArray(list) ? list : [list])
      .filter(d => d.DeviceName)
      .map(d => ({
        name: d.DeviceName, version: d.DriverVersion || '',
        date: d.DriverDate ? d.DriverDate.substring(0,8).replace(/(\d{4})(\d{2})(\d{2})/,'$1/$2/$3') : '',
        manufacturer: d.Manufacturer || '', class: d.DeviceClass || '',
        signed: d.IsSigned !== false,
        compatibility: checkDriverCompat(d.DeviceName, d.DriverDate)
      }));
  } catch { return getDemoDrivers(); }
});

function checkDriverCompat(name, date) {
  const yr = date ? parseInt(date.substring(0,4)) : null;
  if (yr && yr < 2017) return { status:'incompatible', reason:`古いドライバー(${yr}年) — Win11非対応の可能性が高い` };
  if (yr && yr < 2019) return { status:'warning',      reason:`古いドライバー(${yr}年) — Win11用への更新を推奨` };
  const n = (name||'').toLowerCase();
  if (/display|video|graphics|gpu|nvidia|radeon|geforce|intel.*graphics/i.test(n)) return { status:'warning', reason:'ディスプレイドライバー — Win11対応版に更新を推奨', category:'GPU' };
  if (/audio|sound|realtek|high definition audio/i.test(n))  return { status:'warning', reason:'オーディオドライバー — Win11付属ドライバーで確認を', category:'Audio' };
  if (/bluetooth/i.test(n))                                   return { status:'warning', reason:'Bluetoothドライバー — Win11用最新版を推奨',          category:'Bluetooth' };
  if (/wi-fi|wireless|wlan|802\.11/i.test(n))                 return { status:'warning', reason:'Wi-Fiドライバー — Win11対応版の確認を推奨',          category:'WiFi' };
  if (/printer|print/i.test(n))                               return { status:'warning', reason:'プリンタードライバー — Win11では再インストールが必要な場合あり', category:'Printer' };
  return { status:'compatible', reason:'既知の問題なし' };
}
function getDemoDrivers() {
  return [
    { name:'NVIDIA GeForce RTX 3080',         version:'536.99',       date:'2023/08/15', manufacturer:'NVIDIA',     class:'Display',   signed:true,  compatibility:{ status:'warning',      reason:'ディスプレイドライバー — Win11対応版に更新を推奨' } },
    { name:'Realtek High Definition Audio',   version:'6.0.9260.1',   date:'2023/05/10', manufacturer:'Realtek',    class:'MEDIA',     signed:true,  compatibility:{ status:'warning',      reason:'オーディオドライバー — Win11付属ドライバーで確認を' } },
    { name:'Intel Wi-Fi 6 AX200',             version:'22.200.0.4',   date:'2023/07/01', manufacturer:'Intel',      class:'Net',       signed:true,  compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'USB Root Hub (USB 3.0)',           version:'10.0.19041',   date:'2023/01/01', manufacturer:'Microsoft',  class:'USB',       signed:true,  compatibility:{ status:'compatible',   reason:'既知の問題なし' } },
    { name:'Canon iP7200 Printer',            version:'6.71.0.0',     date:'2016/04/15', manufacturer:'Canon',      class:'Printer',   signed:true,  compatibility:{ status:'incompatible', reason:'古いドライバー(2016年) — Win11非対応の可能性が高い' } },
    { name:'Intel HD Graphics 4000',          version:'9.17.10.4229', date:'2014/11/03', manufacturer:'Intel',      class:'Display',   signed:true,  compatibility:{ status:'incompatible', reason:'古いドライバー(2014年) — Win11非対応の可能性が高い' } },
    { name:'Intel Bluetooth',                 version:'22.50.0.3',    date:'2022/11/20', manufacturer:'Intel',      class:'Bluetooth', signed:true,  compatibility:{ status:'warning',      reason:'Bluetoothドライバー — Win11用最新版を推奨' } },
  ];
}

// ─── File Scan (non-blocking: async fs walk) ──────────────────────────────
ipcMain.handle('scan-directory', async (event, dir) => {
  const exts = new Set(['.exe','.msi','.bat','.cmd','.ps1','.com','.scr','.vbs','.wsf']);
  const results = [];

  async function walk(d, depth) {
    if (depth > 4) return;
    let entries;
    try { entries = await fs.promises.readdir(d, { withFileTypes: true }); }
    catch { return; }
    // Yield to event loop on every directory
    await new Promise(r => setImmediate(r));
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      const fp = path.join(d, e.name);
      if (e.isDirectory()) {
        await walk(fp, depth + 1);
      } else if (e.isFile()) {
        const ext = path.extname(e.name).toLowerCase();
        if (exts.has(ext)) {
          try {
            const st = await fs.promises.stat(fp);
            results.push({ name:e.name, path:fp, ext, size:st.size, modified:st.mtime, compatibility:checkFileCompat(e.name, ext) });
          } catch { /* skip locked files */ }
        }
      }
    }
  }

  await walk(dir, 0);
  return results;
});

function checkFileCompat(name, ext) {
  if (ext === '.com')              return { status:'incompatible', reason:'16-bit .COMファイル — 64-bit Win11では動作不可' };
  if (ext === '.scr')              return { status:'warning',      reason:'スクリーンセーバー — 互換性を確認してください' };
  if (ext === '.vbs' || ext==='.wsf') return { status:'warning',  reason:'スクリプトファイル — Win11のポリシー変更に注意' };
  if (ext === '.bat' || ext==='.cmd') return { status:'warning',  reason:'バッチファイル — パス変更が必要な場合あり' };
  if (ext === '.ps1')              return { status:'warning',      reason:'PowerShellスクリプト — 実行ポリシーの確認が必要' };
  if (/setup|install|uninstall/i.test(name)) return { status:'warning', reason:'インストーラー — 実行前に互換確認を推奨' };
  return { status:'compatible', reason:'互換性あり（推定）' };
}

// ─── ZIP Scan ─────────────────────────────────────────────────────────────
ipcMain.handle('scan-zip', async (event, zipPath) => {
  try {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(zipPath);
    return { success:true, zipPath, entries: zip.getEntries().filter(e=>!e.isDirectory).map(e => ({
      name:e.name, path:e.entryName,
      ext:path.extname(e.name).toLowerCase(),
      size:e.header.size,
      compatibility:checkFileCompat(e.name, path.extname(e.name).toLowerCase())
    }))};
  } catch(e) { return { success:false, error:e.message }; }
});

// ─── AI DEEP COMPATIBILITY CHECK ──────────────────────────────────────────
// Queries multiple sources concurrently and synthesises a verdict.
ipcMain.handle('ai-deep-check', async (event, { appName, version }) => {
  const query = encodeURIComponent(`${appName} ${version||''} Windows 11 compatibility`.trim());
  const label = `${appName}${version ? ' ' + version : ''}`;

  // ── Source 1: Google search ──────────────────────────────────────────
  const googlePromise = httpsGet(
    `https://www.google.com/search?q=${query}&num=8&hl=ja`,
    {}, 10000
  ).then(res => {
    const snippets = [];
    const sRe = /<div[^>]+class="[^"]*VwiC3b[^"]*"[^>]*>(.*?)<\/div>/gs;
    let m;
    while ((m = sRe.exec(res.body)) !== null && snippets.length < 5) {
      const t = m[1].replace(/<[^>]+>/g,'').trim();
      if (t.length > 20) snippets.push(t);
    }
    return { source:'Google検索', snippets, url:`https://www.google.com/search?q=${query}` };
  }).catch(() => ({ source:'Google検索', snippets:[], error:'取得失敗' }));

  // ── Source 2: Microsoft Support search ──────────────────────────────
  const msQuery = encodeURIComponent(`${appName} Windows 11`);
  const msPromise = httpsGet(
    `https://support.microsoft.com/en-us/search/results?query=${msQuery}`,
    {}, 8000
  ).then(res => {
    const snippets = [];
    const titleRe = /<h3[^>]*class="[^"]*title[^"]*"[^>]*>(.*?)<\/h3>/gsi;
    let m;
    while ((m = titleRe.exec(res.body)) !== null && snippets.length < 3) {
      const t = m[1].replace(/<[^>]+>/g,'').trim();
      if (t.length > 8) snippets.push(t);
    }
    return { source:'Microsoft Support', snippets, url:`https://support.microsoft.com/search/results?query=${msQuery}` };
  }).catch(() => ({ source:'Microsoft Support', snippets:[], error:'取得失敗' }));

  // ── Source 3: GitHub issues/releases search ──────────────────────────
  const ghQuery = encodeURIComponent(`${appName} windows 11`);
  const ghPromise = httpsGet(
    `https://github.com/search?q=${ghQuery}+windows+11&type=issues`,
    { Accept:'text/html' }, 8000
  ).then(res => {
    const snippets = [];
    const issRe = /<a[^>]+class="[^"]*Link--primary[^"]*"[^>]*>(.*?)<\/a>/gsi;
    let m;
    while ((m = issRe.exec(res.body)) !== null && snippets.length < 3) {
      const t = m[1].replace(/<[^>]+>/g,'').trim();
      if (t.length > 8) snippets.push(t);
    }
    return { source:'GitHub Issues', snippets, url:`https://github.com/search?q=${ghQuery}+windows+11&type=issues` };
  }).catch(() => ({ source:'GitHub Issues', snippets:[], error:'取得失敗' }));

  // ── Source 4: Offine known-incompatible DB ───────────────────────────
  const dbResult = checkDeepDB(appName, version);

  // ── Run all concurrently ─────────────────────────────────────────────
  const [googleR, msR, ghR] = await Promise.all([googlePromise, msPromise, ghPromise]);
  const sources = [googleR, msR, ghR, { source:'内部互換DB', snippets: dbResult.snippets, dbVerdict: dbResult }];

  // ── Synthesise final verdict ─────────────────────────────────────────
  const allText = sources.flatMap(s => s.snippets).join(' ').toLowerCase();
  const verdict = synthesiseVerdict(allText, dbResult);

  return { appName: label, sources, verdict };
});

// ─── Deep DB ──────────────────────────────────────────────────────────────
function checkDeepDB(name, ver) {
  const full = `${name} ${ver||''}`.toLowerCase();
  const DB = [
    // Incompatible
    { re:/internet explorer/i,    status:'incompatible', conf:'高', detail:'MicrosoftはWin11でIEを完全削除。EdgeのIEモードを利用してください。', link:'https://docs.microsoft.com/lifecycle/faq/internet-explorer-microsoft-edge' },
    { re:/quicktime/i,            status:'incompatible', conf:'高', detail:'AppleはQuickTime for Windowsのサポートを2016年に終了。脆弱性あり。', link:'https://support.apple.com/en-us/102019' },
    { re:/virtualbox\s+[45]\./i,  status:'incompatible', conf:'高', detail:'VirtualBox 5以下はHyper-V/Win11と非互換。VirtualBox 7以降に更新してください。', link:'https://www.virtualbox.org/wiki/Downloads' },
    { re:/daemon tools.*lite [34]|daemon tools.*pro [456]/i, status:'incompatible', conf:'高', detail:'旧DAEMON Toolsのドライバーはセキュアブートに非対応。', link:null },
    { re:/adobe.*cs[0-6]/i,       status:'incompatible', conf:'高', detail:'Adobe CS6以前はWin11で公式非サポート。Creative Cloudに移行してください。', link:'https://helpx.adobe.com/support/programs/eol-matrix.html' },
    { re:/microsoft office 200[0-9]|office 2010/i, status:'incompatible', conf:'高', detail:'Office 2010はメインストリームサポート終了(2015年)・延長サポート終了(2020年)。', link:null },
    { re:/winpcap/i,              status:'incompatible', conf:'高', detail:'WinPcapの開発は停止。Npcapに移行してください。', link:'https://npcap.com/' },
    // Warning
    { re:/virtualbox\s+[6]\./i,   status:'warning', conf:'中', detail:'VirtualBox 6.1は動作するがパフォーマンス問題あり。VirtualBox 7推奨。', link:'https://www.virtualbox.org/wiki/Changelog' },
    { re:/vmware workstation\s+1[0-5]\./i, status:'warning', conf:'中', detail:'VMware 15以前はWin11での動作に問題が報告されています。最新版推奨。', link:null },
    { re:/microsoft office 2013/i, status:'warning', conf:'中', detail:'Office 2013は延長サポート終了(2023年4月)。Microsoft 365推奨。', link:null },
    { re:/kaspersky/i,            status:'warning', conf:'中', detail:'Win11ではKaspersky製品の一部機能に制限あり。公式サイトでWin11対応版を確認。', link:'https://www.kaspersky.com/downloads' },
    { re:/avast|avg/i,            status:'warning', conf:'低', detail:'Avast/AVGのWin11対応は確認されていますが最新版への更新を推奨。', link:null },
    { re:/\.net.*3\.5|\.net.*3\.0/i, status:'warning', conf:'高', detail:'.NET 3.5はWin11に標準搭載されていません。オプション機能から手動インストールが必要。', link:'https://docs.microsoft.com/dotnet/framework/install/dotnet-35-windows' },
    // Compatible
    { re:/steam/i,                status:'compatible', conf:'高', detail:'SteamはWindows 11を公式サポート。', link:null },
    { re:/discord/i,              status:'compatible', conf:'高', detail:'DiscordはWindows 11を公式サポート。', link:null },
    { re:/visual studio code|vscode/i, status:'compatible', conf:'高', detail:'VS CodeはWindows 11を公式サポート。', link:null },
    { re:/obs.*studio/i,          status:'compatible', conf:'高', detail:'OBS StudioはWindows 11対応済み。', link:null },
    { re:/vlc/i,                  status:'compatible', conf:'高', detail:'VLC Media PlayerはWindows 11対応済み。', link:null },
    { re:/7-zip/i,                status:'compatible', conf:'高', detail:'7-ZipはWindows 11対応済み(最新版推奨)。', link:null },
    { re:/notepad\+\+/i,          status:'compatible', conf:'高', detail:'Notepad++はWindows 11対応済み。', link:null },
    { re:/mozilla firefox|firefox/i, status:'compatible', conf:'高', detail:'Firefox はWindows 11を公式サポート。', link:null },
    { re:/google chrome/i,        status:'compatible', conf:'高', detail:'ChromeはWindows 11を公式サポート。', link:null },
  ];
  for (const entry of DB) {
    if (entry.re.test(full)) {
      return { found:true, status:entry.status, confidence:entry.conf, detail:entry.detail, link:entry.link, snippets:[`[内部DB] ${entry.detail}`] };
    }
  }
  return { found:false, status:null, snippets:[] };
}

// ─── Verdict synthesis ────────────────────────────────────────────────────
function synthesiseVerdict(allText, dbResult) {
  // DB hit takes priority if high confidence
  if (dbResult.found && dbResult.confidence === '高') {
    return { status:dbResult.status, confidence:'高', basis:'内部DB(高信頼)', summary:dbResult.detail };
  }

  // Count positive/negative signals across all scraped text
  let score = 0;
  const positives = [/officially\s+support/i,/fully\s+support/i,/compatible.*windows.?11/i,/works.*windows.?11/i,/tested.*windows.?11/i,/windows.?11.*support/i];
  const negatives = [/not.*compatible/i,/not.*support/i,/incompatible/i,/does not work/i,/won'?t work/i,/broken.*windows.?11/i,/issue.*windows.?11/i];
  const cautions  = [/issue/i,/problem/i,/workaround/i,/update required/i,/patch/i,/bug/i,/crash/i];

  for (const r of positives) if (r.test(allText)) score += 2;
  for (const r of negatives) if (r.test(allText)) score -= 3;
  for (const r of cautions)  if (r.test(allText)) score -= 1;

  if (dbResult.found) {
    if (dbResult.status === 'compatible')   score += 2;
    if (dbResult.status === 'warning')      score -= 1;
    if (dbResult.status === 'incompatible') score -= 3;
  }

  let status, confidence, summary;
  if      (score >=  3) { status='compatible';   confidence='中'; summary='複数ソースでWindows 11互換性が確認されました。'; }
  else if (score >=  1) { status='compatible';   confidence='低'; summary='一部ソースで互換性の言及がありますが確認を推奨します。'; }
  else if (score >=  0) { status='warning';      confidence='低'; summary='明確な判定ができませんでした。各ソースを直接確認してください。'; }
  else if (score >= -3) { status:'warning';      confidence='中'; summary='問題・警告の報告が見られます。使用前に確認を推奨します。'; }
  else                  { status='incompatible'; confidence='中'; summary='非互換または動作問題の報告が複数ソースで確認されました。'; }

  // Fix typo in object literal above
  if (score >= -3 && score < 0 && !status) { status='warning'; confidence='中'; summary='問題・警告の報告が見られます。使用前に確認を推奨します。'; }

  return { status, confidence, basis:'マルチソース解析', summary };
}

// ─── Single-query internet search ─────────────────────────────────────────
ipcMain.handle('search-compatibility', async (event, appName) => {
  const q = encodeURIComponent(`${appName} Windows 11 compatibility`);
  try {
    const res = await httpsGet(`https://www.google.com/search?q=${q}&num=5&hl=ja`);
    const snippets = [], titles = [];
    let m;
    const sRe = /<div[^>]+class="[^"]*VwiC3b[^"]*"[^>]*>(.*?)<\/div>/gs;
    while ((m = sRe.exec(res.body)) !== null && snippets.length < 4) {
      const t = m[1].replace(/<[^>]+>/g,'').trim();
      if (t.length > 20) snippets.push(t);
    }
    const tRe = /<h3[^>]*>(.*?)<\/h3>/gs;
    while ((m = tRe.exec(res.body)) !== null && titles.length < 5) {
      const t = m[1].replace(/<[^>]+>/g,'').trim();
      if (t.length > 5) titles.push(t);
    }
    return { searchUrl:`https://www.google.com/search?q=${q}`, snippets, titles, autoResult:analyseText([...snippets,...titles]) };
  } catch { return { error:'ネットワーク接続を確認してください', snippets:[], titles:[] }; }
});

// ─── GitHub Release ────────────────────────────────────────────────────────
ipcMain.handle('check-github-release', async (event, { owner, repo }) => {
  try {
    const res = await httpsGet(`https://api.github.com/repos/${owner}/${repo}/releases/latest`, { Accept:'application/vnd.github.v3+json' });
    if (res.status !== 200) return { error:`GitHub API: HTTP ${res.status}` };
    const rel = JSON.parse(res.body);
    const assets = (rel.assets||[]).map(a => ({ name:a.name, size:a.size, downloadCount:a.download_count, downloadUrl:a.browser_download_url, compatibility:checkFileCompat(a.name, path.extname(a.name).toLowerCase()) }));
    let win11Support = 'unknown';
    if (/not.*support.*windows\s*11|incompatible.*win\s*11/i.test(rel.body||'')) win11Support='incompatible';
    else if (/support.*windows\s*11|compatible.*win\s*11|tested.*win\s*11/i.test(rel.body||'')) win11Support='compatible';
    else if (/windows\s*11/i.test(rel.body||'')) win11Support='mentioned';
    return { tagName:rel.tag_name, publishedAt:rel.published_at?.substring(0,10), name:rel.name, htmlUrl:rel.html_url, body:rel.body?.substring(0,500)||'', assets, win11Support };
  } catch(e) { return { error:e.message }; }
});

ipcMain.handle('check-known-incompatible', async (event, appName) => {
  const r = checkDeepDB(appName, '');
  return r.found ? { found:true, status:r.status, reason:r.detail, link:r.link } : { found:false };
});

function analyseText(texts) {
  const c = texts.join(' ').toLowerCase();
  if (/not.*compatible|not.*support|incompatible|does not work/i.test(c)) return { status:'incompatible', confidence:'medium' };
  if (/fully.*support|officially.*support|compatible.*windows.?11/i.test(c)) return { status:'compatible', confidence:'high' };
  if (/compatible|support|works/i.test(c)) return { status:'compatible', confidence:'low' };
  if (/issue|problem|bug|workaround/i.test(c)) return { status:'warning', confidence:'low' };
  return { status:'unknown', confidence:'none' };
}

// ─── Dialogs ─────────────────────────────────────────────────────────────
ipcMain.handle('open-directory-dialog', async () => { const r = await dialog.showOpenDialog(mainWindow,{properties:['openDirectory']}); return r.filePaths[0]||null; });
ipcMain.handle('open-file-dialog',      async () => { const r = await dialog.showOpenDialog(mainWindow,{properties:['openFile'],filters:[{name:'ZIP',extensions:['zip']}]}); return r.filePaths[0]||null; });
ipcMain.handle('open-url', async (e, url) => shell.openExternal(url));

// ─── Export ──────────────────────────────────────────────────────────────
ipcMain.handle('export-results', async (e, data) => {
  const r = await dialog.showSaveDialog(mainWindow,{ defaultPath:`wurs-scan-${ts()}.json`, filters:[{name:'JSON',extensions:['json']},{name:'CSV',extensions:['csv']}] });
  if (!r.filePath) return { success:false };
  fs.writeFileSync(r.filePath, path.extname(r.filePath)==='.csv' ? toCSV(data) : JSON.stringify(data,null,2), 'utf8');
  return { success:true, path:r.filePath };
});

ipcMain.handle('export-html-report', async (e, data) => {
  const r = await dialog.showSaveDialog(mainWindow,{ defaultPath:`wurs-report-${ts()}.html`, filters:[{name:'HTML',extensions:['html']}] });
  if (!r.filePath) return { success:false };
  fs.writeFileSync(r.filePath, buildReport(data), 'utf8');
  return { success:true, path:r.filePath };
});

ipcMain.handle('export-pdf-report', async (e, data) => {
  const r = await dialog.showSaveDialog(mainWindow,{ defaultPath:`wurs-report-${ts()}.pdf`, filters:[{name:'PDF',extensions:['pdf']}] });
  if (!r.filePath) return { success:false };
  const win = new BrowserWindow({ show:false, webPreferences:{ nodeIntegration:false, contextIsolation:true } });
  const tmp = path.join(os.tmpdir(), `wurs-tmp-${Date.now()}.html`);
  fs.writeFileSync(tmp, buildReport(data), 'utf8');
  await win.loadFile(tmp);
  await new Promise(res => setTimeout(res, 800));
  const buf = await win.webContents.printToPDF({ format:'A4', printBackground:true, margins:{ marginType:'custom', top:0.4, bottom:0.4, left:0.4, right:0.4 } });
  fs.writeFileSync(r.filePath, buf);
  win.destroy();
  try { fs.unlinkSync(tmp); } catch {}
  return { success:true, path:r.filePath };
});

// ─── Helpers ─────────────────────────────────────────────────────────────
function ts() { return new Date().toISOString().replace(/[:.]/g,'-').substring(0,19); }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function q(s) { return `"${String(s||'').replace(/"/g,'""')}"`; }
function toCSV(data) {
  const rows = [['\uFEFF種別','名前','バージョン','発行元','ステータス','詳細']];
  for (const a of (data.apps||[]))    rows.push(['App',    q(a.name), q(a.version), q(a.publisher),    a.compatibility?.status||'', q(a.compatibility?.reason||'')]);
  for (const d of (data.drivers||[])) rows.push(['Driver', q(d.name), q(d.version), q(d.manufacturer), d.compatibility?.status||'', q(d.compatibility?.reason||'')]);
  for (const f of (data.files||[]))   rows.push(['File',   q(f.name), f.ext, '',                        f.compatibility?.status||'', q(f.compatibility?.reason||'')]);
  return rows.map(r=>r.join(',')).join('\r\n');
}

function buildReport(data) {
  const { systemInfo:si={}, apps=[], drivers=[], files=[], scanDate } = data;
  const all = [...apps,...drivers,...files];
  const inc  = all.filter(i=>i.compatibility?.status==='incompatible').length;
  const warn = all.filter(i=>i.compatibility?.status==='warning').length;
  const comp = all.filter(i=>i.compatibility?.status==='compatible').length;
  const vColor = inc>0?'#f74f6e':warn>0?'#f5c542':'#22d3a0';
  const vIcon  = inc>0?'🚨':warn>0?'⚠️':'✅';
  const vTitle = inc>0?'非互換アイテム検出':warn>0?'要確認事項あり':'Win11移行 準備完了';

  const tblRows = (items,type) => items.map(item => {
    const s = item.compatibility?.status||'unknown';
    const dot = s==='compatible'?'#22d3a0':s==='warning'?'#f5c542':'#f74f6e';
    const lbl = s==='compatible'?'互換あり':s==='warning'?'要確認':s==='incompatible'?'非互換':'不明';
    return `<tr><td style="color:#666;font-size:10px">${type}</td>
      <td><strong>${esc(item.name)}</strong></td>
      <td style="color:#888;font-size:11px;font-family:monospace">${esc(item.version||item.ext||'')}</td>
      <td style="color:#888;font-size:11px">${esc(item.publisher||item.manufacturer||'')}</td>
      <td><span style="color:${dot};font-weight:700;font-size:11px">● ${lbl}</span></td>
      <td style="color:#999;font-size:11px">${esc(item.compatibility?.reason||'')}</td></tr>`;
  }).join('');

  const sec = (title,items,type) => items.length===0?'':
    `<div style="margin-bottom:28px"><div style="font-size:14px;font-weight:700;color:#9090c0;border-bottom:1px solid #1e1e3a;padding-bottom:7px;margin-bottom:12px;letter-spacing:1px;text-transform:uppercase">${title} (${items.length}件)</div>
    <table style="width:100%;border-collapse:collapse;background:#0d0d1a;border-radius:8px;overflow:hidden">
      <thead><tr>${['種別','名前','バージョン','発行元','互換性','詳細'].map(h=>`<th style="text-align:left;padding:8px 12px;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:#5050a0;background:#111120;border-bottom:1px solid #1e1e3a;font-family:monospace">${h}</th>`).join('')}</tr></thead>
      <tbody>${tblRows(items,type)}</tbody></table></div>`;

  return `<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
<title>WURS Report</title>
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Noto+Sans+JP:wght@400&family=Space+Mono&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#07070d;color:#e8e8f8;font-family:'Noto Sans JP',sans-serif;font-size:13px;padding:36px;line-height:1.5}@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}</style></head>
<body>
<div style="display:flex;justify-content:space-between;border-bottom:2px solid #1e1e3a;padding-bottom:20px;margin-bottom:28px;flex-wrap:wrap;gap:12px">
  <div><div style="font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;color:#4f8ef7;letter-spacing:3px;text-transform:uppercase">Windows Upgrade Requirements Scanner</div>
  <div style="color:#5050a0;font-size:11px;margin-top:3px">Windows 11 移行互換性スキャンレポート — WURS v2.1</div></div>
  <div style="text-align:right;color:#5050a0;font-family:'Space Mono',monospace;font-size:10px;line-height:1.9">
    <div>スキャン日時: ${scanDate||new Date().toLocaleString('ja-JP')}</div>
    <div>ホスト名: ${esc(si.hostname||'N/A')}</div><div>OS: Windows ${esc(si.osVersion||'N/A')}</div></div>
</div>
<div style="background:linear-gradient(135deg,#0d0d1a,#111120);border:1px solid #1e1e3a;border-left:4px solid ${vColor};border-radius:10px;padding:20px 28px;margin-bottom:24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap">
  <div style="font-size:44px;line-height:1">${vIcon}</div>
  <div><div style="font-family:'Rajdhani',sans-serif;font-size:26px;font-weight:700;color:${vColor}">${vTitle}</div>
  <div style="font-size:12px;color:#5050a0;margin-top:4px">${inc}件の非互換、${warn}件の警告、${comp}件の互換あり</div></div>
  <div style="margin-left:auto;text-align:right"><div style="font-size:9px;color:#5050a0;font-family:monospace;letter-spacing:2px">TOTAL</div>
  <div style="font-family:'Rajdhani',sans-serif;font-size:38px;font-weight:700;color:#4f8ef7">${all.length}</div></div>
</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px">
  ${[['非互換',inc,'#f74f6e'],['要確認',warn,'#f5c542'],['互換あり',comp,'#22d3a0'],['総数',all.length,'#4f8ef7']].map(([l,n,c])=>
    `<div style="background:#0d0d1a;border:1px solid #1e1e3a;border-radius:8px;padding:14px;text-align:center">
      <div style="font-family:'Rajdhani',sans-serif;font-size:34px;font-weight:700;color:${c}">${n}</div>
      <div style="font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:#5050a0;margin-top:4px;font-family:monospace">${l}</div>
    </div>`).join('')}
</div>
${sec('◫ インストール済みアプリ',apps,'App')}
${sec('🔧 ドライバー',drivers,'Driver')}
${sec('◧ スキャンファイル',files,'File')}
<div style="margin-top:36px;padding-top:16px;border-top:1px solid #1e1e3a;text-align:center;font-family:monospace;font-size:9px;color:#2a2a50;letter-spacing:2px">
WINDOWS UPGRADE REQUIREMENTS SCANNER (WURS) v2.1 — ${new Date().toISOString()} — FOR REFERENCE ONLY</div>
</body></html>`;
}
