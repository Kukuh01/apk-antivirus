// Di dalam file: electron/main.ts

// <-- 1. TAMBAHKAN 'ipcMain' dan 'dialog'
import { app, BrowserWindow, ipcMain, dialog } from 'electron' 
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ... (Blok path Anda biarkan sama)
process.env.APP_ROOT = path.join(__dirname, '..')
export const VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL']
export const MAIN_DIST = path.join(process.env.APP_ROOT, 'dist-electron')
export const RENDERER_DIST = path.join(process.env.APP_ROOT, 'dist')
process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL ? path.join(process.env.APP_ROOT, 'public') : RENDERER_DIST

let win: BrowserWindow | null

function createWindow() {
  win = new BrowserWindow({
    icon: path.join(process.env.VITE_PUBLIC, 'electron-vite.svg'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.mjs'),
      
      // <-- 2. TAMBAHKAN INI! Wajib agar preload.ts berfungsi
      contextIsolation: true, 
      nodeIntegration: false, // Praktik keamanan yang baik
    },
  })

  // ... (Blok win.webContents.on... biarkan sama)
  win.webContents.on('did-finish-load', () => {
    win?.webContents.send('main-process-message', (new Date).toLocaleString())
  })

  // ... (Blok win.loadURL... biarkan sama)
  if (VITE_DEV_SERVER_URL) {
    win.loadURL(VITE_DEV_SERVER_URL)
  } else {
    win.loadFile(path.join(RENDERER_DIST, 'index.html'))
  }
}

// ... (Blok app.on('window-all-closed') dan 'activate' biarkan sama)
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
    win = null
  }
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow()
  }
})

// <-- 3. TAMBAHKAN FUNGSI HANDLER INI
// Fungsi ini akan menangani logika dialog file
async function handleFileOpen() {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ['openFile'] // Hanya izinkan pilih satu file
  })
  if (canceled) {
    return null // Pengguna membatalkan
  } else {
    return filePaths[0] // Kembalikan path file
  }
}

// <-- 4. MODIFIKASI BLOK INI
// Ganti app.whenReady().then(createWindow) dengan ini:
app.whenReady().then(() => {
  // Daftarkan handler 'dialog:openFile' DULU
  ipcMain.handle('dialog:openFile', handleFileOpen)
  
  // Baru buat window
  createWindow()
})