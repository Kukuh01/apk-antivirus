// preload.mjs

// Gunakan 'import' karena ini file .mjs (ES Module)
import { contextBridge, ipcRenderer } from 'electron';

// --- 1. BLOK API FILE (YANG HILANG) ---
// Ini yang akan dipanggil oleh React (window.electronAPI.openFile)
contextBridge.exposeInMainWorld('electronAPI', {
  /**
   * Membuka dialog file native dan mengembalikan path file yang dipilih.
   * @returns {Promise<string | null>} Path file atau null jika dibatalkan.
   */
  openFile: () => ipcRenderer.invoke('dialog:openFile')
});
// --- AKHIR BLOK ---


// 2. Kode bridge 'ipcRenderer' bawaan Anda (bisa disimpan)
// Ini mengekspos window.ipcRenderer...
contextBridge.exposeInMainWorld("ipcRenderer", {
  on: (channel, listener) => {
    ipcRenderer.on(channel, (event, ...args) => listener(event, ...args));
  },
  off: (channel, ...omit) => {
    ipcRenderer.off(channel, ...omit);
  },
  send: (channel, ...omit) => {
    ipcRenderer.send(channel, ...omit);
  },
  invoke: (channel, ...omit) => {
    return ipcRenderer.invoke(channel, ...omit);
  }
});