import { contextBridge, ipcRenderer } from 'electron';


contextBridge.exposeInMainWorld('electronAPI', {
  /**
   * Membuka dialog file native dan mengembalikan path file yang dipilih.
   * @returns {Promise<string | null>} Path file atau null jika dibatalkan.
   */
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  openFolder: () => ipcRenderer.invoke('dialog:openFolder')
});

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