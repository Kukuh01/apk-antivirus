"use strict";
const electron = require("electron");
electron.contextBridge.exposeInMainWorld("electronAPI", {
  /**
   * Membuka dialog file native dan mengembalikan path file yang dipilih.
   * @returns {Promise<string | null>} Path file atau null jika dibatalkan.
   */
  openFile: () => electron.ipcRenderer.invoke("dialog:openFile")
});
electron.contextBridge.exposeInMainWorld("ipcRenderer", {
  on: (channel, listener) => {
    electron.ipcRenderer.on(channel, (event, ...args) => listener(event, ...args));
  },
  off: (channel, ...omit) => {
    electron.ipcRenderer.off(channel, ...omit);
  },
  send: (channel, ...omit) => {
    electron.ipcRenderer.send(channel, ...omit);
  },
  invoke: (channel, ...omit) => {
    return electron.ipcRenderer.invoke(channel, ...omit);
  }
});
