const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('shadowmap', {
  closeWindow: () => ipcRenderer.send('close-window'),
  minimizeWindow: () => ipcRenderer.send('minimize-window'),

  getShadowScore: async () => {
    const response = await fetch('http://localhost:5000/api/score/shadow');
    return await response.json();
  },

  getActiveUrl: () => ipcRenderer.invoke('get-active-url'),

  // WebSocket / Event Listeners
  onContextUpdate: (callback) => ipcRenderer.on('context-update', (event, data) => callback(data)),
  onScanResult: (callback) => ipcRenderer.on('scan_result', (event, data) => callback(data)),
  onThreatAlert: (callback) => ipcRenderer.on('threat_alert', (event, data) => callback(data)),

  // Legacy trigger support
  onTriggerScan: (callback) => ipcRenderer.on('trigger-scan', callback)
});
