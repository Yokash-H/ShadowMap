const { app, BrowserWindow, globalShortcut, ipcMain, screen } = require('electron');
const path = require('path');
const { io } = require('socket.io-client');

let mainWindow;
let socket;

function createWindow() {
  const { width: screenWidth, height: screenHeight } = screen.getPrimaryDisplay().workAreaSize;

  mainWindow = new BrowserWindow({
    width: 450,
    height: 600,
    x: screenWidth - 480,
    y: Math.floor(screenHeight / 2 - 300),
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    show: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile('renderer/index.html');
}

function initSocket() {
  socket = io('http://127.0.0.1:5000', { reconnection: true });

  socket.on('connect', () => {
    console.log('✅ SOCKET CONNECTED TO BACKEND');
  });

  socket.on('context_update', (data) => {
    if (mainWindow) mainWindow.webContents.send('context-update', data);
  });

  socket.on('scan_result', (data) => {
    if (mainWindow) mainWindow.webContents.send('scan_result', data);
  });
}

app.whenReady().then(() => {
  createWindow();
  initSocket();

  globalShortcut.register('F4', () => {
    console.log('⌨️ F4 TRIGGERED');
    if (mainWindow) {
        // 1. Tell UI to show loading
        mainWindow.webContents.send('trigger-scan');
        // 2. Tell backend to start scan
        if (socket && socket.connected) {
            socket.emit('trigger_full_scan', {});
        }
    }
  });
});

app.on('will-quit', () => globalShortcut.unregisterAll());
ipcMain.on('close-window', () => mainWindow.hide());
ipcMain.on('minimize-window', () => mainWindow.minimize());
