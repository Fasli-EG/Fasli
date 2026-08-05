// main.js — نافذة سطح المكتب بتاعة فَصلي (Electron)
const { app, BrowserWindow, ipcMain, Notification, session } = require('electron');
const path = require('path');
const Store = require('electron-store');

const store = new Store({ name: 'fasli-session' });

// ✅ مهم لويندوز: عشان إشعارات النظام تربط باسم وأيقونة التطبيق صح (من غير كده بتظهر باسم Electron العام)
app.setAppUserModelId('com.fasli.desktop');

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    icon: path.join(__dirname, 'icons', process.platform === 'win32' ? 'icon.ico' : process.platform === 'darwin' ? 'icon.icns' : 'icon-512.png'),
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  win.loadURL('https://fasli-eg.github.io/Fasli/login.html');

  win.webContents.setWindowOpenHandler(({ url }) => {
    require('electron').shell.openExternal(url);
    return { action: 'deny' };
  });
}

ipcMain.handle('store:get', (event, key) => store.get(key) ?? null);
ipcMain.handle('store:set', (event, key, value) => { store.set(key, value); return true; });
ipcMain.handle('store:remove', (event, key) => { store.delete(key); return true; });
ipcMain.handle('store:clear', () => { store.clear(); return true; });
ipcMain.handle('store:keys', () => Object.keys(store.store));

ipcMain.handle('notify:isSupported', () => Notification.isSupported());
ipcMain.handle('notify:show', (event, title, body) => {
  if (!Notification.isSupported()) return false;
  const iconPath = path.join(__dirname, 'icons', 'icon-512.png');
  const notification = new Notification({ title, body, icon: iconPath });
  notification.show();
  return true;
});

app.whenReady().then(() => {
  session.defaultSession.on('select-serial-port', (event, portList, webContents, callback) => {
    event.preventDefault();
    if (portList.length === 0) {
      callback('');
      return;
    }
    callback(portList[0].portId);
  });

  session.defaultSession.setPermissionCheckHandler((webContents, permission) => {
    if (permission === 'serial') return true;
    return false;
  });

  session.defaultSession.setDevicePermissionHandler((details) => {
    if (details.deviceType === 'serial') return true;
    return false;
  });

  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
