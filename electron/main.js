// main.js — نافذة سطح المكتب بتاعة فَصلي (Electron)
const { app, BrowserWindow, ipcMain, Notification } = require('electron');
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
    autoHideMenuBar: true, // نخفي شريط القوائم العلوي (File, Edit...) عشان يبان زي برنامج حقيقي
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // ✅ مهم: غيّر الرابط ده لموقعك المنشور فعلياً (لازم HTTPS)
  win.loadURL('https://fasli-eg.github.io/Fasli/login.html');

  // لو عايز تفتح رابط خارجي (زي واتساب) في متصفح النظام بدل نافذة التطبيق
  win.webContents.setWindowOpenHandler(({ url }) => {
    require('electron').shell.openExternal(url);
    return { action: 'deny' };
  });
}

// ============================================
// تخزين دائم حقيقي (زي SharedPreferences بتاعة أندرويد) — بيفضل موجود حتى بعد إغلاق البرنامج بالكامل
// ============================================
ipcMain.handle('store:get', (event, key) => store.get(key) ?? null);
ipcMain.handle('store:set', (event, key, value) => { store.set(key, value); return true; });
ipcMain.handle('store:remove', (event, key) => { store.delete(key); return true; });
ipcMain.handle('store:clear', () => { store.clear(); return true; });
ipcMain.handle('store:keys', () => Object.keys(store.store));

// ============================================
// إشعارات نظام حقيقية (بتظهر في درج إشعارات ويندوز/ماك زي أي برنامج تاني)
// ============================================
ipcMain.handle('notify:isSupported', () => Notification.isSupported());
ipcMain.handle('notify:show', (event, title, body) => {
  if (!Notification.isSupported()) return false;
  const iconPath = path.join(__dirname, 'icons', 'icon-512.png');
  const notification = new Notification({ title, body, icon: iconPath });
  notification.show();
  return true;
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
