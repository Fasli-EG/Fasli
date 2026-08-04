// main.js — نافذة سطح المكتب بتاعة فَصلي (Electron)
const { app, BrowserWindow } = require('electron');
const path = require('path');

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

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
