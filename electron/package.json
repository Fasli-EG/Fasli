{
  "name": "fasli-desktop",
  "version": "1.0.0",
  "description": "فَصلي - إدارة الدروس الخصوصية (نسخة سطح المكتب)",
  "main": "main.js",
  "author": "فَصلي",
  "scripts": {
    "start": "electron .",
    "build:win": "electron-builder --win",
    "build:mac": "electron-builder --mac",
    "build:all": "electron-builder -mw"
  },
  "dependencies": {
    "electron-store": "^8.2.0"
  },
  "devDependencies": {
    "electron": "^31.0.0",
    "electron-builder": "^24.13.3"
  },
  "build": {
    "appId": "com.fasli.desktop",
    "productName": "فَصلي",
    "directories": { "output": "dist" },
    "files": ["main.js", "preload.js", "icons/**/*"],
    "win": {
      "target": "nsis",
      "icon": "icons/icon.ico"
    },
    "mac": {
      "target": "dmg",
      "icon": "icons/icon.icns"
    },
    "nsis": {
      "oneClick": false,
      "allowToChangeInstallationDirectory": true
    }
  }
}
