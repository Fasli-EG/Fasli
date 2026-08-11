// preload.js — جسر آمن بين نافذة التطبيق (renderer) وتخزين النظام الدائم (main process)
// بيسمح لصفحات الويب العادية تستخدم window.electronStore بدون أي وصول مباشر لـ Node.js (أمان كامل)
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronStore', {
  get: (key) => ipcRenderer.invoke('store:get', key),
  set: (key, value) => ipcRenderer.invoke('store:set', key, value),
  remove: (key) => ipcRenderer.invoke('store:remove', key),
  clear: () => ipcRenderer.invoke('store:clear'),
  keys: () => ipcRenderer.invoke('store:keys'),
});

contextBridge.exposeInMainWorld('electronNotify', {
  // بيرجّع true/false هل الإشعارات مدعومة ومفعّلة على الجهاز ده
  isSupported: () => ipcRenderer.invoke('notify:isSupported'),
  show: (title, body) => ipcRenderer.invoke('notify:show', title, body),
});

contextBridge.exposeInMainWorld('electronAPI', {
  // ✅ بيجبر النافذة تاخد التركيز (focus) تاني على مستوى نظام التشغيل نفسه، مش بس مستوى الصفحة
  // مفيد بعد قفل أي نافذة منبثقة مخصصة، عشان نضمن إن لوحة المفاتيح والماوس يفضلوا شغّالين صح
  refocusWindow: () => ipcRenderer.invoke('window:refocus'),
});
