#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <DNSServer.h>

// =========================================================
// ⚙️ إعدادات الشبكة ونظام فَصلي
// =========================================================
String wifi_ssid = "";
String wifi_password = "";
const char* CLIENT_ID = "S_1";
const char* SUPABASE_URL = "https://yxkyxxzcnxpxefodfxnl.supabase.co";
const char* ANON_KEY     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl4a3l4eHpjbnhweGVmb2RmeG5sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ3MTY0MTEsImV4cCI6MjEwMDI5MjQxMX0.oTWvUOrR7DBnhWQF7ym6PNRlucfsESSJovPhnkqvNZc";
const char* DEVICE_SECRET = "9dea4d628409577f207043e6e0ce70a3";

// =========================================================
// 📶 إعدادات وضع نقطة الوصول (Access Point) وصفحة الإعداد
// =========================================================
const char* AP_SSID_PREFIX = "Fasli-Setup";
const char* AP_PASSWORD = "fasli1234";
const byte DNS_PORT = 53;
DNSServer dnsServer;
WebServer webServer(80);
bool ap_mode_active = false;

int wrongCodeAttempts = 0;
unsigned long lockoutUntil = 0;
const int MAX_WRONG_ATTEMPTS = 5;
const unsigned long LOCKOUT_DURATION = 120000;

unsigned long lastBackgroundRetry = 0;
const unsigned long BACKGROUND_RETRY_INTERVAL = 30000;

// =========================================================
// 🔌 إعدادات الدبابيس
// =========================================================
// ✅ (طلب دفعة 45) إعادة تعريف استخدامات اللمبات كلها:
//   LED_READY (13) = "لمبة الاستعداد" — ثابتة لما النت+السيرفر تمام، وميض مستمر غير ذلك
//   LED_BLUE  (12) = وضع "تسجيل الحضور" مفعّل (ثابتة) — وبيتحول مؤقتاً لمؤشر "وضع الإعداد
//                    (Access Point) شغّال" لما الجهاز يبقى في وضع الإعداد
//   LED_GREEN (14) = وضع "تسجيل مدفوعات الأشهر" مفعّل (ثابتة)
//   LED_RED   (27) = وضع "سداد المذكرات" مفعّل (ثابتة)
//   BUZZER    (15) = بيبة قصيرة عند قراءة أي كارت، بيبة نجاح واحدة / بيبتين فشل بعد رد
//                    السيرفر، وإنذار دوري (3 بيبات) طول ما فيه انقطاع في الشبكة أو السيرفر
#define SS_PIN    5
#define RST_PIN   4
#define LED_READY 13
#define LED_GREEN 14
#define LED_RED   27
#define LED_BLUE  12
#define BUZZER    15

// =========================================================
// 📦 المتغيرات العامة
// =========================================================
MFRC522 mfrc522(SS_PIN, RST_PIN);
QueueHandle_t cardQueue;

struct CardData {
  char uid[16];
};

bool wifi_connected = false;
bool server_online = false;
unsigned long lastPingTime = 0;
const unsigned long PING_INTERVAL = 5000;
bool lastStatusSent = false;

// ✅ أوضاع القارئ الحالية (بيتحدثوا من fetchDeviceModeStatus جوه modeStatusTask المستقلة)
bool modeAttendance = false;
bool modePayment = false;
bool modeBookPayment = false;
unsigned long lastModeStatusPoll = 0;
// ✅ (طلب متابعة: "الاستجابة للتفعيل بطيئة") كانت 15 ثانية وبتحصل جوه pingTask نفسها (يعني
// فعلياً كل 15 ثانية بالظبط لأنها كانت مربوطة بدورة الـ Ping كل 5 ثواني). بقت تاسك منفصلة
// (modeStatusTask) بفاصل زمني قصير جداً (2 ثانية) عشان تفعيل/تغيير أي وضع من لوحة التحكم
// (حضور/دفع/مذكرة/فتح القارئ لمسح كارت تسجيل) ينعكس على الجهاز شبه فوري
const unsigned long MODE_STATUS_POLL_INTERVAL = 2000;

// ✅ (طلب متابعة) هل القارئ مفعّل فعلياً من لوحة التحكم دلوقتي؟ — لو false، هوائي RFID
// بيتقفل تماماً (مفيش مجال كهرومغناطيسي خالص) فمفيش أي كارت ممكن يتقرا أصلاً، مش مجرد
// تجاهل بالسوفت وير. الافتراضي false (آمن) لحد ما نتأكد من السيرفر إنه مفعّل فعلاً
bool readerEnabled = false;
bool cardReaderAntennaOn = false; // الحالة الفعلية الحالية لهوائي RFID (لتفادي تكرار نفس الأمر)

// ✅ حالة وميض لمبة الاستعداد (غير مسدودة/non-blocking عشان ماتوقفش قراءة الكروت)
unsigned long lastStandbyToggle = 0;
bool standbyToggleState = false;
const unsigned long STANDBY_FLASH_INTERVAL = 350;

// =========================================================
// 🔔 دوال البيب (البازر) — بيب قصير للقراءة، نغمة نجاح/فشل، إنذار انقطاع الشبكة
// =========================================================
void beepPulse(int ms) {
  digitalWrite(BUZZER, HIGH);
  delay(ms);
  digitalWrite(BUZZER, LOW);
}

// ✅ بيب قصير فوري لحظة قراءة أي كارت فعلياً (بغض النظر عن نتيجة التسجيل لسه)
void beepCardRead() {
  beepPulse(50);
}

// ✅ بيبة واحدة قصيرة = نجح تسجيل العملية فعلياً
void beepSuccess() {
  beepPulse(120);
}

// ✅ بيبتين قصار = فشلت العملية (مكرر / غير مسجل / خطأ سيرفر / غير مصرح... إلخ)
void beepFailure() {
  beepPulse(90);
  delay(90);
  beepPulse(90);
}

// ✅ إنذار دوري (3 بيبات سريعة) — بينادى من pingTask كل PING_INTERVAL طول ما الجهاز
// مش متصل بالكامل (لا واي فاي أو لا سيرفر)، فيفضل يتكرر لحد ما الاتصال يرجع
void beepNetworkAlarm() {
  for (int i = 0; i < 3; i++) {
    beepPulse(70);
    delay(70);
  }
}

// =========================================================
// 💡 لمبة الاستعداد — ثابتة لما الاتصال بالواي فاي والسيرفر تمام، وميض مستمر غير كده.
// non-blocking عشان تتنادى كل دورة loop() من غير ما توقف قراءة الكروت
// =========================================================
void updateStandbyLed() {
  bool fullyOnline = wifi_connected && server_online;
  if (fullyOnline) {
    digitalWrite(LED_READY, HIGH);
    standbyToggleState = true;
    return;
  }
  if (millis() - lastStandbyToggle >= STANDBY_FLASH_INTERVAL) {
    lastStandbyToggle = millis();
    standbyToggleState = !standbyToggleState;
    digitalWrite(LED_READY, standbyToggleState ? HIGH : LOW);
  }
}

// =========================================================
// 💡 لمبات الأوضاع الثلاثة (حضور 12 / مدفوعات 14 / مذكرات 27) — كل واحدة ثابتة لو
// وضعها مفعّل دلوقتي، وإلا مطفية. لمبة 12 محجوزة لمؤشر وضع الإعداد (AP) طول ما هو شغّال
// =========================================================
void updateModeLeds() {
  if (ap_mode_active) return; // مؤشر AP بياخد أولوية على لمبة 12 طول ما هو شغّال
  digitalWrite(LED_BLUE, modeAttendance ? HIGH : LOW);
  digitalWrite(LED_GREEN, modePayment ? HIGH : LOW);
  digitalWrite(LED_RED, modeBookPayment ? HIGH : LOW);
}

// =========================================================
// 🔒 (طلب متابعة) تشغيل/تقفيل هوائي RFID فعلياً حسب حالة تفعيل القارئ من لوحة التحكم —
// لو القارئ متوقف (readerEnabled = false)، الهوائي بيتقفل تماماً فمفيش أي كارت بيتقرا خالص،
// مش مجرد تجاهل النتيجة بعد القراءة. بتتنادى بعد كل استعلام حالة ناجح من fetchDeviceModeStatus()
// =========================================================
void updateReaderAntenna() {
  if (ap_mode_active) return; // وضع الإعداد بيتحكم في الهوائي لوحده (مقفول طول ما هو شغّال)
  if (readerEnabled && !cardReaderAntennaOn) {
    mfrc522.PCD_AntennaOn();
    cardReaderAntennaOn = true;
    Serial.println("📡 القارئ اتفعّل من لوحة التحكم — هوائي RFID اشتغل، بقى ممكن يقرا كروت.");
  } else if (!readerEnabled && cardReaderAntennaOn) {
    mfrc522.PCD_AntennaOff();
    cardReaderAntennaOn = false;
    Serial.println("🔒 القارئ متوقف من لوحة التحكم — هوائي RFID اتقفل تماماً، مفيش أي كارت هيتقرا.");
  }
}

// =========================================================
// 📤 إرسال الحالة عبر Serial للصفحة
// =========================================================
void sendStatus(String status) {
  Serial.println("STATUS:" + status);
}

// =========================================================
// 📶 تحميل إعدادات الواي فاي
// =========================================================
bool loadWiFiConfig() {
  if (!SPIFFS.begin(true)) {
    Serial.println("❌ فشل تحميل SPIFFS");
    return false;
  }
  if (!SPIFFS.exists("/wifi.json")) {
    Serial.println("📄 ملف الإعدادات غير موجود");
    return false;
  }
  File file = SPIFFS.open("/wifi.json", "r");
  if (!file) {
    Serial.println("❌ فشل فتح ملف الإعدادات");
    return false;
  }
  StaticJsonDocument<200> doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  if (error) {
    Serial.println("❌ خطأ في قراءة ملف الإعدادات");
    return false;
  }
  wifi_ssid = doc["ssid"] | "";
  wifi_password = doc["password"] | "";
  Serial.println("✅ تم تحميل الإعدادات:");
  Serial.println("   SSID: " + wifi_ssid);
  Serial.println("   PASS: " + wifi_password);
  return true;
}

// =========================================================
// 💾 حفظ إعدادات الواي فاي
// =========================================================
bool saveWiFiConfig(String ssid, String password) {
  if (!SPIFFS.begin(true)) {
    Serial.println("❌ فشل تحميل SPIFFS");
    return false;
  }
  File file = SPIFFS.open("/wifi.json", "w");
  if (!file) {
    Serial.println("❌ فشل فتح ملف الإعدادات للكتابة");
    return false;
  }
  StaticJsonDocument<200> doc;
  doc["ssid"] = ssid;
  doc["password"] = password;
  if (serializeJson(doc, file) == 0) {
    Serial.println("❌ فشل كتابة ملف الإعدادات");
    file.close();
    return false;
  }
  file.close();
  Serial.println("✅ تم حفظ الإعدادات");
  Serial.println("   SSID: " + ssid);
  Serial.println("   PASS: " + password);
  wifi_ssid = ssid;
  wifi_password = password;
  return true;
}

// =========================================================
// 📶 الاتصال بالواي فاي
// =========================================================
void connectWiFi() {
  if (wifi_ssid.length() == 0) {
    Serial.println("⚠️ لا توجد إعدادات واي فاي");
    return;
  }
  Serial.print("📶 جاري الاتصال بـ " + wifi_ssid + "...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(wifi_ssid.c_str(), wifi_password.c_str());
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    // ✅ لسه بنوصل — لمبة الاستعداد بتومض (نفس معنى "مفيش اتصال تمام لسه")
    digitalWrite(LED_READY, !digitalRead(LED_READY));
    delay(500);
    Serial.print(".");
    attempts++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    wifi_connected = true;
    Serial.println("\n✅ تم الاتصال! IP: " + WiFi.localIP().toString());
    sendStatus("WIFI_CONNECTED");

    // ✅ (طلب متابعة) الهوائي بيفضل مقفول (الوضع الآمن الافتراضي) لحد ما نسأل السيرفر فعلياً
    // هل القارئ مفعّل ولا لأ — مش بنشغّله أوتوماتيك هنا زي الأول. الاستعلام ده بيحصل فوراً
    // (مش هننتظر أول Poll دوري بعد 15 ثانية)، وهو اللي بيقرر الهوائي يتفتح ولا يفضل مقفول
    fetchDeviceModeStatus();
    lastModeStatusPoll = millis();
  } else {
    wifi_connected = false;
    Serial.println("\n❌ فشل الاتصال");
    sendStatus("WIFI_FAILED");
  }
  // ✅ لمبة الاستعداد نفسها بتتحدث تلقائياً من updateStandbyLed() في loop() —
  // مفيش داعي نحددها هنا يدوياً (بتفضل تومض لحد ما wifi_connected و server_online
  // يبقوا الاتنين true فعلاً)
}

// =========================================================
// 📡 وضع نقطة الوصول (Access Point) + صفحة الإعداد (Captive Portal)
// =========================================================

const char* SETUP_PAGE_HTML = R"HTMLPAGE(
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>إعداد جهاز فَصلي</title>
  <style>
    body { font-family: Tahoma, Arial, sans-serif; background: #0B1C33; color: #fff; margin: 0; padding: 24px 16px; direction: rtl; }
    .card { max-width: 420px; margin: 0 auto; background: rgba(255,255,255,0.06); border-radius: 16px; padding: 24px; border: 1px solid rgba(255,255,255,0.1); }
    h1 { font-size: 20px; text-align: center; margin: 0 0 6px; }
    p.sub { text-align: center; font-size: 13px; color: rgba(255,255,255,0.65); margin: 0 0 20px; }
    label { display: block; font-size: 13px; font-weight: bold; margin: 14px 0 6px; }
    input { width: 100%; padding: 11px 12px; border-radius: 10px; border: 1.5px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.08); color: #fff; font-size: 14px; box-sizing: border-box; }
    input::placeholder { color: rgba(255,255,255,0.4); }
    button { width: 100%; margin-top: 22px; padding: 13px; border: none; border-radius: 10px; background: #F2B705; color: #0B1C33; font-weight: bold; font-size: 15px; cursor: pointer; }
    .hint { font-size: 11.5px; color: rgba(255,255,255,0.5); margin-top: 6px; }
    .msg { text-align: center; margin-top: 16px; font-size: 13px; padding: 10px; border-radius: 8px; display: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>📡 إعداد جهاز فَصلي</h1>
    <p class="sub">أدخل بيانات شبكة الواي فاي وكود المدرس عشان الجهاز يشتغل</p>
    <form id="setupForm">
      <label>كود المدرس (Client ID)</label>
      <input type="text" id="clientId" placeholder="مثال: teacher_001" required>
      <div class="hint">تلاقيه في صفحة "التواصل والنُسخ" في حسابك على فَصلي (هو نفسه اسم المستخدم بتاعك)</div>

      <label>اسم شبكة الواي فاي (SSID)</label>
      <input type="text" id="ssid" placeholder="اسم الشبكة" required>

      <label>كلمة مرور الشبكة</label>
      <input type="password" id="password" placeholder="كلمة المرور">
      <div class="hint">اسيبها فاضية لو الشبكة مفتوحة بدون كلمة مرور</div>

      <button type="submit">💾 حفظ وإعادة التشغيل</button>
      <div class="msg" id="msgBox"></div>
    </form>
  </div>
  <script>
    document.getElementById('setupForm').addEventListener('submit', function(e) {
      e.preventDefault();
      var msgBox = document.getElementById('msgBox');
      msgBox.style.display = 'block';
      msgBox.style.background = 'rgba(255,255,255,0.1)';
      msgBox.textContent = '⏳ جاري الحفظ...';

      var params = new URLSearchParams();
      params.append('clientId', document.getElementById('clientId').value.trim());
      params.append('ssid', document.getElementById('ssid').value.trim());
      params.append('password', document.getElementById('password').value);

      fetch('/save', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString() })
        .then(function(r) { return r.text().then(function(txt) { return { ok: r.ok, status: r.status, text: txt }; }); })
        .then(function(result) {
          if (result.ok) {
            msgBox.style.background = '#F2B70522';
            msgBox.textContent = '✅ اتحفظ! الجهاز بيعيد التشغيل دلوقتي، وهيحاول يتصل بالشبكة الجديدة...';
          } else if (result.status === 403) {
            msgBox.style.background = '#e5484d33';
            msgBox.textContent = '❌ كود المدرس غلط. الجهاز ده مش تابع للكود اللي كتبتيه.';
          } else {
            msgBox.style.background = '#e5484d33';
            msgBox.textContent = '❌ ' + (result.text || 'حصل خطأ، جربي تاني');
          }
        })
        .catch(function() {
          msgBox.style.background = '#e5484d33';
          msgBox.textContent = '❌ تعذر الاتصال بالجهاز، جربي تاني';
        });
    });
  </script>
</body>
</html>
)HTMLPAGE";

void handleRoot() {
  webServer.send(200, "text/html", SETUP_PAGE_HTML);
}

void handleSave() {
  if (millis() < lockoutUntil) {
    int secondsLeft = (lockoutUntil - millis()) / 1000;
    webServer.send(429, "text/plain", "⏳ محاولات كتير غلط. استنّي " + String(secondsLeft) + " ثانية وجرّبي تاني.");
    return;
  }

  String enteredClientId = webServer.arg("clientId");
  String newSsid = webServer.arg("ssid");
  String newPassword = webServer.arg("password");

  enteredClientId.trim();
  newSsid.trim();

  if (enteredClientId.length() == 0 || newSsid.length() == 0) {
    webServer.send(400, "text/plain", "كود المدرس واسم الشبكة مطلوبين");
    return;
  }

  if (enteredClientId != String(CLIENT_ID)) {
    wrongCodeAttempts++;
    Serial.println("⛔ محاولة تغيير واي فاي بكود مدرس غلط: " + enteredClientId + " (محاولة رقم " + String(wrongCodeAttempts) + ")");
    // ✅ (طلب دفعة 45) اللمبات مش متاحة نستخدمها هنا (14/27 محجوزين لمؤشرات الأوضاع)،
    // بيب فشل بس بدل الوميض الأحمر القديم
    beepFailure();

    if (wrongCodeAttempts >= MAX_WRONG_ATTEMPTS) {
      lockoutUntil = millis() + LOCKOUT_DURATION;
      wrongCodeAttempts = 0;
      webServer.send(429, "text/plain", "⛔ محاولات غلط كتير. اتقفل الإعداد لمدة دقيقتين.");
    } else {
      webServer.send(403, "text/plain", "❌ كود المدرس غير صحيح. الجهاز ده مخصص لمدرس تاني.");
    }
    return;
  }

  wrongCodeAttempts = 0;
  saveWiFiConfig(newSsid, newPassword);
  webServer.send(200, "text/plain", "تم الحفظ، الجهاز بيعيد التشغيل...");

  delay(1500);
  ESP.restart();
}

void handleNotFound() {
  webServer.sendHeader("Location", "/", true);
  webServer.send(302, "text/plain", "");
}

void startCaptivePortal() {
  ap_mode_active = true;

  // 🛑 إيقاف هوائي RFID لتقليل التداخل مع الـ Wi-Fi في وضع AP
  mfrc522.PCD_AntennaOff();
  cardReaderAntennaOn = false; // ✅ نحدّث المتغيّر المتابع للحالة الفعلية عشان يفضل مطابق للواقع
  Serial.println("📡 تم إيقاف هوائي RFID (وضع الإعداد).");

  // 📶 رفع قدرة إرسال الـ Wi-Fi إلى أقصى حد (19.5 dBm) لتحسين التغطية رغم التداخل
  WiFi.setTxPower(WIFI_POWER_19_5dBm);
  Serial.println("📶 تم رفع قدرة إرسال الـ Wi-Fi إلى 19.5 dBm.");

  WiFi.disconnect(true, true);
  delay(200);
  WiFi.mode(WIFI_AP_STA);
  delay(200);

  String apName = String(AP_SSID_PREFIX);
  bool apStarted = WiFi.softAP(apName.c_str(), AP_PASSWORD);
  delay(200);

  IPAddress apIP = WiFi.softAPIP();

  if (apStarted) {
    Serial.println("✅ WiFi.softAP() نجحت");
  } else {
    Serial.println("❌ WiFi.softAP() فشلت! (جرّبي إعادة تشغيل الجهاز، أو فيه مشكلة هاردوير/ذاكرة)");
  }
  Serial.println("   عنوان الـIP بتاع نقطة الوصول: " + apIP.toString());
  if (apIP.toString() == "0.0.0.0") {
    Serial.println("⚠️ تحذير: IP طلع 0.0.0.0 — مؤشر قوي إن نقطة الوصول مش شغّالة فعلياً رغم إن الكود اشتغل");
  }

  dnsServer.start(DNS_PORT, "*", apIP);

  webServer.on("/", handleRoot);
  webServer.on("/save", HTTP_POST, handleSave);
  webServer.onNotFound(handleNotFound);
  webServer.begin();

  Serial.println("\n📡 === وضع الإعداد مفعّل ===");
  Serial.println("   اسم الشبكة: " + apName);
  Serial.println("   كلمة المرور: " + String(AP_PASSWORD));
  Serial.println("   العنوان: http://" + apIP.toString());
  Serial.println("   اتصلي بالشبكة دي من موبايلك، وصفحة الإعداد هتفتح لوحدها");
  sendStatus("AP_MODE_ACTIVE:" + apName);

  // ✅ (طلب دفعة 45، بند 6) لمبة رجل 12 بتنور ثابتة عشان تبين إن الجهاز في وضع الإعداد —
  // نفس اللمبة دي في التشغيل العادي بتبين "وضع تسجيل الحضور مفعّل"، لكن وضع الإعداد
  // بياخد الأولوية عليها طول ما هو شغّال (updateModeLeds() بترجع فوراً لو ap_mode_active)
  digitalWrite(LED_BLUE, HIGH);
}

void tryBackgroundReconnect() {
  if (wifi_ssid.length() == 0) return;

  Serial.println("🔄 محاولة اتصال في الخلفية بالشبكة المحفوظة...");
  WiFi.begin(wifi_ssid.c_str(), wifi_password.c_str());

  unsigned long startAttempt = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < 8000) {
    delay(200);
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("✅ رجع الاتصال بالشبكة القديمة! جاري إغلاق وضع الإعداد...");
    dnsServer.stop();
    webServer.close();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    ap_mode_active = false;
    wifi_connected = true;
    // ✅ لمبة 12 ترجع لمعناها العادي (وضع الحضور) بدل مؤشر AP — هتتظبط لقيمتها الحقيقية فوراً
    digitalWrite(LED_BLUE, LOW);
    sendStatus("WIFI_RECONNECTED_AUTO");

    // ✅ (طلب متابعة) الهوائي بيفضل مقفول لحد ما نسأل السيرفر فوراً هل القارئ مفعّل فعلياً
    fetchDeviceModeStatus();
    lastModeStatusPoll = millis();
  } else {
    Serial.println("⏳ لسه مفيش اتصال، هنجرّب تاني بعد شوية (وضع الإعداد لسه شغّال)");
  }
}

// =========================================================
// 🔁 النواة 1: قراءة الكروت
// =========================================================
void loop() {
  // ✅ لمبة الاستعداد بتتحدث كل دورة (non-blocking) بغض النظر عن أي حاجة تانية بتحصل
  updateStandbyLed();

  if (ap_mode_active) {
    dnsServer.processNextRequest();
    webServer.handleClient();

    if (millis() - lastBackgroundRetry > BACKGROUND_RETRY_INTERVAL) {
      lastBackgroundRetry = millis();
      tryBackgroundReconnect();
    }

    delay(2);
    return;
  }

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    loopSerial();
    delay(10);
    return;
  }

  CardData scannedCard;
  String uidString = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) uidString += "0";
    uidString += String(mfrc522.uid.uidByte[i], HEX);
  }
  uidString.toUpperCase();
  uidString.toCharArray(scannedCard.uid, 16);

  Serial.println("⚡ كارت: " + uidString);

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  // ✅ (طلب دفعة 45، بند 5) بيب قصير فوري لحظة قراءة أي كارت — بغض النظر عن نتيجة
  // التسجيل لسه (النتيجة النهائية بتتبين لاحقاً ببيبة نجاح/فشل من uploadTask)
  if (xQueueSend(cardQueue, &scannedCard, 0) == pdPASS) {
    beepCardRead();
  } else {
    // ✅ الطابور ممتلئ — فشل حقيقي، بيبة فشل بدل الوميض الأحمر القديم
    beepFailure();
  }
  loopSerial();
  delay(10);
}

// =========================================================
// 🌐 رفع البيانات (النواة 0)
// =========================================================
void uploadTask(void * pvParameters) {
  CardData cardToUpload;
  while (true) {
    if (ap_mode_active) {
      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }
    if (xQueueReceive(cardQueue, &cardToUpload, portMAX_DELAY) == pdPASS) {
      String uid = String(cardToUpload.uid);
      if (WiFi.status() != WL_CONNECTED) {
        connectWiFi();
        if (WiFi.status() != WL_CONNECTED) {
          xQueueSend(cardQueue, &cardToUpload, 0);
          vTaskDelay(pdMS_TO_TICKS(2000));
          continue;
        }
      }
      sendToRFIDScans(uid);
      recordAttendance(uid);
      vTaskDelay(pdMS_TO_TICKS(500));
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// =========================================================
// 📡 إرسال UID (عن طريق دالة موثّقة بمفتاح الجهاز، مش كتابة مباشرة في الجدول)
// =========================================================
void sendToRFIDScans(String uid) {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  String url = String(SUPABASE_URL) + "/functions/v1/submit-rfid-scan";
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);

  StaticJsonDocument<150> doc;
  doc["uid"] = uid;
  doc["clientId"] = CLIENT_ID;
  doc["deviceSecret"] = DEVICE_SECRET;
  String payload;
  serializeJson(doc, payload);

  int httpCode = http.POST(payload);
  // ✅ (طلب دفعة 45) دي مجرد خطوة تسجيل مساعدة (submit-rfid-scan) مش النتيجة الفعلية
  // لتسجيل الحضور — النتيجة الحقيقية (نجاح/فشل) بتتبين من recordAttendance() تحت،
  // فمفيش بيب أو لمبة هنا خالص عشان نتجنب ازدواج البيب لنفس الكارت
  if (httpCode == 200) {
    Serial.println("✅ تم إرسال UID (موثّق)");
  } else if (httpCode == 401) {
    Serial.println("⛔ مفتاح الجهاز غلط أو الحساب معطّل - راجع DEVICE_SECRET");
  } else {
    Serial.println("❌ فشل إرسال UID: " + String(httpCode));
  }
  http.end();
}

// =========================================================
// 📝 تسجيل الحضور (موثّق بنفس مفتاح الجهاز)
// =========================================================
void recordAttendance(String uid) {
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  String url = String(SUPABASE_URL) + "/functions/v1/record-attendance";
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);

  StaticJsonDocument<200> doc;
  doc["clientId"] = CLIENT_ID;
  doc["uid"] = uid;
  doc["secret"] = DEVICE_SECRET;
  doc["manual"] = false;
  String payload;
  serializeJson(doc, payload);

  int httpCode = http.POST(payload);
  String response = http.getString();

  // ✅ (طلب دفعة 45، بند 5) بيبة نجاح واحدة = اتسجل شيء فعلاً، بيبتين فشل = أي حاجة تانية
  // (مكرر / كارت غير مسجل / غير مصرح / خطأ سيرفر). اللمبات مش بتشارك في النتيجة دي
  // خالص دلوقتي — كل اللمبات التلاتة (12/14/27) محجوزة لمؤشرات الأوضاع الثابتة
  if (httpCode == 200) {
    if (response.indexOf("DUPLICATE_IGNORE") > -1) {
      Serial.println("⚠️ كارت مكرر (مسجل حضور مسبقاً)");
      beepFailure();
    } else {
      Serial.println("✅ تم تسجيل الحضور");
      beepSuccess();
    }
  } else if (httpCode == 401) {
    Serial.println("⛔ مفتاح الجهاز غلط أو الحساب معطّل - راجع DEVICE_SECRET");
    beepFailure();
  } else if (httpCode == 404) {
    if (response.indexOf("UNREGISTERED") > -1) {
      Serial.println("⚠️ كارت غير مسجل");
    } else {
      Serial.println("⚠️ attendance 404: " + response);
    }
    beepFailure();
  } else {
    Serial.println("⚠️ attendance error: " + String(httpCode) + " - " + response);
    beepFailure();
  }
  http.end();
}

// =========================================================
// 📡 استعلام دوري عن الأوضاع الحالية للقارئ (حضور/مدفوعات/مذكرات) — عشان نضيء
// لمبة الوضع الصحيحة على جسم الجهاز. بيتنادى من pingTask كل MODE_STATUS_POLL_INTERVAL
// =========================================================
void fetchDeviceModeStatus() {
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  String url = String(SUPABASE_URL) + "/functions/v1/card-action-mode";
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(4000);

  StaticJsonDocument<150> doc;
  doc["action"] = "get";
  doc["clientId"] = CLIENT_ID;
  doc["secret"] = DEVICE_SECRET;
  String payload;
  serializeJson(doc, payload);

  int httpCode = http.POST(payload);
  if (httpCode == 200) {
    String response = http.getString();
    StaticJsonDocument<512> resDoc;
    DeserializationError err = deserializeJson(resDoc, response);
    if (!err && resDoc["success"] == true) {
      modeAttendance = false;
      modePayment = false;
      modeBookPayment = false;
      // ✅ (طلب متابعة) نحدّث حالة تفعيل القارئ الحقيقية، وبناءً عليها نفتح/نقفل الهوائي فعلياً
      readerEnabled = resDoc["readerEnabled"] == true;
      if (readerEnabled) {
        JsonArray modes = resDoc["modes"].as<JsonArray>();
        for (JsonVariant m : modes) {
          String modeStr = m.as<String>();
          if (modeStr == "attendance") modeAttendance = true;
          else if (modeStr == "payment") modePayment = true;
          else if (modeStr == "book_payment") modeBookPayment = true;
        }
      }
      updateModeLeds();
      updateReaderAntenna();
    } else {
      Serial.println("⚠️ فشل قراءة حالة الأوضاع: " + response);
    }
  } else {
    Serial.println("⚠️ فشل استعلام حالة الأوضاع: " + String(httpCode));
  }
  http.end();
}

// =========================================================
// 📡 نبضات القلب (Ping) مع إرسال الحالة
// =========================================================
void pingTask(void * pvParameters) {
  while (true) {
    vTaskDelay(pdMS_TO_TICKS(PING_INTERVAL));

    if (ap_mode_active) continue;

    if (WiFi.status() == WL_CONNECTED) {
      HTTPClient http;
      String url = String(SUPABASE_URL) + "/rest/v1/";
      http.begin(url);
      http.addHeader("Authorization", "Bearer " + String(ANON_KEY));
      http.addHeader("apikey", String(ANON_KEY));
      http.setTimeout(3000);
      int code = http.GET();

      if (code > 0) {
        server_online = true;
        if (!lastStatusSent) {
          sendStatus("SERVER_ONLINE");
          lastStatusSent = true;
        }
      } else {
        server_online = false;
        // ✅ (طلب دفعة 45، بند 5) إنذار البازر الدوري — بيتكرر كل دورة Ping (PING_INTERVAL)
        // طول ما السيرفر مش راد، لحد ما الاتصال يرجع تمام
        beepNetworkAlarm();
        if (lastStatusSent) {
          sendStatus("SERVER_OFFLINE");
          lastStatusSent = false;
        }
      }
      http.end();
    } else {
      wifi_connected = false;
      server_online = false;
      // ✅ نفس إنذار انقطاع الشبكة، بيتكرر كل دورة طول ما الواي فاي مش متصل
      beepNetworkAlarm();
      if (lastStatusSent) {
        sendStatus("WIFI_DISCONNECTED");
        lastStatusSent = false;
      }
    }
  }
}

// =========================================================
// 📡 (طلب متابعة) استعلام حالة الأوضاع فى تاسك مستقلة بفاصل قصير (MODE_STATUS_POLL_INTERVAL)
// — منفصلة عن pingTask تماماً عشان تفعيل/تغيير الوضع من لوحة التحكم ينعكس على الجهاز بسرعة،
// من غير ما يبقى مربوط بدورة الـ Ping الأبطأ (PING_INTERVAL)
// =========================================================
void modeStatusTask(void * pvParameters) {
  while (true) {
    vTaskDelay(pdMS_TO_TICKS(MODE_STATUS_POLL_INTERVAL));
    if (ap_mode_active) continue;
    if (WiFi.status() != WL_CONNECTED) continue;
    fetchDeviceModeStatus();
    lastModeStatusPoll = millis();
  }
}

// =========================================================
// 💻 معالجة الأوامر التسلسلية (لسه موجودة كخيار احتياطي/تشخيصي)
// =========================================================
void processSerialCommand(String command) {
  command.trim();

  if (command.startsWith("GET_CONFIG")) {
    Serial.println("=== CONFIG_START ===");
    Serial.println("SSID:" + wifi_ssid);
    Serial.println("PASS:" + wifi_password);
    Serial.println("=== CONFIG_END ===");
    return;
  }

  if (command.startsWith("SET_CONFIG:")) {
    String data = command.substring(11);
    int separator = data.indexOf('|');
    if (separator == -1) {
      Serial.println("❌ صيغة غير صحيحة. استخدم: SET_CONFIG:SSID|PASSWORD");
      return;
    }
    String newSSID = data.substring(0, separator);
    String newPassword = data.substring(separator + 1);
    if (newSSID.length() == 0) {
      Serial.println("❌ SSID لا يمكن أن يكون فارغاً");
      return;
    }
    if (saveWiFiConfig(newSSID, newPassword)) {
      Serial.println("✅ تم حفظ الإعدادات. جاري إعادة التشغيل...");
      delay(500);
      ESP.restart();
    }
    return;
  }

  if (command.startsWith("PING")) {
    Serial.println("PONG");
    sendStatus("PONG_RESPONSE");
    return;
  }

  if (command.startsWith("RESET_CONFIG")) {
    if (SPIFFS.begin(true)) {
      if (SPIFFS.remove("/wifi.json")) {
        Serial.println("✅ تم حذف الإعدادات. أعد تشغيل الجهاز.");
        wifi_ssid = "";
        wifi_password = "";
      } else {
        Serial.println("❌ فشل حذف الإعدادات");
      }
    }
    return;
  }

  Serial.println("❓ أمر غير معروف: " + command);
  Serial.println("   الأوامر: GET_CONFIG, SET_CONFIG:SSID|PASS, RESET_CONFIG, PING");
}

// =========================================================
// 🔄 حلقة قراءة الأوامر التسلسلية
// =========================================================
void loopSerial() {
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    processSerialCommand(command);
  }
}

// =========================================================
// 🚀 دالة التشغيل الأولى
// =========================================================
void setup() {
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
  // ✅ (طلب متابعة) الوضع الافتراضي الآمن عند التشغيل: القارئ مقفول تماماً (هوائي RFID مطفي)
  // لحد ما نتأكد من السيرفر إنه مفعّل فعلياً من لوحة التحكم — منعاً لقراءة أي كارت قبل ما
  // يتحدد وضع القارئ (attendance/payment/book_payment) بشكل صريح
  mfrc522.PCD_AntennaOff();
  cardReaderAntennaOn = false;

  pinMode(LED_READY, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_BLUE, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  digitalWrite(LED_READY, LOW);
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED, LOW);
  digitalWrite(LED_BLUE, LOW);
  digitalWrite(BUZZER, LOW);

  loadWiFiConfig();

  if (wifi_ssid.length() == 0) {
    Serial.println("⚠️ لا توجد إعدادات محفوظة. جاري تفعيل وضع الإعداد...");
    startCaptivePortal();
  } else {
    connectWiFi();
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("⚠️ فشل الاتصال بالشبكة المحفوظة. جاري تفعيل وضع الإعداد...");
      startCaptivePortal();
    }
  }

  cardQueue = xQueueCreate(20, sizeof(CardData));

  xTaskCreatePinnedToCore(uploadTask, "UploadTask", 8192, NULL, 1, NULL, 0);
  // ✅ (فِكس دفعة 45 - تعليق تعليقات) PingTask كانت 4096 بايت بس، وكانت شغّالة بالظبط
  // على الحافة أصلاً مع طلب HTTPS واحد (نبضة القلب). لما أضفنا fetchDeviceModeStatus()
  // (طلب HTTPS تاني + StaticJsonDocument<512> + JsonArray) جوه نفس التاسك، بقت المكدس
  // مش كافي فحصل "stack overflow in task PingTask" وإعادة تشغيل متكررة (وهو سبب ظاهرة
  // "البوردة بتعيد الاتصال بالنت كل شوية" اللي لاحظتها، ونفس سبب إن لمبات الأوضاع مكنتش
  // بتضيء: الجهاز كان بيعمل Reboot قبل ما يوصل لأول استعلام حالة أوضاع أصلاً). رفعنا
  // المكدس لـ 8192 بايت (زي UploadTask بالظبط اللي بيعمل نفس نوع الطلبات) كهامش أمان كافي.
  // ✅ (طلب متابعة: استجابة فورية) استعلام حالة الأوضاع بقى مش جوه PingTask خالص، بقى ليه
  // تاسك منفصلة (modeStatusTask) تحت — سيبنا مكدس PingTask زي ما هو (8192) من غير تقليل،
  // مفيش داعي نخاطر بعد اللي حصل قبل كده لمجرد إنها بقت بتعمل طلب واحد بس دلوقتي
  xTaskCreatePinnedToCore(pingTask, "PingTask", 8192, NULL, 1, NULL, 0);
  // ✅ (طلب متابعة) تاسك مستقلة لاستعلام حالة الأوضاع كل MODE_STATUS_POLL_INTERVAL (2 ثانية) —
  // نفس نوع الطلب اللي كان بيحصل جوه PingTask، فمكدس 8192 بايت بنفس المنطق (هامش أمان كافي
  // لطلب HTTPS + تحليل JSON، بدل المخاطرة بـ stack overflow تاني زي اللي حصل قبل كده)
  xTaskCreatePinnedToCore(modeStatusTask, "ModeStatusTask", 8192, NULL, 1, NULL, 0);

  Serial.println("\n✅ فَصلي - جهاز الحضور جاهز.");
  Serial.println("📡 أوامر Serial (احتياطية): GET_CONFIG, SET_CONFIG:SSID|PASS, RESET_CONFIG, PING");
}
