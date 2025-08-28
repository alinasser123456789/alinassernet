# 🔹 NetMaster - أداة إدارة الشبكات المتقدمة

<div align="center">

![NetMaster Logo](https://img.shields.io/badge/NetMaster-Network%20Management-blue?style=for-the-badge&logo=network-wired)

[![Python](https://img.shields.io/badge/Python-3.6+-blue?style=flat-square&logo=python)](https://python.org)
[![Linux](https://img.shields.io/badge/Linux-Compatible-green?style=flat-square&logo=linux)](https://linux.org)
[![Termux](https://img.shields.io/badge/Termux-Compatible-orange?style=flat-square&logo=android)](https://termux.com)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)

**أداة شاملة لإدارة الشبكات وتغيير عناوين MAC مع دعم كامل لـ Termux**

</div>

---

## 📋 جدول المحتويات

- [🌟 المميزات](#-المميزات)
- [📱 الإصدارات المتاحة](#-الإصدارات-المتاحة)
- [🚀 التثبيت والتشغيل](#-التثبيت-والتشغيل)
- [💻 الاستخدام](#-الاستخدام)
- [🔧 المتطلبات](#-المتطلبات)
- [📱 استخدام Termux](#-استخدام-termux)
- [🖥️ التصميم المتجاوب](#️-التصميم-المتجاوب)
- [⚠️ تحذيرات مهمة](#️-تحذيرات-مهمة)
- [🐛 استكشاف الأخطاء](#-استكشاف-الأخطاء)
- [🤝 المساهمة](#-المساهمة)

---

## 🌟 المميزات

### 🔍 **مسح الشبكة المتقدم**
- مسح تلقائي للأجهزة المتصلة بالشبكة
- كشف نوع الجهاز من عنوان MAC
- عرض معلومات مفصلة (IP, MAC, نوع الجهاز)
- دعم طرق مسح متعددة (nmap, ping sweep)

### 🔄 **إدارة عناوين MAC**
- تغيير عنوان MAC لأي واجهة شبكة
- اختيار MAC من جدول الأجهزة المكتشفة
- إدخال عنوان MAC يدوياً
- توليد عناوين MAC عشوائية
- استعادة العنوان الأصلي

### 🖥️ **واجهة مستخدم متجاوبة**
- تصميم يتكيف مع جميع أحجام الشاشات
- جداول متجاوبة (50-120+ عمود)
- ألوان وأيقونات تفاعلية
- أشرطة تقدم متحركة

### 📱 **دعم Termux الكامل**
- كشف تلقائي لبيئة Termux
- تحذيرات واضحة للقيود
- طرق بديلة للعمليات المحدودة
- معالجة أخطاء محسنة

---

## 📱 الإصدارات المتاحة

| الملف | الوصف | البيئة المدعومة |
|-------|--------|------------------|
| `netmaster_english.py` | الإصدار الأساسي | Linux فقط (يتطلب root) |
| `netmaster_termux.py` | إصدار Termux المحسن | Termux + Linux |
| `netmaster_english_termux_compatible.py` | إصدار متوافق شامل | جميع البيئات |

---

## 🚀 التثبيت والتشغيل

### 🐧 **على Linux:**

```bash
# تحميل المشروع
git clone https://github.com/your-repo/netmaster.git
cd netmaster

# تشغيل الأداة (يتطلب صلاحيات root)
sudo python3 netmaster_english.py

# أو الإصدار المتوافق
sudo python3 netmaster_english_termux_compatible.py
```

### 📱 **على Termux:**

```bash
# تحديث النظام
pkg update && pkg upgrade

# تثبيت Python
pkg install python

# تثبيت الأدوات المساعدة (اختياري)
pkg install nmap
pkg install iproute2

# تشغيل الأداة
python3 netmaster_termux.py

# أو الإصدار المتوافق
python3 netmaster_english_termux_compatible.py
```

---

## 💻 الاستخدام

### 🔧 **القائمة الرئيسية:**

```
╔══════════════════════════════════════════════════════════════════╗
║                        🔧 NetMaster Menu                        ║
╠══════════════════════════════════════════════════════════════════╣
║              Current Interface: wlan0                           ║
╠══════════════════════════════════════════════════════════════════╣
║  [1] Select MAC from devices table                              ║
║  [2] Enter MAC manually                                         ║
║  [3] Generate random MAC                                        ║
║  [4] Restore original MAC                                       ║
║  [5] Rescan network                                             ║
║  [6] Show current MAC                                           ║
║  [7] Change interface                                           ║
╠══════════════════════════════════════════════════════════════════╣
║  [0] Exit                                                       ║
╚══════════════════════════════════════════════════════════════════╝
```

### 📊 **جدول الأجهزة:**

```
╔══════════════════════════════════════════════════════════════════╗
║                📡 Found 4 device(s) on network ✅                ║
╠══════════════════════════════════════════════════════════════════╣
║ No.  │ IP Address      │ MAC Address       │ Device              ║
╠══════════════════════════════════════════════════════════════════╣
║ [1]  │ 192.168.1.1     │ DC:2C:6E:A3:DF:09 │ Router Gateway      ║
║ [2]  │ 192.168.1.12    │ 00:1B:63:84:45:E6 │ Apple iPhone        ║
║ [3]  │ 192.168.1.13    │ 28:18:78:FF:FE:07 │ Samsung Galaxy      ║
║ [4]  │ 192.168.1.18    │ 08:00:27:12:34:56 │ VirtualBox VM       ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 🔧 المتطلبات

### 🐧 **Linux:**
- Python 3.6+
- صلاحيات root
- أدوات الشبكة: `ip`, `arp`, `ping`
- اختياري: `nmap` للمسح المتقدم

### 📱 **Termux:**
- Python 3.6+
- حزم Termux: `python`, `iproute2`
- اختياري: `nmap`, `root access`

---

## 📱 استخدام Termux

### ✅ **الميزات المدعومة:**
- ✅ مسح الشبكة (ping sweep)
- ✅ عرض واجهات الشبكة
- ✅ قراءة عناوين MAC
- ✅ واجهة مستخدم كاملة

### ⚠️ **الميزات المحدودة:**
- ⚠️ تغيير MAC (يتطلب root)
- ⚠️ بعض أوامر الشبكة المتقدمة

### 🔓 **للحصول على الوظائف الكاملة:**
```bash
# تثبيت Magisk أو SuperSU للحصول على root
# ثم تشغيل:
su
python3 netmaster_termux.py
```

---

## 🖥️ التصميم المتجاوب

الأداة تتكيف تلقائياً مع حجم الشاشة:

### 📱 **الشاشات الصغيرة (< 70 عمود):**
```
╔═══════════════════════════════════════════════════════════════╗
║                     📡 Found 3 device(s) ✅                     ║
╠═══════════════════════════════════════════════════════════════╣
║ #  │ IP            │ Device                                      ║
╠═══════════════════════════════════════════════════════════════╣
║ 1  │ 192.168.1.1   │ Router Gateway                              ║
║ 2  │ 192.168.1.12  │ Apple iPhone                                ║
╚═══════════════════════════════════════════════════════════════╝
```

### 💻 **الشاشات المتوسطة (70-90 عمود):**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          📡 Found 3 device(s) ✅                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ #  │ IP Address      │ MAC          │ Device                                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 1  │ 192.168.1.1     │ DC:2C:6E:A3  │ Router Gateway                          ║
║ 2  │ 192.168.1.12    │ 00:1B:63:84  │ Apple iPhone                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### 🖥️ **الشاشات الكبيرة (> 90 عمود):**
```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                           📡 Found 3 device(s) on network ✅                                           ║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║ No.  │ IP Address      │ MAC Address       │ Device                                                                      ║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║ [1]  │ 192.168.1.1     │ DC:2C:6E:A3:DF:09 │ Router Gateway                                                              ║
║ [2]  │ 192.168.1.12    │ 00:1B:63:84:45:E6 │ Apple iPhone 13 Pro Max                                                     ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## ⚠️ تحذيرات مهمة

### 🔒 **الأمان:**
- استخدم الأداة بمسؤولية
- لا تستخدمها على شبكات لا تملكها
- احتفظ بنسخة احتياطية من عنوان MAC الأصلي

### ⚖️ **القانونية:**
- تأكد من الامتثال للقوانين المحلية
- استخدم الأداة للأغراض التعليمية والاختبار فقط
- لا تستخدمها لأنشطة ضارة

### 🔧 **التقنية:**
- قد تحتاج إعادة تشغيل الشبكة بعد تغيير MAC
- بعض الأجهزة قد لا تدعم تغيير MAC
- النتائج قد تختلف حسب نوع الجهاز

---

## 🐛 استكشاف الأخطاء

### ❌ **"This tool requires root privileges"**
```bash
# الحل: تشغيل بصلاحيات root
sudo python3 netmaster_english.py
```

### ❌ **"No network interfaces found"**
```bash
# التحقق من واجهات الشبكة
ip link show

# أو
ifconfig -a
```

### ❌ **"Network scan failed"**
```bash
# التحقق من الاتصال
ping -c 1 8.8.8.8

# تثبيت nmap (اختياري)
sudo apt install nmap  # Linux
pkg install nmap       # Termux
```

### ❌ **"Failed to change MAC address"**
```bash
# التحقق من دعم الجهاز
sudo ip link set dev wlan0 address 00:11:22:33:44:55

# أو إعادة تشغيل الواجهة
sudo ip link set dev wlan0 down
sudo ip link set dev wlan0 up
```

---

## 📁 هيكل المشروع

```
netmaster/
├── README.md                                    # هذا الملف
├── netmaster_english.py                        # الإصدار الأساسي (Linux)
├── netmaster_termux.py                         # إصدار Termux المحسن
├── netmaster_english_termux_compatible.py      # الإصدار المتوافق الشامل
├── netmaster_config.json                       # ملف الإعدادات (يُنشأ تلقائياً)
├── netmaster_log.txt                          # ملف السجلات (يُنشأ تلقائياً)
└── LICENSE                                     # رخصة المشروع
```

---

## 🔄 التحديثات الأخيرة

### v2.0 - التصميم المتجاوب
- ✅ واجهة متجاوبة مع جميع أحجام الشاشات
- ✅ جداول تتكيف تلقائياً (50-120+ عمود)
- ✅ أشرطة تقدم متحركة
- ✅ تحسينات في الألوان والتنسيق

### v1.5 - دعم Termux
- ✅ كشف تلقائي لبيئة Termux
- ✅ طرق بديلة للمسح الشبكي
- ✅ معالجة أخطاء محسنة
- ✅ رسائل تحذيرية واضحة

---

## 🤝 المساهمة

نرحب بمساهماتكم! يمكنكم:

1. **الإبلاغ عن الأخطاء** عبر Issues
2. **اقتراح ميزات جديدة**
3. **تحسين الكود** عبر Pull Requests
4. **تحسين التوثيق**

### 📝 **خطوات المساهمة:**
```bash
# 1. Fork المشروع
# 2. إنشاء فرع جديد
git checkout -b feature/amazing-feature

# 3. إضافة التغييرات
git commit -m 'Add amazing feature'

# 4. رفع التغييرات
git push origin feature/amazing-feature

# 5. إنشاء Pull Request
```

---

## 📞 الدعم والتواصل

- 🐛 **الأخطاء:** [GitHub Issues](https://github.com/your-repo/netmaster/issues)
- 💡 **الاقتراحات:** [GitHub Discussions](https://github.com/your-repo/netmaster/discussions)
- 📧 **التواصل:** your-email@example.com

---

## 📄 الرخصة

هذا المشروع مرخص تحت رخصة MIT - راجع ملف [LICENSE](LICENSE) للتفاصيل.

---

## 🙏 شكر وتقدير

- **مطوري Python** لتوفير لغة برمجة رائعة
- **مجتمع Linux** للأدوات مفتوحة المصدر
- **فريق Termux** لجعل Linux متاحاً على Android
- **جميع المساهمين** في تطوير هذا المشروع

---

<div align="center">

**⭐ إذا أعجبك المشروع، لا تنس إعطاؤه نجمة! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/your-repo/netmaster?style=social)](https://github.com/your-repo/netmaster/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/your-repo/netmaster?style=social)](https://github.com/your-repo/netmaster/network)

**صُنع بـ ❤️ للمجتمع العربي**

</div>
