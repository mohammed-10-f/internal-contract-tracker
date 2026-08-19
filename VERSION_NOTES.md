# Version 20.5.1

- تحسين أمان كلمات المرور باستخدام PBKDF2-SHA256 مع Salt عشوائي.
- ترقية تلقائية لكلمات المرور القديمة عند أول تسجيل دخول ناجح.
- إنهاء الجلسات الأخرى عند تغيير كلمة المرور مع إبقاء الجلسة الحالية.
- إضافة تنبيه واضح عند انتهاء جلسة المستخدم وإعادته للدخول.
- تحسين قائمة الجوال: الرئيسية، المعاملات، الرفع، المزيد، حسابي، خروج.
- نقل العناصر الثانوية إلى قائمة «المزيد» لتقليل ازدحام شريط الجوال.
- إضافة تأكيد قبل تسجيل الخروج.
- إضافة إظهار/إخفاء كلمة المرور في صفحة حسابي.
- منع إعادة استخدام كلمة المرور الحالية عند تغييرها.
- تحديث رقم الإصدار إلى 20.5.1.


### V20.5.1 — Login hotfix
- Fixed a deployment/runtime failure that could prevent login.
- Added interrupted migration recovery for users/records temporary tables.
- Added JSON error handling around Worker requests.
- PBKDF2-SHA256 remains enabled with 100,000 iterations.
