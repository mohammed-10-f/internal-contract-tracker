# Contract Control — V20.5.1

منصة داخلية لإدارة دورة المعاملة وربطها مباشرة بالمسؤول.

## مبادئ V20.3.1
- لا يوجد مفهوم إقليم.
- المعاملة مرتبطة مباشرة بالمستخدم المسؤول.
- مركز القيادة مساحة تشغيلية يومية لجميع المستخدمين.
- تحليل الأداء شاشة مستقلة لقياس: إجمالي المعاملات، تم التوثيق، منسحب الموظف، المعاملات المتأخرة، وأُغلقت بعد التأخير، مع مقارنة عادلة على نفس الفترة.
- نموذج Excel للرفع الجماعي يُنشأ ديناميكيًا ويضع المسؤولين النشطين في قائمة منسدلة.
- فتح تفاصيل المعاملة يتم من زر «التفاصيل» فقط؛ النسخ لا يفتح المعاملة.

## V20.5.1 — تحسينات الأمان وتجربة الجوال
- كلمات المرور الجديدة تُخزن باستخدام PBKDF2-SHA256 مع Salt عشوائي.
- كلمات المرور القديمة تُرقّى تلقائيًا عند أول تسجيل دخول ناجح.
- تغيير كلمة المرور ينهي الجلسات الأخرى للمستخدم.
- انتهاء الجلسة يعيد المستخدم إلى شاشة الدخول برسالة واضحة.
- شريط الجوال أصبح مختصرًا مع قائمة «المزيد» للعناصر الثانوية.
- تأكيد قبل تسجيل الخروج وإظهار/إخفاء كلمات المرور في حسابي.


## 20.5.1 hotfix
- Hardened schema migration recovery after interrupted deployments.
- Added safe recovery for temporary migration tables.
- Wrapped Worker requests so runtime exceptions return JSON diagnostics instead of the Cloudflare HTML exception page.
- Reduced PBKDF2 iteration count to 100,000 for a safer Cloudflare Workers runtime budget while retaining salted password hashing.
