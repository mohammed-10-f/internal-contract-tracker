# V20.6.1

- إصلاح استيراد المستخدمين بالجملة: تقليل تكلفة PBKDF2 داخل دفعة الاستيراد لتجنب تجاوز حد CPU في Cloudflare Workers، مع بقاء التحقق متوافقًا مع اختلاف عدد الدورات.
- تحسين رسائل أخطاء الاستيراد لتوضيح سبب فشل الخادم بدل رسالة عامة.
- إضافة زر «تنظيف بيانات الاختبار» لمدير النظام فقط.
- التنظيف يعيد النظام إلى حالة البداية: يحذف المعاملات والمراحل والتفويضات وسجل النشاط والمستخدمين غير الإداريين، ويُبقي حساب المدير الحالي وتسجيل دخوله.
- مسح الكاش الداخلي وإعادة تسلسل أرقام الجداول التشغيلية بعد التنظيف.
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


## V20.6.0
- إعادة تصميم مضغوطة وكاملة لتفاصيل المعاملة مع إبراز اسم الموظف والرقم الوظيفي في عنوان واحد.
- تحسين توزيع الملخص، الإجراء، وسجل النشاط وتقليل المساحات الفارغة دون تغيير منطق الإجراءات.
- إضافة نموذج Excel ثابت لإضافة المستخدمين بالجملة مع التحقق الكامل قبل الإنشاء.
- دعم استيراد حتى 50 مستخدمًا في الدفعة الواحدة، مع تطبيق الصلاحيات الافتراضية للدور.

## V20.6.2
- تحسين توزيع صفوف المعاملات على سطح المكتب لمنع تداخل الاسم والحالة والإجراءات دون تغيير تخطيط الجوال.
- إصلاح تحليل الأداء ليحترم الفترة المحددة ويعتمد على تاريخ دخول المعاملة مرحلة المسؤول.
- إضافة تحقق من نطاق التاريخ وتحديث مباشر للنتائج مع خيار مسح الفترة.

## V20.6.8 — Code Refactoring
- تنظيف الدوال المساعدة غير المستخدمة وإزالة طبقات التطوير القديمة غير المرتبطة بأي مسار تشغيلي.
- توحيد رقم الإصدار في ملفات المشروع.
- تحسين تنظيم وتعليقات الملفات الرئيسية دون تغيير واجهة المستخدم أو مسارات API أو الصلاحيات أو منطق المعاملات.
- لا توجد تغييرات وظيفية مقصودة في هذه النسخة.

## V20.6.9 — Performance KPI visual alignment
- Desktop performance KPI cards now use six equal columns so all six indicators stay on one aligned row at supported desktop widths.
- KPI cards have a consistent visual height and vertically centered content.
- Added the missing teal visual treatment for the "المعاملات النشطة الآن" indicator.
- No business logic, API, workflow, permissions, or mobile layout changes.


## V20.6.10 — Performance comparison alignment
- Fixed the desktop comparison table grid: 9 visual columns now map 1:1 between headings and values.
- Kept the existing visual design and mobile layout unchanged.
- No workflow, API, permissions, or business logic changes.
