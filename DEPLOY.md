# نشر نظام متابعة العقود — V19.3.0

## سبب تحديث هذه النسخة
تمت إزالة `wrangler` من `devDependencies` حتى لا يفشل بناء المشروع عندما تمنع بيئة Cloudflare الوصول إلى `registry.npmjs.org`.

المشروع نفسه لا يحتاج أي حزمة npm لتشغيل ملفات الـWorker والـAssets؛ إعداد النشر موجود في `wrangler.toml`.

## إعداد Cloudflare Workers

1. اربط مستودع Git بمشروع **Cloudflare Workers**.
2. تأكد أن المشروع يستخدم ملف `wrangler.toml` الموجود في جذر المشروع.
3. تأكد من وجود D1 binding باسم `DB`.
4. تأكد أن `database_id` في `wrangler.toml` هو معرّف قاعدة D1 الحقيقية.
5. في إعدادات Build، لا تستخدم `bun run deploy` لأن Wrangler غير موجود كاعتماد npm في هذه النسخة.
6. استخدم آلية النشر الأصلية في Cloudflare Workers/Workers Builds التي تقرأ `wrangler.toml`.
7. إذا كانت لوحة Cloudflare تطلب **Build command** فقط لبناء الواجهة، اتركه فارغًا لهذا المشروع؛ مجلد `public` هو الـAssets المحددة في `wrangler.toml`.
8. نفّذ الـmigrations الموجودة في مجلد `migrations` على قاعدة D1 قبل أول نشر للنسخة التي تتطلبها بيئتك.

## فحص محلي بدون تثبيت Wrangler

يمكن التحقق من JavaScript مباشرة:

```bash
bun run check
```

## التحقق بعد النشر

افتح:

- `/api/health` للتحقق من حالة Worker وD1 والإصدار وأعمدة جدول regions.
- `/` للتأكد من ظهور V19.3.0.

يجب ألا تظهر النسخة القديمة `V18.1`.
