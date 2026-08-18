# V19.2.1

- إزالة `wrangler` من `devDependencies` لمنع فشل `bun install` عندما تكون بيئة البناء غير قادرة على الوصول إلى `registry.npmjs.org`.
- إبقاء إعدادات Cloudflare Workers وD1 في `wrangler.toml`.
- إضافة فحص محلي لا يعتمد على npm packages.
- تحديث تعليمات النشر لتجنب استخدام `bun run deploy` في بيئة لا توفر Wrangler.
