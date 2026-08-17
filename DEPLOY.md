# 1S.1 Deployment

1. اربط المستودع بمشروع Cloudflare Workers.
2. تأكد من وجود D1 binding باسم `DB` مع `database_id` الصحيح في `wrangler.toml`.
3. نفذ migrations الموجودة في مجلد `migrations` حسب بيئة النشر.
4. Deploy باستخدام أمر المشروع الموجود في `package.json`.
5. بعد النشر تحقق من `/api/me` ثم افتح المعاملات والمستخدمين والإحصائيات.

الإصدار: 1S.1
