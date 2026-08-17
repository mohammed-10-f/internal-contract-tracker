const COOKIE = "ict_session";
const DAYS = 30;
const SLA_HOURS = 48;

const CLOSED = ["final_documented", "final_withdrawn", "cancelled"];
const PAUSED = ["stopped"];

const LABELS = {
  waiting_region: "مطلوبة منك",
  returned: "مرتجع للتصحيح",
  region_documented: "بانتظار اعتماد HR",
  region_withdrawn: "بانتظار اعتماد HR",
  final_documented: "تم التوثيق",
  final_withdrawn: "منسحب الموظف",
  cancelled: "ملغاة",
  stopped: "موقوفة",
};

const ROLE_LABELS = {
  admin: "مدير النظام",
  requester: "HR",
  region: "مسؤول إقليم",
  viewer: "مشاهد",
};

const ALL_PERMS = [
  "view_records","upload_contracts","respond_region","approve",
  "manage_users","manage_regions","settings","stop_records","export",
  "reassign_records","view_closed","reactivate_records","view_stats",
  "cancel_records","manage_delegations","view_login_audit"
];

const ROLE_DEFAULTS = {
  admin: ALL_PERMS,
  requester: [
    "view_records","upload_contracts","approve","export","view_stats",
    "cancel_records","manage_delegations","view_closed"
  ],
  region: ["view_records","respond_region","view_stats"],
  viewer: ["view_records","export"]
};

const json = (data, status=200, extra={}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {"content-type":"application/json;charset=utf-8", ...extra}
  });

const text = (body, status=200, type="text/html;charset=utf-8") =>
  new Response(body, {status, headers: {"content-type": type}});

const nowISO = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0,10);

const hash = async (value) => {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value))
  );
  return [...new Uint8Array(bytes)]
    .map(x => x.toString(16).padStart(2,"0")).join("");
};

const token = () => {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return [...a].map(x => x.toString(16).padStart(2,"0")).join("");
};

function cookie(req) {
  const raw = req.headers.get("Cookie") || "";
  const item = raw.split(";").map(x=>x.trim())
    .find(x=>x.startsWith(COOKIE+"="));
  return item ? item.slice(COOKIE.length+1) : null;
}

function permsOf(u) {
  if (!u) return [];
  if (u.role === "admin") return ALL_PERMS;
  return String(u.permissions || "")
    .split(",").map(x=>x.trim()).filter(Boolean);
}

function allow(u, p) {
  return !!(u && (u.role === "admin" || permsOf(u).includes(p)));
}

function statusLabel(s) {
  return LABELS[s] || s || "غير معروف";
}

function isFinished(r) {
  return CLOSED.includes(r?.status);
}

function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function elapsedNow(r) {
  const stored = Number(r.elapsed_seconds || 0);
  if (!r.timer_running || !r.stage_started_at) return Math.max(0, stored);
  const started = parseDate(r.stage_started_at);
  if (!started) return stored;
  return stored + Math.max(0, Math.floor((Date.now()-started.getTime())/1000));
}

function withMeta(r) {
  const elapsed = elapsedNow(r);
  return {
    ...r,
    status_label: statusLabel(r.status),
    elapsed_seconds: elapsed,
    timer_running: !!r.timer_running && !isFinished(r),
    overdue: !!r.timer_running && !isFinished(r) && elapsed >= SLA_HOURS*3600,
    elapsed_minutes: Math.floor(elapsed/60),
  };
}

async function currentUser(req, env) {
  const t = cookie(req);
  if (!t) return null;

  const row = await env.DB.prepare(`
    SELECT u.*, s.login_at, s.last_seen_at, s.expires_at
    FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token=? AND s.expires_at>? AND u.active=1
  `).bind(t, Math.floor(Date.now()/1000)).first();

  if (!row) return null;

  await env.DB.prepare(
    "UPDATE sessions SET last_seen_at=? WHERE token=?"
  ).bind(nowISO(), t).run();

  return row;
}

async function audit(env, {
  recordId=null, userId=null, action, note="", meta={}
}) {
  try {
    await env.DB.prepare(`
      INSERT INTO audit_log(record_id,user_id,action,note,created_at,meta)
      VALUES(?,?,?,?,?,?)
    `).bind(
      recordId, userId, action, note, nowISO(), JSON.stringify(meta)
    ).run();
  } catch {
    // Legacy databases may not have meta/created_at yet.
    await env.DB.prepare(
      "INSERT INTO audit_log(record_id,user_id,action,note) VALUES(?,?,?,?)"
    ).bind(recordId,userId,action,note).run();
  }
}

async function loginAudit(env, req, userId, action, success=1, note="") {
  try {
    await env.DB.prepare(`
      INSERT INTO login_audit(user_id,event_at,action,success,ip,user_agent,note)
      VALUES(?,?,?,?,?,?,?)
    `).bind(
      userId, nowISO(), action, success,
      req.headers.get("CF-Connecting-IP") || "",
      req.headers.get("User-Agent") || "",
      note
    ).run();
  } catch {}
}

async function activeDelegation(env, sourceId) {
  return await env.DB.prepare(`
    SELECT d.*, u.name target_name, u.username target_username
    FROM delegations d
    JOIN users u ON u.id=d.target_user_id
    WHERE d.source_user_id=?
      AND d.active=1
      AND d.starts_at<=?
      AND (d.ends_at IS NULL OR d.ends_at>=?)
      AND u.active=1
    ORDER BY d.id DESC LIMIT 1
  `).bind(sourceId, nowISO(), nowISO()).first();
}

async function assignedUserFor(env, sourceUserId) {
  const d = await activeDelegation(env, sourceUserId);
  return d ? d.target_user_id : sourceUserId;
}

async function ensureSchema(env) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      region TEXT,
      permissions TEXT DEFAULT '',
      active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS regions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS records(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_no TEXT NOT NULL,
      employee_name TEXT NOT NULL,
      region TEXT NOT NULL,
      start_date TEXT,
      transaction_no TEXT,
      interruption_transaction_no TEXT,
      status TEXT NOT NULL,
      requester_id INTEGER,
      region_user_id INTEGER,
      delegated_to_user_id INTEGER,
      region_note TEXT,
      requester_note TEXT,
      end_date TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT,
      stage_started_at TEXT,
      elapsed_seconds INTEGER DEFAULT 0,
      timer_running INTEGER DEFAULT 1,
      completed_at TEXT,
      stopped_at TEXT,
      stopped_by INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS audit_log(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      record_id INTEGER,
      user_id INTEGER,
      action TEXT NOT NULL,
      note TEXT DEFAULT '',
      created_at TEXT,
      meta TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      login_at TEXT,
      last_seen_at TEXT,
      logout_at TEXT,
      ip TEXT,
      user_agent TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS login_audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      event_at TEXT NOT NULL,
      action TEXT NOT NULL,
      success INTEGER DEFAULT 1,
      ip TEXT DEFAULT '',
      user_agent TEXT DEFAULT '',
      note TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS delegations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_user_id INTEGER NOT NULL,
      target_user_id INTEGER NOT NULL,
      starts_at TEXT NOT NULL,
      ends_at TEXT,
      active INTEGER DEFAULT 1,
      created_by INTEGER,
      created_at TEXT NOT NULL,
      revoked_at TEXT,
      revoked_by INTEGER,
      note TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`
  ];

  for (const sql of statements) {
    try { await env.DB.prepare(sql).run(); } catch {}
  }

  // Safe additive migrations for existing D1 databases.
  const adds = [
    ["users","permissions","TEXT DEFAULT ''"],
    ["users","region","TEXT"],
    ["records","employee_no","TEXT"],
    ["records","employee_name","TEXT"],
    ["records","region","TEXT"],
    ["records","start_date","TEXT"],
    ["records","transaction_no","TEXT"],
    ["records","interruption_transaction_no","TEXT"],
    ["records","region_note","TEXT"],
    ["records","requester_note","TEXT"],
    ["records","end_date","TEXT"],
    ["records","updated_at","TEXT"],
    ["records","stage_started_at","TEXT"],
    ["records","elapsed_seconds","INTEGER DEFAULT 0"],
    ["records","timer_running","INTEGER DEFAULT 1"],
    ["records","completed_at","TEXT"],
    ["records","stopped_at","TEXT"],
    ["records","stopped_by","INTEGER"],
    ["records","delegated_to_user_id","INTEGER"],
    ["audit_log","created_at","TEXT"],
    ["audit_log","meta","TEXT DEFAULT ''"],
    ["sessions","login_at","TEXT"],
    ["sessions","last_seen_at","TEXT"],
    ["sessions","logout_at","TEXT"],
    ["sessions","ip","TEXT"],
    ["sessions","user_agent","TEXT"]
  ];

  for (const [table,col,type] of adds) {
    try {
      await env.DB.prepare(
        `ALTER TABLE ${table} ADD COLUMN ${col} ${type}`
      ).run();
    } catch {}
  }

  for (const [role, perms] of Object.entries(ROLE_DEFAULTS)) {
    try {
      await env.DB.prepare(`
        UPDATE users SET permissions=?
        WHERE role=? AND (permissions IS NULL OR permissions='')
      `).bind(perms.join(","), role).run();
    } catch {}
  }

  try {
    const c = await env.DB.prepare("SELECT COUNT(*) c FROM settings").first();
    if (!Number(c?.c)) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO settings(key,value) VALUES('sla_hours',?)"
      ).bind(String(SLA_HOURS)).run();
    }
  } catch {}

  try {
    const c = await env.DB.prepare("SELECT COUNT(*) c FROM regions").first();
    if (!Number(c?.c)) {
      for (const name of ["الرياض","جدة","الشرقية","مكة المكرمة"]) {
        await env.DB.prepare(
          "INSERT OR IGNORE INTO regions(name,active,created_at) VALUES(?,?,?)"
        ).bind(name,1,nowISO()).run();
      }
    }
  } catch {}
}

async function regionUser(env, region) {
  const direct = await env.DB.prepare(`
    SELECT * FROM users
    WHERE role='region' AND active=1 AND region=?
    ORDER BY id LIMIT 1
  `).bind(region).first();
  return direct || null;
}

async function chooseManager(env, region) {
  const rows = (await env.DB.prepare(`
    SELECT u.id,u.name,u.username,u.region,COUNT(r.id) load
    FROM users u
    LEFT JOIN records r
      ON r.region_user_id=u.id
      AND r.status NOT IN ('final_documented','final_withdrawn','cancelled')
    WHERE u.role='region' AND u.active=1 AND u.region=?
    GROUP BY u.id
    ORDER BY load ASC,u.id ASC
  `).bind(region).all()).results;
  return rows[0] || null;
}

async function scopedRecords(env, u, url) {
  const q=(url.searchParams.get("q")||"").trim();
  const status=(url.searchParams.get("status")||"").trim();
  const region=(url.searchParams.get("region")||"").trim();
  const managerId=Number(url.searchParams.get("manager_id")||0);
  const from=(url.searchParams.get("from")||"").trim();
  const to=(url.searchParams.get("to")||"").trim();

  let sql=`
    SELECT r.*,
      ru.name region_user_name,
      req.name requester_name,
      del.name delegated_to_name
    FROM records r
    LEFT JOIN users ru ON ru.id=r.region_user_id
    LEFT JOIN users req ON req.id=r.requester_id
    LEFT JOIN users del ON del.id=r.delegated_to_user_id
    WHERE 1=1
  `;
  const args=[];

  if (u.role==="region") {
    sql += " AND r.region_user_id=?";
    args.push(u.id);
  } else if (u.role==="requester") {
    sql += " AND (r.requester_id=? OR r.delegated_to_user_id=?)";
    args.push(u.id,u.id);
  }

  if (managerId) {
    sql += " AND r.region_user_id=?";
    args.push(managerId);
  }

  if (region) {
    sql += " AND r.region=?";
    args.push(region);
  }

  if (q) {
    sql += ` AND (
      r.employee_no LIKE ? OR r.employee_name LIKE ? OR
      r.transaction_no LIKE ? OR r.interruption_transaction_no LIKE ?
    )`;
    const z=`%${q}%`;
    args.push(z,z,z,z);
  }

  if (status==="closed") {
    sql += " AND r.status IN ('final_documented','final_withdrawn','cancelled')";
  } else if (status==="required") {
    sql += " AND r.status IN ('waiting_region','returned')";
  } else if (status==="awaiting_hr") {
    sql += " AND r.status IN ('region_documented','region_withdrawn')";
  } else if (status==="stopped") {
    sql += " AND r.status='stopped'";
  } else if (status) {
    sql += " AND r.status=?";
    args.push(status);
  }

  if (from) { sql += " AND substr(r.created_at,1,10)>=?"; args.push(from); }
  if (to) { sql += " AND substr(r.created_at,1,10)<=?"; args.push(to); }

  sql += " ORDER BY r.id DESC LIMIT 2000";
  return (await env.DB.prepare(sql).bind(...args).all()).results.map(withMeta);
}

async function finalizeTimer(env, r, extra={}) {
  const elapsed=elapsedNow(r);
  await env.DB.prepare(`
    UPDATE records SET
      elapsed_seconds=?,
      timer_running=0,
      completed_at=?,
      updated_at=?
      ${extra.stopped ? ",stopped_at=?" : ""}
      ${extra.stoppedBy ? ",stopped_by=?" : ""}
    WHERE id=?
  `).bind(
    elapsed,
    nowISO(),
    nowISO(),
    ...(extra.stopped ? [nowISO()] : []),
    ...(extra.stoppedBy ? [extra.stoppedBy] : []),
    r.id
  ).run();
}

async function startTimer(env,id) {
  await env.DB.prepare(`
    UPDATE records SET timer_running=1,stage_started_at=?,updated_at=? WHERE id=?
  `).bind(nowISO(),nowISO(),id).run();
}

async function recordEvent(env,id,userId,action,note="",meta={}) {
  await audit(env,{recordId:id,userId,action,note,meta});
}

async function csvExport(rows) {
  const headers=[
    "رقم الموظف","اسم الموظف","الإقليم","الحالة",
    "مسؤول الإقليم","مقدم الطلب","المفوض إليه",
    "رقم معاملة التعيين","رقم معاملة الانقطاع",
    "تاريخ المباشرة","تاريخ الرفع","المدة بالدقائق","منتهية"
  ];
  const esc=v=>`"${String(v??"").replaceAll('"','""')}"`;
  const lines=[headers.map(esc).join(",")];
  for(const r of rows){
    lines.push([
      r.employee_no,r.employee_name,r.region,statusLabel(r.status),
      r.region_user_name,r.requester_name,r.delegated_to_name,
      r.transaction_no,r.interruption_transaction_no,r.start_date,
      r.created_at,Math.floor(elapsedNow(r)/60),
      isFinished(r)?"نعم":"لا"
    ].map(esc).join(","));
  }
  return "\uFEFF"+lines.join("\n");
}

const HTML = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>متابعة العقود</title>
<style>
:root{--navy:#0d1b38;--blue:#245ea8;--blue2:#eaf2ff;--bg:#f5f8fc;--text:#18243b;--muted:#73809a;--line:#e1e8f2;--green:#16885b;--red:#c9343e;--amber:#d98a18;--shadow:0 12px 30px rgba(25,55,95,.07)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Tahoma,Arial,sans-serif}
button,input,select{font:inherit}button{cursor:pointer;border:0}.app{display:flex;min-height:100vh}.side{width:255px;background:linear-gradient(180deg,#0c1a36,#101f40);color:#fff;padding:22px 16px;position:fixed;right:0;top:0;bottom:0;z-index:20}.brand{font-weight:800;font-size:19px;padding:12px 10px 25px}.nav a{display:flex;gap:10px;padding:13px 12px;border-radius:14px;color:#dce7fb;text-decoration:none;margin:4px 0}.nav a.active,.nav a:hover{background:#234575;color:#fff}.main{margin-right:255px;width:calc(100% - 255px);padding:30px 34px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.title{font-size:30px;font-weight:850}.sub{font-size:12px;color:var(--muted);margin-bottom:5px}.toolbar{display:grid;grid-template-columns:1fr 180px 120px;gap:10px;margin-bottom:18px}.input,.select,.btn{height:48px;border:1px solid var(--line);background:#fff;border-radius:14px;padding:0 15px;outline:none}.btn{background:var(--blue);color:#fff;font-weight:800}.btn.secondary{background:#fff;color:var(--blue);border-color:#cddbed}.pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}.pill{background:#fff;border:1px solid var(--line);border-radius:999px;padding:9px 14px;color:var(--muted)}.pill.active{background:var(--blue);color:#fff;border-color:var(--blue)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.card{background:#fff;border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:var(--shadow)}.record{border-right:4px solid #4f82c6}.record.late{border-right-color:var(--red)}.record.wait{border-right-color:var(--amber)}.record.done{border-right-color:var(--green)}.row{display:flex;justify-content:space-between;gap:16px}.name{font-size:20px;font-weight:800}.meta{color:var(--muted);font-size:13px;margin-top:8px}.badges{display:flex;gap:7px;flex-wrap:wrap;margin-top:14px}.badge{font-size:12px;padding:6px 10px;border-radius:999px;background:#eef3fa}.badge.green{background:#e8f7ef;color:var(--green)}.badge.red{background:#fff0f1;color:var(--red)}.badge.amber{background:#fff6e7;color:#a96809}.badge.blue{background:#edf4ff;color:#205da9}.cardfoot{border-top:1px solid var(--line);margin-top:16px;padding-top:13px;display:flex;justify-content:space-between;align-items:center}.drawer{position:fixed;inset:0;background:rgba(8,20,42,.5);z-index:40;display:none}.drawer.open{display:block}.panel{position:absolute;right:0;top:0;bottom:0;width:min(680px,96vw);background:#fff;overflow:auto;padding:28px}.x{width:42px;height:42px;border-radius:13px;background:#eef2f7;color:#1d2a42}.steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));align-items:start;gap:0;margin:10px 0 14px;padding:2px 0}.step{position:relative;text-align:center;font-size:10px;color:#8a96aa;min-width:0;padding:0 3px}.step:not(:last-child):after{content:"";position:absolute;left:0;right:50%;top:10px;height:2px;background:#dce5f0;z-index:0}.step i{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:#edf1f6;border:2px solid #dce5f0;margin:0 auto 4px;font-style:normal}.step.on{color:var(--blue);font-weight:800}.step.on i{background:#eaf2ff;border-color:#6fa4e8;color:var(--blue)}.external-info{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:9px}.external-info .badge{font-size:11px;padding:5px 9px}.external-date{font-size:11px;color:var(--muted)}.stats-table{width:100%;border-collapse:separate;border-spacing:0 7px}.stats-table th{font-size:11px;color:var(--muted);font-weight:700;text-align:right;padding:0 10px}.stats-table td{background:#f7f9fc;padding:10px;font-size:12px}.stats-table tr td:first-child{border-radius:0 12px 12px 0;font-weight:800}.stats-table tr td:last-child{border-radius:12px 0 0 12px}.delta-up{color:var(--green);font-weight:800}.delta-down{color:var(--red);font-weight:800}.section{margin-top:16px}.section h3{margin:0 0 10px}.kv{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}.kv div{background:#f7f9fc;border-radius:14px;padding:12px}.kv small{display:block;color:var(--muted);margin-bottom:5px}.timeline{border-right:2px solid #d8e1ef;padding-right:14px}.event{margin:0 0 14px;position:relative}.event:before{content:"";position:absolute;right:-21px;top:5px;width:9px;height:9px;border-radius:50%;background:var(--blue)}.event small{color:var(--muted)}.login{max-width:430px;margin:12vh auto}.login h1{text-align:center}.hidden{display:none}.mobilebar{display:none}@media(max-width:850px){.side{display:none}.main{margin:0;width:100%;padding:18px 14px 90px}.mobilebar{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.toolbar{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.title{font-size:26px}.panel{width:100%;padding:18px 14px}.kv{grid-template-columns:1fr}.top{display:block}.top .pill{margin-top:10px}.card{border-radius:18px}.steps{gap:0;margin:8px 0 12px}.step{font-size:8px}.step i{width:20px;height:20px}.step:not(:last-child):after{top:9px}.record .row{align-items:flex-start}.record .name{font-size:18px}}
</style></head><body><div id="app"></div>
<script>
const state={user:null,records:[],status:"",q:"",region:"",from:"",to:"",selected:null,events:[],users:[],regions:[],delegations:[],stats:null};
const api=async(path,opt={})=>{const r=await fetch(path,{headers:{"content-type":"application/json"},...opt});const d=await r.json().catch(()=>({error:"استجابة غير صالحة"}));if(!r.ok)throw Error(d.error||"حدث خطأ غير متوقع");return d};
const esc=s=>String(s??"").replace(/[&<>"]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[m]));
const mins=s=>{s=Number(s||0);return Math.floor(s/3600)+"س "+Math.floor((s%3600)/60)+"د"};
const badge=s=>'<span class="badge '+(s.includes("تم")||s.includes("نهائي")?"green":s.includes("مؤجل")||s.includes("مرتجع")||s.includes("متأخر")?"red":"blue")+'">'+esc(s)+'</span>';
async function load(){const m=await api("/api/me");state.user=m.user;if(!state.user){login();return}await records();render();}
async function records(){const p=new URLSearchParams({q:state.q,status:state.status,region:state.region,from:state.from,to:state.to});state.records=(await api("/api/records?"+p)).records}
function login(){document.getElementById("app").innerHTML='<div class="login card"><h1>متابعة العقود</h1><p class="meta">دخول آمن للنظام</p><input id="un" class="input" placeholder="اسم المستخدم" style="width:100%;margin:7px 0"><input id="pw" type="password" class="input" placeholder="كلمة المرور" style="width:100%;margin:7px 0"><button class="btn" style="width:100%;margin-top:8px" onclick="doLogin()">دخول</button><p id="err" style="color:#c9343e"></p></div>'}
async function doLogin(){try{await api("/api/login",{method:"POST",body:JSON.stringify({username:un.value,password:pw.value})});await load()}catch(e){err.textContent=e.message}}
function shell(content){document.getElementById("app").innerHTML='<aside class="side"><div class="brand">▣ متابعة العقود</div><nav class="nav"><a class="active">⌂ الرئيسية</a><a onclick="showRecords()">▣ المعاملات</a><a onclick="upload()">＋ رفع عقد</a><a onclick="bulk()">⇧ رفع جماعي</a><a onclick="showStats()">◔ الإحصائيات</a><a>✓ المعاملات المنتهية</a><a onclick="exportData()">⇩ تصدير التقرير</a><hr><a onclick="showUsers()">♟ المستخدمون والصلاحيات</a><a onclick="showRegions()">⌘ الأقاليم</a><a onclick="showDelegations()">↗ التفويضات</a><a onclick="showLoginAudit()">◉ سجل النشاط</a></nav></aside><main class="main"><div class="mobilebar"><b>متابعة العقود</b><button class="x" onclick="alert('القائمة الجانبية متاحة على سطح المكتب')">☰</button></div>'+content+'<div style="text-align:center;color:#9aa6b8;margin-top:25px">hr_Mohammed</div></main><div id="drawer" class="drawer"></div>'}
function showRecords(){const pills=[["","الكل"],["required","مطلوبة مني"],["awaiting_hr","بانتظار اعتماد HR"],["closed","منتهية"],["stopped","موقوفة"],["cancelled","ملغاة"]];shell('<div class="top"><div><div class="sub">نظام متابعة المعاملات</div><div class="title">المعاملات</div></div><span class="pill">● متصل الآن</span></div><div class="toolbar"><input class="input" value="'+esc(state.q)+'" placeholder="ابحث برقم الموظف أو الاسم أو رقم المعاملة" oninput="state.q=this.value"><select class="select" onchange="state.status=this.value;showRecords()">'+pills.map(x=>'<option value="'+x[0]+'" '+(state.status===x[0]?"selected":"")+'>'+x[1]+'</option>').join("")+'</select><button class="btn" onclick="records().then(renderRecords)">بحث</button></div><div id="cards"></div>');renderRecords()}
function renderRecords(){document.getElementById("cards").innerHTML='<div class="grid">'+state.records.map(r=>{const external=r.status==="final_withdrawn"||r.interruption_transaction_no||r.end_date;return '<article class="card record '+(r.overdue?"late":r.status==="waiting_region"?"wait":isDone(r)?"done":"")+'"><div class="row"><div><div class="name">'+esc(r.employee_name)+'</div><div class="meta">#'+r.id+' · '+esc(r.employee_no)+' · '+esc(r.region)+'</div></div><div>'+badge(r.status_label)+(r.overdue?'<div style="color:#c9343e;font-size:12px;margin-top:8px">متأخرة</div>':"")+'</div></div><div class="badges"><span class="badge">📅 '+esc((r.created_at||"").slice(0,10))+'</span><span class="badge">👤 '+esc(r.region_user_name||"—")+'</span><span class="badge">⏱ '+mins(r.elapsed_seconds)+'</span></div>'+(external?'<div class="external-info"><span class="badge '+(r.status==="final_withdrawn"?"red":"blue")+'">↗ منسحب الموظف</span>'+(r.interruption_transaction_no?'<span class="badge">اتخاذ الإجراء #'+esc(r.interruption_transaction_no)+'</span>':"")+(r.end_date?'<span class="external-date">آخر يوم عمل: '+esc(r.end_date)+'</span>':"")+'</div>':"")+'<div class="cardfoot"><small>'+esc(r.delegated_to_name?("مفوض إلى "+r.delegated_to_name):"")+'</small><button class="btn secondary" onclick="openRecord('+r.id+')">فتح التفاصيل ←</button></div></article>'}).join("")+'</div>'}
const isDone=r=>["final_documented","final_withdrawn","cancelled"].includes(r.status);
function stepClass(status,index){const order={waiting_region:1,returned:1,region_documented:2,region_withdrawn:2,final_documented:4,final_withdrawn:4,cancelled:4,stopped:0};const current=order[status]||1;return index<=current?"on":""}
async function openRecord(id){try{const d=await api("/api/records/"+id);state.selected=d.record;state.events=d.events;const steps=["رفع","إفادة الإقليم","اعتماد HR","إغلاق"];document.getElementById("drawer").innerHTML='<div class="panel"><button class="x" onclick="closeDrawer()">×</button><div style="margin-top:14px"><div class="sub">#'+id+'</div><h1>'+esc(state.selected.employee_name)+'</h1><div class="meta">'+esc(state.selected.region)+' · '+esc(state.selected.status_label)+'</div></div><div class="steps">'+steps.map((x,i)=>'<div class="step '+stepClass(state.selected.status,i+1)+'"><i>'+(i+1)+'</i>'+x+'</div>').join("")+'</div><div class="card section"><h3>بيانات الموظف والمعاملة</h3><div class="kv">'+[["رقم الموظف",state.selected.employee_no],["رقم التعيين",state.selected.transaction_no],["الإقليم",state.selected.region],["مسؤول الإقليم",state.selected.region_user_name],["مقدم الطلب",state.selected.requester_name],["المفوض إليه",state.selected.delegated_to_name||"—"],["تاريخ الرفع",(state.selected.created_at||"").slice(0,16)],["المدة",mins(state.selected.elapsed_seconds)]].map(x=>'<div><small>'+x[0]+'</small><b>'+esc(x[1])+'</b></div>').join("")+'</div>'+(state.selected.status==="final_withdrawn"||state.selected.interruption_transaction_no||state.selected.end_date?'<div class="external-info"><span class="badge red">↗ منسحب الموظف</span>'+(state.selected.interruption_transaction_no?'<span class="badge">اتخاذ الإجراء #'+esc(state.selected.interruption_transaction_no)+'</span>':"")+(state.selected.end_date?'<span class="external-date">آخر يوم عمل: '+esc(state.selected.end_date)+'</span>':"")+'</div>':"")+'</div><div class="card section"><h3>سجل المتابعة</h3><div class="timeline">'+state.events.map(e=>'<div class="event"><b>'+esc(e.action)+'</b><div>'+esc(e.note||"")+'</div><small>'+esc(e.created_at||e.event_at||"")+' · '+esc(e.actor_name||"")+'</small></div>').join("")+'</div></div><div class="card section"><h3>إدارة الحالة</h3><button class="btn" style="width:100%" onclick="returnRecord()">إرجاع للتصحيح</button><button class="btn secondary" style="width:100%;margin-top:8px" onclick="finishRecord()">اعتماد وإنهاء</button></div></div>';document.getElementById("drawer").classList.add("open")}catch(e){alert(e.message)}}

function closeDrawer(){drawer.classList.remove("open")}
async function returnRecord(){const note=prompt("سبب الإرجاع:")||"";try{await api("/api/records/"+state.selected.id,{method:"POST",body:JSON.stringify({action:"return",note})});closeDrawer();await records();renderRecords()}catch(e){alert(e.message)}}
async function finishRecord(){try{await api("/api/records/"+state.selected.id,{method:"POST",body:JSON.stringify({action:"final_documented"})});closeDrawer();await records();renderRecords()}catch(e){alert(e.message)}}
function render(){showRecords()}
async function showStats(){try{const d=await api("/api/dashboard");const top=[["إجمالي المعاملات",d.total],["تم التوثيق",d.documented],["منسحب الموظف",d.withdrawn],["تحتاج إجراء الآن",d.required],["متأخرة الآن",d.overdue],["نسبة الالتزام بالوقت",d.sla_percent+"%"]];shell('<div class="top"><div><div class="sub">لوحة قياس الأداء</div><div class="title">تحليلات الأداء</div></div></div><div class="grid">'+top.map(x=>'<div class="card"><div class="sub">'+x[0]+'</div><div style="font-size:28px;font-weight:850">'+x[1]+'</div></div>').join("")+'</div><div class="card" style="margin-top:16px"><div class="row"><div><h3 style="margin:0">مقارنة أداء المستخدمين</h3><div class="meta">القياس على المستخدم مباشرة — HR ومسؤول الإقليم</div></div><span class="badge blue">'+d.user_stats.length+' مستخدم</span></div><div style="overflow:auto;margin-top:12px"><table class="stats-table"><thead><tr><th>المستخدم</th><th>الدور</th><th>المعاملات</th><th>التوثيق</th><th>الانسحاب</th><th>المتأخرة</th><th>زمن التأخير</th><th>الالتزام</th></tr></thead><tbody>'+d.user_stats.map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.role_label)+'</td><td>'+x.handled+'</td><td>'+x.documented+'</td><td>'+x.withdrawn+'</td><td>'+(x.overdue||0)+'</td><td>'+mins(x.delay_seconds||0)+'</td><td><span class="'+(Number(x.sla_percent)>=90?"delta-up":Number(x.sla_percent)<75?"delta-down":"")+'">'+x.sla_percent+'%</span></td></tr>').join("")+'</tbody></table></div></div>')}catch(e){alert(e.message)}}

async function showUsers(){const d=await api("/api/users");state.users=d.users;shell('<div class="top"><div><div class="sub">الإدارة</div><div class="title">المستخدمون والصلاحيات</div></div><button class="btn" onclick="newUser()">＋ مستخدم جديد</button></div><div class="grid">'+state.users.map(u=>'<div class="card"><div class="row"><b>'+esc(u.name)+'</b><span class="badge">'+esc(u.active?"نشط":"موقوف")+'</span></div><div class="meta">@'+esc(u.username)+' · '+esc(u.role)+'</div><div class="badges">'+u.permissions.map(p=>'<span class="badge blue">'+esc(p)+'</span>').join("")+'</div><div class="cardfoot"><button class="btn secondary" onclick="editUser('+u.id+')">تعديل</button></div></div>').join("")+'</div>')}
function newUser(){alert("نموذج المستخدم الجديد: عند اختيار الدور تُحدد الصلاحيات المقترحة تلقائياً، ثم يمكن تعديلها قبل الحفظ.")}
function editUser(id){alert("تعديل المستخدم #"+id)}
async function showRegions(){shell('<div class="top"><div><div class="sub">الإدارة</div><div class="title">إدارة الأقاليم</div></div><button class="btn" onclick="addRegion()">＋ إضافة إقليم</button></div><div class="grid" id="regions"></div>');const d=await api("/api/regions");document.getElementById("regions").innerHTML=d.regions.map(r=>'<div class="card"><div class="row"><b>'+esc(r.name)+'</b><span class="badge '+(r.active?"green":"red")+'">'+(r.active?"نشط":"موقوف")+'</span></div><div class="cardfoot"><button class="btn secondary" onclick="editRegion('+r.id+')">تعديل</button><button class="btn secondary" onclick="toggleRegion('+r.id+')">'+(r.active?"تعطيل":"تفعيل")+'</button></div></div>').join("")}
async function addRegion(){const name=prompt("اسم الإقليم:");if(!name)return;try{await api("/api/regions",{method:"POST",body:JSON.stringify({name})});showRegions()}catch(e){alert(e.message)}}
async function editRegion(id){const name=prompt("الاسم الجديد:");if(!name)return;try{await api("/api/regions/"+id,{method:"POST",body:JSON.stringify({name})});showRegions()}catch(e){alert(e.message)}}
async function toggleRegion(id){try{await api("/api/regions/"+id,{method:"POST",body:JSON.stringify({action:"toggle"})});showRegions()}catch(e){alert(e.message)}}
async function showDelegations(){const d=await api("/api/delegations");shell('<div class="top"><div><div class="sub">الإدارة</div><div class="title">تفويض المعاملات</div></div><button class="btn" onclick="newDelegation()">＋ تفويض جديد</button></div><div class="grid">'+d.delegations.map(x=>'<div class="card"><b>'+esc(x.source_name)+' ← '+esc(x.target_name)+'</b><div class="meta">من '+esc(x.starts_at)+' إلى '+esc(x.ends_at||"حتى الإلغاء")+'</div><div class="badges"><span class="badge '+(x.active?"green":"red")+'">'+(x.active?"فعال":"ملغى")+'</span></div><div class="cardfoot">'+(x.active?'<button class="btn secondary" onclick="revokeDelegation('+x.id+')">إلغاء التفويض</button>':"")+'</div></div>').join("")+'</div>')}
async function newDelegation(){const source=prompt("رقم المستخدم المُفوِّض:");const target=prompt("رقم المستخدم المفوَّض إليه:");if(!source||!target)return;try{await api("/api/delegations",{method:"POST",body:JSON.stringify({source_user_id:Number(source),target_user_id:Number(target)})});showDelegations()}catch(e){alert(e.message)}}
async function revokeDelegation(id){try{await api("/api/delegations/"+id,{method:"POST",body:JSON.stringify({action:"revoke"})});showDelegations()}catch(e){alert(e.message)}}
async function showLoginAudit(){const d=await api("/api/login-audit");shell('<div class="top"><div><div class="sub">الرقابة</div><div class="title">سجل دخول المستخدمين</div></div><button class="btn" onclick="exportLogin()">تصدير Excel/CSV</button></div><div class="card"><div class="grid">'+d.rows.map(x=>'<div class="card"><b>'+esc(x.user_name||"—")+'</b><div class="meta">'+esc(x.action)+' · '+esc(x.event_at)+'</div><div class="meta">'+esc(x.ip||"")+'</div></div>').join("")+'</div></div>')}
async function exportData(){const d=await api("/api/export");const blob=new Blob([d.csv],{type:"text/csv;charset=utf-8"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="transactions.csv";a.click()}
async function exportLogin(){const d=await api("/api/login-audit");const blob=new Blob(["\\uFEFF"+d.rows.map(x=>[x.user_name,x.action,x.event_at,x.ip].map(v=>'\"'+String(v||"").replaceAll('\"','\"\"')+'\"').join(",")).join("\\n")],{type:"text/csv"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="login-audit.csv";a.click()}
async function upload(){alert("رفع عقد مفرد أو جماعي سيكون من نفس المسار في النسخة النهائية.")}
async function bulk(){alert("الرفع الجماعي يستخدم نفس شاشة الرفع مع اختيار نوع الإدخال.")}
load().catch(()=>login());
</script></body></html>`;

export default {
  async fetch(req, env) {
    await ensureSchema(env);

    const u = await currentUser(req, env);
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === "/api/me") {
      return json({user:u ? {
        id:u.id,name:u.name,username:u.username,role:u.role,
        region:u.region,permissions:permsOf(u),
        login_at:u.login_at,last_seen_at:u.last_seen_at
      } : null});
    }

    if (p === "/api/setup" && req.method === "POST") {
      const c = await env.DB.prepare("SELECT COUNT(*) c FROM users").first();
      if (Number(c?.c)) return json({error:"تمت التهيئة مسبقاً"},400);
      const b = await req.json();
      const h = await hash(String(b.password || "1234"));
      await env.DB.prepare(`
        INSERT INTO users(username,name,password_hash,role,permissions,active,created_at)
        VALUES('admin',?,?, 'admin',?,1,?)
      `).bind(b.name||"مدير النظام",h,ALL_PERMS.join(","),nowISO()).run();
      return json({ok:true});
    }

    if (p === "/api/login" && req.method === "POST") {
      const b = await req.json();
      const username = String(b.username||"").trim();
      const x = await env.DB.prepare(
        "SELECT * FROM users WHERE username=? AND active=1"
      ).bind(username).first();

      if (!x || x.password_hash !== await hash(String(b.password||""))) {
        await loginAudit(env,req,x?.id||null,"تسجيل دخول فاشل",0,"بيانات غير صحيحة");
        return json({error:"بيانات الدخول غير صحيحة"},401);
      }

      const t=token();
      const exp=Math.floor(Date.now()/1000)+DAYS*86400;
      const ip=req.headers.get("CF-Connecting-IP")||"";
      const ua=req.headers.get("User-Agent")||"";

      await env.DB.prepare(`
        INSERT INTO sessions(token,user_id,expires_at,login_at,last_seen_at,ip,user_agent)
        VALUES(?,?,?,?,?,?,?)
      `).bind(t,x.id,exp,nowISO(),nowISO(),ip,ua).run();

      await loginAudit(env,req,x.id,"تسجيل دخول ناجح",1,"");

      return json({ok:true},200,{
        "set-cookie":`${COOKIE}=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${DAYS*86400}`
      });
    }

    if (p === "/api/logout") {
      const t=cookie(req);
      if(t){
        const s=await env.DB.prepare(
          "SELECT user_id FROM sessions WHERE token=?"
        ).bind(t).first();
        await env.DB.prepare(
          "UPDATE sessions SET logout_at=? WHERE token=?"
        ).bind(nowISO(),t).run();
        if(s) await loginAudit(env,req,s.user_id,"تسجيل خروج",1,"");
      }
      return json({ok:true},200,{
        "set-cookie":`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
      });
    }

    if (!u) {
      if (p.startsWith("/api/")) return json({error:"غير مصرح"},401);
      return text(HTML);
    }

    if (p === "/api/regions" && req.method === "GET") {
      if(!allow(u,"manage_regions") && u.role!=="admin")
        return json({error:"غير مصرح"},403);
      const rows=(await env.DB.prepare(
        "SELECT * FROM regions ORDER BY active DESC,name"
      ).all()).results;
      return json({regions:rows});
    }

    if (p === "/api/regions" && req.method === "POST") {
      if(!allow(u,"manage_regions")) return json({error:"غير مصرح"},403);
      const b=await req.json();
      const name=String(b.name||"").trim();
      if(!name)return json({error:"اسم الإقليم مطلوب"},400);
      try{
        await env.DB.prepare(
          "INSERT INTO regions(name,active,created_at) VALUES(?,?,?)"
        ).bind(name,1,nowISO()).run();
      }catch{
        return json({error:"الإقليم موجود مسبقاً"},400);
      }
      return json({ok:true});
    }

    const rm=p.match(/^\/api\/regions\/(\d+)$/);
    if(rm && req.method==="POST"){
      if(!allow(u,"manage_regions"))return json({error:"غير مصرح"},403);
      const id=Number(rm[1]),b=await req.json();
      const r=await env.DB.prepare("SELECT * FROM regions WHERE id=?").bind(id).first();
      if(!r)return json({error:"الإقليم غير موجود"},404);

      if(b.action==="toggle"){
        await env.DB.prepare(
          "UPDATE regions SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?"
        ).bind(id).run();
        return json({ok:true});
      }

      const name=String(b.name||"").trim();
      if(!name)return json({error:"اسم الإقليم مطلوب"},400);
      try{
        await env.DB.prepare("UPDATE regions SET name=? WHERE id=?").bind(name,id).run();
      }catch{
        return json({error:"اسم الإقليم مستخدم"},400);
      }
      return json({ok:true});
    }

    if (p === "/api/users" && req.method === "GET") {
      if(u.role!=="admin")return json({error:"للمدير فقط"},403);
      const rows=(await env.DB.prepare(
        "SELECT id,username,name,role,region,active,permissions,created_at FROM users ORDER BY id DESC"
      ).all()).results;
      return json({users:rows.map(x=>({...x,role_label:ROLE_LABELS[x.role]||x.role,permissions:permsOf(x)}))});
    }

    if (p === "/api/users" && req.method === "POST") {
      if(u.role!=="admin")return json({error:"للمدير فقط"},403);
      const b=await req.json();
      if(!b.username||!b.name||!b.password||!b.role)
        return json({error:"أكمل بيانات المستخدم"},400);
      const ps=(b.permissions?.length?b.permissions:ROLE_DEFAULTS[b.role]||[])
        .filter(x=>ALL_PERMS.includes(x));
      try{
        await env.DB.prepare(`
          INSERT INTO users(username,name,password_hash,role,region,permissions,active,created_at)
          VALUES(?,?,?,?,?,?,1,?)
        `).bind(b.username,b.name,await hash(b.password),b.role,b.region||null,ps.join(","),nowISO()).run();
      }catch{
        return json({error:"اسم المستخدم مستخدم مسبقاً"},400);
      }
      return json({ok:true,permissions:ps});
    }

    const um=p.match(/^\/api\/users\/(\d+)$/);
    if(um && req.method==="POST"){
      if(u.role!=="admin")return json({error:"للمدير فقط"},403);
      const id=Number(um[1]),b=await req.json();
      const target=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
      if(!target)return json({error:"المستخدم غير موجود"},404);

      if(b.action==="toggle" && target.username!=="admin"){
        await env.DB.prepare(
          "UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?"
        ).bind(id).run();
        return json({ok:true});
      }

      const role=b.role||target.role;
      const ps=(b.permissions?.length?b.permissions:ROLE_DEFAULTS[role]||[])
        .filter(x=>ALL_PERMS.includes(x));

      await env.DB.prepare(`
        UPDATE users SET name=?,role=?,region=?,permissions=?,active=? WHERE id=?
      `).bind(
        b.name||target.name,role,b.region??target.region,
        ps.join(","),b.active===undefined?target.active:(b.active?1:0),id
      ).run();

      if(b.password){
        await env.DB.prepare(
          "UPDATE users SET password_hash=? WHERE id=?"
        ).bind(await hash(b.password),id).run();
      }
      return json({ok:true,permissions:ps});
    }

    if(p==="/api/delegations"&&req.method==="GET"){
      if(!allow(u,"manage_delegations"))return json({error:"غير مصرح"},403);
      const rows=(await env.DB.prepare(`
        SELECT d.*,s.name source_name,t.name target_name
        FROM delegations d
        LEFT JOIN users s ON s.id=d.source_user_id
        LEFT JOIN users t ON t.id=d.target_user_id
        ORDER BY d.active DESC,d.id DESC
      `).all()).results;
      return json({delegations:rows});
    }

    if(p==="/api/delegations"&&req.method==="POST"){
      if(!allow(u,"manage_delegations"))return json({error:"غير مصرح"},403);
      const b=await req.json();
      const sourceId=Number(b.source_user_id||u.id);
      const targetId=Number(b.target_user_id||0);
      if(!targetId||sourceId===targetId)return json({error:"اختر مستخدمين مختلفين"},400);

      const source=await env.DB.prepare(
        "SELECT * FROM users WHERE id=? AND active=1"
      ).bind(sourceId).first();
      const target=await env.DB.prepare(
        "SELECT * FROM users WHERE id=? AND active=1"
      ).bind(targetId).first();
      if(!source||!target)return json({error:"المستخدم غير صحيح أو غير نشط"},400);

      // Close any previous active delegation for the same source.
      await env.DB.prepare(`
        UPDATE delegations SET active=0,revoked_at=?,revoked_by=?
        WHERE source_user_id=? AND active=1
      `).bind(nowISO(),u.id,sourceId).run();

      const starts=b.starts_at||nowISO();
      const ends=b.ends_at||null;
      const d=await env.DB.prepare(`
        INSERT INTO delegations(source_user_id,target_user_id,starts_at,ends_at,active,created_by,created_at,note)
        VALUES(?,?,?,?,1,?,?,?)
        RETURNING id
      `).bind(sourceId,targetId,starts,ends,u.id,nowISO(),b.note||"").first();

      // Transfer all currently pending transactions.
      await env.DB.prepare(`
        UPDATE records SET delegated_to_user_id=?,updated_at=updated_at
        WHERE requester_id=?
          AND status NOT IN ('final_documented','final_withdrawn','cancelled')
      `).bind(targetId,sourceId).run();

      await audit(env,{
        userId:u.id,
        action:"إنشاء تفويض",
        note:`من ${source.name} إلى ${target.name}`,
        meta:{delegation_id:d.id,source_user_id:sourceId,target_user_id:targetId}
      });

      return json({ok:true,id:d.id});
    }

    const dm=p.match(/^\/api\/delegations\/(\d+)$/);
    if(dm&&req.method==="POST"){
      if(!allow(u,"manage_delegations"))return json({error:"غير مصرح"},403);
      const id=Number(dm[1]),b=await req.json();
      if(b.action!=="revoke")return json({error:"إجراء غير معروف"},400);
      const d=await env.DB.prepare("SELECT * FROM delegations WHERE id=?").bind(id).first();
      if(!d)return json({error:"التفويض غير موجود"},404);
      await env.DB.prepare(`
        UPDATE delegations SET active=0,revoked_at=?,revoked_by=? WHERE id=?
      `).bind(nowISO(),u.id,id).run();
      await env.DB.prepare(`
        UPDATE records SET delegated_to_user_id=NULL,updated_at=updated_at
        WHERE delegated_to_user_id=?
          AND status NOT IN ('final_documented','final_withdrawn','cancelled')
      `).bind(d.target_user_id).run();
      await audit(env,{
        userId:u.id,action:"إلغاء تفويض",
        note:`تفويض #${id}`,
        meta:{delegation_id:id}
      });
      return json({ok:true});
    }

    if(p==="/api/records"&&req.method==="GET"){
      const rows=await scopedRecords(env,u,url);
      return json({records:rows});
    }

    if(p==="/api/records"&&req.method==="POST"){
      if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية رفع المعاملات"},403);
      const b=await req.json();
      if(!b.employee_no||!b.employee_name||!b.region||!b.start_date||!b.transaction_no)
        return json({error:"أكمل بيانات العقد المطلوبة"},400);

      const ru=await chooseManager(env,b.region);
      if(!ru)return json({error:"لا يوجد مسؤول نشط لهذا الإقليم"},400);

      const effective=await assignedUserFor(env,u.id);
      const r=await env.DB.prepare(`
        INSERT INTO records(
          employee_no,employee_name,region,start_date,transaction_no,status,
          requester_id,region_user_id,delegated_to_user_id,created_at,updated_at,
          stage_started_at,elapsed_seconds,timer_running
        )
        VALUES(?,?,?,?,?,'waiting_region',?,?,?,?,?,?,0,1)
        RETURNING *
      `).bind(
        b.employee_no,b.employee_name,b.region,b.start_date,b.transaction_no,
        u.id,ru.id,effective!==u.id?effective:null,nowISO(),nowISO(),nowISO()
      ).first();

      await recordEvent(env,r.id,u.id,"إنشاء المعاملة",
        `إسناد مسؤول الإقليم: ${ru.name}`);

      return json({ok:true,id:r.id});
    }

    if(p==="/api/records/bulk"&&req.method==="POST"){
      if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية الرفع الجماعي"},403);
      const b=await req.json();let added=0,errors=[];
      for(let i=0;i<(b.rows||[]).length;i++){
        const x=b.rows[i],rowNo=Number(x.row_no||i+2);
        if(!x.employee_no||!x.employee_name||!x.region||!x.start_date||!x.transaction_no){
          errors.push({row:rowNo,reason:"بيانات أساسية ناقصة"});continue;
        }
        const ru=await chooseManager(env,x.region);
        if(!ru){errors.push({row:rowNo,reason:"لا يوجد مسؤول نشط لهذا الإقليم"});continue;}
        try{
          const effective=await assignedUserFor(env,u.id);
          const r=await env.DB.prepare(`
            INSERT INTO records(
              employee_no,employee_name,region,start_date,transaction_no,
              interruption_transaction_no,status,requester_id,region_user_id,
              delegated_to_user_id,created_at,updated_at,stage_started_at,
              elapsed_seconds,timer_running
            )
            VALUES(?,?,?,?,?,?,'waiting_region',?,?,?,?,?,?,?,0,1)
            RETURNING id
          `).bind(
            x.employee_no,x.employee_name,x.region,x.start_date,x.transaction_no,
            x.interruption_transaction_no||null,u.id,ru.id,
            effective!==u.id?effective:null,nowISO(),nowISO(),nowISO()
          ).first();
          await recordEvent(env,r.id,u.id,"رفع جماعي",`مسؤول الإقليم: ${ru.name}`);
          added++;
        }catch(e){
          errors.push({row:rowNo,reason:"تعذر إنشاء المعاملة"});
        }
      }
      return json({ok:true,added,skipped:errors.length,errors});
    }

    const m=p.match(/^\/api\/records\/(\d+)$/);
    if(m&&req.method==="GET"){
      const id=Number(m[1]);
      const r=await env.DB.prepare(`
        SELECT r.*,ru.name region_user_name,req.name requester_name,
               del.name delegated_to_name
        FROM records r
        LEFT JOIN users ru ON ru.id=r.region_user_id
        LEFT JOIN users req ON req.id=r.requester_id
        LEFT JOIN users del ON del.id=r.delegated_to_user_id
        WHERE r.id=?
      `).bind(id).first();
      if(!r)return json({error:"المعاملة غير موجودة"},404);

      const allowed =
        u.role==="admin" ||
        u.role==="viewer" ||
        (u.role==="region"&&r.region_user_id===u.id) ||
        (u.role==="requester"&&(r.requester_id===u.id||r.delegated_to_user_id===u.id));

      if(!allowed)return json({error:"لا تملك صلاحية فتح هذه المعاملة"},403);

      const ev=(await env.DB.prepare(`
        SELECT a.*,u.name actor_name
        FROM audit_log a
        LEFT JOIN users u ON u.id=a.user_id
        WHERE a.record_id=? ORDER BY a.id ASC
      `).bind(id).all()).results;

      return json({record:withMeta(r),events:ev});
    }

    if(m&&req.method==="POST"){
      const id=Number(m[1]);
      const b=await req.json();
      const r=await env.DB.prepare("SELECT * FROM records WHERE id=?").bind(id).first();
      if(!r)return json({error:"المعاملة غير موجودة"},404);

      const owner =
        u.role==="admin" ||
        (u.role==="region"&&r.region_user_id===u.id) ||
        (u.role==="requester"&&(r.requester_id===u.id||r.delegated_to_user_id===u.id));

      if(!owner)return json({error:"هذه المعاملة ليست ضمن معاملاتك"},403);

      if(b.action==="return"){
        if(!allow(u,"respond_region") && u.role!=="admin")
          return json({error:"ليس لديك صلاحية الإرجاع"},403);
        await env.DB.prepare(`
          UPDATE records SET status='returned',requester_note=?,
            stage_started_at=?,timer_running=1,updated_at=? WHERE id=?
        `).bind(b.note||null,nowISO(),nowISO(),id).run();
        await recordEvent(env,id,u.id,"إرجاع للتصحيح",b.note||"");
        return json({ok:true});
      }

      if(b.action==="stop"){
        if(!allow(u,"stop_records"))return json({error:"ليس لديك صلاحية إيقاف المعاملة"},403);
        await finalizeTimer(env,r,{stopped:true,stoppedBy:u.id});
        await env.DB.prepare("UPDATE records SET status='stopped',stopped_by=?,stopped_at=? WHERE id=?")
          .bind(u.id,nowISO(),id).run();
        await recordEvent(env,id,u.id,"إيقاف المعاملة",b.note||"");
        return json({ok:true});
      }

      if(b.action==="reactivate"){
        if(!allow(u,"reactivate_records"))return json({error:"ليس لديك صلاحية إعادة تنشيط المعاملة"},403);
        if(!(isFinished(r)||r.status==="stopped"))
          return json({error:"المعاملة ليست منتهية أو موقوفة"},400);
        const next=r.status==="final_withdrawn"?"region_withdrawn":
          r.status==="final_documented"?"region_documented":"waiting_region";
        await env.DB.prepare(`
          UPDATE records SET status=?,completed_at=NULL,stopped_at=NULL,
            stopped_by=NULL,stage_started_at=?,timer_running=1,updated_at=? WHERE id=?
        `).bind(next,nowISO(),nowISO(),id).run();
        await recordEvent(env,id,u.id,"إعادة تنشيط المعاملة",b.note||"");
        return json({ok:true});
      }

      if(isFinished(r))return json({error:"المعاملة منتهية ولا يمكن تعديلها"},403);

      if(b.action==="region_documented"||b.action==="region_withdrawn"){
        if(!allow(u,"respond_region"))return json({error:"ليس لديك صلاحية إفادة الإقليم"},403);
        if(u.role!=="region"&&u.role!=="admin")return json({error:"غير مصرح"},403);

        if(b.action==="region_withdrawn"&&(!b.end_date||!b.interruption_transaction_no))
          return json({error:"الانسحاب يتطلب تاريخ نهاية الدوام ورقم المعاملة"},400);

        const next=b.action==="region_documented"?"region_documented":"region_withdrawn";
        const oldElapsed=elapsedNow(r);

        await env.DB.prepare(`
          UPDATE records SET status=?,end_date=?,interruption_transaction_no=?,
            region_note=?,region_responded_at=?,elapsed_seconds=?,
            stage_started_at=?,timer_running=1,updated_at=? WHERE id=?
        `).bind(
          next,b.end_date||r.end_date||null,
          b.interruption_transaction_no||r.interruption_transaction_no||null,
          b.note||null,nowISO(),oldElapsed,nowISO(),nowISO(),id
        ).run();

        await recordEvent(env,id,u.id,
          next==="region_documented"?"إفادة: تم التوثيق":"إفادة: منسحب الموظف",
          b.note||"");
        return json({ok:true});
      }

      if(b.action==="final_documented"||b.action==="final_withdrawn"){
        if(!allow(u,"approve"))return json({error:"ليس لديك صلاحية الاعتماد النهائي"},403);
        if(u.role!=="admin"&&r.requester_id!==u.id&&r.delegated_to_user_id!==u.id)
          return json({error:"الاعتماد النهائي من HR المفوض/الأصلي"},403);
        if(b.action==="final_withdrawn"&&(!r.end_date||!r.interruption_transaction_no))
          return json({error:"بيانات الانسحاب غير مكتملة"},400);

        const next=b.action==="final_documented"?"final_documented":"final_withdrawn";
        await finalizeTimer(env,r);
        await env.DB.prepare(`
          UPDATE records SET status=?,requester_note=?,final_approved_at=? WHERE id=?
        `).bind(next,b.note||null,nowISO(),id).run();
        await recordEvent(env,id,u.id,
          next==="final_documented"?"اعتماد نهائي: تم التوثيق":"اعتماد نهائي: منسحب الموظف",
          b.note||"");
        return json({ok:true});
      }

      if(b.action==="cancelled"){
        if(!allow(u,"cancel_records"))return json({error:"ليس لديك صلاحية إلغاء المعاملة"},403);
        await finalizeTimer(env,r);
        await env.DB.prepare(`
          UPDATE records SET status='cancelled',requester_note=?,final_approved_at=? WHERE id=?
        `).bind(b.note||null,nowISO(),id).run();
        await recordEvent(env,id,u.id,"إلغاء المعاملة",b.note||"");
        return json({ok:true});
      }

      if(b.action==="reassign"){
        if(!allow(u,"reassign_records"))return json({error:"ليس لديك صلاحية إعادة الإسناد"},403);
        const manager=await env.DB.prepare(
          "SELECT * FROM users WHERE id=? AND role='region' AND active=1"
        ).bind(Number(b.region_user_id)).first();
        if(!manager)return json({error:"اختر مسؤول إقليم نشط"},400);

        await env.DB.prepare(`
          UPDATE records SET region=?,region_user_id=?,updated_at=? WHERE id=?
        `).bind(manager.region,manager.id,nowISO(),id).run();
        await recordEvent(env,id,u.id,"سحب وإعادة إسناد المعاملة",
          `تم إسنادها إلى ${manager.name} — ${manager.region}${b.note?` — ${b.note}`:""}`);
        return json({ok:true});
      }

      return json({error:"إجراء غير معروف"},400);
    }

    if(p==="/api/dashboard"||p==="/api/manager-stats"){
      if(!allow(u,"view_stats"))return json({error:"ليس لديك صلاحية عرض الإحصائيات"},403);

      const rows=await scopedRecords(env,u,url);
      const total=rows.length;
      const count=s=>rows.filter(r=>r.status===s).length;
      const documented=count("final_documented");
      const withdrawn=count("final_withdrawn");
      const required=rows.filter(r=>["waiting_region","returned"].includes(r.status)).length;
      const overdue=rows.filter(r=>r.overdue).length;
      const slaEligible=rows.filter(r=>Number(r.elapsed_seconds||0)>0).length;
      const slaOk=rows.filter(r=>Number(r.elapsed_seconds||0)>0 && Number(r.elapsed_seconds||0)<=SLA_HOURS*3600).length;
      const sla_percent=slaEligible?Math.round(slaOk/slaEligible*100):0;

      const users=await env.DB.prepare(`
        SELECT id,name,username,role,region
        FROM users
        WHERE active=1 AND role IN ('requester','region')
        ORDER BY role,name
      `).all();

      const user_stats=[];
      for(const usr of (users.results||[])){
        const handledRows=(rows||[]).filter(r =>
          usr.role==="region"
            ? Number(r.region_user_id)===Number(usr.id)
            : (Number(r.requester_id)===Number(usr.id)||Number(r.delegated_to_user_id)===Number(usr.id))
        );
        if(u.role!=="admin" && Number(usr.id)!==Number(u.id)) continue;

        const handled=handledRows.length;
        const doc=handledRows.filter(r=>r.status==="final_documented").length;
        const wd=handledRows.filter(r=>r.status==="final_withdrawn").length;
        const late=handledRows.filter(r=>r.overdue).length;
        const delay_seconds=handledRows.reduce((sum,r)=>{
          const elapsed=Number(r.elapsed_seconds||0);
          return sum+Math.max(0,elapsed-SLA_HOURS*3600);
        },0);
        const eligible=handledRows.filter(r=>Number(r.elapsed_seconds||0)>0).length;
        const ok=handledRows.filter(r=>Number(r.elapsed_seconds||0)>0 && Number(r.elapsed_seconds||0)<=SLA_HOURS*3600).length;

        user_stats.push({
          id:usr.id,
          name:usr.name,
          username:usr.username,
          role:usr.role,
          role_label:ROLE_LABELS[usr.role]||usr.role,
          region:usr.region||"",
          handled,
          documented:doc,
          withdrawn:wd,
          overdue:late,
          delay_seconds,
          sla_percent:eligible?Math.round(ok/eligible*100):0
        });
      }

      user_stats.sort((a,b)=>
        b.documented-a.documented ||
        b.handled-a.handled ||
        a.delay_seconds-b.delay_seconds
      );

      const stats={
        total,
        required,
        awaiting_hr:rows.filter(r=>["region_documented","region_withdrawn"].includes(r.status)).length,
        documented,
        withdrawn,
        returned:count("returned"),
        overdue,
        sla_percent,
        user_stats,
        report_date:today()
      };
      return json(stats);
    }

    if(p==="/api/export"){
      if(!allow(u,"export"))return json({error:"ليس لديك صلاحية التصدير"},403);
      const rows=await scopedRecords(env,u,url);
      return json({csv:await csvExport(rows),report_date:today()});
    }

    if(p==="/api/login-audit"&&req.method==="GET"){
      if(!allow(u,"view_login_audit"))return json({error:"غير مصرح"},403);
      const rows=(await env.DB.prepare(`
        SELECT l.*,u.name user_name,u.username
        FROM login_audit l LEFT JOIN users u ON u.id=l.user_id
        ORDER BY l.id DESC LIMIT 5000
      `).all()).results;
      return json({rows});
    }

    if(!p.startsWith("/api/")) return text(HTML);
    return json({error:"غير موجود"},404);
  }
};
