
/* 1S — workflow semantics */
const CASE_STATUS_1S = Object.freeze({
  REQUIRED:'waiting_region',
  APPROVAL:'waiting_approval',
  WITHDRAWAL_APPROVAL:'waiting_withdrawal_approval',
  CLOSED:'closed',
  STOPPED:'stopped',
  CANCELLED:'cancelled',
  WITHDRAWN:'withdrawn'
});
function caseNeedsRegionAction1S(status){
  return ['waiting_region','returned'].includes(String(status||'').toLowerCase());
}
function caseNeedsApproval1S(status){
  return ['waiting_approval','waiting_withdrawal_approval'].includes(String(status||'').toLowerCase());
}
function caseIsFinishedForRegion1S(status){
  return ['closed','stopped','cancelled','withdrawn','verified','documented'].includes(String(status||'').toLowerCase());
}


/* V18.7 — region action semantics */
function isRegionRequiredAction(record){
  const s=String(record?.status||'').trim().toLowerCase();
  return /بانتظار.*إفادة|مطلوب.*إجراء|returned|needs.?action|waiting.*region|correction/.test(s)
         && !/منسحب|withdraw|cancel|ملغ/.test(s);
}
function isRegionWithdrawn(record){
  const s=String(record?.status||'').trim().toLowerCase();
  return /منسحب|withdraw/.test(s);
}
function filterRegionRequiredActions(records){
  return (records||[]).filter(isRegionRequiredAction);
}
function openRegionExternalAction(record, action){
  // External action must execute directly; withdrawn is not routed through
  // the required-actions list and does not open another duplicate card.
  if(action==='withdrawn') return window.location.assign(`/records/${record.id}?action=withdrawn`);
  if(action==='respond') return window.location.assign(`/records/${record.id}?action=respond`);
  if(action==='approve') return window.location.assign(`/records/${record.id}?action=approve`);
}

/* V18.5 — region manager workspace */
function regionManagerBucket(status){
  const s=String(status||'').trim().toLowerCase();
  if(/بانتظار الاعتماد|waiting.*approv|pending.*approv|approval/.test(s)) return 'approval';
  if(/مطلوب.*إجراء|waiting.*region|required|respond/.test(s)) return 'required';
  // "منتهية" means all cases that have already passed through this region,
  // including externally completed/withdrawn/cancelled/stopped/closed states.
  if(/تم التوثيق|منسحب|ملغاة|موقوف|closed|document|withdraw|cancel/.test(s)) return 'completed';
  return 'completed';
}

function buildRegionManagerBuckets(records){
  const out={completed:[],approval:[],required:[]};
  (records||[]).forEach(r=>{
    const b=regionManagerBucket(r.status);
    out[b].push(r);
  });
  return out;
}

const COOKIE="ict_session", DAYS=30, SLA_HOURS=48, IDLE_TIMEOUT_SECONDS=1800, SCHEMA_VERSION=16;
const dashboardCache=new Map();
let schemaReady=null;
const seenSessions=new Map();
const CLOSED=["final_documented","final_withdrawn","cancelled"];
const labels={
 waiting_region:"بانتظار إفادة مسؤول الإقليم",
 returned:"مرتجع للتصحيح",
 region_documented:"تمت الإفادة — بانتظار مراجعة HR",
 region_withdrawn:"تمت الإفادة بالانسحاب — بانتظار مراجعة HR",
 final_documented:"تم التوثيق",
 final_withdrawn:"منسحب الموظف",
 cancelled:"المعاملة ملغاة",
 stopped:"موقوفة"
};
const ALL_PERMS=["view_records","upload_contracts","respond_region","approve","manage_users","manage_regions","manage_delegations","settings","stop_records","cancel_records","export","reassign_records","delegate_records","view_closed","reactivate_records","view_stats","manage_data","view_audit_log","export_audit_log"];
const DEFAULT_REGIONS=["الرياض","مكة المكرمة","المدينة المنورة","القصيم","المنطقة الشرقية","عسير","تبوك","حائل","الحدود الشمالية","جازان","نجران","الباحة","الجوف"];
const ROLE_DEFAULTS={
 admin:ALL_PERMS,
 manager:["view_records","upload_contracts","respond_region","approve","manage_users","manage_regions","manage_delegations","settings","stop_records","cancel_records","export","reassign_records","delegate_records","view_closed","reactivate_records","view_stats","view_audit_log","export_audit_log"],
 supervisor:["view_records","upload_contracts","respond_region","approve","reassign_records","view_closed","view_stats","view_audit_log","export"],
 requester:["view_records","upload_contracts","approve","export","reassign_records","delegate_records","manage_delegations","view_stats","view_audit_log","export_audit_log"],
 region:["view_records","respond_region"],
 viewer:["view_records"]
};
const json=(x,s=200,h={})=>new Response(JSON.stringify(x),{status:s,headers:{"content-type":"application/json;charset=utf-8",...h}});
const hash=async p=>{const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(p));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")};
const token=()=>{const a=new Uint8Array(32);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(2,"0")).join("")};
function cookie(req){const x=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="));return x?x.slice(COOKIE.length+1):null}
function nowIso(){return new Date().toISOString().replace("T"," ").replace(/\.\d{3}Z$/,"")}
async function user(req,env){
 const t=cookie(req); if(!t)return null;
 const u=await env.DB.prepare(`SELECT u.*,s.login_at,s.last_seen_at,s.token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.active=1`).bind(t,Math.floor(Date.now()/1000)).first();
 if(!u)return null;
 const last=parseTs(u.last_seen_at);
 if(last && Date.now()-last > IDLE_TIMEOUT_SECONDS*1000){
   await env.DB.prepare("UPDATE sessions SET logout_at=CURRENT_TIMESTAMP WHERE token=?").bind(t).run();
   await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(t).run();
   seenSessions.delete(t);
   return null;
 }
 const now=Date.now(), seen=seenSessions.get(t)||0;
 if(now-seen>30000){
   seenSessions.set(t,now);
   await env.DB.prepare("UPDATE sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE token=?").bind(t).run();
 }
 return u;
}
async function log(env,r,u,a,n=""){await env.DB.prepare("INSERT INTO audit_log(record_id,user_id,action,note) VALUES(?,?,?,?)").bind(r||null,u||null,a,n||"").run()}
async function regionUser(env,region){return await env.DB.prepare(`SELECT u.*,COUNT(r.id) AS active_load FROM users u LEFT JOIN records r ON r.region_user_id=u.id AND r.status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') WHERE u.role='region' AND u.active=1 AND u.region=? GROUP BY u.id ORDER BY active_load ASC,u.id ASC LIMIT 1`).bind(region).first()}
function permsOf(u){if(!u)return [];if(u.role==="admin")return ALL_PERMS;return String(u.permissions||"").split(",").map(x=>x.trim()).filter(Boolean)}
function allow(u,p){return !!(u&&(u.role==="admin"||permsOf(u).includes(p)))}
async function ensureSchema(env){
 if(schemaReady) return schemaReady;
 schemaReady=(async()=>{
   await env.DB.prepare(`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`).run();
   const meta=await env.DB.prepare(`SELECT value FROM schema_meta WHERE key='version'`).first();
   if(Number(meta?.value||0) >= SCHEMA_VERSION) return;
   const adds=[
    ["users","permissions","TEXT DEFAULT ''"],
    ["records","transaction_no","TEXT"],["records","interruption_transaction_no","TEXT"],["records","region_note","TEXT"],["records","requester_note","TEXT"],["records","region_responded_at","TEXT"],["records","final_approved_at","TEXT"],["records","updated_at","TEXT DEFAULT CURRENT_TIMESTAMP"],["records","end_date","TEXT"],["records","original_region_user_id","INTEGER"],["records","delegated_from_user_id","INTEGER"],["records","delegated_at","TEXT"],["records","timer_paused_at","TEXT"],["records","timer_end_at","TEXT"],["records","paused_seconds","INTEGER DEFAULT 0"],["records","stage_started_at","TEXT"],["records","stopped_at","TEXT"],["records","stopped_by","INTEGER"],["records","completed_at","TEXT"],["records","delegated_to_user_id","INTEGER"],
    ["sessions","login_at","TEXT DEFAULT CURRENT_TIMESTAMP"],["sessions","last_seen_at","TEXT DEFAULT CURRENT_TIMESTAMP"],["sessions","logout_at","TEXT"],["sessions","ip","TEXT"],["sessions","user_agent","TEXT"]
   ];
   for(const [table,col,type] of adds){try{await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`).run()}catch{}}
   await env.DB.prepare(`CREATE TABLE IF NOT EXISTS regions(name TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
   await env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,login_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,logout_at TEXT,ip TEXT,user_agent TEXT)`).run();
   await env.DB.prepare(`CREATE TABLE IF NOT EXISTS delegations_v2(id INTEGER PRIMARY KEY AUTOINCREMENT,source_user_id INTEGER NOT NULL,target_user_id INTEGER NOT NULL,starts_at TEXT,ends_at TEXT,active INTEGER NOT NULL DEFAULT 1,created_by INTEGER,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,revoked_at TEXT,revoked_by INTEGER,note TEXT DEFAULT '')`).run();
   await env.DB.prepare(`CREATE TABLE IF NOT EXISTS record_stages(id INTEGER PRIMARY KEY AUTOINCREMENT,record_id INTEGER NOT NULL,stage TEXT NOT NULL,user_id INTEGER,started_at TEXT NOT NULL,ended_at TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
   for(const name of DEFAULT_REGIONS) await env.DB.prepare("INSERT OR IGNORE INTO regions(name,active) VALUES(?,1)").bind(name).run();
   const existing=await env.DB.prepare("SELECT DISTINCT region FROM users WHERE region IS NOT NULL AND TRIM(region)<>''").all();
   for(const x of existing.results) await env.DB.prepare("INSERT OR IGNORE INTO regions(name,active) VALUES(?,1)").bind(x.region).run();
   for(const [role,perms] of Object.entries(ROLE_DEFAULTS)) { try { await env.DB.prepare("UPDATE users SET permissions=? WHERE role=? AND (permissions IS NULL OR permissions='')").bind(perms.join(","),role).run(); } catch {} }
   try { await env.DB.prepare("UPDATE records SET original_region_user_id=region_user_id WHERE original_region_user_id IS NULL").run(); } catch {}
   try { await env.DB.prepare("UPDATE records SET updated_at=COALESCE(updated_at,created_at)").run(); } catch {}
   const indexes=[
    "CREATE INDEX IF NOT EXISTS idx_sessions_token_expires ON sessions(token,expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_users_username_active ON users(username,active)",
    "CREATE INDEX IF NOT EXISTS idx_users_role_active_region ON users(role,active,region)",
    "CREATE INDEX IF NOT EXISTS idx_records_region_status_created ON records(region_user_id,status,created_at)",
    "CREATE INDEX IF NOT EXISTS idx_records_requester_status ON records(requester_id,status)",
    "CREATE INDEX IF NOT EXISTS idx_records_delegated_status ON records(delegated_to_user_id,status)",
    "CREATE INDEX IF NOT EXISTS idx_records_created ON records(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_record_id ON audit_log(record_id,id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_stages_record ON record_stages(record_id,ended_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_delegations_source_active ON delegations_v2(source_user_id,active,starts_at,ends_at)",
    "CREATE INDEX IF NOT EXISTS idx_delegations_target_active ON delegations_v2(target_user_id,active,starts_at,ends_at)"
   ];
   for(const sql of indexes){try{await env.DB.prepare(sql).run()}catch{}}
   await env.DB.prepare("INSERT INTO schema_meta(key,value) VALUES('version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(String(SCHEMA_VERSION)).run();
 })().catch(e=>{schemaReady=null;throw e});
 return schemaReady;
}
function canSeeClosed(u){return u?.role==="region" || allow(u,"view_closed")}
function parseTs(x){if(!x)return null;const s=String(x).trim().replace(" ","T");return new Date(/Z$/.test(s)?s:s+"Z").getTime()}
function durationSeconds(r){const start=parseTs(r?.created_at);if(!start)return 0;let end=parseTs(r?.timer_end_at);if(!end&&r?.status!=="stopped")end=Date.now();if(!end)end=parseTs(r?.timer_paused_at)||Date.now();const paused=Number(r?.paused_seconds||0)*1000;return Math.max(0,Math.floor((end-start-paused)/1000))}
function durationLabel(sec){sec=Math.max(0,Number(sec)||0);let d=Math.floor(sec/86400);sec%=86400;let h=Math.floor(sec/3600);sec%=3600;let m=Math.floor(sec/60);let s=sec%60;return `${d?d+" يوم ":""}${h?h+" ساعة ":""}${m?m+" دقيقة ":""}${s+" ثانية"}`.trim()||"0 ثانية"}
function responseDuration(r){if(!r?.region_responded_at)return null;return Math.max(0,Math.floor((parseTs(r.region_responded_at)-parseTs(r.created_at))/1000))}
function withMeta(r){const start=r?.created_at||null;const age=durationSeconds(r);const timerEnd=r?.timer_end_at||(r?.status==="stopped"?r?.stopped_at:null);return {...r,status_label:labels[r.status]||r.status,timer_start_at:start,timer_end_at:timerEnd,sla_hours:SLA_HOURS,age_seconds:age,duration_label:durationLabel(age),overdue:!CLOSED.includes(r.status)&&r?.status!=="stopped"&&!!start&&age>=SLA_HOURS*3600}}
async function currentDelegation(env,sourceId){
 const now=nowIso();
 return await env.DB.prepare(`SELECT d.*,u.name target_name FROM delegations_v2 d JOIN users u ON u.id=d.target_user_id WHERE d.source_user_id=? AND d.active=1 AND u.active=1 AND (d.starts_at IS NULL OR d.starts_at<=?) AND (d.ends_at IS NULL OR d.ends_at>=?) ORDER BY d.id DESC LIMIT 1`).bind(sourceId,now,now).first();
}
async function stageStart(env,recordId,stage,userId){
 await env.DB.prepare("INSERT INTO record_stages(record_id,stage,user_id,started_at) VALUES(?,?,?,CURRENT_TIMESTAMP)").bind(recordId,stage,userId||null).run();
}
async function stageClose(env,recordId,stage){
 await env.DB.prepare("UPDATE record_stages SET ended_at=CURRENT_TIMESTAMP WHERE record_id=? AND stage=? AND ended_at IS NULL").bind(recordId,stage).run();
}
async function stageTransition(env,record,stage,userId){
 if(record?.id){
   const current=await env.DB.prepare("SELECT stage FROM record_stages WHERE record_id=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1").bind(record.id).first();
   if(current?.stage) await stageClose(env,record.id,current.stage);
   if(stage) await stageStart(env,record.id,stage,userId);
 }
}
async function syncDelegations(env){
 const now=nowIso();
 const active=(await env.DB.prepare(`SELECT * FROM delegations_v2 WHERE active=1 AND starts_at IS NOT NULL AND starts_at<=? AND (ends_at IS NULL OR ends_at>=?)`).bind(now,now).all()).results;
 for(const d of active){
   await env.DB.prepare(`UPDATE records SET delegated_to_user_id=?,delegated_from_user_id=CASE WHEN delegated_to_user_id IS NULL THEN ? ELSE delegated_from_user_id END,delegated_at=COALESCE(delegated_at,CURRENT_TIMESTAMP) WHERE requester_id=? AND status NOT IN ('final_documented','final_withdrawn','cancelled','stopped')`).bind(d.target_user_id,d.source_user_id,d.source_user_id).run();
 }
 const expired=(await env.DB.prepare(`SELECT * FROM delegations_v2 WHERE active=1 AND ends_at IS NOT NULL AND ends_at<?`).bind(now).all()).results;
 for(const d of expired){
   await env.DB.prepare(`UPDATE delegations_v2 SET active=0,revoked_at=CURRENT_TIMESTAMP WHERE id=?`).bind(d.id).run();
   await env.DB.prepare(`UPDATE records SET delegated_to_user_id=NULL,delegated_from_user_id=NULL,delegated_at=NULL WHERE requester_id=? AND delegated_to_user_id=? AND status NOT IN ('final_documented','final_withdrawn','cancelled','stopped')`).bind(d.source_user_id,d.target_user_id).run();
 }
}
async function delegatedTo(env,sourceId){
 const d=await currentDelegation(env,sourceId);
 return d?.target_user_id||null;
}
async function isEffectiveRequester(env,r,u){
 if(!r||!u)return false;
 if(r.requester_id===u.id)return true;
 const d=await currentDelegation(env,r.requester_id);
 return !!d&&d.target_user_id===u.id;
}
function stageForStatus(status){
 if(status==="waiting_region")return "region";
 if(status==="returned")return "hr";
 if(status==="region_documented"||status==="region_withdrawn")return "approval";
 if(status==="stopped")return "stopped";
 if(CLOSED.includes(status))return "closed";
 return null;
}
function stageSeconds(rows,stage){
 const now=Date.now(); return (rows||[]).filter(x=>x.stage===stage).reduce((sum,x)=>{
   const a=parseTs(x.started_at), b=x.ended_at?parseTs(x.ended_at):now;
   return sum+(a&&b?Math.max(0,Math.floor((b-a)/1000)):0);
 },0);
}
function reportDate(){return new Date().toISOString().slice(0,10)}
function clientIp(req){return req.headers.get("CF-Connecting-IP")||req.headers.get("X-Forwarded-For")||"—"}
function roleFilterRequired(u){return u.role==="region"?"r.status IN ('waiting_region','returned')":"r.status IN ('region_documented','region_withdrawn','returned')"}

export default {async fetch(req,env){
 await ensureSchema(env); const url=new URL(req.url),p=url.pathname; const u=await user(req,env);
 if(p==="/api/me")return json({user:u?{id:u.id,name:u.name,username:u.username,role:u.role,region:u.region,permissions:permsOf(u)}:null});
 if(p==="/api/setup"&&req.method==="POST"){const c=await env.DB.prepare("SELECT COUNT(*) c FROM users").first();if(Number(c.c))return json({error:"تمت التهيئة مسبقاً"},400);const b=await req.json(),h=await hash(String(b.password||"1234"));await env.DB.prepare("INSERT INTO users(username,name,password_hash,role,permissions,active) VALUES('admin',?,?, 'admin',?,1)").bind(b.name||"المدير",h,ALL_PERMS.join(",")).run();return json({ok:true})}
 if(p==="/api/login"&&req.method==="POST"){const b=await req.json(),username=String(b.username||"").trim(),x=await env.DB.prepare("SELECT * FROM users WHERE username=? AND active=1").bind(username).first();if(!x||x.password_hash!==await hash(String(b.password||""))){await log(env,null,null,"محاولة دخول فاشلة",`اسم المستخدم: ${username}`);return json({error:"بيانات الدخول غير صحيحة"},401)}const t=token(),exp=Math.floor(Date.now()/1000)+DAYS*86400;await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at,login_at,last_seen_at,ip,user_agent) VALUES(?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?,?)").bind(t,x.id,exp,clientIp(req),req.headers.get("User-Agent")||"—").run();await log(env,null,x.id,"تسجيل دخول",`IP: ${clientIp(req)}`);return json({ok:true},200,{"set-cookie":`${COOKIE}=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${DAYS*86400}`})}
 if(p==="/api/logout"){const t=cookie(req);if(t){const s=await env.DB.prepare("SELECT user_id FROM sessions WHERE token=?").bind(t).first();if(s)await log(env,null,s.user_id,"تسجيل خروج",`IP: ${clientIp(req)}`);await env.DB.prepare("UPDATE sessions SET logout_at=CURRENT_TIMESTAMP,last_seen_at=CURRENT_TIMESTAMP WHERE token=?").bind(t).run();await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(t).run()}return json({ok:true},200,{"set-cookie":`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`})}
 if(!u)return json({error:"غير مصرح"},401);
 if(p==="/api/delegations"&&req.method==="GET"){
   await syncDelegations(env);
   if(!allow(u,"manage_delegations")&&u.role!=="admin")return json({error:"غير مصرح"},403);
   const rows=await env.DB.prepare(`SELECT d.*,s.name source_name,t.name target_name FROM delegations_v2 d LEFT JOIN users s ON s.id=d.source_user_id LEFT JOIN users t ON t.id=d.target_user_id ORDER BY d.id DESC`).all();
   return json({delegations:rows.results});
 }
 if(p==="/api/delegations"&&req.method==="POST"){
   if(!allow(u,"manage_delegations")&&u.role!=="admin")return json({error:"غير مصرح"},403);
   const b=await req.json(),sourceId=Number(b.source_user_id),targetId=Number(b.target_user_id);
   if(!sourceId||!targetId||sourceId===targetId)return json({error:"اختر مستخدمين مختلفين"},400);
   const source=await env.DB.prepare("SELECT * FROM users WHERE id=? AND active=1").bind(sourceId).first();
   const target=await env.DB.prepare("SELECT * FROM users WHERE id=? AND active=1").bind(targetId).first();
   if(!source||!target)return json({error:"المستخدم المصدر أو المفوض إليه غير موجود"},400);
   if(!["requester","admin"].includes(source.role))return json({error:"التفويض متاح لحسابات HR أو المدير فقط"},400);
   await env.DB.prepare("UPDATE delegations_v2 SET active=0,revoked_at=CURRENT_TIMESTAMP,revoked_by=? WHERE source_user_id=? AND active=1").bind(u.id,sourceId).run();
   const d=await env.DB.prepare(`INSERT INTO delegations_v2(source_user_id,target_user_id,starts_at,ends_at,active,created_by,note) VALUES(?,?,?,?,1,?,?) RETURNING id`).bind(sourceId,targetId,b.starts_at||nowIso(),b.ends_at||null,u.id,b.note||"").first();
   if(!b.starts_at || parseTs(b.starts_at)<=Date.now()) await env.DB.prepare(`UPDATE records SET delegated_to_user_id=? WHERE requester_id=? AND status NOT IN ('final_documented','final_withdrawn','cancelled')`).bind(targetId,sourceId).run();
   await log(env,null,u.id,"إنشاء تفويض",`من ${source.name} إلى ${target.name}${b.ends_at?` حتى ${b.ends_at}`:""}`);
   return json({ok:true,id:d.id});
 }
 const dg=p.match(/^\/api\/delegations\/(\d+)$/);
 if(dg&&req.method==="POST"){
   if(!allow(u,"manage_delegations")&&u.role!=="admin")return json({error:"غير مصرح"},403);
   const id=Number(dg[1]),d=await env.DB.prepare("SELECT * FROM delegations_v2 WHERE id=?").bind(id).first();
   if(!d)return json({error:"التفويض غير موجود"},404);
   await env.DB.prepare("UPDATE delegations_v2 SET active=0,revoked_at=CURRENT_TIMESTAMP,revoked_by=? WHERE id=?").bind(u.id,id).run();
   await env.DB.prepare("UPDATE records SET delegated_to_user_id=NULL,delegated_at=NULL WHERE requester_id=? AND delegated_to_user_id=? AND status NOT IN ('final_documented','final_withdrawn','cancelled')").bind(d.source_user_id,d.target_user_id).run();
   await log(env,null,u.id,"إلغاء تفويض",`تفويض #${id}`);
   return json({ok:true});
 }
 if(p==="/api/audit"&&req.method==="GET"){
   if(!allow(u,"view_audit_log"))return json({error:"ليس لديك صلاحية سجل النشاط"},403);
   const q=url.searchParams.get("q")||"",action=url.searchParams.get("action")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"";
   let sql=`SELECT a.*,u.name actor_name,u.username,u.role FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE 1=1`,args=[];
   if(q){const z="%"+q+"%";sql+=" AND (u.name LIKE ? OR u.username LIKE ? OR a.action LIKE ? OR a.note LIKE ?)";args.push(z,z,z,z)}
   if(action){sql+=" AND a.action=?";args.push(action)}
   if(from){sql+=" AND a.created_at>=?";args.push(from+" 00:00:00")}
   if(to){sql+=" AND a.created_at<=?";args.push(to+" 23:59:59")}
   sql+=" ORDER BY a.id DESC LIMIT 3000";
   const rows=await env.DB.prepare(sql).bind(...args).all();
   return json({events:rows.results});
 }
 if(p==="/api/audit/export"&&req.method==="GET"){
   if(!allow(u,"export_audit_log"))return json({error:"ليس لديك صلاحية تصدير سجل النشاط"},403);
   const rows=(await env.DB.prepare(`SELECT a.created_at AS "التاريخ والوقت",u.name AS "المستخدم",u.username AS "اسم المستخدم",u.role AS "الدور",a.action AS "النشاط",a.record_id AS "رقم المعاملة",a.note AS "التفاصيل" FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 10000`).all()).results;
   return json({rows,report_date:reportDate()});
 }
 if(p==="/api/records"&&req.method==="GET"){
  await syncDelegations(env);
  const q=url.searchParams.get("q")||"",s=url.searchParams.get("status")||"",region=url.searchParams.get("region")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"",limit=Math.min(100,Math.max(1,Number(url.searchParams.get("limit")||60))),offset=Math.max(0,Number(url.searchParams.get("offset")||0));let sql=`SELECT r.*,ru.name region_user_name,req.name requester_name,ou.name original_manager_name,du.name delegated_from_name FROM records r LEFT JOIN users ru ON ru.id=r.region_user_id LEFT JOIN users req ON req.id=r.requester_id LEFT JOIN users ou ON ou.id=r.original_region_user_id LEFT JOIN users du ON du.id=r.delegated_from_user_id WHERE 1=1`,a=[];
  if(u.role==="region"){sql+=" AND (r.region_user_id=? OR r.original_region_user_id=?)";a.push(u.id,u.id)}
  if(u.role==="requester"){sql+=" AND (r.requester_id=? OR r.delegated_to_user_id=?)";a.push(u.id,u.id)}
  if(region){sql+=" AND r.region=?";a.push(region)}
  if(from){sql+=" AND r.created_at>=?";a.push(from+" 00:00:00")}
  if(to){sql+=" AND r.created_at<=?";a.push(to+" 23:59:59")}
  if(!canSeeClosed(u))sql+=" AND r.status NOT IN ('final_documented','final_withdrawn','cancelled')";
  if(q){sql+=" AND (r.employee_no LIKE ? OR r.employee_name LIKE ? OR r.transaction_no LIKE ? OR r.interruption_transaction_no LIKE ?)";const z="%"+q+"%";a.push(z,z,z,z)}
  if(s==="required")sql+=` AND ${roleFilterRequired(u)}`;else if(s==="mine")sql+=` AND ${u.role==='region'?"(r.region_user_id=? OR r.original_region_user_id=?)":"r.requester_id=?"}`,a.push(...(u.role==='region'?[u.id,u.id]:[u.id]));else if(s==="approval")sql+=" AND r.status IN ('region_documented','region_withdrawn')";else if(s==="closed")sql+=" AND r.status IN ('final_documented','final_withdrawn','cancelled','stopped')";else if(s==="overdue"){}else if(s)sql+=" AND r.status=?",a.push(s);
  const countSql=sql; const countArgs=a.slice(); sql+=" ORDER BY r.id DESC LIMIT ? OFFSET ?";a.push(limit+1,offset); const [countRow,rows]=await env.DB.batch([env.DB.prepare(`SELECT COUNT(*) c FROM (${countSql})`).bind(...countArgs),env.DB.prepare(sql).bind(...a)]); let out=rows.results.map(withMeta);let hasMore=out.length>limit;if(hasMore)out=out.slice(0,limit);if(s==="overdue")out=out.filter(x=>x.overdue);return json({records:out,has_more:hasMore,offset,limit,total_count:Number(countRow.results?.[0]?.c||0)})
 }
 if(p==="/api/managers"&&req.method==="GET"){if(!allow(u,"view_stats")&&!allow(u,"reassign_records"))return json({error:"غير مصرح"},403);const rows=await env.DB.prepare("SELECT id,name,username,region FROM users WHERE role='region' AND active=1 ORDER BY name").all();return json({managers:rows.results})}
 if(p==="/api/regions"&&req.method==="GET"){const all=url.searchParams.get("include_inactive")==="1"&&allow(u,"manage_regions");const rows=await env.DB.prepare(`SELECT name,active,created_at FROM regions ${all?"":"WHERE active=1"} ORDER BY active DESC,name`).all();return json({regions:rows.results})}
 if(p==="/api/regions"&&req.method==="POST"){if(!allow(u,"manage_regions"))return json({error:"ليس لديك صلاحية إدارة الأقاليم"},403);const b=await req.json(),action=String(b.action||"add"),name=String(b.name||"").trim();if(action==="add"){if(!name)return json({error:"أدخل اسم الإقليم"},400);try{await env.DB.prepare("INSERT INTO regions(name,active) VALUES(?,1)").bind(name).run()}catch{return json({error:"الإقليم موجود مسبقاً"},400)}await log(env,null,u.id,"إضافة إقليم",name);return json({ok:true})}const oldName=String(b.old_name||"").trim();if(!oldName)return json({error:"الإقليم غير محدد"},400);if(action==="edit"){if(!name)return json({error:"أدخل اسم الإقليم الجديد"},400);if(name===oldName)return json({ok:true});if(await env.DB.prepare("SELECT 1 FROM regions WHERE name=?").bind(name).first())return json({error:"اسم الإقليم مستخدم مسبقاً"},400);if(!await env.DB.prepare("SELECT 1 FROM regions WHERE name=? AND active=1").bind(oldName).first())return json({error:"الإقليم غير موجود"},404);await env.DB.prepare("UPDATE regions SET name=? WHERE name=?").bind(name,oldName).run();await env.DB.prepare("UPDATE users SET region=? WHERE region=?").bind(name,oldName).run();await env.DB.prepare("UPDATE records SET region=? WHERE region=?").bind(name,oldName).run();await log(env,null,u.id,"تعديل إقليم",`${oldName} → ${name}`);return json({ok:true})}if(action==="toggle"){const current=await env.DB.prepare("SELECT active FROM regions WHERE name=?").bind(oldName).first();if(!current)return json({error:"الإقليم غير موجود"},404);if(Number(current.active)===1){if(await env.DB.prepare("SELECT 1 FROM users WHERE role='region' AND active=1 AND region=? LIMIT 1").bind(oldName).first())return json({error:"انقل أو عطّل مسؤول الإقليم أولاً قبل تعطيل الإقليم"},400);}await env.DB.prepare("UPDATE regions SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE name=?").bind(oldName).run();await log(env,null,u.id,"تغيير حالة إقليم",oldName);return json({ok:true})}if(action==="delete"){if(!await env.DB.prepare("SELECT 1 FROM regions WHERE name=? AND active=1").bind(oldName).first())return json({error:"الإقليم غير موجود"},404);if(await env.DB.prepare("SELECT 1 FROM users WHERE role='region' AND active=1 AND region=? LIMIT 1").bind(oldName).first())return json({error:"لا يمكن حذف الإقليم قبل نقل أو تعطيل مسؤول الإقليم المرتبط به"},400);await env.DB.prepare("UPDATE regions SET active=0 WHERE name=?").bind(oldName).run();await log(env,null,u.id,"حذف/أرشفة إقليم",oldName);return json({ok:true})}return json({error:"إجراء غير معروف"},400)}
 if(p==="/api/records"&&req.method==="POST"){if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية رفع المعاملات"},403);const b=await req.json();if(!b.employee_no||!b.employee_name||!b.region||!b.start_date||!b.transaction_no)return json({error:"أكمل رقم الموظف والاسم والإقليم وتاريخ المباشرة ورقم معاملة التعيين"},400);const ru=await regionUser(env,b.region);if(!ru)return json({error:"لا يوجد مسؤول إقليم نشط مرتبط بهذا الإقليم"},400);const delegation=await currentDelegation(env,u.id);
const r=await env.DB.prepare(`INSERT INTO records(employee_no,employee_name,region,start_date,transaction_no,status,requester_id,region_user_id,original_region_user_id,delegated_to_user_id,stage_started_at,updated_at) VALUES(?,?,?,?,?,'waiting_region',?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id`).bind(b.employee_no.trim(),b.employee_name.trim(),b.region,b.start_date,b.transaction_no.trim(),u.id,ru.id,ru.id,delegation?.target_user_id||null).first();
await stageStart(env,r.id,"region",ru.id);
dashboardCache.clear();
await log(env,r.id,u.id,"إنشاء المعاملة",`أُسندت إلى ${ru.name}${delegation?` — والمفوض الحالي: ${delegation.target_name}`:""}`);
return json({ok:true,id:r.id})}
 if(p==="/api/records/bulk"&&req.method==="POST"){if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية الرفع الجماعي"},403);const b=await req.json(),rows=Array.isArray(b.rows)?b.rows:[];let added=0,errors=[];for(const x of rows){if(!x.employee_no&&!x.employee_name&&!x.region)continue;if(!x.employee_no||!x.employee_name||!x.region||!x.start_date||!x.transaction_no){errors.push({row:x.row_no||"?",reason:"بيانات أساسية ناقصة"});continue}const ru=await regionUser(env,x.region);if(!ru){errors.push({row:x.row_no,reason:"لا يوجد مسؤول نشط لهذا الإقليم"});continue}try{const delegation=await currentDelegation(env,u.id);
const r=await env.DB.prepare(`INSERT INTO records(employee_no,employee_name,region,start_date,transaction_no,interruption_transaction_no,status,requester_id,region_user_id,original_region_user_id,delegated_to_user_id,stage_started_at,updated_at) VALUES(?,?,?,?,?,?,'waiting_region',?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id`).bind(x.employee_no.trim(),x.employee_name.trim(),x.region,x.start_date,x.transaction_no.trim(),null,u.id,ru.id,ru.id,delegation?.target_user_id||null).first();
await stageStart(env,r.id,"region",ru.id);
await log(env,r.id,u.id,"إنشاء المعاملة من رفع جماعي",`أُسندت إلى ${ru.name}${delegation?` — والمفوض الحالي: ${delegation.target_name}`:""}`);
dashboardCache.clear(); added++}catch{errors.push({row:x.row_no,reason:"تعذر إنشاء المعاملة"})}}return json({ok:true,added,skipped:errors.length,errors})}
 const m=p.match(/^\/api\/records\/(\d+)$/);if(m&&req.method==="GET"){const id=Number(m[1]),r=await env.DB.prepare(`SELECT r.*,ru.name region_user_name,req.name requester_name,ou.name original_manager_name,du.name delegated_from_name FROM records r LEFT JOIN users ru ON ru.id=r.region_user_id LEFT JOIN users req ON req.id=r.requester_id LEFT JOIN users ou ON ou.id=r.original_region_user_id LEFT JOIN users du ON du.id=r.delegated_from_user_id WHERE r.id=?`).bind(id).first();if(!r)return json({error:"المعاملة غير موجودة"},404);
const allowed=u.role==="admin"||u.role==="viewer"||u.role==="region"&&r.region_user_id===u.id||u.role==="requester"&&(await isEffectiveRequester(env,r,u));
if(!allowed)return json({error:"لا تملك صلاحية فتح هذه المعاملة"},403);
const ev=await env.DB.prepare(`SELECT a.*,u.name actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.record_id=? ORDER BY a.id ASC`).bind(id).all();
let stages=(await env.DB.prepare(`SELECT rs.*,u.name user_name FROM record_stages rs LEFT JOIN users u ON u.id=rs.user_id WHERE rs.record_id=? ORDER BY rs.id ASC`).bind(id).all()).results;
if(!stages.length&&stageForStatus(r.status)){await stageStart(env,id,stageForStatus(r.status),r.region_user_id||r.requester_id);stages=(await env.DB.prepare(`SELECT rs.*,u.name user_name FROM record_stages rs LEFT JOIN users u ON u.id=rs.user_id WHERE rs.record_id=? ORDER BY rs.id ASC`).bind(id).all()).results;}
return json({record:withMeta(r),events:ev.results,stages})}
 if(m&&req.method==="POST"){
  const id=Number(m[1]),b=await req.json(),r=await env.DB.prepare("SELECT * FROM records WHERE id=?").bind(id).first();
  if(!r)return json({error:"المعاملة غير موجودة"},404);
  const owner=u.role==="admin"||u.role==="region"&&r.region_user_id===u.id||u.role==="requester"&&(await isEffectiveRequester(env,r,u));
  if(!owner)return json({error:"لا تملك صلاحية تعديل هذه المعاملة"},403);
  dashboardCache.clear();

  if(b.action==="reassign"){
    if(!allow(u,"reassign_records"))return json({error:"ليس لديك صلاحية إعادة الإسناد"},403);
    const manager=await env.DB.prepare("SELECT * FROM users WHERE id=? AND role='region' AND active=1").bind(Number(b.region_user_id)).first();
    if(!manager)return json({error:"المسؤول الجديد غير موجود"},400);
    await env.DB.prepare("UPDATE records SET region=?,region_user_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(manager.region,manager.id,id).run();
    await stageTransition(env,r,"region",manager.id);
    await log(env,id,u.id,"سحب وإعادة إسناد",`تم إسناد المعاملة إلى ${manager.name} — ${manager.region}${b.note?` — ${b.note}`:""}`);
    return json({ok:true});
  }

  if(b.action==="return"){
    if(!allow(u,"approve"))return json({error:"ليس لديك صلاحية إرجاع المعاملة"},403);
    if(!["requester","admin"].includes(u.role))return json({error:"الإرجاع متاح لـ HR أو المدير"},403);
    if(!b.note?.trim())return json({error:"اكتب سبب الإرجاع قبل الإرسال"},400);
    await env.DB.prepare("UPDATE records SET status='returned',requester_note=?,stage_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,timer_paused_at=NULL,timer_end_at=NULL WHERE id=?").bind(b.note.trim(),id).run();
    await stageTransition(env,r,"hr",u.id);
    await log(env,id,u.id,"إرجاع للتصحيح",b.note.trim());
    return json({ok:true});
  }

  if(b.action==="stop"){
    if(!allow(u,"stop_records"))return json({error:"ليس لديك صلاحية إيقاف المعاملة"},403);
    if(CLOSED.includes(r.status)||r.status==="stopped")return json({error:"المعاملة ليست نشطة"},400);
    const pausedAt=nowIso();
    await env.DB.prepare("UPDATE records SET status='stopped',requester_note=?,timer_paused_at=?,timer_end_at=?,stopped_at=?,stopped_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(b.note||"",pausedAt,pausedAt,pausedAt,u.id,id).run();
    await stageTransition(env,r,"stopped",u.id);
    await log(env,id,u.id,"إيقاف المعاملة",b.note||"");
    return json({ok:true});
  }

  if(b.action==="reactivate"){
    if(!allow(u,"reactivate_records"))return json({error:"ليس لديك صلاحية إعادة تنشيط المعاملة"},403);
    if(!(CLOSED.includes(r.status)||r.status==="stopped"))return json({error:"المعاملة ليست منتهية أو موقوفة"},400);
    const next=r.status==="final_withdrawn"?"region_withdrawn":r.status==="final_documented"?"region_documented":"waiting_region";
    let pauseAdd=0;if(r.timer_paused_at)pauseAdd=Math.max(0,Math.floor((Date.now()-parseTs(r.timer_paused_at))/1000));
await env.DB.prepare("UPDATE records SET status=?,final_approved_at=NULL,timer_end_at=NULL,timer_paused_at=NULL,paused_seconds=COALESCE(paused_seconds,0)+?,stopped_at=NULL,stopped_by=NULL,stage_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(next,pauseAdd,id).run();
    await stageTransition(env,r,next==="waiting_region"||next==="returned"?"region":"approval",u.id);
    await log(env,id,u.id,"إعادة تنشيط المعاملة",`الحالة الجديدة: ${labels[next]}`);
    return json({ok:true});
  }

  if(b.action==="region_documented"||b.action==="region_withdrawn"){
    if(!allow(u,"respond_region"))return json({error:"ليس لديك صلاحية إفادة مسؤول الإقليم"},403);
    if(u.role!=="region"&&u.role!=="admin")return json({error:"هذا الإجراء لمسؤول الإقليم فقط"},403);
    if(b.action==="region_withdrawn"&&(!b.end_date||!b.interruption_transaction_no))return json({error:"الانسحاب يتطلب تاريخ نهاية الدوام ورقم معاملة الانقطاع أو اتخاذ الإجراء"},400);
    const next=b.action==="region_documented"?"region_documented":"region_withdrawn";
    await env.DB.prepare("UPDATE records SET status=?,end_date=?,interruption_transaction_no=?,region_note=?,region_responded_at=CURRENT_TIMESTAMP,stage_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,timer_paused_at=NULL,timer_end_at=NULL WHERE id=?").bind(next,b.end_date||r.end_date||null,b.interruption_transaction_no||r.interruption_transaction_no||null,b.note||null,id).run();
    await stageTransition(env,r,"approval",u.id);
    await log(env,id,u.id,next==="region_documented"?"إفادة: تم التوثيق":"إفادة: منسحب الموظف",b.note||"");
    return json({ok:true});
  }

  if(b.action==="final_documented"||b.action==="final_withdrawn"||b.action==="cancelled"){
    if(!allow(u,"approve")&&!(b.action==="cancelled"&&allow(u,"cancel_records")))return json({error:"ليس لديك صلاحية الاعتماد أو الإلغاء"},403);
    if(u.role!=="admin"&&u.role!=="requester")return json({error:"الاعتماد النهائي متاح لـ HR أو المدير"},403);
    if(b.action==="final_withdrawn"&&(!r.end_date||!r.interruption_transaction_no))return json({error:"بيانات الانسحاب غير مكتملة"},400);
    const next=b.action==="final_documented"?"final_documented":b.action==="final_withdrawn"?"final_withdrawn":"cancelled";
    await env.DB.prepare("UPDATE records SET status=?,requester_note=?,final_approved_at=CURRENT_TIMESTAMP,timer_end_at=CURRENT_TIMESTAMP,timer_paused_at=NULL,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(next,b.note||null,id).run();
    await stageTransition(env,r,"closed",u.id);
    dashboardCache.clear();
    await log(env,id,u.id,next==="cancelled"?"إلغاء المعاملة":next==="final_withdrawn"?"اعتماد نهائي: منسحب الموظف":"اعتماد نهائي: تم التوثيق",b.note||"");
    return json({ok:true});
  }

  return json({error:"إجراء غير معروف"},400);
 }
 if(p==="/api/dashboard"){
  await syncDelegations(env);
  if(!allow(u,"view_stats")&&u.role!=="region")return json({error:"ليس لديك صلاحية عرض الإحصائيات"},403);
  const cacheKey=`${u.id}:${u.role}:${u.region||""}`; const cached=dashboardCache.get(cacheKey); if(cached && Date.now()-cached.at<5000) return json(cached.data);

  const regionOnly=u.role==="region";
  const where=regionOnly?" WHERE region_user_id=? AND created_at>=datetime('now','-6 day')":" WHERE 1=1";
  const bind=regionOnly?[u.id]:[];
  const summary=await env.DB.prepare(`SELECT COUNT(*) total,
    SUM(CASE WHEN status IN ('waiting_region','returned') THEN 1 ELSE 0 END) required,
    SUM(CASE WHEN status='final_documented' THEN 1 ELSE 0 END) documented,
    SUM(CASE WHEN status='final_withdrawn' THEN 1 ELSE 0 END) withdrawn,
    SUM(CASE WHEN status='stopped' THEN 1 ELSE 0 END) stopped,
    SUM(CASE WHEN status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') THEN 1 ELSE 0 END) inprog,
    SUM(CASE WHEN status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') AND created_at<=datetime('now','-48 hour') THEN 1 ELSE 0 END) overdue
    FROM records${where}`).bind(...bind).first();
  let sql=`SELECT u.id,u.name,u.username,u.region,
    COUNT(r.id) total,
    SUM(CASE WHEN r.status IN ('waiting_region','returned') THEN 1 ELSE 0 END) required,
    SUM(CASE WHEN r.status IN ('region_documented','region_withdrawn') THEN 1 ELSE 0 END) awaiting_approval,
    SUM(CASE WHEN r.status IN ('final_documented','final_withdrawn') THEN 1 ELSE 0 END) completed,
    SUM(CASE WHEN r.status='returned' THEN 1 ELSE 0 END) returned,
    SUM(CASE WHEN r.status='stopped' THEN 1 ELSE 0 END) stopped
    FROM users u LEFT JOIN records r ON r.region_user_id=u.id AND r.created_at>=datetime('now','-6 day')
    WHERE u.role='region' AND u.active=1`;
  const ma=[]; if(regionOnly){sql+=" AND u.id=?";ma.push(u.id)} sql+=" GROUP BY u.id ORDER BY required DESC,total DESC";
  const managers=(await env.DB.prepare(sql).bind(...ma).all()).results;
  const activitySql=regionOnly?`SELECT a.*,u.name actor_name,r.employee_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN records r ON r.id=a.record_id WHERE r.region_user_id=? ORDER BY a.id DESC LIMIT 10`:`SELECT a.*,u.name actor_name,r.employee_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN records r ON r.id=a.record_id WHERE a.record_id IS NOT NULL ORDER BY a.id DESC LIMIT 10`;
  const activity=await env.DB.prepare(activitySql).bind(...(regionOnly?[u.id]:[])).all();
  const payload={total:Number(summary?.total||0),required:Number(summary?.required||0),documented:Number(summary?.documented||0),withdrawn:Number(summary?.withdrawn||0),stopped:Number(summary?.stopped||0),overdue:Number(summary?.overdue||0),inprog:Number(summary?.inprog||0),managers,recent_activity:activity.results,sla_hours:SLA_HOURS,report_date:reportDate()}; dashboardCache.set(cacheKey,{at:Date.now(),data:payload}); return json(payload);
 }
 if(p==="/api/manager-stats"&&req.method==="GET"){
  if(!allow(u,"view_stats")&&u.role!=="region")return json({error:"ليس لديك صلاحية إحصائيات المسؤولين"},403);
  const requested=Number(url.searchParams.get("manager_id")||0),region=url.searchParams.get("region")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"";
  const managerId=u.role==="region"?u.id:requested;
  if(!managerId)return json({error:"اختر مسؤولاً"},400);
  const manager=await env.DB.prepare("SELECT id,name,username,region FROM users WHERE id=? AND role='region' AND active=1").bind(managerId).first();
  if(!manager)return json({error:"المسؤول غير موجود"},404);
  let where=" WHERE region_user_id=?",args=[managerId];
  if(region){where+=" AND region=?";args.push(region)}
  if(from){where+=" AND created_at>=?";args.push(from+" 00:00:00")}
  if(to){where+=" AND created_at<=?";args.push(to+" 23:59:59")}
  const summaryStmt=env.DB.prepare(`SELECT COUNT(*) total,
    COALESCE(SUM(CASE WHEN status IN ('waiting_region','returned') THEN 1 ELSE 0 END),0) required,
    COALESCE(SUM(CASE WHEN status IN ('region_documented','region_withdrawn') THEN 1 ELSE 0 END),0) awaiting,
    COALESCE(SUM(CASE WHEN status IN ('final_documented','final_withdrawn') THEN 1 ELSE 0 END),0) completed,
    COALESCE(SUM(CASE WHEN status='returned' THEN 1 ELSE 0 END),0) returned,
    COALESCE(SUM(CASE WHEN status='final_documented' THEN 1 ELSE 0 END),0) documented,
    COALESCE(SUM(CASE WHEN status='final_withdrawn' THEN 1 ELSE 0 END),0) withdrawn,
    COALESCE(SUM(CASE WHEN status='stopped' THEN 1 ELSE 0 END),0) stopped,
    COALESCE(SUM(CASE WHEN delegated_to_user_id IS NOT NULL THEN 1 ELSE 0 END),0) delegated,
    COALESCE(SUM(CASE WHEN status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') AND created_at<=datetime('now','-48 hour') THEN 1 ELSE 0 END),0) overdue,
    AVG(CASE WHEN final_approved_at IS NOT NULL THEN (julianday(final_approved_at)-julianday(created_at))*86400 END) avg_duration,
    AVG(CASE WHEN region_responded_at IS NOT NULL THEN (julianday(region_responded_at)-julianday(created_at))*86400 END) avg_response
    FROM records${where}`).bind(...args);
  const recentStmt=env.DB.prepare(`SELECT substr(created_at,1,7) month,COUNT(*) count FROM records${where} GROUP BY substr(created_at,1,7) ORDER BY month DESC LIMIT 12`).bind(...args);
  const statusStmt=env.DB.prepare(`SELECT status key,COUNT(*) value FROM records${where} GROUP BY status`).bind(...args);
  const closedStmt=env.DB.prepare(`SELECT (julianday(final_approved_at)-julianday(created_at))*86400 seconds FROM records${where} AND final_approved_at IS NOT NULL ORDER BY seconds`).bind(...args);
  const [summary,recentRows,statusRows,closedRows]=await env.DB.batch([summaryStmt,recentStmt,statusStmt,closedStmt]);
  const recent=(recentRows.results||[]).reverse();
  const statusBreakdown=(statusRows.results||[]).map(x=>({key:x.key,label:labels[x.key]||x.key,value:Number(x.value||0)}));
  const closedDur=(closedRows.results||[]).map(x=>Number(x.seconds||0)).filter(x=>x>=0);
  const median=closedDur.length?(closedDur.length%2?closedDur[(closedDur.length-1)/2]:Math.round((closedDur[closedDur.length/2-1]+closedDur[closedDur.length/2])/2)):0;
  const total=Number(summary?.results?.[0]?.total||0),row=summary?.results?.[0]||{},completed=Number(row.completed||0),avgDuration=Math.round(Number(row.avg_duration||0)),avgResponse=Math.round(Number(row.avg_response||0));
  const withinSla=closedDur.length?Math.round(closedDur.filter(x=>x<SLA_HOURS*3600).length/closedDur.length*100):0;
  const returned=Number(row.returned||0),documented=Number(row.documented||0),withdrawn=Number(row.withdrawn||0),stopped=Number(row.stopped||0),delegated=Number(row.delegated||0);
  const quality={documentation_rate:total?Math.round(documented/total*100):0,withdrawal_rate:total?Math.round(withdrawn/total*100):0,rework_rate:total?Math.round(returned/total*100):0,stopped_rate:total?Math.round(stopped/total*100):0,sla_rate:withinSla};
  return json({manager,filters:{region,from,to},total,required:Number(row.required||0),awaiting:Number(row.awaiting||0),completed,overdue:Number(row.overdue||0),returned,documented,withdrawn,stopped,delegated,receivedByDelegation:delegated,delegatedOut:0,completionRate:total?Math.round(completed/total*100):0,withinSlaRate:withinSla,quality,avg_duration_seconds:avgDuration,avg_duration_label:durationLabel(avgDuration),median_duration_seconds:median,median_duration_label:durationLabel(median),avg_response_seconds:avgResponse,avg_response_label:durationLabel(avgResponse),recent,statusBreakdown,report_date:reportDate()});
 }
 if(p==="/api/users"&&req.method==="GET"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const rows=await env.DB.prepare("SELECT id,username,name,role,region,active,permissions,created_at FROM users ORDER BY id DESC").all();return json({users:rows.results.map(x=>({...x,permissions:permsOf(x)}))})}
 if(p==="/api/users"&&req.method==="POST"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const b=await req.json();if(!b.username||!b.name||!b.password||!b.role)return json({error:"أكمل بيانات المستخدم"},400);const ps=(Array.isArray(b.permissions)?b.permissions:(ROLE_DEFAULTS[b.role]||[])).filter(x=>ALL_PERMS.includes(x));try{await env.DB.prepare("INSERT INTO users(username,name,password_hash,role,region,permissions,active) VALUES(?,?,?,?,?,?,1)").bind(b.username,b.name,await hash(b.password),b.role,b.region||null,ps.join(",")).run()}catch{return json({error:"اسم المستخدم مستخدم مسبقاً"},400)}await log(env,null,u.id,"إنشاء مستخدم",`${b.name} — ${b.role}`);return json({ok:true})}
 const um=p.match(/^\/api\/users\/(\d+)$/);if(um&&req.method==="POST"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const id=Number(um[1]),b=await req.json(),target=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();if(!target)return json({error:"المستخدم غير موجود"},404);const ps=(b.permissions||[]).filter(x=>ALL_PERMS.includes(x));if(b.action==="toggle"&&target.username!=="admin")await env.DB.prepare("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?").bind(id).run();else{await env.DB.prepare("UPDATE users SET name=?,role=?,region=?,permissions=?,active=? WHERE id=?").bind(b.name||target.name,b.role||target.role,b.region||null,ps.join(","),b.active===undefined?target.active:b.active?1:0,id).run();if(b.password)await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hash(b.password),id).run()}await log(env,null,u.id,"تعديل مستخدم",target.name);return json({ok:true})}
 if(p==="/api/admin/clear-test-data"&&req.method==="POST"){
  if(u.role!=="admin"||!allow(u,"manage_data"))return json({error:"للمدير فقط"},403);
  const b=await req.json().catch(()=>({}));
  if(String(b.confirm||"")!=="RESET")return json({error:"اكتب RESET للتأكيد"},400);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM record_stages"),
    env.DB.prepare("DELETE FROM audit_log WHERE record_id IS NOT NULL OR user_id IS NOT NULL"),
    env.DB.prepare("DELETE FROM sessions"),
    env.DB.prepare("DELETE FROM delegations_v2"),
    env.DB.prepare("DELETE FROM records"),
    env.DB.prepare("DELETE FROM users WHERE username<>? AND role<>? ").bind("admin","admin")
  ]);
  await log(env,null,u.id,"تنظيف بيانات الاختبار","تم حذف المعاملات والمستخدمين التجريبيين والإسنادات والتفويضات والجلسات");
  return json({ok:true});
}
 if(p==="/api/audit"&&req.method==="GET"){if(!allow(u,"view_audit_log"))return json({error:"ليس لديك صلاحية سجل النشاط"},403);const q=url.searchParams.get("q")||"",action=url.searchParams.get("action")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"";let sql=`SELECT a.*,u.name actor_name,u.username, u.role FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE 1=1`,args=[];if(q){sql+=" AND (u.name LIKE ? OR u.username LIKE ? OR a.action LIKE ? OR a.note LIKE ?)";const z="%"+q+"%";args.push(z,z,z,z)}if(action){sql+=" AND a.action=?";args.push(action)}if(from){sql+=" AND a.created_at>=?";args.push(from+" 00:00:00")}if(to){sql+=" AND a.created_at<=?";args.push(to+" 23:59:59")}sql+=" ORDER BY a.id DESC LIMIT 2000";const rows=(await env.DB.prepare(sql).bind(...args).all()).results;const sessions=(await env.DB.prepare(`SELECT s.*,u.name,u.username,u.role,u.region FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.expires_at>? ORDER BY s.login_at DESC LIMIT 300`).bind(Math.floor(Date.now()/1000)).all()).results;return json({events:rows,sessions})}
 if(p==="/api/audit/export"&&req.method==="GET"){if(!allow(u,"export_audit_log"))return json({error:"ليس لديك صلاحية تصدير سجل النشاط"},403);const rows=(await env.DB.prepare(`SELECT a.created_at AS "التاريخ والوقت",u.name AS "المستخدم",u.username AS "اسم المستخدم",u.role AS "الدور",a.action AS "النشاط",a.record_id AS "رقم المعاملة",a.note AS "التفاصيل" FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 10000`).all()).results;return json({rows,report_date:reportDate()})}
 if(p==="/api/export"){if(!allow(u,"export"))return json({error:"ليس لديك صلاحية التصدير"},403);const today=reportDate(),region=url.searchParams.get("region")||"",status=url.searchParams.get("status")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"",managerId=Number(url.searchParams.get("manager_id")||0);let esql=`SELECT r.*,ru.name region_user_name,ou.name original_manager_name FROM records r LEFT JOIN users ru ON ru.id=r.region_user_id LEFT JOIN users ou ON ou.id=r.original_region_user_id WHERE 1=1`,ea=[];
if(u.role==="region"){esql+=" AND r.region_user_id=?";ea.push(u.id)}
if(u.role==="requester"){esql+=" AND r.requester_id=?";ea.push(u.id)}if(region){esql+=" AND r.region=?";ea.push(region)}if(status){esql+=" AND r.status=?";ea.push(status)}if(managerId){esql+=" AND r.region_user_id=?";ea.push(managerId)}if(from){esql+=" AND r.created_at>=?";ea.push(from+" 00:00:00")}if(to){esql+=" AND r.created_at<=?";ea.push(to+" 23:59:59")}esql+=" ORDER BY r.id DESC";const raw=await env.DB.prepare(esql).bind(...ea).all();await log(env,null,u.id,"تصدير التقرير",`${raw.results.length} معاملة`);const rows=raw.results.map(r=>({"رقم الموظف":r.employee_no,"اسم الموظف":r.employee_name,"رقم معاملة التعيين":r.transaction_no||"","رقم معاملة الانقطاع أو اتخاذ الإجراء":r.status==="final_withdrawn"||r.status==="region_withdrawn"?r.interruption_transaction_no||"":"","الإقليم":r.region||"","المسؤول الأصلي":r.original_manager_name||r.region_user_name||"","المسؤول الحالي":r.region_user_name||"","تاريخ المباشرة":r.start_date||"","الحالة":labels[r.status]||r.status,"تاريخ نهاية الدوام":r.end_date||"","تاريخ الرفع":r.created_at||"","تاريخ التوثيق":r.region_responded_at||"","تاريخ اعتماد التوثيق":r.final_approved_at||"","مدة المعاملة":durationLabel(durationSeconds(r)),"متأخرة":(!CLOSED.includes(r.status)&&durationSeconds(r)>=SLA_HOURS*3600)?"نعم":"لا","تاريخ التقرير":today}));return json({rows,report_date:today})}
 const ur=p.match(/^\/api\/users\/(\d+)\/reset-password$/);if(ur&&req.method==="POST"){
  if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);
  const id=Number(ur[1]),target=await env.DB.prepare("SELECT id,username,name,active FROM users WHERE id=?").bind(id).first();
  if(!target)return json({error:"المستخدم غير موجود"},404);
  if(target.username==="admin")return json({error:"لا يمكن إعادة تعيين كلمة مرور مدير النظام من هنا"},400);
  const temporary=token().slice(0,12)+"!Aa9";
  await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hash(temporary),id).run();
  await log(env,null,u.id,"إعادة تعيين كلمة مرور",target.name);
  return json({ok:true,temporary_password:temporary});
 }
 if(p==="/api/password"&&req.method==="POST"){const b=await req.json();if(!b.password)return json({error:"أدخل الرمز الجديد"},400);await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hash(b.password),u.id).run();return json({ok:true})}
 if(p==="/template.xlsx"||p==="/contract_upload_template.xlsx"){const asset=await env.ASSETS.fetch(new Request(new URL("/contract_upload_template.xlsx",url)));if(!asset.ok)return asset;const h=new Headers(asset.headers);h.set("content-disposition",'attachment; filename="contract_upload_template.xlsx"');h.set("content-type","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");return new Response(asset.body,{status:asset.status,headers:h});}
 if(!p.startsWith("/api/"))return env.ASSETS.fetch(req);return json({error:"غير موجود"},404);
}}


