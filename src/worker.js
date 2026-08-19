
/* 1S v2 — permission & workflow hardening */
function canViewCase1S(user, record){
  const role=String(user?.role||user?.user_role||'').toLowerCase();
  if(['admin','manager','supervisor','viewer'].includes(role)) return true;
  if(role==='responsible'){
    const me=String(user?.id||user?.username||'');
    const assigned=String(record?.assigned_to??record?.responsible_manager_id??record?.manager_id??'');
    return assigned===me || String(record?.responsible_manager_id||'')===me;
  }
  return !!record?.visible;
}
function filterByResponsibleManager1S(records, managerId){
  if(!managerId) return records||[];
  const id=String(managerId);
  return (records||[]).filter(r=>String(r?.assigned_to??r?.responsible_manager_id??r?.manager_id??'')===id);
}
function isWithdrawn1S(record){
  return /منسحب|withdraw/i.test(String(record?.status||''));
}
function buildWithdrawalSubmission1S(record, values){
  return {record_id:record.id,status:'withdrawn',
    last_work_day:values.last_work_day,
    action_case_number:values.action_case_number||null,
    note:values.note||''};
}


/* 1S — workflow semantics */
const CASE_STATUS_1S = Object.freeze({
  REQUIRED:'waiting_responsible',
  APPROVAL:'waiting_approval',
  WITHDRAWAL_APPROVAL:'waiting_withdrawal_approval',
  CLOSED:'closed',
  STOPPED:'stopped',
  CANCELLED:'cancelled',
  WITHDRAWN:'withdrawn'
});
function caseNeedsResponsibleAction1S(status){
  return ['waiting_responsible','returned'].includes(String(status||'').toLowerCase());
}
function caseNeedsApproval1S(status){
  return ['waiting_approval','waiting_withdrawal_approval'].includes(String(status||'').toLowerCase());
}
function caseIsFinishedForResponsible1S(status){
  return ['closed','stopped','cancelled','withdrawn','verified','documented'].includes(String(status||'').toLowerCase());
}


/* V18.7 — responsible action semantics */
function isResponsibleRequiredAction(record){
  const s=String(record?.status||'').trim().toLowerCase();
  return /بانتظار.*إفادة|مطلوب.*إجراء|returned|needs.?action|waiting.*responsible|correction/.test(s)
         && !/منسحب|withdraw|cancel|ملغ/.test(s);
}
function isResponsibleWithdrawn(record){
  const s=String(record?.status||'').trim().toLowerCase();
  return /منسحب|withdraw/.test(s);
}
function filterResponsibleRequiredActions(records){
  return (records||[]).filter(isResponsibleRequiredAction);
}
function openResponsibleExternalAction(record, action){
  // Keep this helper worker-safe: the browser owns navigation.
  const routes={withdrawn:'withdrawn',respond:'respond',approve:'approve'};
  return routes[action]?`/records/${record.id}?action=${routes[action]}`:null;
}

/* V18.5 — responsible manager workspace */
function responsibleManagerBucket(status){
  const s=String(status||'').trim().toLowerCase();
  if(/بانتظار الاعتماد|waiting.*approv|pending.*approv|approval/.test(s)) return 'approval';
  if(/مطلوب.*إجراء|waiting.*responsible|required|respond/.test(s)) return 'required';
  // "منتهية" means all cases that have already passed through this responsible,
  // including externally completed/withdrawn/cancelled/stopped/closed states.
  if(/تم التوثيق|منسحب|ملغاة|موقوف|closed|document|withdraw|cancel/.test(s)) return 'completed';
  return 'completed';
}

function buildResponsibleManagerBuckets(records){
  const out={completed:[],approval:[],required:[]};
  (records||[]).forEach(r=>{
    const b=responsibleManagerBucket(r.status);
    out[b].push(r);
  });
  return out;
}

const COOKIE="ict_session", DAYS=30, SLA_HOURS=48, IDLE_TIMEOUT_SECONDS=1800, SCHEMA_VERSION=23;
const dashboardCache=new Map();
let schemaReady=null;
const seenSessions=new Map();
const CLOSED=["final_documented","final_withdrawn","cancelled"];
const labels={
 waiting_responsible:"بانتظار إفادة المسؤول",
 returned:"↩ معاد للمسؤول",
 responsible_documented:"تمت الإفادة — بانتظار مراجعة HR",
 responsible_withdrawn:"تمت الإفادة بالانسحاب — بانتظار مراجعة HR",
 final_documented:"تم التوثيق",
 final_withdrawn:"منسحب الموظف",
 cancelled:"المعاملة ملغاة",
 stopped:"موقوفة"
};
const ALL_PERMS=["view_records","upload_contracts","respond_responsible","approve","manage_users","manage_delegations","settings","stop_records","cancel_records","export","reassign_records","delegate_records","view_closed","reactivate_records","view_stats","manage_data","view_audit_log","export_audit_log"];
const ROLE_DEFAULTS={
 admin:ALL_PERMS,
 manager:["view_records","upload_contracts","respond_responsible","approve","manage_users","manage_delegations","settings","stop_records","cancel_records","export","reassign_records","delegate_records","view_closed","reactivate_records","view_stats","view_audit_log","export_audit_log"],
 supervisor:["view_records","view_closed","view_stats","view_audit_log","export"],
 requester:["view_records","upload_contracts","approve","export","reassign_records","delegate_records","manage_delegations","view_stats","view_audit_log","export_audit_log"],
 responsible:["view_records","respond_responsible"],
 viewer:["view_records"]
};
const json=(x,s=200,h={})=>new Response(JSON.stringify(x),{status:s,headers:{"content-type":"application/json;charset=utf-8",...h}});
const PBKDF2_ITERATIONS=120000;
const bytesToB64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const b64ToBytes=s=>{const t=String(s).replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(String(s).length/4)*4,"=");const bin=atob(t);return Uint8Array.from(bin,c=>c.charCodeAt(0));};
const legacyHash=async p=>{const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(p));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")};
const passwordHash=async p=>{
  const salt=new Uint8Array(16); crypto.getRandomValues(salt);
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(String(p)),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},key,256);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(bits)}`;
};
const constantTimeEqual=(a,b)=>{const x=String(a||""),y=String(b||"");if(x.length!==y.length)return false;let d=0;for(let i=0;i<x.length;i++)d|=x.charCodeAt(i)^y.charCodeAt(i);return d===0};
const verifyPassword=async(p,stored)=>{
  const s=String(stored||"");
  if(s.startsWith("pbkdf2$")){
    const [,it,saltB64,hashB64]=s.split("$");
    const iterations=Math.max(10000,Number(it)||PBKDF2_ITERATIONS);
    try{
      const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(String(p)),"PBKDF2",false,["deriveBits"]);
      const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:b64ToBytes(saltB64),iterations,hash:"SHA-256"},key,256);
      return constantTimeEqual(bytesToB64(bits),hashB64);
    }catch{return false}
  }
  return constantTimeEqual(await legacyHash(String(p)),s);
};
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
async function responsibleUser(env,id){return await env.DB.prepare(`SELECT u.*,COUNT(r.id) AS active_load FROM users u LEFT JOIN records r ON r.responsible_user_id=u.id AND r.status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') WHERE u.role='responsible' AND u.active=1 AND u.id=? GROUP BY u.id`).bind(Number(id)).first()}
function permsOf(u){if(!u)return [];if(u.role==="admin")return ALL_PERMS;return String(u.permissions||"").split(",").map(x=>x.trim()).filter(Boolean)}
function allow(u,p){return !!(u&&(u.role==="admin"||permsOf(u).includes(p)))}
function allowRoleFallback(u,p){if(!u)return false;if(allow(u,p))return true;const defaults=ROLE_DEFAULTS[u.role]||[];return !String(u.permissions||"").trim()&&defaults.includes(p)}
async function ensureSchema(env){
 if(schemaReady) return schemaReady;
 schemaReady=(async()=>{
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'viewer',permissions TEXT DEFAULT '',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT,employee_no TEXT NOT NULL,employee_name TEXT NOT NULL,start_date TEXT NOT NULL,transaction_no TEXT,transaction_date TEXT,interruption_transaction_no TEXT,end_date TEXT,status TEXT NOT NULL DEFAULT 'waiting_responsible',requester_id INTEGER NOT NULL,responsible_user_id INTEGER,responsible_note TEXT,requester_note TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,responsible_responded_at TEXT,final_approved_at TEXT,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,timer_paused_at TEXT,timer_end_at TEXT,paused_seconds INTEGER NOT NULL DEFAULT 0,stage_started_at TEXT,original_responsible_user_id INTEGER,delegated_from_user_id INTEGER,delegated_at TEXT,stopped_at TEXT,stopped_by INTEGER,completed_at TEXT,delegated_to_user_id INTEGER)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,record_id INTEGER,user_id INTEGER,action TEXT NOT NULL,note TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,login_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,logout_at TEXT,ip TEXT,user_agent TEXT)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS delegations_v2 (id INTEGER PRIMARY KEY AUTOINCREMENT,source_user_id INTEGER NOT NULL,target_user_id INTEGER NOT NULL,starts_at TEXT,ends_at TEXT,active INTEGER NOT NULL DEFAULT 1,created_by INTEGER,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,revoked_at TEXT,revoked_by INTEGER,note TEXT DEFAULT '')`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS record_stages (id INTEGER PRIMARY KEY AUTOINCREMENT,record_id INTEGER NOT NULL,stage TEXT NOT NULL,user_id INTEGER,started_at TEXT NOT NULL,ended_at TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  const add=async(t,c,ty)=>{try{await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${ty}`).run()}catch{}};
  await add('users','permissions',"TEXT DEFAULT ''");
  for(const [c,ty] of [['transaction_no','TEXT'],['transaction_date','TEXT'],['interruption_transaction_no','TEXT'],['end_date','TEXT'],['responsible_user_id','INTEGER'],['responsible_note','TEXT'],['requester_note','TEXT'],['responsible_responded_at','TEXT'],['final_approved_at','TEXT'],['updated_at','TEXT DEFAULT CURRENT_TIMESTAMP'],['timer_paused_at','TEXT'],['timer_end_at','TEXT'],['paused_seconds','INTEGER DEFAULT 0'],['stage_started_at','TEXT'],['original_responsible_user_id','INTEGER'],['delegated_from_user_id','INTEGER'],['delegated_at','TEXT'],['stopped_at','TEXT'],['stopped_by','INTEGER'],['completed_at','TEXT'],['delegated_to_user_id','INTEGER']]) await add('records',c,ty);
  for(const [c,ty] of [['login_at','TEXT DEFAULT CURRENT_TIMESTAMP'],['last_seen_at','TEXT DEFAULT CURRENT_TIMESTAMP'],['logout_at','TEXT'],['ip','TEXT'],['user_agent','TEXT']]) await add('sessions',c,ty);
  const uc=(await env.DB.prepare('PRAGMA table_info(users)').all()).results||[], rc=(await env.DB.prepare('PRAGMA table_info(records)').all()).results||[];
  const legacyUserRegion=uc.some(x=>x.name==='region'), legacyRecordRegion=rc.some(x=>x.name==='region');
  if(legacyUserRegion) await env.DB.prepare("UPDATE users SET role='responsible' WHERE role='region'").run();
  await env.DB.prepare("UPDATE users SET permissions=REPLACE(REPLACE(COALESCE(permissions,''),'respond_region','respond_responsible'),'manage_regions','')").run();
  if(legacyRecordRegion){
   await env.DB.prepare("UPDATE records SET responsible_user_id=region_user_id WHERE responsible_user_id IS NULL AND region_user_id IS NOT NULL").run();
   await env.DB.prepare("UPDATE records SET original_responsible_user_id=original_region_user_id WHERE original_responsible_user_id IS NULL AND original_region_user_id IS NOT NULL").run();
  }
  await env.DB.prepare("UPDATE records SET status='waiting_responsible' WHERE status='waiting_region'").run();
  await env.DB.prepare("UPDATE records SET status='responsible_documented' WHERE status='region_documented'").run();
  await env.DB.prepare("UPDATE records SET status='responsible_withdrawn' WHERE status='region_withdrawn'").run();
  await env.DB.prepare("UPDATE record_stages SET stage='responsible' WHERE stage='region'").run();
  await env.DB.prepare("UPDATE audit_log SET action=REPLACE(REPLACE(REPLACE(action,'الإقليم','المسؤول'),'إقليم','مسؤول'),'اقليم','مسؤول'),note=REPLACE(REPLACE(REPLACE(note,'الإقليم','المسؤول'),'إقليم','مسؤول'),'اقليم','مسؤول')").run();
  if(legacyUserRegion){
   await env.DB.prepare(`CREATE TABLE users_v20 (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'viewer',permissions TEXT DEFAULT '',active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
   await env.DB.prepare(`INSERT INTO users_v20(id,username,name,password_hash,role,permissions,active,created_at) SELECT id,username,name,password_hash,role,COALESCE(permissions,''),active,created_at FROM users`).run();
   await env.DB.prepare('DROP TABLE users').run(); await env.DB.prepare('ALTER TABLE users_v20 RENAME TO users').run();
  }
  if(legacyRecordRegion){
   await env.DB.prepare(`CREATE TABLE records_v20 (id INTEGER PRIMARY KEY AUTOINCREMENT,employee_no TEXT NOT NULL,employee_name TEXT NOT NULL,start_date TEXT NOT NULL,transaction_no TEXT,transaction_date TEXT,interruption_transaction_no TEXT,end_date TEXT,status TEXT NOT NULL DEFAULT 'waiting_responsible',requester_id INTEGER NOT NULL,responsible_user_id INTEGER,responsible_note TEXT,requester_note TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,responsible_responded_at TEXT,final_approved_at TEXT,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,timer_paused_at TEXT,timer_end_at TEXT,paused_seconds INTEGER NOT NULL DEFAULT 0,stage_started_at TEXT,original_responsible_user_id INTEGER,delegated_from_user_id INTEGER,delegated_at TEXT,stopped_at TEXT,stopped_by INTEGER,completed_at TEXT,delegated_to_user_id INTEGER)`).run();
   await env.DB.prepare(`INSERT INTO records_v20(id,employee_no,employee_name,start_date,transaction_no,transaction_date,interruption_transaction_no,end_date,status,requester_id,responsible_user_id,responsible_note,requester_note,created_at,responsible_responded_at,final_approved_at,updated_at,timer_paused_at,timer_end_at,paused_seconds,stage_started_at,original_responsible_user_id,delegated_from_user_id,delegated_at,stopped_at,stopped_by,completed_at,delegated_to_user_id) SELECT id,employee_no,employee_name,start_date,transaction_no,transaction_date,interruption_transaction_no,end_date,status,requester_id,responsible_user_id,responsible_note,requester_note,created_at,responsible_responded_at,final_approved_at,updated_at,timer_paused_at,timer_end_at,paused_seconds,stage_started_at,original_responsible_user_id,delegated_from_user_id,delegated_at,stopped_at,stopped_by,completed_at,delegated_to_user_id FROM records`).run();
   await env.DB.prepare('DROP TABLE records').run(); await env.DB.prepare('ALTER TABLE records_v20 RENAME TO records').run();
  }
  await env.DB.prepare('DROP TABLE IF EXISTS regions').run();
  for(const [role,perms] of Object.entries(ROLE_DEFAULTS)){try{await env.DB.prepare("UPDATE users SET permissions=? WHERE role=? AND (permissions IS NULL OR TRIM(permissions)='')").bind(perms.join(','),role).run()}catch{}}
  await env.DB.prepare("UPDATE records SET original_responsible_user_id=responsible_user_id WHERE original_responsible_user_id IS NULL AND responsible_user_id IS NOT NULL").run();
  await env.DB.prepare("UPDATE records SET updated_at=COALESCE(updated_at,created_at)").run();
  for(const q of ['CREATE INDEX IF NOT EXISTS idx_sessions_token_expires ON sessions(token,expires_at)','CREATE INDEX IF NOT EXISTS idx_users_username_active ON users(username,active)','CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role,active)','CREATE INDEX IF NOT EXISTS idx_records_responsible_status_created ON records(responsible_user_id,status,created_at)','CREATE INDEX IF NOT EXISTS idx_records_requester_status ON records(requester_id,status)','CREATE INDEX IF NOT EXISTS idx_records_delegated_status ON records(delegated_to_user_id,status)','CREATE INDEX IF NOT EXISTS idx_records_created ON records(created_at)','CREATE INDEX IF NOT EXISTS idx_audit_record_id ON audit_log(record_id,id)','CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)','CREATE INDEX IF NOT EXISTS idx_stages_record ON record_stages(record_id,ended_at,id)','CREATE INDEX IF NOT EXISTS idx_delegations_source_active ON delegations_v2(source_user_id,active,starts_at,ends_at)','CREATE INDEX IF NOT EXISTS idx_delegations_target_active ON delegations_v2(target_user_id,active,starts_at,ends_at)']){try{await env.DB.prepare(q).run()}catch{}}
  await env.DB.prepare("INSERT INTO schema_meta(key,value) VALUES('version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(String(SCHEMA_VERSION)).run();
 })().catch(e=>{schemaReady=null;throw e});
 return schemaReady;
}
function canSeeClosed(u){return u?.role==="responsible" || allow(u,"view_closed")}
function parseTs(x){if(!x)return null;const s=String(x).trim().replace(" ","T");return new Date(/Z$/.test(s)?s:s+"Z").getTime()}
function durationSeconds(r){const start=parseTs(r?.created_at);if(!start)return 0;let end=parseTs(r?.timer_end_at);if(!end&&r?.status!=="stopped")end=Date.now();if(!end)end=parseTs(r?.timer_paused_at)||Date.now();const paused=Number(r?.paused_seconds||0)*1000;return Math.max(0,Math.floor((end-start-paused)/1000))}
function durationLabel(sec){sec=Math.max(0,Number(sec)||0);let d=Math.floor(sec/86400);sec%=86400;let h=Math.floor(sec/3600);sec%=3600;let m=Math.floor(sec/60);let s=sec%60;return `${d?d+" يوم ":""}${h?h+" ساعة ":""}${m?m+" دقيقة ":""}${s+" ثانية"}`.trim()||"0 ثانية"}
function responseDuration(r){if(!r?.responsible_responded_at)return null;return Math.max(0,Math.floor((parseTs(r.responsible_responded_at)-parseTs(r.created_at))/1000))}
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
 if(status==="waiting_responsible")return "responsible";
 if(status==="returned")return "hr";
 if(status==="responsible_documented"||status==="responsible_withdrawn")return "approval";
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
function roleFilterRequired(u){return u.role==="responsible"?"r.status IN ('waiting_responsible','returned')":"r.status IN ('responsible_documented','responsible_withdrawn','returned')"}

export default {async fetch(req,env){
 await ensureSchema(env); const url=new URL(req.url),p=url.pathname; const u=await user(req,env);
 if(p==="/api/me")return json({user:u?{id:u.id,name:u.name,username:u.username,role:u.role,permissions:permsOf(u)}:null});
 if(p==="/api/health"&&req.method==="GET"){try{const v=await env.DB.prepare("SELECT value FROM schema_meta WHERE key='version'").first();const r=await env.DB.prepare("SELECT COUNT(*) c,SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) active FROM users WHERE role='responsible'").first();const cols=await env.DB.prepare("PRAGMA table_info(records)").all();return json({ok:true,version:Number(v?.value||0),responsible_users:{total:Number(r?.c||0),active:Number(r?.active||0)},record_columns:(cols.results||[]).map(x=>x.name),user:u?{id:u.id,role:u.role,permissions:permsOf(u)}:null});}catch(e){return json({ok:false,error:String(e?.message||e)},500)}}
 if(p==="/api/setup"&&req.method==="POST"){const c=await env.DB.prepare("SELECT COUNT(*) c FROM users").first();if(Number(c.c))return json({error:"تمت التهيئة مسبقاً"},400);const b=await req.json(),h=await passwordHash(String(b.password||"1234"));await env.DB.prepare("INSERT INTO users(username,name,password_hash,role,permissions,active) VALUES('admin',?,?, 'admin',?,1)").bind(b.name||"المدير",h,ALL_PERMS.join(",")).run();return json({ok:true})}
 if(p==="/api/login"&&req.method==="POST"){const b=await req.json(),username=String(b.username||"").trim(),password=String(b.password||""),x=await env.DB.prepare("SELECT * FROM users WHERE username=? AND active=1").bind(username).first();if(!x||!(await verifyPassword(password,x.password_hash))){await log(env,null,null,"محاولة دخول فاشلة",`اسم المستخدم: ${username}`);return json({error:"بيانات الدخول غير صحيحة"},401)}if(!String(x.password_hash||"").startsWith("pbkdf2$")){await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(password),x.id).run()}const t=token(),exp=Math.floor(Date.now()/1000)+DAYS*86400;await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at,login_at,last_seen_at,ip,user_agent) VALUES(?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?,?)").bind(t,x.id,exp,clientIp(req),req.headers.get("User-Agent")||"—").run();await log(env,null,x.id,"تسجيل دخول",`IP: ${clientIp(req)}`);return json({ok:true},200,{"set-cookie":`${COOKIE}=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${DAYS*86400}`})}
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
   if(!source.active)return json({error:"المفوِّض غير نشط"},400);
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
  const q=url.searchParams.get("q")||"",s=url.searchParams.get("status")||"",managerId=Number(url.searchParams.get("manager_id")||0),from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"",limit=Math.min(100,Math.max(1,Number(url.searchParams.get("limit")||60))),offset=Math.max(0,Number(url.searchParams.get("offset")||0));let sql=`SELECT r.*,ru.name responsible_user_name,req.name requester_name,ou.name original_manager_name,du.name delegated_from_name FROM records r LEFT JOIN users ru ON ru.id=r.responsible_user_id LEFT JOIN users req ON req.id=r.requester_id LEFT JOIN users ou ON ou.id=r.original_responsible_user_id LEFT JOIN users du ON du.id=r.delegated_from_user_id WHERE 1=1`,a=[];
  if(u.role==="responsible"){sql+=" AND (r.responsible_user_id=? OR r.original_responsible_user_id=?)";a.push(u.id,u.id)}
  if(u.role==="requester"){sql+=" AND (r.requester_id=? OR r.delegated_to_user_id=?)";a.push(u.id,u.id)}
  if(managerId){sql+=" AND r.responsible_user_id=?";a.push(managerId)}
  if(from){sql+=" AND r.created_at>=?";a.push(from+" 00:00:00")}
  if(to){sql+=" AND r.created_at<=?";a.push(to+" 23:59:59")}
  if(!["admin","manager","supervisor","viewer"].includes(u.role) && !canSeeClosed(u))sql+=" AND r.status NOT IN ('final_documented','final_withdrawn','cancelled')";
  if(q){sql+=" AND (r.employee_no LIKE ? OR r.employee_name LIKE ? OR r.transaction_no LIKE ? OR r.interruption_transaction_no LIKE ?)";const z="%"+q+"%";a.push(z,z,z,z)}
  if(s==="required")sql+=` AND ${roleFilterRequired(u)}`;else if(s==="mine")sql+=` AND ${u.role==='responsible'?"(r.responsible_user_id=? OR r.original_responsible_user_id=?)":"r.requester_id=?"}`,a.push(...(u.role==='responsible'?[u.id,u.id]:[u.id]));else if(s==="approval")sql+=" AND r.status IN ('responsible_documented','responsible_withdrawn')";else if(s==="closed")sql+=" AND r.status IN ('final_documented','final_withdrawn','cancelled','stopped')";else if(s==="overdue")sql+=" AND r.status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') AND (julianday('now')-julianday(r.created_at))*86400>=?",a.push(SLA_HOURS*3600);else if(s)sql+=" AND r.status=?",a.push(s);
  const countSql=sql; const countArgs=a.slice(); sql+=" ORDER BY r.id DESC LIMIT ? OFFSET ?";a.push(limit+1,offset); const [countRow,rows]=await env.DB.batch([env.DB.prepare(`SELECT COUNT(*) c FROM (${countSql})`).bind(...countArgs),env.DB.prepare(sql).bind(...a)]); let out=rows.results.map(withMeta);let hasMore=out.length>limit;if(hasMore)out=out.slice(0,limit);if(s==="overdue")out=out.filter(x=>x.overdue);return json({records:out,has_more:hasMore,offset,limit,total_count:Number(countRow.results?.[0]?.c||0)})
 }
 if(p==="/api/managers"&&req.method==="GET"){if(!allowRoleFallback(u,"view_stats")&&!allow(u,"reassign_records"))return json({error:"غير مصرح"},403);const rows=await env.DB.prepare("SELECT id,name,username FROM users WHERE role='responsible' AND active=1 ORDER BY name").all();return json({managers:rows.results})}
 if(p==="/api/records"&&req.method==="POST"){if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية رفع المعاملات"},403);const b=await req.json(),responsibleId=Number(b.responsible_user_id||0);if(!b.employee_no||!b.employee_name||!responsibleId||!b.start_date||!b.transaction_no)return json({error:"أكمل رقم الموظف والاسم والمسؤول وتاريخ المباشرة ورقم معاملة التعيين"},400);const ru=await responsibleUser(env,responsibleId);if(!ru)return json({error:"المسؤول المحدد غير موجود أو غير نشط"},400);const delegation=await currentDelegation(env,u.id);const r=await env.DB.prepare(`INSERT INTO records(employee_no,employee_name,start_date,transaction_no,transaction_date,status,requester_id,responsible_user_id,original_responsible_user_id,delegated_to_user_id,stage_started_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id`).bind(b.employee_no.trim(),b.employee_name.trim(),b.start_date,b.transaction_no.trim(),b.transaction_date||b.start_date,'waiting_responsible',u.id,ru.id,ru.id,delegation?.target_user_id||null).first();await stageStart(env,r.id,"responsible",ru.id);dashboardCache.clear();await log(env,r.id,u.id,"إنشاء المعاملة",`أُسندت إلى ${ru.name}${delegation?` — والمفوض الحالي: ${delegation.target_name}`:""}`);return json({ok:true,id:r.id})}
 if(p==="/api/records/bulk"&&req.method==="POST"){if(!allow(u,"upload_contracts"))return json({error:"ليس لديك صلاحية الرفع الجماعي"},403);const b=await req.json(),rows=Array.isArray(b.rows)?b.rows:[];let added=0,errors=[];for(const x of rows){if(!x.employee_no&&!x.employee_name&&!x.responsible_user_id)continue;const responsibleId=Number(x.responsible_user_id||0);if(!x.employee_no||!x.employee_name||!responsibleId||!x.start_date||!x.transaction_no){errors.push({row:x.row_no||"?",reason:"بيانات أساسية ناقصة"});continue}const ru=await responsibleUser(env,responsibleId);if(!ru){errors.push({row:x.row_no,reason:"المسؤول غير موجود أو غير نشط"});continue}try{const delegation=await currentDelegation(env,u.id);const r=await env.DB.prepare(`INSERT INTO records(employee_no,employee_name,start_date,transaction_no,transaction_date,interruption_transaction_no,status,requester_id,responsible_user_id,original_responsible_user_id,delegated_to_user_id,stage_started_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING id`).bind(x.employee_no.trim(),x.employee_name.trim(),x.start_date,x.transaction_no.trim(),x.start_date,null,'waiting_responsible',u.id,ru.id,ru.id,delegation?.target_user_id||null).first();await stageStart(env,r.id,"responsible",ru.id);await log(env,r.id,u.id,"إنشاء المعاملة من رفع جماعي",`أُسندت إلى ${ru.name}${delegation?` — والمفوض الحالي: ${delegation.target_name}`:""}`);dashboardCache.clear();added++}catch(e){errors.push({row:x.row_no,reason:`تعذر إنشاء المعاملة: ${e?.message||"خطأ غير معروف"}`})}}return json({ok:true,added,skipped:errors.length,errors})}

 const m=p.match(/^\/api\/records\/(\d+)$/);if(m&&req.method==="GET"){const id=Number(m[1]),r=await env.DB.prepare(`SELECT r.*,ru.name responsible_user_name,req.name requester_name,ou.name original_manager_name,du.name delegated_from_name FROM records r LEFT JOIN users ru ON ru.id=r.responsible_user_id LEFT JOIN users req ON req.id=r.requester_id LEFT JOIN users ou ON ou.id=r.original_responsible_user_id LEFT JOIN users du ON du.id=r.delegated_from_user_id WHERE r.id=?`).bind(id).first();if(!r)return json({error:"المعاملة غير موجودة"},404);
const allowed=["admin","manager","supervisor","viewer","مشرف","مدير"].includes(String(u.role||"").toLowerCase())||u.role==="responsible"&&(r.responsible_user_id===u.id||r.original_responsible_user_id===u.id)||u.role==="requester"&&(await isEffectiveRequester(env,r,u));
if(!allowed)return json({error:"لا تملك صلاحية فتح هذه المعاملة"},403);
const ev=await env.DB.prepare(`SELECT a.*,u.name actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.record_id=? ORDER BY a.id ASC`).bind(id).all();
let stages=(await env.DB.prepare(`SELECT rs.*,u.name user_name FROM record_stages rs LEFT JOIN users u ON u.id=rs.user_id WHERE rs.record_id=? ORDER BY rs.id ASC`).bind(id).all()).results;
if(!stages.length&&stageForStatus(r.status)){await stageStart(env,id,stageForStatus(r.status),r.responsible_user_id||r.requester_id);stages=(await env.DB.prepare(`SELECT rs.*,u.name user_name FROM record_stages rs LEFT JOIN users u ON u.id=rs.user_id WHERE rs.record_id=? ORDER BY rs.id ASC`).bind(id).all()).results;}
return json({record:withMeta(r),events:ev.results,stages})}
 if(m&&req.method==="POST"){
  const id=Number(m[1]),b=await req.json(),r=await env.DB.prepare("SELECT * FROM records WHERE id=?").bind(id).first();
  if(!r)return json({error:"المعاملة غير موجودة"},404);
  const owner=u.role==="admin"||u.role==="responsible"&&r.responsible_user_id===u.id||u.role==="requester"&&(await isEffectiveRequester(env,r,u));
  if(!owner)return json({error:"لا تملك صلاحية تعديل هذه المعاملة"},403);
  dashboardCache.clear();

  if(b.action==="reassign"){
    if(!allow(u,"reassign_records"))return json({error:"ليس لديك صلاحية إعادة الإسناد"},403);
    const manager=await env.DB.prepare("SELECT * FROM users WHERE id=? AND role='responsible' AND active=1").bind(Number(b.responsible_user_id)).first();
    if(!manager)return json({error:"المسؤول الجديد غير موجود"},400);
    await env.DB.prepare("UPDATE records SET responsible_user_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(manager.id,id).run();
    await stageTransition(env,r,"responsible",manager.id);
    await log(env,id,u.id,"سحب وإعادة إسناد",`تم إسناد المعاملة إلى ${manager.name}${b.note?` — ${b.note}`:""}`);
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
    const next=String(b.new_status||"").trim();
    if(!["final_documented","final_withdrawn"].includes(next))return json({error:"حدد الحالة الجديدة: تم التوثيق أو منسحب الموظف"},400);
    if(!b.transaction_no||!b.transaction_date)return json({error:"إعادة التنشيط تتطلب رقم المعاملة وتاريخها"},400);
    if(next==="final_withdrawn"&&(!b.end_date||!b.interruption_transaction_no))return json({error:"حالة منسحب الموظف تتطلب رقم معاملة الانقطاع / اتخاذ الإجراء وتاريخ آخر يوم عمل"},400);
    const previous=`الحالة السابقة: ${labels[r.status]||r.status}${r.status==='final_withdrawn'&&r.end_date?` — آخر يوم عمل سابق: ${r.end_date}`:''}${r.status==='final_withdrawn'&&r.interruption_transaction_no?` — رقم معاملة الانقطاع/اتخاذ الإجراء السابق: ${r.interruption_transaction_no}`:''}`;
    const details=next==="final_withdrawn"?`الحالة الجديدة: منسحب الموظف — رقم معاملة الانقطاع/اتخاذ الإجراء: ${b.interruption_transaction_no} — آخر يوم عمل: ${b.end_date} — رقم المعاملة: ${b.transaction_no} — تاريخ المعاملة: ${b.transaction_date}`:`الحالة الجديدة: تم التوثيق — رقم المعاملة: ${b.transaction_no} — تاريخ المعاملة: ${b.transaction_date}`;
    let pauseAdd=0;if(r.timer_paused_at)pauseAdd=Math.max(0,Math.floor((Date.now()-parseTs(r.timer_paused_at))/1000));
    await env.DB.prepare(`UPDATE records SET status=?,transaction_no=?,transaction_date=?,end_date=?,interruption_transaction_no=?,final_approved_at=NULL,responsible_responded_at=NULL,responsible_note=NULL,timer_end_at=NULL,timer_paused_at=NULL,paused_seconds=COALESCE(paused_seconds,0)+?,stopped_at=NULL,stopped_by=NULL,completed_at=NULL,stage_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(next,b.transaction_no.trim(),b.transaction_date,next==="final_withdrawn"?b.end_date:null,next==="final_withdrawn"?b.interruption_transaction_no.trim():null,pauseAdd,id).run();
    await stageTransition(env,r,"closed",u.id);
    await log(env,id,u.id,"إعادة تنشيط المعاملة",`${previous} — ${details}`);
    return json({ok:true});
  }

  if(b.action==="responsible_documented"||b.action==="responsible_withdrawn"){
    if(!allow(u,"respond_responsible"))return json({error:"ليس لديك صلاحية إفادة المسؤول"},403);
    if(u.role!=="responsible"&&u.role!=="admin")return json({error:"هذا الإجراء لمسؤول المسؤول فقط"},403);
    if(b.action==="responsible_withdrawn"&&(!b.end_date||!b.interruption_transaction_no))return json({error:"الانسحاب يتطلب تاريخ نهاية الدوام ورقم معاملة الانقطاع أو اتخاذ الإجراء"},400);
    const next=b.action==="responsible_documented"?"responsible_documented":"responsible_withdrawn";
    // A new documented decision supersedes any previous withdrawal decision.
    const endDate=next==="responsible_withdrawn"?(b.end_date||r.end_date||null):null;
    const actionNo=next==="responsible_withdrawn"?(b.interruption_transaction_no||r.interruption_transaction_no||null):null;
    await env.DB.prepare("UPDATE records SET status=?,end_date=?,interruption_transaction_no=?,responsible_note=?,responsible_responded_at=CURRENT_TIMESTAMP,stage_started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,timer_paused_at=NULL,timer_end_at=NULL WHERE id=?").bind(next,endDate,actionNo,b.note||null,id).run();
    await stageTransition(env,r,"approval",u.id);
    await log(env,id,u.id,next==="responsible_documented"?"إفادة: تم التوثيق":"إفادة: منسحب الموظف",b.note||"");
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
  const cacheKey=`${u.id}:${u.role}`; const cached=dashboardCache.get(cacheKey); if(cached && Date.now()-cached.at<5000) return json(cached.data);

  let attentionWhere="", attentionArgs=[];
  if(u.role==="responsible"){
    attentionWhere=" AND (r.responsible_user_id=? OR r.original_responsible_user_id=?) AND r.status IN ('waiting_responsible','returned')";
    attentionArgs=[u.id,u.id];
  }else if(u.role==="requester"){
    attentionWhere=" AND (r.requester_id=? OR r.delegated_to_user_id=?) AND r.status IN ('responsible_documented','responsible_withdrawn','returned')";
    attentionArgs=[u.id,u.id];
  }else{
    attentionWhere=" AND r.status IN ('waiting_responsible','returned','responsible_documented','responsible_withdrawn')";
  }
  const attention=(await env.DB.prepare(`SELECT r.id,r.employee_name,r.employee_no,r.status,r.updated_at,r.stage_started_at,ru.name responsible_user_name,
    ROUND(MAX(0,(julianday('now')-julianday(COALESCE(r.stage_started_at,r.updated_at)))*86400)) stage_age_seconds
    FROM records r LEFT JOIN users ru ON ru.id=r.responsible_user_id
    WHERE 1=1 ${attentionWhere}
    ORDER BY CASE WHEN r.status IN ('waiting_responsible','returned') THEN 0 ELSE 1 END,
             CASE WHEN (julianday('now')-julianday(COALESCE(r.stage_started_at,r.updated_at)))*86400>=? THEN 0 ELSE 1 END,
             r.updated_at ASC LIMIT 8`).bind(...attentionArgs,SLA_HOURS*3600).all()).results;

  let overdueWhere=" AND r.status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') AND (julianday('now')-julianday(COALESCE(r.stage_started_at,r.updated_at)))*86400>=?", overdueArgs=[SLA_HOURS*3600];
  if(u.role==="responsible"){overdueWhere+=" AND (r.responsible_user_id=? OR r.original_responsible_user_id=?)";overdueArgs.push(u.id,u.id)}
  else if(u.role==="requester"){overdueWhere+=" AND (r.requester_id=? OR r.delegated_to_user_id=?)";overdueArgs.push(u.id,u.id)}
  const counts=await env.DB.prepare(`SELECT
    (SELECT COUNT(*) FROM records r WHERE 1=1 ${attentionWhere}) AS needs_action,
    (SELECT COUNT(*) FROM records r WHERE r.status IN ('responsible_documented','responsible_withdrawn') ${u.role==="requester"?'AND (r.requester_id=? OR r.delegated_to_user_id=?)':''}) AS waiting_approval,
    (SELECT COUNT(*) FROM records r WHERE 1=1 ${overdueWhere}) AS overdue,
    (SELECT COUNT(*) FROM records r WHERE r.status NOT IN ('final_documented','final_withdrawn','cancelled','stopped') ${u.role==="responsible"?'AND (r.responsible_user_id=? OR r.original_responsible_user_id=?)':u.role==="requester"?'AND (r.requester_id=? OR r.delegated_to_user_id=?)':''}) AS active,
    (SELECT COUNT(*) FROM records r WHERE r.status IN ('final_documented','final_withdrawn') AND date(r.updated_at)=date('now') ${u.role==="responsible"?'AND (r.responsible_user_id=? OR r.original_responsible_user_id=?)':u.role==="requester"?'AND (r.requester_id=? OR r.delegated_to_user_id=?)':''}) AS closed_today`).bind(
      ...attentionArgs,
      ...(u.role==="requester"?[u.id,u.id]:[]),
      ...overdueArgs,
      ...(u.role==="responsible"?[u.id,u.id]:u.role==="requester"?[u.id,u.id]:[]),
      ...(u.role==="responsible"?[u.id,u.id]:u.role==="requester"?[u.id,u.id]:[])
    ).first();
  let activitySql=`SELECT a.id,a.record_id,a.action,a.note,a.created_at,u.name actor_name,r.employee_name,r.status FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN records r ON r.id=a.record_id WHERE a.record_id IS NOT NULL`;
  const activityArgs=[];
  if(u.role==="responsible"){activitySql+=" AND (r.responsible_user_id=? OR r.original_responsible_user_id=?)";activityArgs.push(u.id,u.id)}
  else if(u.role==="requester"){activitySql+=" AND (r.requester_id=? OR r.delegated_to_user_id=?)";activityArgs.push(u.id,u.id)}
  activitySql+=" ORDER BY a.id DESC LIMIT 8";
  const activity=(await env.DB.prepare(activitySql).bind(...activityArgs).all()).results;
  const payload={needs_action:Number(counts?.needs_action||0),waiting_approval:Number(counts?.waiting_approval||0),overdue:Number(counts?.overdue||0),active:Number(counts?.active||0),closed_today:Number(counts?.closed_today||0),attention:attention.map(x=>({...x,status_label:labels[x.status]||x.status})),recent_activity:activity,sla_hours:SLA_HOURS,report_date:reportDate()};
  dashboardCache.set(cacheKey,{at:Date.now(),data:payload}); return json(payload);
 }
 if(p==="/api/manager-stats"&&req.method==="GET"){
  if(!allowRoleFallback(u,"view_stats")&&u.role!=="responsible")return json({error:"ليس لديك صلاحية إحصائيات الأداء"},403);
  const requestedRaw=String(url.searchParams.get("manager_id")||"").trim(),from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"";
  const isAll=requestedRaw.toLowerCase()==="all";
  if(u.role==="responsible" && (isAll || Number(requestedRaw||u.id)!==u.id))return json({error:"غير مصرح"},403);
  if(!requestedRaw && u.role!=="responsible")return json({error:"اختر المستخدم المسؤول"},400);
  const dateParts=[];if(from)dateParts.push("r.created_at>=?");if(to)dateParts.push("r.created_at<=?");
  const dateSql=dateParts.length?" AND "+dateParts.join(" AND "):"";const dateArgs=[];if(from)dateArgs.push(from+" 00:00:00");if(to)dateArgs.push(to+" 23:59:59");
  const touchedSql=(userExpr)=>`SELECT DISTINCT r.id,r.status FROM records r JOIN record_stages rs ON rs.record_id=r.id WHERE rs.stage='responsible' ${userExpr}${dateSql}`;
  let rows=[],manager;
  if(isAll){
    rows=(await env.DB.prepare(touchedSql("")).bind(...dateArgs).all()).results||[];
    manager={id:0,name:"جميع المسؤولين",username:"all",role:"aggregate"};
  }else{
    const managerId=u.role==="responsible"?u.id:Number(requestedRaw);
    if(!managerId)return json({error:"اختر المستخدم المسؤول"},400);
    manager=await env.DB.prepare("SELECT id,name,username,role FROM users WHERE id=? AND active=1 AND role='responsible'").bind(managerId).first();
    if(!manager)return json({error:"المستخدم المسؤول غير موجود أو غير نشط"},404);
    rows=(await env.DB.prepare(touchedSql(" AND rs.user_id=?")).bind(managerId,...dateArgs).all()).results||[];
  }
  const total=rows.length,documented=rows.filter(r=>r.status==='final_documented').length,withdrawn=rows.filter(r=>r.status==='final_withdrawn').length;
  const overdueSql=`SELECT DISTINCT rs.record_id FROM record_stages rs JOIN records r ON r.id=rs.record_id WHERE rs.stage='responsible' ${isAll?'':' AND rs.user_id=?'}${dateSql} GROUP BY rs.record_id HAVING SUM((julianday(COALESCE(rs.ended_at,CURRENT_TIMESTAMP))-julianday(rs.started_at))*86400)>=?`;
  const overdueArgs=isAll?[...dateArgs,SLA_HOURS*3600]:[Number(manager.id),...dateArgs,SLA_HOURS*3600];
  const overdueStage=await env.DB.prepare(overdueSql).bind(...overdueArgs).all();
  const delayedIds=new Set((overdueStage.results||[]).map(x=>Number(x.record_id)));const overdue=delayedIds.size;
  const closedAfterDelay=rows.filter(r=>delayedIds.has(Number(r.id))&&['final_documented','final_withdrawn'].includes(r.status)).length;
  const users=(await env.DB.prepare("SELECT id,name,username,role FROM users WHERE active=1 AND role='responsible' ORDER BY name").all()).results||[];
  const comparison=[];
  for(const person of users){
    const pr=await env.DB.prepare(touchedSql(" AND rs.user_id=?")).bind(person.id,...dateArgs).all();
    const prows=pr.results||[];
    const pdel=await env.DB.prepare(`SELECT DISTINCT rs.record_id FROM record_stages rs JOIN records r ON r.id=rs.record_id WHERE rs.stage='responsible' AND rs.user_id=?${dateSql} GROUP BY rs.record_id HAVING SUM((julianday(COALESCE(rs.ended_at,CURRENT_TIMESTAMP))-julianday(rs.started_at))*86400)>=?`).bind(person.id,...dateArgs,SLA_HOURS*3600).all();
    const ids=new Set((pdel.results||[]).map(x=>Number(x.record_id)));
    comparison.push({id:person.id,name:person.name,username:person.username,role:person.role,total:prows.length,documented:prows.filter(r=>r.status==='final_documented').length,withdrawn:prows.filter(r=>r.status==='final_withdrawn').length,overdue:ids.size,closed_after_delay:prows.filter(r=>ids.has(Number(r.id))&&['final_documented','final_withdrawn'].includes(r.status)).length});
  }
  return json({manager,filters:{from,to},total,documented,withdrawn,overdue,closed_after_delay:closedAfterDelay,comparison,report_date:reportDate()});
 }
 if(p==="/api/stats-users"&&req.method==="GET"){if(!allowRoleFallback(u,"view_stats")&&u.role!=="responsible")return json({error:"ليس لديك صلاحية إحصائيات الأداء"},403);if(u.role==="responsible")return json({users:[{id:u.id,name:u.name,username:u.username,role:u.role,active:u.active}]});const rows=await env.DB.prepare("SELECT id,username,name,role,active FROM users WHERE active=1 AND role='responsible' ORDER BY name").all();return json({users:rows.results});}
 if(p==="/api/users"&&req.method==="GET"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const rows=await env.DB.prepare("SELECT id,username,name,role,active,permissions,created_at FROM users ORDER BY id DESC").all();return json({users:rows.results.map(x=>({...x,permissions:permsOf(x)}))})}
 if(p==="/api/users"&&req.method==="POST"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const b=await req.json();if(!b.username||!b.name||!b.password||!b.role)return json({error:"أكمل بيانات المستخدم"},400);if(!ROLE_DEFAULTS[b.role])return json({error:"الدور غير صالح"},400);const ps=(Array.isArray(b.permissions)?b.permissions:(ROLE_DEFAULTS[b.role]||[])).filter(x=>ALL_PERMS.includes(x));try{await env.DB.prepare("INSERT INTO users(username,name,password_hash,role,permissions,active) VALUES(?,?,?,?,?,1)").bind(b.username,b.name,await passwordHash(b.password),b.role,ps.join(",")).run()}catch{return json({error:"اسم المستخدم مستخدم مسبقاً"},400)}await log(env,null,u.id,"إنشاء مستخدم",`${b.name} — ${b.role}`);return json({ok:true})}
 const um=p.match(/^\/api\/users\/(\d+)$/);if(um&&req.method==="POST"){if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);const id=Number(um[1]),b=await req.json(),target=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();if(!target)return json({error:"المستخدم غير موجود"},404);const nextRole=b.role||target.role,nextActive=b.active===undefined?Number(target.active):b.active?1:0;if(!ROLE_DEFAULTS[nextRole])return json({error:"الدور غير صالح"},400);const ps=(b.permissions||[]).filter(x=>ALL_PERMS.includes(x));if(b.action==="toggle"&&target.username!=="admin")await env.DB.prepare("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?").bind(id).run();else{await env.DB.prepare("UPDATE users SET name=?,role=?,permissions=?,active=? WHERE id=?").bind(b.name||target.name,nextRole,ps.join(","),nextActive,id).run();if(b.password)await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(b.password),id).run()}await log(env,null,u.id,"تعديل مستخدم",target.name);return json({ok:true})}
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
 if(p==="/api/audit"&&req.method==="GET"){if(!allow(u,"view_audit_log"))return json({error:"ليس لديك صلاحية سجل النشاط"},403);const q=url.searchParams.get("q")||"",action=url.searchParams.get("action")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"";let sql=`SELECT a.*,u.name actor_name,u.username, u.role FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE 1=1`,args=[];if(q){sql+=" AND (u.name LIKE ? OR u.username LIKE ? OR a.action LIKE ? OR a.note LIKE ?)";const z="%"+q+"%";args.push(z,z,z,z)}if(action){sql+=" AND a.action=?";args.push(action)}if(from){sql+=" AND a.created_at>=?";args.push(from+" 00:00:00")}if(to){sql+=" AND a.created_at<=?";args.push(to+" 23:59:59")}sql+=" ORDER BY a.id DESC LIMIT 2000";const rows=(await env.DB.prepare(sql).bind(...args).all()).results;const sessions=(await env.DB.prepare(`SELECT s.*,u.name,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.expires_at>? ORDER BY s.login_at DESC LIMIT 300`).bind(Math.floor(Date.now()/1000)).all()).results;return json({events:rows,sessions})}
 if(p==="/api/audit/export"&&req.method==="GET"){if(!allow(u,"export_audit_log"))return json({error:"ليس لديك صلاحية تصدير سجل النشاط"},403);const rows=(await env.DB.prepare(`SELECT a.created_at AS "التاريخ والوقت",u.name AS "المستخدم",u.username AS "اسم المستخدم",u.role AS "الدور",a.action AS "النشاط",a.record_id AS "رقم المعاملة",a.note AS "التفاصيل" FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 10000`).all()).results;return json({rows,report_date:reportDate()})}
 if(p==="/api/export"){if(!allow(u,"export"))return json({error:"ليس لديك صلاحية التصدير"},403);const today=reportDate(),status=url.searchParams.get("status")||"",from=url.searchParams.get("from")||"",to=url.searchParams.get("to")||"",managerId=Number(url.searchParams.get("manager_id")||0);let esql=`SELECT r.*,ru.name responsible_user_name,ou.name original_manager_name FROM records r LEFT JOIN users ru ON ru.id=r.responsible_user_id LEFT JOIN users ou ON ou.id=r.original_responsible_user_id WHERE 1=1`,ea=[];
if(u.role==="responsible"){esql+=" AND r.responsible_user_id=?";ea.push(u.id)}
if(u.role==="requester"){esql+=" AND r.requester_id=?";ea.push(u.id)}if(status){esql+=" AND r.status=?";ea.push(status)}if(managerId){esql+=" AND r.responsible_user_id=?";ea.push(managerId)}if(from){esql+=" AND r.created_at>=?";ea.push(from+" 00:00:00")}if(to){esql+=" AND r.created_at<=?";ea.push(to+" 23:59:59")}esql+=" ORDER BY r.id DESC";const raw=await env.DB.prepare(esql).bind(...ea).all();await log(env,null,u.id,"تصدير التقرير",`${raw.results.length} معاملة`);const rows=raw.results.map(r=>({"رقم الموظف":r.employee_no,"اسم الموظف":r.employee_name,"رقم معاملة التعيين":r.transaction_no||"","رقم معاملة الانقطاع أو اتخاذ الإجراء":r.status==="final_withdrawn"||r.status==="responsible_withdrawn"?r.interruption_transaction_no||"":"","المسؤول الأصلي":r.original_manager_name||r.responsible_user_name||"","المسؤول الحالي":r.responsible_user_name||"","تاريخ المباشرة":r.start_date||"","الحالة":labels[r.status]||r.status,"تاريخ نهاية الدوام":r.end_date||"","تاريخ الرفع":r.created_at||"","تاريخ التوثيق":r.responsible_responded_at||"","تاريخ اعتماد التوثيق":r.final_approved_at||"","مدة المعاملة":durationLabel(durationSeconds(r)),"متأخرة":(!CLOSED.includes(r.status)&&durationSeconds(r)>=SLA_HOURS*3600)?"نعم":"لا","تاريخ التقرير":today}));return json({rows,report_date:today})}
 const ur=p.match(/^\/api\/users\/(\d+)\/reset-password$/);if(ur&&req.method==="POST"){
  if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);
  const id=Number(ur[1]),target=await env.DB.prepare("SELECT id,username,name,active FROM users WHERE id=?").bind(id).first();
  if(!target)return json({error:"المستخدم غير موجود"},404);
  if(target.username==="admin")return json({error:"لا يمكن إعادة تعيين كلمة مرور مدير النظام من هنا"},400);
  const temporary=token().slice(0,12)+"!Aa9";
  await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(temporary),id).run();
  await log(env,null,u.id,"إعادة تعيين كلمة مرور",target.name);
  return json({ok:true,temporary_password:temporary});
 }
 if(p==="/api/password"&&req.method==="POST"){const b=await req.json();if(!b.current_password||!b.password)return json({error:"أدخل كلمة المرور الحالية والجديدة"},400);if(String(b.password).length<8)return json({error:"كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف"},400);if(String(b.current_password)===String(b.password))return json({error:"اختر كلمة مرور جديدة مختلفة عن الحالية"},400);if(!(await verifyPassword(String(b.current_password),u.password_hash)))return json({error:"كلمة المرور الحالية غير صحيحة"},400);await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await passwordHash(String(b.password)),u.id).run();await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token<>? ").bind(u.id,u.token).run();await log(env,null,u.id,"تغيير كلمة المرور","تغيير كلمة المرور من الحساب — تم إنهاء الجلسات الأخرى");return json({ok:true})}
 if(p==="/template.xlsx"||p==="/contract_upload_template.xlsx"){const asset=await env.ASSETS.fetch(new Request(new URL("/contract_upload_template.xlsx",url)));if(!asset.ok)return asset;const h=new Headers(asset.headers);h.set("content-disposition",'attachment; filename="contract_upload_template.xlsx"');h.set("content-type","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");return new Response(asset.body,{status:asset.status,headers:h});}
 if(!p.startsWith("/api/"))return env.ASSETS.fetch(req);return json({error:"غير موجود"},404);
}}


