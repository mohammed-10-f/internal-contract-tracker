
/* 1S v2 — permission & workflow hardening */
function canViewCase1S(user, record){
  const role=String(user?.role||user?.user_role||'').toLowerCase();
  if(['admin','manager','supervisor','viewer'].includes(role)) return true;
  if(role==='region'){
    const me=String(user?.id||user?.username||'');
    const assigned=String(record?.assigned_to??record?.region_manager_id??record?.manager_id??'');
    return assigned===me || String(record?.region_manager_id||'')===me;
  }
  return !!record?.visible;
}
function filterByResponsibleManager1S(records, managerId){
  if(!managerId) return records||[];
  const id=String(managerId);
  return (records||[]).filter(r=>String(r?.assigned_to??r?.region_manager_id??r?.manager_id??'')===id);
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


const app = document.querySelector("#app");

const roleLabel = {admin:"مدير النظام", manager:"مدير", supervisor:"مشرف", requester:"HR", region:"مسؤول إقليم", viewer:"مشاهد"};
const statusLabel = {
  waiting_region:"بانتظار الإفادة",
  returned:"مرتجع للتصحيح",
  region_documented:"بانتظار الاعتماد",
  region_withdrawn:"بانتظار اعتماد الانسحاب",
  final_documented:"تم التوثيق",
  final_withdrawn:"منسحب الموظف",
  cancelled:"ملغاة",
  stopped:"موقوفة"
};
const permLabel = {
  view_records:"استعراض المعاملات", upload_contracts:"رفع المعاملات",
  respond_region:"إفادة مسؤول الإقليم", approve:"الاعتماد النهائي",
  manage_users:"إدارة المستخدمين", manage_regions:"إدارة الأقاليم",
  manage_delegations:"إدارة التفويضات", settings:"الإعدادات",
  stop_records:"إيقاف المعاملات", cancel_records:"إلغاء المعاملات",
  export:"تصدير البيانات", reassign_records:"سحب وإعادة إسناد",
  delegate_records:"تفويض معاملة", view_closed:"عرض المنتهية",
  reactivate_records:"إعادة تنشيط", view_stats:"تحليلات الأداء",
  manage_data:"إدارة البيانات", view_audit_log:"سجل النشاط",
  export_audit_log:"تصدير سجل النشاط"
};
const roleDefaults = {
  admin: Object.keys(permLabel),
  manager: ["view_records","upload_contracts","respond_region","approve","manage_users","manage_regions","manage_delegations","settings","stop_records","cancel_records","export","reassign_records","delegate_records","view_closed","reactivate_records","view_stats","view_audit_log","export_audit_log"],
  supervisor: ["view_records","upload_contracts","respond_region","approve","reassign_records","view_closed","view_stats","view_audit_log","export"],
  requester: ["view_records","upload_contracts","approve","export","reassign_records","delegate_records","manage_delegations","view_stats","view_audit_log","export_audit_log","view_closed"],
  region: ["view_records","respond_region"],
  viewer: ["view_records"]
};
const permGroups = [
  {title:"المعاملات", items:["view_records","upload_contracts","respond_region","approve","stop_records","cancel_records","reassign_records","delegate_records","view_closed","reactivate_records","export","view_stats"]},
  {title:"الإدارة", items:["manage_users","manage_regions","manage_delegations","settings","manage_data","view_audit_log","export_audit_log"]}
];

let ME=null, VIEW="home", timerInterval=null, selectedRecord=null;
let usersCache=[], regionsCache=null;

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const can = p => ME?.role==="admin" || ME?.permissions?.includes(p);
const fmtDate = x => {
  if(!x) return "—";
  const s=String(x).slice(0,10);
  if(/^\d{4}-\d{2}-\d{2}$/.test(s)){const [y,m,d]=s.split("-");return `${d}/${m}/${y}`;}
  return s;
};
const fmtDateTime = x => {
  if(!x) return "—";
  const s=String(x).replace(" ","T");
  const m=s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  return m ? `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}` : fmtDate(x);
};
const compactDuration = sec => { sec=Math.max(0,Math.floor(Number(sec)||0)); const d=Math.floor(sec/86400); sec%=86400; const h=Math.floor(sec/3600); sec%=3600; const m=Math.floor(sec/60); if(d)return `${d}ي ${h}س`; if(h)return `${h}س ${m}د`; return `${m}د`; };
const duration = sec => {
  sec=Math.max(0,Math.floor(Number(sec)||0));
  const d=Math.floor(sec/86400); sec%=86400;
  const h=Math.floor(sec/3600); sec%=3600;
  const m=Math.floor(sec/60); const s=sec%60;
  const clock=`${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
  return d ? `${d} يوم · ${clock}` : clock;
};
const liveDuration = (start, paused, end) => {
  if(!start) return "—";
  const a=new Date(String(start).replace(" ","T")+"Z").getTime();
  const b=end ? new Date(String(end).replace(" ","T")+"Z").getTime() : Date.now();
  return duration(Math.max(0,Math.floor((b-a)/1000)-Number(paused||0)));
};
const apiCache=new Map();
async function api(url, opts={}) {
  const isGet=!opts.method || String(opts.method).toUpperCase()==="GET";
  const cacheable=isGet && url==="/api/regions";
  if(cacheable){const c=apiCache.get(url);if(c&&Date.now()-c.at<30000)return c.data;}
  const requestUrl=opts.cacheBust?`${url}${url.includes("?")?"&":"?"}_=${opts.cacheBust}`:url;
  const r=await fetch(requestUrl,{...opts,headers:{"content-type":"application/json",...(opts.headers||{})}});
  let data={}; try{data=await r.json()}catch{}
  if(!r.ok) throw Error(data.error||"تعذر تنفيذ العملية");
  if(cacheable){apiCache.set(url,{at:Date.now(),data});regionsCache=data;}
  return data;
}
async function ensureXLSX(){
  if(window.XLSX)return window.XLSX;
  if(window.__xlsxPromise)return window.__xlsxPromise;
  window.__xlsxPromise=new Promise((resolve,reject)=>{
    const script=document.createElement("script");
    script.src="https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js";
    script.async=true;
    script.onload=()=>window.XLSX?resolve(window.XLSX):reject(new Error("محرك Excel غير متاح"));
    script.onerror=()=>reject(new Error("تعذر تحميل محرك Excel. جرّب CSV أو تحقق من الاتصال."));
    document.head.appendChild(script);
  });
  return window.__xlsxPromise;
}
function toast(message,type="ok"){
  document.querySelector(".toast")?.remove();
  document.body.insertAdjacentHTML("beforeend",`<div class="toast ${type}"><span>${type==="err"?"!":"✓"}</span><b>${esc(message)}</b></div>`);
  setTimeout(()=>document.querySelector(".toast")?.remove(),3500);
}
function icon(type){return ({blue:"◷",green:"✓",orange:"!",red:"×",purple:"↗"})[type]||"•";}
function navIcon(name){
 const m={home:'<svg viewBox="0 0 24 24"><path d="M3 10.8 12 3l9 7.8v9.2a1 1 0 0 1-1 1h-5.2v-6h-5.6v6H4a1 1 0 0 1-1-1z"/></svg>',records:'<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 12h8M8 15h5"/></svg>',upload:'<svg viewBox="0 0 24 24"><path d="M12 16V4m0 0-4 4m4-4 4 4M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/></svg>',stats:'<svg viewBox="0 0 24 24"><path d="M5 19V10M12 19V5M19 19v-8"/></svg>',archive:'<svg viewBox="0 0 24 24"><path d="M4 7h16v12H4zM3 4h18v3H3zM9 11h6"/></svg>',users:'<svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M3.5 20a5.5 5.5 0 0 1 11 0M15 5.5a3 3 0 0 1 0 5.8M16 14a5 5 0 0 1 4.5 6"/></svg>',regions:'<svg viewBox="0 0 24 24"><path d="M5 4h6v6H5zM13 14h6v6h-6zM13 4h6v6h-6zM5 14h6v6H5z"/></svg>',audit:'<svg viewBox="0 0 24 24"><path d="M6 4h12v16H6zM9 8h6M9 12h6M9 16h4"/></svg>'};return m[name]||m.records;}
function stat(label,value,type="blue",sub=""){return `<div class="statCard"><span class="statIcon ${type}">${icon(type)}</span><div><small>${esc(label)}</small><strong>${value}</strong>${sub?`<em>${esc(sub)}</em>`:""}</div></div>`;}
function navActive(key){document.querySelectorAll("[data-nav]").forEach(x=>x.classList.toggle("active",x.dataset.nav===key));}
function enhanceSelects(root=document){
  const scope=root.querySelectorAll?root:document;
  scope.querySelectorAll('select:not([data-enhanced="1"])').forEach(sel=>{
    sel.dataset.enhanced='1';
    const wrap=document.createElement('div'); wrap.className='appSelect';
    sel.parentNode.insertBefore(wrap,sel); wrap.appendChild(sel);
    const btn=document.createElement('button'); btn.type='button'; btn.className='appSelectButton';
    const menu=document.createElement('div'); menu.className='appSelectMenu';
    const rebuild=()=>{
      const opts=[...sel.options];
      btn.innerHTML=`<span>${esc(sel.selectedOptions[0]?.text||'اختر')}</span><i>⌄</i>`;
      menu.innerHTML=opts.map((o,i)=>`<button type="button" class="${o.selected?'selected':''}" data-value="${esc(o.value)}"><span>${esc(o.text)}</span>${o.selected?'<b>✓</b>':''}</button>`).join('');
      menu.querySelectorAll('button').forEach(item=>item.addEventListener('click',()=>{
        sel.value=item.dataset.value; sel.dispatchEvent(new Event('change',{bubbles:true})); rebuild(); menu.classList.remove('open'); btn.setAttribute('aria-expanded','false');
      }));
    };
    btn.setAttribute('aria-haspopup','listbox'); btn.setAttribute('aria-expanded','false');
    btn.addEventListener('click',e=>{e.stopPropagation();document.querySelectorAll('.appSelectMenu.open').forEach(x=>x!==menu&&x.classList.remove('open'));menu.classList.toggle('open');btn.setAttribute('aria-expanded',menu.classList.contains('open'));});
    sel.addEventListener('change',rebuild);
    wrap.append(btn,menu); rebuild();
    const observer=new MutationObserver(rebuild); observer.observe(sel,{childList:true,subtree:true,attributes:true,attributeFilter:['selected']});
  });
}
document.addEventListener('click',()=>document.querySelectorAll('.appSelectMenu.open').forEach(x=>x.classList.remove('open')));
const selectObserver=new MutationObserver(m=>{if(m.some(x=>x.addedNodes.length)) enhanceSelects(document)});
selectObserver.observe(document.body,{childList:true,subtree:true});
function layout(u){
  const admin=u.role==="admin";
  const navItems=[];
  navItems.push(`<button data-nav="home" onclick="dash()"><i class="navIcon">${navIcon("home")}</i><span>الرئيسية</span></button>`);
  navItems.push(`<button data-nav="records" onclick="list()"><i class="navIcon">${navIcon("records")}</i><span>المعاملات</span></button>`);
  if(can("upload_contracts")) navItems.push(`<button data-nav="upload" onclick="uploadPage()"><i class="navIcon">${navIcon("upload")}</i><span>رفع</span></button>`);
  if(can("view_stats")) navItems.push(`<button data-nav="stats" onclick="statsPage()"><i class="navIcon">${navIcon("stats")}</i><span>تحليل الأداء</span></button>`);
  if(can("view_closed")) navItems.push(`<button data-nav="closed" onclick="list('closed')"><i class="navIcon">${navIcon("archive")}</i><span>الأرشيف</span></button>`);
  if(can("manage_users")) navItems.push(`<button data-nav="users" onclick="users()"><i class="navIcon">${navIcon("users")}</i><span>المستخدمون</span></button>`);
  if(can("manage_regions")) navItems.push(`<button data-nav="regions" onclick="regions()"><i class="navIcon">${navIcon("regions")}</i><span>الأقاليم</span></button>`);
  if(can("view_audit_log")) navItems.push(`<button data-nav="audit" onclick="auditPage()"><i class="navIcon">${navIcon("audit")}</i><span>سجل النشاط</span></button>`);
  app.innerHTML=`<div class="appShell">
    <main class="main">
      <header class="topbar">
        <div class="topBrand"><div class="brandMark">CC</div><div><strong>متابعة العقود</strong><small>Contract Control</small></div></div>
        <nav class="topNav">${navItems.join("")}</nav>
        <div class="topActions"><div class="connection"><i></i> متصل</div><button class="avatarTop" onclick="${admin?"users()":"dash()"}">${esc(u.name?.[0]||"م")}</button><button class="logoutTop" onclick="logout()">خروج</button></div>
      </header>
      <div class="pageHeader"><div><span class="eyebrow">نظام متابعة المعاملات</span><h1 id="pageTitle">الرئيسية</h1><p id="pageSub"></p></div><div class="workspacePill">${u.role==="region"?"إقليمك":"المركز الرئيسي"}</div></div>
      <section id="view"></section>
      <footer class="appFooter"><span>Contract Control</span><b>V18.1</b><span>نظام متابعة العقود</span></footer>
    </main>
    <div class="mobileBar">
      <button data-mnav="home" onclick="dash()">${navIcon("home")}<span>الرئيسية</span></button>
      <button data-mnav="records" onclick="list()">${navIcon("records")}<span>المعاملات</span></button>
${u.role==="region"?`<button data-mnav="stats" onclick="statsPage()">${navIcon("stats")}<span>أدائي</span></button>`:`<button data-mnav="stats" onclick="statsPage()">${navIcon("stats")}<span>تحليل</span></button>`}
      ${can("manage_users")?`<button data-mnav="users" onclick="users()">${navIcon("users")}<span>المستخدمون</span></button>`:""}
    </div>
  </div>`;
  dash();

}
function login(){
  clearInterval(timerInterval);clearInterval(idleGuard);ME=null;
  app.innerHTML=`<main class="loginPage"><div class="loginGlow"></div><section class="loginPanel"><div class="loginBrand"><div>CC</div><span>CONTROL CENTER</span></div><h1>متابعة العقود</h1><p>منصة داخلية لإدارة دورة المعاملة، المسؤوليات، الزمن، والتقارير.</p><form id="loginForm"><label>اسم المستخدم<input id="username" required autocomplete="username" placeholder="أدخل اسم المستخدم"></label><label>كلمة المرور<input id="password" type="password" required autocomplete="current-password" placeholder="••••••••"></label><button class="primary wide">الدخول إلى مركز التحكم</button><small id="loginError"></small></form><footer>نظام داخلي · Contract Control</footer></section></main>`;
  document.querySelector("#loginForm").onsubmit=async e=>{
    e.preventDefault(); loginError.textContent="";
    try{await api("/api/login",{method:"POST",body:JSON.stringify({username:username.value.trim(),password:password.value})});wireDatePickers();
boot();}
    catch(x){loginError.textContent=x.message;}
  };
}
async function boot(){try{const d=await api("/api/me");ME=d.user;if(ME){layout(ME);startIdleGuard();}else login();}catch{login();}}
let idleGuard=null;
function startIdleGuard(){clearInterval(idleGuard);idleGuard=setInterval(async()=>{if(!ME)return;try{const d=await api("/api/me",{cacheBust:Date.now()});if(!d.user){clearInterval(idleGuard);ME=null;toast("انتهت الجلسة بسبب عدم النشاط لمدة 30 دقيقة","err");login();}}catch(e){if(String(e.message).includes("غير مصرح")){clearInterval(idleGuard);ME=null;login();}}},60000)}
async function dash(){
  VIEW="home";navActive("home");title("الرئيسية",ME?.role==="region"?"ملخص أدائك خلال آخر 7 أيام":"مركز القيادة والمتابعة");
  const view=document.querySelector("#view"); view.innerHTML=`<div class="loading">جاري تجهيز مركز القيادة…</div>`;
  try{
    const d=await api("/api/dashboard");
    const done=(d.documented||0)+(d.withdrawn||0);
    const pct=d.total?Math.round(done/d.total*100):0;
    const heroTitle=ME.role==="region"?`مرحباً ${esc(ME.name)}`:"مركز القيادة";
    view.innerHTML=`<section class="commandHero"><div class="heroCopy"><span>LIVE CONTROL</span><h2>${heroTitle}</h2><p>${ME.role==="region"?"صورة مختصرة عن معاملات إقليمك خلال آخر أسبوع، وما يحتاج تدخلك الآن.":"نظرة تنفيذية على حجم العمل، الاختناقات، الأداء، وآخر حركة في النظام."}</p><div class="heroActions">${can("upload_contracts")?`<button class="heroBtn" onclick="add()">＋ معاملة جديدة</button>`:""}<button class="heroGhost" onclick="list()">استعراض المعاملات ←</button></div></div><div class="heroMetric"><small>نسبة الإنجاز</small><strong>${pct}%</strong><div><i style="width:${pct}%"></i></div><span>${done} من ${d.total||0} منجزة</span></div></section>
    <div class="statsGrid">${stat("إجمالي المعاملات",d.total||0,"blue")}${stat(ME.role==="region"?"مطلوب منك":"تحتاج إجراء",d.required||0,"orange")}${stat("منجز نهائياً",done,"green")}${stat("متأخر",d.overdue||0,"red",d.overdue?"يتطلب تدخلاً":"ضمن SLA")}</div>
    ${ME.role==="region"?regionHome(d):adminHome(d)}
    ${ME.role==="admin"?activityPanel(d.recent_activity||[]):""}`;
    startLiveTimers();
  }catch(e){view.innerHTML=errorState(e.message);}
}
function regionHome(d){
  const pct=d.total?Math.round(((d.documented||0)+(d.withdrawn||0))/d.total*100):0;
  return `<section class="section"><div class="sectionHead"><div><span class="eyebrow">REGION PULSE</span><h2>نبض الإقليم</h2><p>المؤشرات التي تحتاجها لاتخاذ القرار بسرعة.</p></div><button class="soft" onclick="statsPage()">تحليل أدائي ←</button></div><div class="regionPulse"><div class="pulseMain"><small>المعاملات النشطة</small><strong>${d.inprog||0}</strong><span>منها ${d.required||0} مطلوب منك الآن</span><div class="progress"><i style="width:${Math.min(100,Math.round((d.required||0)/Math.max(1,d.inprog||1)*100))}%"></i></div></div><div class="pulseList"><div><span>مطلوب إفادة</span><b>${d.required||0}</b></div><div><span>بانتظار الاعتماد</span><b>${(d.inprog||0)-(d.required||0)-(d.stopped||0)<0?0:(d.inprog||0)-(d.required||0)-(d.stopped||0)}</b></div><div><span>موقوف</span><b class="dangerText">${d.stopped||0}</b></div><div><span>متأخر</span><b class="dangerText">${d.overdue||0}</b></div></div></div></section>`;
}
function adminHome(d){
  const managers=d.managers||[];
  return `<section class="section"><div class="sectionHead"><div><span class="eyebrow">MANAGER PERFORMANCE</span><h2>أداء مسؤولي الأقاليم</h2><p>المؤشرات مصممة لتحديد الاختناق قبل أن يصبح تأخيراً.</p></div><button class="soft" onclick="statsPage()">فتح التحليل الكامل ←</button></div><div class="managerGrid">${managers.map((m,i)=>managerCard(m,i)).join("")||emptyState("لا يوجد مسؤولون نشطون")}</div></section>`;
}
function managerCard(m,i){
  const total=Number(m.total||0), req=Number(m.required||0), done=Number(m.completed||0), stop=Number(m.stopped||0);
  const pct=total?Math.round(done/total*100):0;
  return `<article class="managerCard"><div class="managerTop"><div class="rankBadge">${i+1}</div><div class="avatar">${esc(m.name?.[0]||"م")}</div><div class="managerIdentity"><h3>${esc(m.name)}</h3><span>${esc(m.region||"بدون إقليم")}</span></div><button class="iconBtn" onclick="statsPage(${m.id})">↗</button></div><div class="managerNumbers"><div><small>نشطة</small><b>${total}</b></div><div><small>مطلوب منه</small><b class="orangeText">${req}</b></div><div><small>موقوفة</small><b class="dangerText">${stop}</b></div></div><div class="progress"><i style="width:${pct}%"></i></div><div class="managerBottom"><span>${pct}% إنجاز</span><button class="textBtn" onclick="statsPage(${m.id})">تفاصيل الأداء</button></div></article>`;
}
function activityPanel(items){
  return `<section class="section"><div class="sectionHead"><div><span class="eyebrow">AUDIT STREAM</span><h2>آخر النشاطات</h2><p>الحركة الأخيرة على المعاملات في المركز.</p></div><button class="soft" onclick="auditPage()">السجل الكامل ←</button></div><div class="activityTable"><div class="activityHeader"><span>النشاط</span><span>المعاملة</span><span>المستخدم</span><span>التاريخ</span></div>${items.length?items.slice(0,8).map(e=>`<div class="activityRow"><span><i></i>${esc(e.action||"نشاط")}</span><b>#${esc(e.record_id||"—")} ${esc(e.employee_name||"")}</b><span>${esc(e.actor_name||"النظام")}</span><small>${fmtDateTime(e.created_at)}</small></div>`).join(""):`<div class="emptyRow">لا توجد نشاطات حديثة</div>`}</div></section>`;
}
function title(a,b=""){document.querySelector("#pageTitle").textContent=a;document.querySelector("#pageSub").textContent=b;}
function errorState(msg){return `<div class="errorState"><div>!</div><h3>تعذر تحميل الشاشة</h3><p>${esc(msg)}</p><button class="primary" onclick="dash()">إعادة المحاولة</button></div>`;}
function emptyState(msg){return `<div class="emptyState"><span>⌁</span><b>${esc(msg)}</b></div>`;}
async function list(mode=""){
  if(ME.role==="region" && !mode) mode="required";
  VIEW=mode||"records"; navActive(mode==="closed"?"closed":"records");
  const pageTitle=ME.role==="region"?(mode==="closed"?"منتهية":mode==="approval"?"بانتظار الاعتماد":"مطلوب مني"):(mode==="closed"?"الأرشيف":mode==="required"?"المطلوب مني":"المعاملات");
  const sub=ME.role==="region"?"":(mode==="required"?"المعاملات التي تحتاج إجراءك الآن":"");
  title(pageTitle,sub);
  const v=document.querySelector("#view");
  v.innerHTML=`<section class="section">
    <div class="sectionHead"><div><span class="eyebrow">TRANSACTION INBOX</span><h2>${esc(pageTitle)}</h2></div>${can("export")?`<button class="soft" onclick="exportFromList()">تصدير النتائج</button>`:""}</div>
    ${ME.role==="region"?`<div class="regionWorkspace"><div class="regionWorkspaceIntro"><span class="eyebrow">REGION WORKSPACE</span><strong>صندوق عمل الإقليم</strong><small>مطلوب منك · بانتظار الاعتماد · منتهية</small></div><div class="inboxTabs regionTabs"><button class="${mode==="required"?"active":""}" onclick="list('required')"><span>مطلوب مني</span><b id="reqBadge">0</b></button><button class="${mode==="approval"?"active":""}" onclick="list('approval')"><span>بانتظار الاعتماد</span><b id="approvalBadge">0</b></button><button class="${mode==="closed"?"active":""}" onclick="list('closed')"><span>منتهية</span><b id="closedBadge">0</b></button></div></div>`:""}
    <div class="filterBar"><input id="q" placeholder="بحث برقم الموظف، الاسم، أو رقم المعاملة">${ME.role==="region"?"":`<select id="statusFilter"><option value="">كل الحالات</option><option value="required">مطلوب إجراء</option><option value="waiting_region">بانتظار إفادة الإقليم</option><option value="returned">مرتجع للتصحيح</option><option value="region_documented">تمت الإفادة — بانتظار الاعتماد</option><option value="region_withdrawn">إفادة انسحاب — بانتظار الاعتماد</option><option value="stopped">موقوفة</option><option value="final_documented">تم التوثيق</option><option value="final_withdrawn">منسحب الموظف</option><option value="cancelled">ملغاة</option></select>`}${ME.role==="region"?"":`<select id="managerFilter"><option value="">كل المسؤولين</option></select>`}<label>من<input id="fromFilter" type="date"></label><label>إلى<input id="toFilter" type="date"></label><button class="primary" onclick="loadRecords()">بحث</button></div><div id="recordCards" class="recordGrid"></div>
  </section>`;
  if(ME.role!=="region"){const sf=document.querySelector("#statusFilter");if(sf)sf.value=mode||"";}
  try{const d=await api("/api/managers");const mf=document.querySelector("#managerFilter");if(mf)mf.innerHTML=`<option value="">كل المسؤولين</option>${(d.managers||[]).map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("")}`}catch{}
  await loadRecords();
  if(ME.role==="region") refreshRegionWorkspaceCounts();
}
async function refreshRegionWorkspaceCounts(){
  if(ME?.role!=="region")return;
  try{
    const [a,b,c]=await Promise.all([api("/api/records?status=required&limit=1"),api("/api/records?status=approval&limit=1"),api("/api/records?status=closed&limit=1")]);
    const put=(id,v)=>{const e=document.querySelector(id);if(e)e.textContent=Number(v||0)};
    put("#reqBadge",a.total_count??a.total??(a.records||[]).length);
    put("#approvalBadge",b.total_count??b.total??(b.records||[]).length);
    put("#closedBadge",c.total_count??c.total??(c.records||[]).length);
  }catch(_){ }
}
async function loadRecords(){
  const q=document.querySelector("#q")?.value||"", status=document.querySelector("#statusFilter")?.value||"", manager_id=document.querySelector("#managerFilter")?.value||"", from=document.querySelector("#fromFilter")?.value||"", to=document.querySelector("#toFilter")?.value||"";
  const qs=new URLSearchParams({q,status,manager_id,from,to});
  const target=document.querySelector("#recordCards");if(!target)return;
  target.innerHTML=`<div class="loading">جاري جلب المعاملات…</div>`;
  try{
    qs.set("limit","60");qs.set("offset","0");
    const d=await api("/api/records?"+qs);let rows=d.records||[];
    
    target.innerHTML=(rows.map(recordCard).join("")||emptyState("لا توجد معاملات مطابقة"))+(d.has_more?`<button class="soft loadMoreBtn" onclick="loadMoreRecords(this)">تحميل المزيد</button>`:"");
    startLiveTimers();refreshBadge();
  }catch(e){target.innerHTML=errorState(e.message);}
}
async function loadMoreRecords(btn){
 const q=document.querySelector("#q")?.value||"",status=document.querySelector("#statusFilter")?.value||"",manager_id=document.querySelector("#managerFilter")?.value||"",from=document.querySelector("#fromFilter")?.value||"",to=document.querySelector("#toFilter")?.value||"";
 const current=document.querySelectorAll(".recordCard").length;btn.disabled=true;btn.textContent="جاري التحميل…";
 try{const qs=new URLSearchParams({q,status,manager_id,from,to,limit:"60",offset:String(current)});const d=await api("/api/records?"+qs);let rows=d.records||[];if(VIEW==="closed")rows=rows.filter(r=>["final_documented","final_withdrawn","cancelled"].includes(r.status));btn.insertAdjacentHTML("beforebegin",rows.map(recordCard).join(""));if(!d.has_more)btn.remove();else{btn.disabled=false;btn.textContent="تحميل المزيد"}startLiveTimers()}catch(e){btn.disabled=false;btn.textContent="إعادة المحاولة";toast(e.message,"err")}}
function recordCard(r){
  const finished=["final_documented","final_withdrawn","cancelled","stopped"].includes(r.status);
  const canRegion=ME?.role==="region" && can("respond_region") && ["waiting_region","returned"].includes(r.status);
  const canApprove=(ME?.role==="requester"||ME?.role==="admin") && can("approve") && ["region_documented","region_withdrawn"].includes(r.status);
  const actionNo=r.interruption_transaction_no||"";
  const withdrawn=["region_withdrawn","final_withdrawn"].includes(r.status)||!!actionNo;
  const status=statusLabel[r.status]||r.status||"—";
  const waitingAt=(r.status==="waiting_region"||r.status==="returned")?(r.region_user_name||"مسؤول الإقليم"):"";
  const primary=canRegion
    ? `<button class="v3-action primaryAction" onclick="event.stopPropagation();quickRegion(${r.id})">إفادة</button>`
    : canApprove
      ? `<button class="v3-action primaryAction" onclick="event.stopPropagation();quickApprove(${r.id},'${r.status}')">اعتماد</button>`
      : `<button class="v3-action ghostAction" onclick="event.stopPropagation();openRecord(${r.id})">تفاصيل</button>`;

  return `<div class="v3-case-row" onclick="openRecord(${r.id})">
    <div class="v3-case-identity">
      <span class="v3-case-number">#${r.id}</span>
      <div><strong>${esc(r.employee_name)}</strong><small>${esc(r.employee_no||"—")}</small></div>
    </div>
    <div class="v3-case-type"><span class="v3-label">رقم معاملة التعيين</span><b class="v3-monoValue">${esc(r.transaction_no||"—")}</b></div>
    <div class="v3-case-region"><span class="v3-label">الإقليم</span><b>${esc(r.region||"—")}</b></div>
    <div class="v3-case-assignee"><span class="v3-label">المسؤول</span><b>${esc(r.region_user_name||"—")}</b></div>
    <div class="v3-case-status v3-case-status-stack">
      ${withdrawn
        ? `<span class="v3-status is-danger">↗ منسحب الموظف</span><span class="v3-status is-danger v3-action-badge">#${esc(actionNo||"—")} — انقطاع / اتخاذ إجراء</span>`
        : waitingAt
          ? `<span class="v3-status is-pending">بانتظار الإفادة</span><span class="v3-status is-pending v3-waiting-user">متوقف عند: ${esc(waitingAt)}</span>`
          : `<span class="v3-status ${finished?'is-done':r.status==='region_withdrawn'?'is-danger':'is-pending'}">${esc(status)}</span>`}
    </div>
    <div class="v3-case-action">${primary}<button class="v3-open" aria-label="فتح">↗</button></div>
  </div>`;
}
async function quickRegion(id){
  document.querySelector(".quickActionStrip")?.remove();
  try{
    const d=await api(`/api/records/${id}`),r=d.record;
    const cards=document.querySelector("#recordCards"); if(!cards)return;
    cards.insertAdjacentHTML("beforebegin",`<section class="quickActionStrip" data-record="${id}">
      <div class="qaIdentity"><span class="qaBadge">إف</span><div><strong>إفادة سريعة · #${esc(r.id)}</strong><small>${esc(r.employee_name)} · ${esc(r.employee_no)} · ${esc(r.region)}</small></div></div>
      <div class="qaField"><small>معاملة التعيين</small><b>${esc(r.transaction_no||"—")}</b></div>
      <div class="qaActions"><button class="qaPrimary" onclick="quickRegionSubmit(${id},'documented')">تم التوثيق</button><button class="qaDanger" onclick="quickRegionWithdraw(${id})">منسحب</button></div>
      <div id="quickRegionArea" class="qaArea"><label>الإفادة<textarea id="quickRegionNote" placeholder="الإفادة المختصرة..."></textarea></label></div>
    </section>`);
    document.querySelector(".quickActionStrip")?.scrollIntoView({behavior:"smooth",block:"nearest"});
  }catch(e){toast(e.message,"err")}
}
async function quickRegionSubmit(id,kind){
  const note=document.querySelector("#quickRegionNote")?.value||"";
  if(kind!=="documented")return;
  try{await api(`/api/records/${id}`,{method:"POST",body:JSON.stringify({action:"region_documented",note})});document.querySelector(".quickActionStrip")?.remove();toast("تم تسجيل الإفادة");loadRecords();}catch(e){toast(e.message,"err")}
}
function quickRegionWithdraw(id){
  document.querySelector(".withdrawalModal1s")?.remove();
  document.body.insertAdjacentHTML("beforeend",`<div class="modalShade withdrawalModal1s"><div class="withdrawalModal1s__box">
    <button class="modalClose" onclick="this.closest('.withdrawalModal1s').remove()">×</button>
    <span class="eyebrow">REGION DECISION</span><h2>إفادة انسحاب الموظف</h2>
    <p class="withdrawalModal1s__hint">سجل آخر يوم عمل ورقم معاملة الانقطاع / اتخاذ الإجراء ثم اعتمد الإفادة.</p>
    <div class="withdrawal-1s__grid">
      <label class="withdrawal-1s__field">آخر يوم عمل<input id="qEnd" type="date"></label>
      <label class="withdrawal-1s__field">رقم معاملة الانقطاع / اتخاذ الإجراء<input id="qTxn" inputmode="numeric" placeholder="رقم المعاملة"></label>
    </div>
    <button class="danger wide big" onclick="quickRegionWithdrawSubmit(${id})">تسجيل إفادة الانسحاب</button>
  </div></div>`);
}
async function quickRegionWithdrawSubmit(id){
  const note=document.querySelector("#quickRegionNote")?.value||"",end=document.querySelector("#qEnd")?.value||"",txn=document.querySelector("#qTxn")?.value.trim()||"";
  if(!end||!txn)return toast("أكمل آخر يوم عمل ورقم معاملة الانقطاع / اتخاذ الإجراء","err");
  try{await api(`/api/records/${id}`,{method:"POST",body:JSON.stringify({action:"region_withdrawn",note,end_date:end,interruption_transaction_no:txn})});document.querySelector(".withdrawalModal1s")?.remove();toast("تم تسجيل إفادة الانسحاب");loadRecords()}catch(e){toast(e.message,"err")}
}
async function quickApprove(id,status){const action=status==="region_withdrawn"?"final_withdrawn":"final_documented";try{await api(`/api/records/${id}`,{method:"POST",body:JSON.stringify({action,note:"اعتماد"})});toast("تم الاعتماد وإغلاق المعاملة");loadRecords()}catch(e){toast(e.message,"err")}}
async function openRecord(id){
  document.querySelector(".recordModal")?.remove();
  document.body.insertAdjacentHTML("beforeend",`<div class="recordModal"><div class="recordSheet v4-sheet"><button class="modalClose v4-close" onclick="closeRecord()" title="إغلاق تفاصيل المعاملة" aria-label="إغلاق تفاصيل المعاملة">× إغلاق</button><div class="loading">جاري تحميل المعاملة…</div></div></div>`);
  try{
    const d=await api(`/api/records/${id}`),r=d.record,events=d.events||[],stages=d.stages||[];
    selectedRecord=r;
    const actionNo=r.interruption_transaction_no||"";
    const withdrawn=["region_withdrawn","final_withdrawn"].includes(r.status)||!!actionNo;
    const finished=["final_documented","final_withdrawn","cancelled","stopped"].includes(r.status);

    const identity=`
      <section class="v4-identity">
        <div class="v4-identity-main">
          <div class="v4-case-mark">CASE<br><b>#${r.id}</b></div>
          <div>
            <span class="v4-eyebrow">معاملة موظف</span>
            <h2>${esc(r.employee_name)}</h2>
            <p>${esc(r.employee_no||"—")} <i>•</i> ${esc(r.region||"—")} <i>•</i> تعيين</p>
          </div>
        </div>
        <div class="v4-identity-status">
          <span class="v4-status ${finished?'done':withdrawn?'danger':'pending'}">${esc(statusLabel[r.status]||r.status)}</span>
          <small>آخر تحديث ${fmtDateTime(r.updated_at)}</small>
        </div>
      </section>`;

    const overview=`
      <section class="v4-panel">
        <div class="v4-panel-head"><div><span class="v4-eyebrow">OVERVIEW</span><h3>ملخص المعاملة</h3></div></div>
        <div class="v4-overview-grid">
          <div><span>رقم معاملة التعيين</span><b>${esc(r.transaction_no||"—")}</b></div>
          <div><span>تاريخ المباشرة</span><b>${fmtDate(r.start_date)}</b></div>
          <div><span>مسؤول الإقليم</span><b>${esc(r.region_user_name||"—")}</b></div>
          <div><span>مقدم الطلب</span><b>${esc(r.requester_name||"—")}</b></div>
          ${withdrawn?`<div class="v4-withdraw-data"><span>الانقطاع / اتخاذ الإجراء</span><b>${esc(actionNo||"—")}</b></div><div class="v4-withdraw-data"><span>آخر يوم عمل</span><b>${fmtDate(r.end_date)}</b></div>`:""}
        </div>
      </section>`;

    const process=`
      <section class="v4-panel">
        <div class="v4-panel-head"><div><span class="v4-eyebrow">WORKFLOW</span><h3>مسار المعاملة</h3></div></div>
        ${horizontalTimeline(r,stages)}
      </section>`;

    const activity=events.length?events.slice().reverse().map((e,n)=>`
      <div class="v4-event">
        <span class="v4-event-dot ${n===0?'current':''}"></span>
        <div><b>${esc(e.action)}</b><small>${fmtDateTime(e.created_at)} · ${esc(e.actor_name||"النظام")}</small>${e.note?`<p>${esc(e.note)}</p>`:""}</div>
      </div>`).join(""):`<div class="emptyState">لا يوجد نشاط مسجل</div>`;

    let actionHtml=actionsHtml(r);
    document.querySelector(".recordSheet").innerHTML=`<button class="modalClose v4-close" onclick="closeRecord()" title="إغلاق تفاصيل المعاملة" aria-label="إغلاق تفاصيل المعاملة">×</button>
      ${identity}
      <div class="v4-body">
        <main class="v4-main">
          ${overview}
          ${process}
          ${r.region_note?`<section class="v4-panel v4-note"><div class="v4-panel-head"><h3>إفادة مسؤول الإقليم</h3></div><p>${esc(r.region_note)}</p></section>`:""}
          <section class="v4-panel v4-action-panel">
            <div class="v4-panel-head"><div><span class="v4-eyebrow">ACTION</span><h3>الإجراء</h3></div></div>
            ${actionHtml}
          </section>
        </main>
        <aside class="v4-side">
          <section class="v4-panel">
            <div class="v4-panel-head"><div><span class="v4-eyebrow">ACTIVITY</span><h3>سجل المعاملة</h3></div></div>
            <div class="v4-events">${activity}</div>
          </section>
        </aside>
      </div>`;
    startLiveTimers();
  }catch(e){
    const msg=String(e?.message||"تعذر تحميل المعاملة");
    document.querySelector(".recordSheet").innerHTML=`<button class="modalClose v4-close" onclick="closeRecord()" title="إغلاق تفاصيل المعاملة" aria-label="إغلاق تفاصيل المعاملة">×</button><div class="cw-error"><b>تعذر تحميل المعاملة</b><span>${esc(msg)}</span><button onclick="closeRecord()">إغلاق</button></div>`;
  }
}
function finishedStatusClass(status){
  if(["final_documented","region_documented"].includes(status)) return "success";
  if(["stopped","waiting_region","returned","region_withdrawn"].includes(status)) return "warning";
  return "";
}
function stageSecondsClient(rows,stage){
  const now=Date.now();
  return (rows||[]).filter(x=>x.stage===stage).reduce((sum,x)=>{
    const a=new Date(String(x.started_at).replace(" ","T")+"Z").getTime();
    const b=x.ended_at?new Date(String(x.ended_at).replace(" ","T")+"Z").getTime():now;
    return sum+Math.max(0,Math.floor((b-a)/1000));
  },0);
}
function info(label,value){return `<div><small>${label}</small><b>${esc(value||"—")}</b></div>`}
function horizontalTimeline(r,stages){
 const defs=[['upload','رفع المعاملة','↑'],['region','إفادة الإقليم','✓'],['approval','الاعتماد','◆'],['closed','الإغلاق','✓']];
 const status=r.status;
 const idx=(status==='waiting_region'||status==='returned')?1:(status==='region_documented'||status==='region_withdrawn'?2:(['final_documented','final_withdrawn','cancelled'].includes(status)?3:0));
 return `<div class="hTimeline">${defs.map((d,i)=>{const done=i<idx||i===0&&idx>0,active=i===idx;const sec=stageSecondsClient(stages,d[0]);return `<div class="hStep ${done?'done ':''}${active?'active ':''}"><div class="hNode">${d[2]}</div><b>${d[1]}</b><small>${done?'مكتمل':active?'المرحلة الحالية':'قادم'}${sec?` · ${duration(sec)}`:''}</small></div>${i<defs.length-1?`<div class="hLine ${done?'done':''}"></div>`:''}`}).join('')}</div>`;
}
function actionsHtml(r){
  const admin=ME.role==="admin";
  const regionCan=can("respond_region")&&(ME.role==="region"||admin);
  const approveCan=can("approve")&&(ME.role==="requester"||admin);
  const active=!["final_documented","final_withdrawn","cancelled","stopped"].includes(r.status);

  let h="";
  if((r.status==="waiting_region"||r.status==="returned")&&regionCan){
    h+=`<div class="v4-action-card">
      <div class="v4-action-title"><span class="v4-action-icon">إف</span><div><b>إفادة الإقليم</b><small>اختر النتيجة ثم نفذ الإجراء</small></div></div>
      <textarea id="detailNote" placeholder="ملاحظة الإفادة — اختيارية"></textarea>
      <div class="v4-action-buttons">
        <button class="v4-btn success" onclick="perform(${r.id},'region_documented')">✓ تم التوثيق</button>
        <button class="v4-btn danger" onclick="withdrawForm(${r.id})">منسحب الموظف</button>
      </div>
      <div id="withdrawArea"></div>
    </div>`;
  }
  if((r.status==="region_documented"||r.status==="region_withdrawn")&&approveCan){
    h+=`<div class="v4-action-card approval">
      <div class="v4-action-title"><span class="v4-action-icon">✓</span><div><b>مراجعة واعتماد</b><small>${r.status==="region_withdrawn"?"اعتماد الانسحاب أو إعادة المعاملة":"اعتماد التوثيق أو إعادة المعاملة"}</small></div></div>
      <div class="v4-action-buttons">
        ${r.status==="region_withdrawn"?`<button class="v4-btn danger" onclick="perform(${r.id},'final_withdrawn','approveNote')">اعتماد الانسحاب</button>`:`<button class="v4-btn success" onclick="perform(${r.id},'final_documented','approveNote')">اعتماد التوثيق</button>`}
        <button class="v4-btn light" onclick="perform(${r.id},'return','approveNote')">↩ إرجاع للتصحيح</button>
      </div>
      <textarea id="approveNote" placeholder="ملاحظة الاعتماد — اختيارية"></textarea>
    </div>`;
  }
  if(active&&can("stop_records"))
    h+=`<div class="v4-secondary-action"><span>إيقاف المعاملة</span><button class="v4-btn danger small" onclick="perform(${r.id},'stop','stopNote')">إيقاف</button><textarea id="stopNote" placeholder="سبب الإيقاف — اختياري"></textarea></div>`;
  if(can("reassign_records")&&active)
    h+=`<div class="v4-secondary-action"><span>إسناد المعاملة</span><div id="reassignWrap">جاري تحميل المسؤولين…</div><textarea id="reassignNote" placeholder="سبب الإسناد — اختياري"></textarea><button class="v4-btn primary small" onclick="reassign(${r.id})">إسناد</button></div>`;
  if(can("reactivate_records")&&["stopped","final_documented","final_withdrawn","cancelled"].includes(r.status))
    h+=`<div class="v4-secondary-action"><span>إعادة تنشيط المعاملة</span><button class="v4-btn primary small" onclick="perform(${r.id},'reactivate')">إعادة تنشيط</button></div>`;
  if(r.requester_note) h+=`<div class="v4-note-inline"><b>ملاحظة الطلب</b><p>${esc(r.requester_note)}</p></div>`;
  return h||`<div class="v4-no-action"><span>✓</span><div><b>لا يوجد إجراء مطلوب</b><small>المعاملة في حالة مستقرة حاليًا.</small></div></div>`;
}
async function withdrawForm(id){
  const area=document.querySelector("#withdrawArea"); if(!area)return;
  area.innerHTML=`<div class="v4-withdraw-form">
    <div class="v4-withdraw-head"><span>انسحاب الموظف</span><small>بيانات إلزامية</small></div>
    <div class="v4-withdraw-fields">
      <label><span>آخر يوم عمل</span><input id="withdrawEnd" type="date" onclick="this.showPicker?.()"></label>
      <label><span>رقم الانقطاع / اتخاذ الإجراء</span><input id="withdrawTxn" inputmode="numeric" placeholder="رقم المعاملة"></label>
    </div>
    <div class="v4-withdraw-actions"><button class="v4-btn light small" onclick="document.querySelector('#withdrawArea').innerHTML=''">إلغاء</button><button class="v4-btn danger small" onclick="perform(${id},'region_withdrawn')">تسجيل الانسحاب</button></div>
  </div>`;
}
async function perform(id,action,noteId="detailNote"){
  const note=document.querySelector("#"+noteId)?.value||"";
  const body={action,note};
  if(action==="region_withdrawn"){body.end_date=document.querySelector("#withdrawEnd")?.value||"";body.interruption_transaction_no=document.querySelector("#withdrawTxn")?.value.trim()||"";if(!body.end_date||!body.interruption_transaction_no){toast("أكمل بيانات الانسحاب","err");return;}}
  if(action==="return"&&!note.trim()){toast("اكتب سبب الإرجاع","err");return;}
  try{await api(`/api/records/${id}`,{method:"POST",body:JSON.stringify(body)});toast(action==="stop"?"تم إيقاف المعاملة":action==="return"?"تم إرجاع المعاملة للتصحيح":"تم تحديث المعاملة");closeRecord();await list(VIEW==="required"?"required":VIEW==="closed"?"closed":"");}
  catch(e){toast(e.message,"err");}
}
async function reassign(id){
  const sel=document.querySelector("#reassignManager");if(!sel?.value){toast("اختر المسؤول الجديد","err");return;}
  try{await api(`/api/records/${id}`,{method:"POST",body:JSON.stringify({action:"reassign",region_user_id:Number(sel.value),note:document.querySelector("#reassignNote")?.value||""})});toast("تم الإسناد بنجاح");openRecord(id);}
  catch(e){toast(e.message,"err");}
}
async function loadReassignManagers(){
  const w=document.querySelector("#reassignWrap");if(!w)return;
  try{const d=await api("/api/managers");w.innerHTML=`<select id="reassignManager"><option value="">اختر المسؤول</option>${d.managers.map(m=>`<option value="${m.id}">${esc(m.name)} — ${esc(m.region||"بدون إقليم")}</option>`).join("")}</select>`}
  catch(e){w.innerHTML=`<span class="err">${esc(e.message)}</span>`}
}
function closeRecord(){document.querySelector(".recordModal")?.remove();selectedRecord=null;}
function startLiveTimers(){
  clearInterval(timerInterval);
  const tick=()=>document.querySelectorAll(".liveTimer").forEach(el=>el.textContent=liveDuration(el.dataset.start,el.dataset.paused,el.dataset.end));
  tick();timerInterval=setInterval(tick,1000);
  if(selectedRecord && document.querySelector("#reassignWrap"))loadReassignManagers();
}
async function uploadPage(){
  navActive("upload"); VIEW="upload"; title("رفع المعاملات","مركز إدخال موحد — معاملة فردية ورفع جماعي في شاشة واحدة.");
  const v=document.querySelector("#view");
  v.innerHTML=`<section class="section uploadWorkspace"><div class="sectionHead"><div><span class="eyebrow">TRANSACTION INTAKE</span><h2>مركز رفع المعاملات</h2><p>مسار فردي وجماعي في شاشة واحدة بدون تنقل.</p></div><a class="soft" href="/contract_upload_template.xlsx" download="نموذج_رفع_المعاملات.xlsx">↓ تحميل نموذج Excel</a></div><div class="intakeHub"><section class="intakeCard singleCard"><div class="intakeCardHead"><span class="intakeNumber">01</span><div><span class="eyebrow">SINGLE INTAKE</span><h3>معاملة واحدة</h3><p>إسناد تلقائي لمسؤول الإقليم.</p></div></div><div class="formGrid intakeForm"><label>رقم الموظف<input id="en" placeholder="مثال: 10245"></label><label>اسم الموظف<input id="nm" placeholder="اسم الموظف"></label><label>رقم معاملة التعيين<input id="tn" placeholder="رقم المعاملة"></label><label>الإقليم<select id="rg"></select></label><label>تاريخ المباشرة<input id="sd" type="date"></label></div><button class="primary big wide" onclick="save()">إنشاء المعاملة</button><p id="msg" class="formMessage"></p></section><section class="intakeCard bulkCard"><div class="intakeCardHead"><span class="intakeNumber">02</span><div><span class="eyebrow">BULK IMPORT</span><h3>رفع جماعي</h3><p>فحص الصفوف قبل الإنشاء.</p></div></div><div class="dropzone" id="dropzone"><div class="uploadGlyph">↑</div><h3>اسحب ملف Excel هنا</h3><p>XLSX · XLSM · XLS · CSV</p><span class="dropHint">أو اضغط لاختيار الملف</span><input id="fileInput" type="file" accept=".xlsx,.xlsm,.xls,.csv"></div><div class="bulkActions"><div><b>فحص آمن قبل الإنشاء</b><span>الصفوف الناقصة تُرفض دون إيقاف الصفوف الصحيحة.</span></div><button class="primary big" onclick="importFile()">فحص الملف وإنشاء المعاملات</button></div><div id="importMsg"></div></section></div></section>`;
  const rg=document.querySelector("#rg"); try{const d=await api("/api/regions");if(rg)rg.innerHTML=(d.regions||[]).map(r=>`<option>${esc(r.name||r)}</option>`).join("");}catch{if(rg)rg.innerHTML=`<option>تعذر تحميل الأقاليم</option>`;}
  const dz=document.querySelector("#dropzone"),fi=document.querySelector("#fileInput"); dz.onclick=e=>{if(e.target!==fi)fi.click()};
  ["dragenter","dragover"].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add("drag")})); ["dragleave","drop"].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove("drag")}));
  dz.addEventListener("drop",e=>{if(e.dataTransfer.files[0]){fi.files=e.dataTransfer.files;dz.querySelector("h3").textContent=e.dataTransfer.files[0].name}}); fi.onchange=()=>{if(fi.files[0])dz.querySelector("h3").textContent=fi.files[0].name};
}
async function add(){return uploadPage()}
function bulk(){return uploadPage()}
async function save(){
 const en=document.querySelector("#en"),nm=document.querySelector("#nm"),tn=document.querySelector("#tn"),rg=document.querySelector("#rg"),sd=document.querySelector("#sd"),msg=document.querySelector("#msg");
 try{await api("/api/records",{method:"POST",body:JSON.stringify({employee_no:en?.value.trim(),employee_name:nm?.value.trim(),transaction_no:tn?.value.trim(),region:rg?.value,start_date:sd?.value})});msg.className="formMessage ok";msg.textContent="تم إنشاء المعاملة وإسنادها تلقائياً.";en.value=nm.value=tn.value="";sd.value="";}catch(e){msg.className="formMessage err";msg.textContent=e.message;}
}
function firstVal(row,keys){for(const k of keys)if(row[k]!=null&&String(row[k]).trim()!=="")return String(row[k]).trim();return "";}
function normalizeDate(v){if(!v)return "";const s=String(v).trim();if(/^\d{4}-\d{2}-\d{2}$/.test(s))return s;const m=s.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4})$/);return m?`${m[3]}-${m[2].padStart(2,"0")}-${m[1].padStart(2,"0")}`:s;}
async function importFile(){
  const file=document.querySelector("#fileInput")?.files?.[0],msg=document.querySelector("#importMsg");if(!file){toast("اختر ملف Excel أولاً","err");return;}
  try{msg.innerHTML=`<div class="loadingMini">جاري تجهيز محرك Excel وفحص ${esc(file.name)}…</div>`;const XLSX=await ensureXLSX();const wb=XLSX.read(await file.arrayBuffer(),{cellDates:true,raw:false});const sheet=wb.Sheets[wb.SheetNames[0]],raw=XLSX.utils.sheet_to_json(sheet,{defval:"",raw:false});if(!raw.length)throw Error("الملف فارغ.");
    const rows=raw.map((x,i)=>({row_no:i+2,employee_no:firstVal(x,["رقم الموظف","الرقم الوظيفي","employee_no"]),employee_name:firstVal(x,["اسم الموظف","employee_name","name"]),transaction_no:firstVal(x,["رقم معاملة التعيين","رقم المعاملة","transaction_no"]),interruption_transaction_no:firstVal(x,["رقم معاملة الانقطاع أو اتخاذ الإجراء","رقم معاملة الانقطاع","interruption_transaction_no"]),region:firstVal(x,["الإقليم","الاقليم","المنطقة","region"]),start_date:normalizeDate(firstVal(x,["تاريخ المباشرة","start_date"]))}));
    const d=await api("/api/records/bulk",{method:"POST",body:JSON.stringify({rows})});
    msg.innerHTML=d.skipped?`<div class="importResult warn">تم إنشاء <b>${d.added}</b> ومعالجة <b>${d.skipped}</b> صفوف تحتاج تصحيح.<br>${esc((d.errors||[]).slice(0,8).map(x=>`صف ${x.row}: ${x.reason}`).join(" · "))}</div>`:`<div class="importResult ok">تم إنشاء ${d.added} معاملة بنجاح.</div>`;
  }catch(e){msg.innerHTML=`<div class="importResult err">${esc(e.message)}</div>`}
}
function impactMetric(label,value,total,color,percent=false){const n=Number(value||0),pct=percent?n:((Number(total||0)?Math.round(n/Number(total)*100):0));return `<div class="impactMetric"><div><span>${label}</span><b>${percent?pct+"%":n}</b></div><i class="${color}" style="width:${Math.min(100,pct)}%"></i></div>`}
async function statsPage(managerId=""){
  VIEW="stats";navActive("stats");title("تحليلات الأداء","قياس أثر المستخدمين بالوقت والنتائج، بعيداً عن عدد الإقليم.");
  const v=document.querySelector("#view");v.innerHTML=`<div class="loading">جاري بناء التحليل…</div>`;
  try{
    const all=ME.role==="admin"?await api("/api/users"):null;
    const selected=ME.role==="region"?String(ME.id):String(managerId||"0");
    const [d]=await Promise.all([api(`/api/manager-stats?manager_id=${encodeURIComponent(selected)}&from=${encodeURIComponent(localStorage.getItem("statsFrom")||"")}&to=${encodeURIComponent(localStorage.getItem("statsTo")||"")}`)]);
    const selectableUsers=(all?.users||[]).filter(x=>x.active&&["requester","region"].includes(x.role));
    const userOptions=all?`<select class="statsUserSelect" onchange="statsPage(this.value)"><option value="0" ${selected==="0"?"selected":""}>كل المستخدمين</option>${selectableUsers.map(m=>`<option value="${m.id}" ${Number(m.id)===Number(d.manager.id)?"selected":""}>${esc(m.name)} — ${esc(roleLabel[m.role]||m.role)}${m.region?` — ${esc(m.region)}`:""}</option>`).join("")}</select>`:"";
    const roleText=d.manager.role==="region"?"مسؤول إقليم":d.manager.role==="requester"?"HR":"جميع المستخدمين";
    const compareRows=(d.comparison||[]).map(x=>`<div class="performanceCompareRow ${Number(x.id)===Number(d.manager.id)&&Number(d.manager.id)!==0?'current':''}">
      <strong>${esc(x.name)}<small>${esc(roleLabel[x.role]||x.role)}${x.region?` · ${esc(x.region)}`:""}</small></strong>
      <b>${x.documented}</b>
      <b>${x.withdrawn}</b>
      <b>${esc(x.avg_time_label||"—")}</b>
      <b class="${x.sla_rate>=90?'goodText':x.sla_rate>=70?'warnText':'dangerText'}">${x.sla_rate}%</b>
    </div>`).join("");
    v.innerHTML=`<section class="section">
      <div class="analysisToolbar">
        <div><span class="eyebrow">PERFORMANCE INTELLIGENCE</span><h2>${esc(d.manager.name)}</h2><span class="analysisMeta">${esc(roleText)} · ${esc(d.manager.region||"")}</span></div>
        ${userOptions}
      </div>
      <div class="analyticsFilters"><label>من<input id="statsFrom" type="date" value="${esc(d.filters.from)}"></label><label>إلى<input id="statsTo" type="date" value="${esc(d.filters.to)}"></label><button class="primary" onclick="applyStats(${Number(d.manager.id)||0})">تطبيق</button><button class="soft" onclick="exportStats(${Number(d.manager.id)||0})">تصدير Excel</button></div>
      <div class="statsGrid performanceKpis">
        ${stat("إجمالي المعاملات",d.total,"blue")}
        ${stat("تم التوثيق",d.documented,"green")}
        ${stat("منسحب الموظف",d.withdrawn,"orange")}
        ${stat("متوسط مدة الإغلاق",d.avg_duration_label,"blue")}
        ${stat("متوسط استجابة الإقليم",d.avg_response_label,"orange")}
        ${stat("نسبة الالتزام",d.withinSlaRate+"%","green")}
      </div>
      <div class="analysisGrid performancePanels">
        <section class="chartCard"><div class="chartHead"><h3>الأثر الفعلي</h3><span>${d.total} معاملة</span></div><div class="impactMetrics">
          ${impactMetric("نسبة التوثيق",d.quality.documentation_rate,"","green",true)}
          ${impactMetric("نسبة الانسحاب",d.quality.withdrawal_rate,"","orange",true)}
          ${impactMetric("الالتزام بالوقت",d.withinSlaRate,"","blue",true)}
          ${impactMetric("متأخرة الآن",d.overdue,d.total,"red")}
          ${impactMetric("متوسط التأخير",d.avg_delay_label,"","red",true)}
        </div></section>
        <section class="chartCard"><div class="chartHead"><h3>توزيع النتائج</h3><span>${d.total} معاملة</span></div>${(d.statusBreakdown||[]).filter(x=>!['returned','stopped','cancelled'].includes(x.key)).map(x=>analysisBar(x.label,x.value,d.total)).join("")||`<div class="chartEmpty">لا توجد بيانات</div>`}</section>
      </div>
      <section class="chartCard"><div class="chartHead"><h3>مقارنة أداء المستخدمين</h3><span>HR ومسؤولي الأقاليم · نفس الفترة</span></div><div class="performanceCompare">
        <div class="performanceCompareHead"><span>المستخدم</span><span>التوثيق</span><span>الانسحاب</span><span>متوسط الزمن</span><span>الالتزام</span></div>
        ${compareRows||`<div class="chartEmpty">لا توجد بيانات مقارنة</div>`}
      </div></section>
      <section class="chartCard"><div class="chartHead"><h3>المعاملات حسب الشهر</h3><span>آخر 12 شهر</span></div>${bars(d.recent)}</section>
    </section>`;
  }catch(e){v.innerHTML=errorState(e.message);}
}
function analysisBar(label,value,max){const p=max?Math.round(value/max*100):0;return `<div class="analysisBar"><div><span>${esc(label)}</span><b>${value}</b></div><i><em style="width:${p}%"></em></i></div>`;}
function bars(items){if(!items?.length)return `<div class="chartEmpty">لا توجد بيانات</div>`;const max=Math.max(...items.map(x=>x.count),1);return `<div class="bars">${items.map(x=>`<div class="barCol"><b>${x.count}</b><i style="height:${Math.max(8,Math.round(x.count/max*150))}px"></i><small>${esc(x.month)}</small></div>`).join("")}</div>`;}
function applyStats(id){localStorage.setItem("statsFrom",document.querySelector("#statsFrom")?.value||"");localStorage.setItem("statsTo",document.querySelector("#statsTo")?.value||"");localStorage.setItem("statsRegion",document.querySelector("#statsRegion")?.value||"");statsPage(id);}
async function exportStats(id){try{const qs=new URLSearchParams({manager_id:id,from:localStorage.getItem("statsFrom")||"",to:localStorage.getItem("statsTo")||"",region:localStorage.getItem("statsRegion")||""});const d=await api("/api/export?"+qs);downloadRows(d.rows||[],"تحليل_الأداء");}catch(e){toast(e.message,"err");}}
async function exportFromList(){try{const qs=new URLSearchParams({q:document.querySelector("#q")?.value||"",status:document.querySelector("#statusFilter")?.value||"",manager_id:document.querySelector("#managerFilter")?.value||"",from:document.querySelector("#fromFilter")?.value||"",to:document.querySelector("#toFilter")?.value||""});const d=await api("/api/export?"+qs);downloadRows(d.rows||[],"تقرير_المعاملات");}catch(e){toast(e.message,"err");}}
function downloadRows(rows,name){
 if(!rows.length){toast("لا توجد بيانات للتصدير","err");return;}
 const keys=Object.keys(rows[0]);
 const csv="\uFEFF"+[keys.join(","),...rows.map(r=>keys.map(k=>`"${String(r[k]??"").replace(/"/g,'""')}"`).join(","))].join("\n");
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));a.download=`${name}_${new Date().toISOString().slice(0,10)}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast("تم تصدير البيانات بصيغة CSV — تفتح مباشرة في Excel");
}
async function users(){
  if(!can("manage_users")){toast("لا تملك صلاحية إدارة المستخدمين","err");return}
  VIEW="users";navActive("users");title("المستخدمون والتفويض","إدارة الوصول والتفويض المركزي للمعاملات الحالية والمستقبلية.");
  const v=document.querySelector("#view");v.innerHTML=`<div class="loading">جاري تحميل المستخدمين…</div>`;
  try{
    const [ud,dd]=await Promise.all([api("/api/users"),api("/api/delegations")]);
    usersCache=ud.users||[];
    v.innerHTML=`<section class="section"><div class="sectionHead"><div><h2>الحسابات</h2></div><div class="headActions"><button class="danger" onclick="clearTestData()">تنظيف بيانات الاختبار</button><button class="primary" onclick="userForm()">＋ مستخدم جديد</button></div></div><div class="usersTable"><div class="usersHead"><span>المستخدم</span><span>الدور</span><span>الإقليم</span><span>الحالة</span><span>الصلاحيات</span><span></span></div>${usersCache.map(x=>`<div class="userRow"><div class="userIdentity"><span class="avatar">${esc(x.name?.[0]||"م")}</span><div><b>${esc(x.name)}</b><small>${esc(x.username)}</small></div></div><span>${roleLabel[x.role]||x.role}</span><span>${esc(x.region||"—")}</span><span><em class="userState ${x.active?"on":"off"}">${x.active?"نشط":"معطل"}</em></span><span class="permCount">${(x.permissions||[]).length} صلاحية</span><div class="rowActions"><button class="soft" onclick="userFormById(${x.id})">الصلاحيات</button><button class="ghost" onclick="resetUserPassword(${x.id})">إعادة كلمة المرور</button><button class="ghost" onclick="toggleUser(${x.id})">${x.active?"تعطيل":"تفعيل"}</button></div></div>`).join("")}</div></section>
    <section class="section"><div class="sectionHead"><div><h2>التفويض</h2></div></div><div class="delegationCreate"><label>المفوِّض<select id="delSource">${ud.users.filter(x=>x.active&&["requester","admin"].includes(x.role)).map(x=>`<option value="${x.id}">${esc(x.name)} — ${roleLabel[x.role]}</option>`).join("")}</select></label><label>المفوَّض إليه<select id="delTarget">${ud.users.filter(x=>x.active).map(x=>`<option value="${x.id}">${esc(x.name)} — ${roleLabel[x.role]}</option>`).join("")}</select></label><label>يبدأ في<input id="delStart" type="datetime-local"></label><label>ينتهي في<input id="delEnd" type="datetime-local"></label><label class="wide">ملاحظة<input id="delNote" placeholder="سبب أو نطاق التفويض"></label><button class="primary wide" onclick="createDelegation()">تفعيل التفويض</button></div><div class="delegationTable">${(dd.delegations||[]).filter(x=>x.active).map(d=>`<div class="delegationRow"><div><b>${esc(d.source_name||"—")}</b><span>→</span><b>${esc(d.target_name||"—")}</b></div><small>${fmtDateTime(d.starts_at)}${d.ends_at?" — "+fmtDateTime(d.ends_at):" — مفتوح"}</small><button class="danger" onclick="revokeDelegation(${d.id})">إلغاء</button></div>`).join("")||emptyState("لا يوجد تفويض نشط")}</div></section>`;
  }catch(e){v.innerHTML=errorState(e.message);}
}
function togglePermGroup(btn){const group=btn.closest(".permGroup");if(!group)return;const boxes=[...group.querySelectorAll("input[name=perm]")];const all=boxes.length&&boxes.every(x=>x.checked);boxes.forEach(x=>x.checked=!all);btn.textContent=all?"تحديد الكل":"إلغاء تحديد الكل";}
function userFormById(id){const x=usersCache.find(u=>Number(u.id)===Number(id));if(x)userForm(x);else toast("تعذر العثور على المستخدم","err");}
function userForm(x={role:"requester",permissions:roleDefaults.requester}){
  const suggested=(x.id?((x.permissions&&x.permissions.length)?x.permissions:roleDefaults[x.role]||[]):(x.permissions&&x.permissions.length?x.permissions:roleDefaults[x.role]||[]));
  const checks=permGroups.map(g=>`<div class="permGroup"><div class="permGroupHead"><h3>${g.title}</h3><button type="button" class="miniLink" onclick="togglePermGroup(this)">تحديد الكل</button></div>${g.items.map(k=>`<label class="check"><input type="checkbox" name="perm" value="${k}" ${suggested.includes(k)?"checked":""}><span><b>${permLabel[k]}</b><small>السماح بـ ${permLabel[k]}</small></span></label>`).join("")}</div>`).join("");
  document.body.insertAdjacentHTML("beforeend",`<div class="modalShade"><div class="userModal"><button class="modalClose" onclick="this.closest('.modalShade').remove()">×</button><h2>${x.id?"تعديل المستخدم":"إنشاء مستخدم"}</h2><div class="formGrid"><label>اسم المستخدم<input id="fu" value="${esc(x.username||"")}" ${x.id?"readonly":""}></label><label>الاسم<input id="fn" value="${esc(x.name||"")}"></label><label>كلمة المرور<input id="fp" type="password" placeholder="${x.id?"اتركها فارغة دون تغيير":"مطلوبة"}"></label><label>الدور<select id="fr" onchange="applySuggestedPerms()"><option value="requester">HR</option><option value="supervisor">مشرف</option><option value="manager">مدير</option><option value="region">مسؤول إقليم</option><option value="viewer">مشاهد</option><option value="admin">مدير النظام</option></select></label><label>الإقليم<select id="freg"><option value="">بدون إقليم</option></select></label></div><div class="permGrid">${checks}</div><div class="userFormActions"><button class="primary wide big" onclick="saveUser(${x.id||0})">حفظ التغييرات</button></div></div></div>`);
  const fr=document.querySelector("#fr"),freg=document.querySelector("#freg"); fr.value=x.role||"requester";
  api("/api/regions").then(d=>{if(freg){freg.innerHTML=`<option value="">بدون إقليم</option>${(d.regions||[]).map(r=>`<option ${String(r.name||r)===String(x.region||"")?"selected":""} value="${esc(r.name||r)}">${esc(r.name||r)}</option>`).join("")}`;freg.disabled=(fr.value!=="region");}});
  const roleEl=document.querySelector("#fr");
  if(roleEl){ roleEl.value=x.role||"requester"; roleEl.addEventListener("change",()=>{
    applySuggestedPerms();
    const freg=document.querySelector("#freg");
    if(freg) freg.disabled=roleEl.value!=="region";
    if(roleEl.value!=="region") freg.value="";
    toast("تم تحديث الصلاحيات المقترحة حسب الدور");
  }); }
  const head=modal.querySelector(".permGrid");
  if(head){ head.insertAdjacentHTML("beforebegin",`<div class="permSuggestion"><span><b>الصلاحيات المقترحة</b><small>يتم اقتراحها تلقائيًا حسب الدور ويمكن تعديلها قبل الحفظ.</small></span><button type="button" class="soft" onclick="applySuggestedPerms()">تطبيق المقترح</button></div>`); }
}
function applySuggestedPerms(){ const modal=document.querySelector(".userModal"); const role=modal?.querySelector("#fr")?.value||"requester"; const wanted=new Set(roleDefaults[role]||[]); modal?.querySelectorAll('input[name="perm"]').forEach(c=>c.checked=wanted.has(c.value)); toast("تم تطبيق الصلاحيات المقترحة"); }
async function saveUser(id){
  const modal=document.querySelector(".userModal");
  const permissions=[...modal.querySelectorAll('input[name="perm"]:checked')].map(x=>x.value);
  const username=modal.querySelector("#fu")?.value.trim()||"", name=modal.querySelector("#fn")?.value.trim()||"", password=modal.querySelector("#fp")?.value||"", role=modal.querySelector("#fr")?.value||"requester", region=modal.querySelector("#freg")?.value||"";
  if(role==="region"&&!region)return toast("اختر إقليم مسؤول الإقليم","err"); const b={name,role,region,permissions};if(password)b.password=password;
  if(!id){b.username=username;if(!b.password)return toast("كلمة المرور مطلوبة للمستخدم الجديد","err");}
  try{await api(id?`/api/users/${id}`:"/api/users",{method:"POST",body:JSON.stringify(b)});document.querySelector(".modalShade")?.remove();toast("تم حفظ المستخدم والصلاحيات");users();}
  catch(e){toast(e.message,"err");}
}
async function clearTestData(){
  const ok=prompt("هذا الإجراء يحذف المعاملات والمستخدمين التجريبيين والجلسات والتفويضات. اكتب RESET للتأكيد:");
  if(ok!=="RESET")return;
  try{await api("/api/admin/clear-test-data",{method:"POST",body:JSON.stringify({confirm:"RESET"})});toast("تم تنظيف بيانات الاختبار بنجاح");users();}catch(e){toast(e.message,"err");}
}
async function resetUserPassword(id){
  try{
    const d=await api(`/api/users/${id}/reset-password`,{method:'POST'});
    const box=document.querySelector('.tempPasswordBanner'); box?.remove();
    document.querySelector('#view')?.insertAdjacentHTML('afterbegin',`<div class="tempPasswordBanner"><div><b>كلمة المرور المؤقتة</b><span>${esc(d.temporary_password)}</span><small>تظهر مرة واحدة — انسخها وسلّمها للمستخدم.</small></div><button class="soft" onclick="navigator.clipboard?.writeText(${JSON.stringify(d.temporary_password)});toast('تم نسخ كلمة المرور')">نسخ</button><button class="ghost" onclick="this.parentElement.remove()">إخفاء</button></div>`);
  }catch(e){toast(e.message,'err')}
}
async function toggleUser(id){try{await api(`/api/users/${id}`,{method:"POST",body:JSON.stringify({action:"toggle"})});users();}catch(e){toast(e.message,"err");}}
async function createDelegation(){
  const source=Number(document.querySelector("#delSource").value),target=Number(document.querySelector("#delTarget").value);if(source===target)return toast("المفوِّض والمفوَّض إليه يجب أن يكونا مختلفين","err");
  try{await api("/api/delegations",{method:"POST",body:JSON.stringify({source_user_id:source,target_user_id:target,starts_at:document.querySelector("#delStart").value||null,ends_at:document.querySelector("#delEnd").value||null,note:document.querySelector("#delNote").value||""})});toast("تم تفعيل التفويض");users();}catch(e){toast(e.message,"err");}
}
async function revokeDelegation(id){try{await api(`/api/delegations/${id}`,{method:"POST",body:JSON.stringify({action:"revoke"})});toast("تم إلغاء التفويض");users();}catch(e){toast(e.message,"err");}}
async function regions(){
  if(!can("manage_regions")){toast("لا تملك صلاحية إدارة الأقاليم","err");return}
  VIEW="regions";navActive("regions");title("الأقاليم","إدارة الأقاليم وحالة التفعيل من مكان واحد.");
  const v=document.querySelector("#view");v.innerHTML=`<section class="section"><div class="sectionHead"><div><span class="eyebrow">REGION DIRECTORY</span><h2>دليل الأقاليم</h2></div><button class="primary" onclick="regionForm()">＋ إضافة إقليم</button></div><div id="regionTable" class="regionTable"><div class="loading">جاري التحميل…</div></div></section>`;
  try{const d=await api("/api/regions?include_inactive=1");document.querySelector("#regionTable").innerHTML=`<div class="regionHead"><span>الإقليم</span><span>الحالة</span><span>إجراء</span></div>${(d.regions||[]).map(r=>`<div class="regionRow"><b>${esc(r.name||r)}</b><span class="userState ${r.active?"on":"off"}">${r.active?"نشط":"معطل"}</span><div class="rowActions"><button class="soft" onclick="regionForm(decodeURIComponent('${encodeURIComponent(r.name||r)}'))">تعديل</button><button class="ghost" onclick="toggleRegion(decodeURIComponent('${encodeURIComponent(r.name||r)}'))">${r.active?"تعطيل":"تفعيل"}</button></div></div>`).join("")}`;}catch(e){document.querySelector("#regionTable").innerHTML=errorState(e.message);}
}
function regionForm(oldName=""){document.body.insertAdjacentHTML("beforeend",`<div class="modalShade"><div class="smallModal"><button class="modalClose" onclick="this.closest('.modalShade').remove()">×</button><span class="eyebrow">REGION</span><h2>${oldName?"تعديل الإقليم":"إضافة إقليم"}</h2><input id="regionName" value="${esc(oldName)}" placeholder="اسم الإقليم"><div class="actionButtons"><button class="primary" onclick="saveRegion(${JSON.stringify(oldName)})">حفظ</button>${oldName?`<button class="danger" onclick="archiveRegion(${JSON.stringify(oldName)})">أرشفة</button>`:""}</div></div></div>`);}
async function saveRegion(oldName){try{const input=document.querySelector("#regionName");const name=String(input?.value||"").trim();if(!name)return toast("أدخل اسم الإقليم","err");await api("/api/regions",{method:"POST",body:JSON.stringify(oldName?{action:"edit",old_name:oldName,name}:{action:"add",name})});document.querySelector(".modalShade")?.remove();apiCache.delete("/api/regions");toast("تم حفظ الإقليم وتحديث ارتباطاته");regions();}catch(e){toast(e.message,"err");}}
async function toggleRegion(oldName){try{await api("/api/regions",{method:"POST",body:JSON.stringify({action:"toggle",old_name:oldName})});apiCache.delete("/api/regions");toast("تم تغيير حالة الإقليم");regions();}catch(e){toast(e.message,"err");}}
async function archiveRegion(oldName){try{await api("/api/regions",{method:"POST",body:JSON.stringify({action:"delete",old_name:oldName})});document.querySelector(".modalShade")?.remove();apiCache.delete("/api/regions");toast("تمت أرشفة الإقليم");regions();}catch(e){toast(e.message,"err");}}
async function auditPage(){
  if(!can("view_audit_log")){toast("لا تملك صلاحية سجل النشاط","err");return}
  VIEW="audit";navActive("audit");title("سجل النشاط","سجل تدقيق كامل قابل للبحث والتصفية والتصدير.");
  const v=document.querySelector("#view");v.innerHTML=`<section class="section"><div class="sectionHead"><div><span class="eyebrow">AUDIT LOG</span><h2>سجل النشاط</h2></div>${can("export_audit_log")?`<button class="primary" onclick="exportAudit()">تصدير السجل</button>`:""}</div><div class="auditFilters"><input id="auditQ" placeholder="ابحث بالمستخدم أو النشاط أو التفاصيل"><label>من<input id="auditFrom" type="date"></label><label>إلى<input id="auditTo" type="date"></label><button class="soft" onclick="loadAudit()">تطبيق</button></div><div id="auditTable" class="auditTable"></div></section>`;loadAudit();
}
async function loadAudit(){
  try{const qs=new URLSearchParams({q:document.querySelector("#auditQ")?.value||"",from:document.querySelector("#auditFrom")?.value||"",to:document.querySelector("#auditTo")?.value||""});const d=await api("/api/audit?"+qs);document.querySelector("#auditTable").innerHTML=`<div class="auditHead"><span>التاريخ</span><span>المستخدم</span><span>النشاط</span><span>المعاملة</span><span>التفاصيل</span></div>${(d.events||[]).map(e=>`<div class="auditRow"><small>${fmtDateTime(e.created_at)}</small><span>${esc(e.actor_name||"النظام")}</span><b>${esc(e.action)}</b><span>#${esc(e.record_id||"—")}</span><p>${esc(e.note||"—")}</p></div>`).join("")||`<div class="emptyRow">لا توجد نتائج</div>`}`;}catch(e){document.querySelector("#auditTable").innerHTML=errorState(e.message);}
}
async function exportAudit(){try{const d=await api("/api/audit/export");downloadRows(d.rows||[],"سجل_النشاط");}catch(e){toast(e.message,"err");}}
async function refreshBadge(){if(ME?.role!=="region")return;try{const d=await api("/api/records?status=required");const b=document.querySelector("#reqBadge");if(b)b.textContent=d.records?.length||0;}catch{}}
async function logout(){try{await api("/api/logout")}finally{ME=null;login();}}
document.addEventListener("pointerdown",e=>{
  const input=e.target.closest("input[type=date],input[type=datetime-local]");
  if(input){ try{ input.showPicker?.(); }catch{} return; }
  const wrapper=e.target.closest("label,.date-field,.date-picker-field,[data-date-field]");
  const field=wrapper?.querySelector("input[type=date],input[type=datetime-local]");
  if(field){ e.preventDefault(); try{ field.showPicker?.(); }catch{ try{field.focus();}catch{} } }
});
window.loadMoreRecords=loadMoreRecords;window.uploadPage=uploadPage;window.quickRegion=quickRegion;window.quickRegionSubmit=quickRegionSubmit;window.quickRegionWithdraw=quickRegionWithdraw;window.quickRegionWithdrawSubmit=quickRegionWithdrawSubmit;window.quickApprove=quickApprove;window.dash=dash;window.list=list;window.loadRecords=loadRecords;window.openRecord=openRecord;window.closeRecord=closeRecord;window.add=add;window.save=save;window.bulk=bulk;window.importFile=importFile;window.statsPage=statsPage;window.applyStats=applyStats;window.exportStats=exportStats;window.exportFromList=exportFromList;window.users=users;window.userForm=userForm;window.togglePermGroup=togglePermGroup;window.userFormById=userFormById;window.saveUser=saveUser;window.toggleUser=toggleUser;window.resetUserPassword=resetUserPassword;window.createDelegation=createDelegation;window.revokeDelegation=revokeDelegation;window.regions=regions;window.regionForm=regionForm;window.saveRegion=saveRegion;window.toggleRegion=toggleRegion;window.archiveRegion=archiveRegion;window.auditPage=auditPage;window.loadAudit=loadAudit;window.exportAudit=exportAudit;window.perform=perform;window.withdrawForm=withdrawForm;window.reassign=reassign;window.logout=logout;
boot();


function wireDatePickers(root=document){
  root.querySelectorAll('input[type="date"]').forEach(el=>{
    if(el.dataset.pickerWired) return;
    el.dataset.pickerWired='1';
    el.addEventListener('click',()=>{
      try{ if(typeof el.showPicker==='function') el.showPicker(); }catch(_){}
    });
    el.addEventListener('keydown',e=>{
      if(e.key==='Enter'||e.key===' '){
        try{ if(typeof el.showPicker==='function') el.showPicker(); }catch(_){}
      }
    });
  });
}


function applyRolePreset(role){ const modal=document.querySelector(".userModal"); const wanted=new Set(roleDefaults[role]||[]); modal?.querySelectorAll('input[name="perm"]').forEach(c=>c.checked=wanted.has(c.value)); }
