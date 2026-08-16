from pathlib import Path
p=Path('/mnt/data/v18/public/app.js')
s=p.read_text()
# Compact status labels and region action labels
s=s.replace('  waiting_region:"بانتظار إفادة الإقليم",\n  returned:"مرتجع للتصحيح",\n  region_documented:"تمت الإفادة — بانتظار اعتماد HR",\n  region_withdrawn:"إفادة انسحاب — بانتظار اعتماد HR",\n  final_documented:"مكتملة",\n  final_withdrawn:"منتهية",\n  cancelled:"منتهية",\n  stopped:"موقوفة"', '  waiting_region:"بانتظار الإفادة",\n  returned:"مرتجع للتصحيح",\n  region_documented:"بانتظار الاعتماد",\n  region_withdrawn:"بانتظار اعتماد الانسحاب",\n  final_documented:"تم التوثيق",\n  final_withdrawn:"منسحب الموظف",\n  cancelled:"ملغاة",\n  stopped:"موقوفة"')
# Replace record card actions for region
old='${(ME?.role==="region"&&["waiting_region","returned"].includes(r.status)&&can("respond_region"))?`<button class="quickBtn" onclick="event.stopPropagation();quickRegion(${r.id})">إفادة</button>`:""}${(can("approve")&&["region_documented","region_withdrawn"].includes(r.status))?`<button class="quickBtn approve" onclick="event.stopPropagation();quickApprove(${r.id},\'${r.status}\')">اعتماد</button>`:""}<button class="openBtn" onclick="event.stopPropagation();openRecord(${r.id})">التفاصيل ↗</button>'
new='${(ME?.role==="region"&&["waiting_region","returned"].includes(r.status)&&can("respond_region"))?`<button class="quickBtn qaPrimary" onclick="event.stopPropagation();quickRegionSubmit(${r.id},\'documented\')">تم التوثيق</button><button class="quickBtn qaDanger" onclick="event.stopPropagation();quickRegion(${r.id})">منسحب</button>`:""}${(can("approve")&&["region_documented","region_withdrawn"].includes(r.status))?`<button class="quickBtn approve" onclick="event.stopPropagation();quickApprove(${r.id},\'${r.status}\')">اعتماد</button>`:""}<button class="openBtn" onclick="event.stopPropagation();openRecord(${r.id})">التفاصيل</button>'
if old not in s:
    print('record action pattern not found')
else:
    s=s.replace(old,new)
# Add custom select enhancer before layout
marker='function layout(u){'
custom=r'''function enhanceSelects(root=document){
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
'''
s=s.replace(marker,custom+marker)
# version footer
s=s.replace('<b>V17.1</b>','<b>V18.0</b>')
# improve quick strip title and buttons
s=s.replace('<strong>إجراء المعاملة #${esc(r.id)}</strong><small>${esc(r.employee_name)} · ${esc(r.employee_no)} · ${esc(r.region)}</small>', '<strong>إجراء سريع · #${esc(r.id)}</strong><small>${esc(r.employee_name)} · ${esc(r.employee_no)} · ${esc(r.region)}</small>')
s=s.replace('تسجيل الإفادة</button><button class="qaDanger" onclick="quickRegionWithdraw(${id})">إفادة انسحاب', 'تم التوثيق</button><button class="qaDanger" onclick="quickRegionWithdraw(${id})">منسحب')
# add reset password button in user row
needle='<button class="soft" onclick="userFormById(${x.id})">الصلاحيات</button><button class="ghost" onclick="toggleUser(${x.id})">${x.active?"تعطيل":"تفعيل"}</button>'
rep='<button class="soft" onclick="userFormById(${x.id})">الصلاحيات</button><button class="ghost" onclick="resetUserPassword(${x.id})">إعادة كلمة المرور</button><button class="ghost" onclick="toggleUser(${x.id})">${x.active?"تعطيل":"تفعيل"}</button>'
s=s.replace(needle,rep)
# add function and export
insert_before='async function toggleUser(id){'
resetfun=r'''async function resetUserPassword(id){
  try{
    const d=await api(`/api/users/${id}/reset-password`,{method:'POST'});
    const box=document.querySelector('.tempPasswordBanner'); box?.remove();
    document.querySelector('#view')?.insertAdjacentHTML('afterbegin',`<div class="tempPasswordBanner"><div><b>كلمة المرور المؤقتة</b><span>${esc(d.temporary_password)}</span><small>تظهر مرة واحدة — انسخها وسلّمها للمستخدم.</small></div><button class="soft" onclick="navigator.clipboard?.writeText(${JSON.stringify(d.temporary_password)});toast('تم نسخ كلمة المرور')">نسخ</button><button class="ghost" onclick="this.parentElement.remove()">إخفاء</button></div>`);
  }catch(e){toast(e.message,'err')}
}
'''
s=s.replace(insert_before,resetfun+insert_before)
s=s.replace('window.toggleUser=toggleUser;', 'window.toggleUser=toggleUser;window.resetUserPassword=resetUserPassword;')
p.write_text(s)

# Worker endpoint for admin password reset
p=Path('/mnt/data/v18/src/worker.js'); s=p.read_text()
needle=' if(p==="/api/password"&&req.method==="POST")'
endpoint=r''' const ur=p.match(/^\/api\/users\/(\d+)\/reset-password$/);if(ur&&req.method==="POST"){
  if(!allow(u,"manage_users"))return json({error:"ليس لديك صلاحية إدارة المستخدمين"},403);
  const id=Number(ur[1]),target=await env.DB.prepare("SELECT id,username,name,active FROM users WHERE id=?").bind(id).first();
  if(!target)return json({error:"المستخدم غير موجود"},404);
  if(target.username==="admin")return json({error:"لا يمكن إعادة تعيين كلمة مرور مدير النظام من هنا"},400);
  const temporary=token().slice(0,12)+"!Aa9";
  await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(await hash(temporary),id).run();
  await log(env,null,u.id,"إعادة تعيين كلمة مرور",target.name);
  return json({ok:true,temporary_password:temporary});
 }
'''
if needle not in s: print('worker needle missing')
else: s=s.replace(needle,endpoint+needle)
p.write_text(s)

# version notes replace/add
p=Path('/mnt/data/v18/VERSION_NOTES.md'); p.write_text('''# V18.0 — Enterprise UX Re-engineering\n\n- Redesigned navigation and responsive behavior.\n- Single mobile navigation; desktop uses top navigation.\n- Custom modern select component across the application.\n- Compact performance metrics and clearer transaction action hierarchy.\n- Region quick actions: تم التوثيق / منسحب / التفاصيل.\n- Admin temporary password reset for non-admin users.\n- No confirmation dialogs for normal actions; test-data cleanup remains protected.\n- Preserves existing D1 database binding.\n''',encoding='utf-8')
