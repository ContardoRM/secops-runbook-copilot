'use strict';
const $ = id => document.getElementById(id);
const CASES = {
  kernel: {title:'Linux / Kernel', host:'secops-kernel-lab', number:'01', subtitle:'Una corrección instalada no es una corrección activa.', actionable:'fixed_kernel_installed_not_active', success:'fixed_kernel_active_for_lab_case', runbook:'activate-fixed-kernel', phrase:'APROBAR REINICIO', impact:'Se seleccionará el kernel 1013 y se programará un reinicio de VM1. Se interrumpirán todos sus servicios. El coordinador esperará y verificará el nuevo arranque.'},
  docker: {title:'Docker / SSH', host:'ssh-vulnerable', number:'02', subtitle:'Mitigar el acceso no es lo mismo que parchear la imagen.', actionable:'exposure_conditions_present', success:'password_authentication_mitigated', runbook:'disable-ssh-password-authentication', phrase:'APROBAR', impact:'Se deshabilitará la autenticación por contraseña y se reiniciará solo el contenedor ssh-vulnerable. labuser no tendrá acceso SSH sin claves. El SSH del host Ubuntu no se modifica.'}
};
const STATUS = {fixed_kernel_installed_not_active:'Pendiente de activar',fixed_kernel_active_for_lab_case:'Kernel corregido activo',exposure_conditions_present:'Condiciones presentes',password_authentication_mitigated:'Mitigado por configuración',requires_review:'Requiere revisión'};
let mode='demo', asset='kernel', token='', state=null, activeJob=null, polling=false, reportText='';
const messages = new Map();
const sessionHistory=[];
function key(){return mode+':'+asset;}
function escapeError(message){$('error').textContent=message;$('error').hidden=false;}
function clearError(){$('error').hidden=true;}
async function api(path,data){
  const response=await fetch(path,{method:data?'POST':'GET',headers:{'X-Secops-Token':token,...(data?{'Content-Type':'application/json'}:{})},...(data?{body:JSON.stringify(data)}:{})});
  const result=await response.json();
  if(!response.ok)throw new Error(result.error||'No se pudo completar la solicitud.');
  return result;
}
function addMessage(text,role='assistant',action=false){
  const list=messages.get(key())||[];list.push({text,role,action});messages.set(key(),list);renderMessages();
}
function renderMessages(){
  const list=messages.get(key())||[];$('messages').replaceChildren();
  const welcome=mode==='demo'
    ? `Selecciona un servidor y recorre el flujo completo. Este es un ejemplo simulado: no consulta Oracle ni consume tokens.\n\n${asset==='kernel'?'En este escenario, la corrección del kernel está instalada, pero todavía no está activa.':'En este escenario, OpenSSH presenta las condiciones del aviso de Alpine. No hay puertos publicados.'}`
    : `Estoy conectado a los reportes locales de ${CASES[asset].host}. Consulta el estado para recoger evidencia nueva. Analizar y conversar usan tu API de Gemini.\n\nNo se han realizado pruebas de explotación ni detección de intrusiones.`;
  [{text:welcome,role:'assistant'},...list].forEach(item=>{
    const el=document.createElement('div');el.className='message '+item.role;
    const label=document.createElement('div');label.className='message-label';label.textContent=item.role==='user'?'TÚ':item.role==='system'?'OPERACIÓN':mode==='demo'?'✳ COPILOTO · EJEMPLO':'✳ COPILOTO · GEMINI';
    const p=document.createElement('p');p.textContent=item.text;el.append(label,p);
    if(item.action){const b=document.createElement('button');b.className='message-action';b.textContent='Preparar procedimiento para revisión ↗';b.disabled=!!activeJob;b.onclick=()=>start('execute');el.append(b);}
    $('messages').append(el);
  });
  $('messages').scrollTop=$('messages').scrollHeight;
}
function dateLabel(value){if(!value)return 'Sin evidencia';const d=new Date(value);return Number.isNaN(d.getTime())?'Sin fecha':d.toLocaleTimeString('es-CL',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function render(){
  if(!state)return;
  $('demo-mode').classList.toggle('selected',mode==='demo');$('live-mode').classList.toggle('selected',mode==='live');
  $('demo-mode').setAttribute('aria-pressed',String(mode==='demo'));$('live-mode').setAttribute('aria-pressed',String(mode==='live'));
  $('environment-badge').textContent=mode==='demo'?'ENTORNO DE DEMOSTRACIÓN':'LABORATORIO REAL · CONEXIÓN LOCAL';
  $('mode-description').textContent=mode==='demo'?'Escenario simulado · sin conexiones a Oracle ni llamadas a IA.':'Acciones sobre Oracle mediante tu coordinador local.';
  $('notice').classList.toggle('real',mode==='live');
  $('notice-text').textContent=mode==='demo'?'Estás en modo demo. Explora el flujo sin modificar tus máquinas.':'Estás en modo real. Consultar usa SSH; analizar y conversar envían evidencia a Gemini. Ejecutar requiere tu aprobación.';
  $('reset-demo').hidden=mode!=='demo';$('scene-mode').textContent=mode==='demo'?'ESCENARIO SIMULADO':'REPORTES DEL LABORATORIO';
  $('room-state').textContent=mode==='demo'?'Demo interactiva':'Evidencia local';
  $('agent-model').textContent=mode==='demo'?'Gemini · respuesta de ejemplo':state.model;
  $('agent-online').textContent=mode==='demo'?'DEMO':state.api_ready?'API LISTA':'SIN CLAVE';
  $('connection-label').textContent=mode==='demo'?'Local · modo demo':'Local · laboratorio real';
  for(const name of Object.keys(CASES)){
    const data=state.assets[name];const status=data.assessment.status;const good=status===CASES[name].success;
    const side=$(name+'-side-state');side.textContent=data.stale?'Evidencia pendiente':STATUS[status]||'Sin evaluar';side.classList.toggle('good',good&&!data.stale);
    $('rack-'+name).classList.toggle('good',good);$('rack-'+name).classList.toggle('selected',asset===name);$('rack-'+name).setAttribute('aria-pressed',String(asset===name));
  }
  document.querySelectorAll('.asset-card').forEach(b=>b.classList.toggle('selected',b.dataset.asset===asset));
  const selected=state.assets[asset], inv=selected.inventory, status=selected.assessment.status, c=CASES[asset];
  $('detail-number').textContent='ACTIVO / '+c.number;$('detail-title').textContent=c.title;$('detail-subtitle').textContent=c.subtitle;
  $('detail-status').textContent=selected.stale?'Evidencia antigua / sin validar':STATUS[status]||'Sin evidencia';
  $('detail-status').className='status-pill '+(selected.stale?'unknown':status===c.success?'good':'warning');
  if(asset==='kernel'){
    $('fact-primary').textContent=inv.active_kernel||'Sin datos';$('fact-secondary-label').textContent='CORRECCIÓN INSTALADA';
    $('fact-secondary').textContent=inv.installed_kernel_packages?.['linux-image-7.0.0-1013-oracle']?'7.0.0-1013-oracle':'Sin confirmar';
  }else{
    $('fact-primary').textContent='Contraseñas: '+(inv.ssh_configuration?.passwordauthentication?.join(', ')||'sin datos');$('fact-secondary-label').textContent='VERSIÓN OPENSSH';
    $('fact-secondary').textContent=(inv.software?.openssh||'Sin datos').split(',')[0];
  }
  $('fact-time').textContent=mode==='demo'?'Ejemplo simulado':dateLabel(inv.collected_at)+(selected.stale?' · antigua':' · UTC '+new Date(inv.collected_at).toISOString().slice(11,19));
  const busy=!!activeJob;
  $('collect-button').disabled=busy;
  $('analyze-button').disabled=busy||(mode==='live'&&!state.api_ready);
  $('demo-mode').disabled=busy;$('live-mode').disabled=busy;$('reset-demo').disabled=busy;
  $('question').disabled=busy;document.querySelector('#chat-form button').disabled=busy||(mode==='live'&&!state.api_ready);
  document.querySelectorAll('[data-question]').forEach(b=>b.disabled=busy||(mode==='live'&&!state.api_ready));
  renderEvidence();renderHistory();
}
async function refresh(){state=await api('/api/state?mode='+mode);render();}
function setAsset(name){if(activeJob&&activeJob.asset!==name){escapeError('Espera a que termine la operación para cambiar de activo.');return;}asset=name;clearError();render();renderMessages();}
async function setMode(next){if(activeJob)return;mode=next;clearError();setFlow(-1);$('job-stage').textContent='Listo para consultar';$('job-log').textContent='Todavía no hay operaciones en este modo.';await refresh();renderMessages();}
function setFlow(index,completed=false){document.querySelectorAll('#flow li').forEach((el,i)=>{el.className=i<index||completed?'done':i===index?'current':'';});}
function updateJob(job){
  activeJob=job;$('job-stage').textContent=job.stage;$('job-log').textContent=job.log||'Modo demo: no se ejecutan comandos reales.';
  $('job-actions').hidden=job.status!=='waiting_approval';
  let index=0;if(/Evaluando|evaluación/i.test(job.stage))index=1;if(/propuesta|Gemini/i.test(job.stage))index=2;if(job.status==='waiting_approval'||/aprobado|ejecución|arranque|verificando/i.test(job.stage))index=3;if(/verificación posterior|evidencia posterior/i.test(job.stage))index=4;
  setFlow(index,job.status==='completed'&&job.action==='execute');render();
}
async function start(action,question){
  if(activeJob)return;clearError();
  try{
    const job=await api('/api/jobs',{action,asset,mode,...(question?{question}:{})});
    sessionStorage.setItem('secops-job',job.id);updateJob(job);poll(job.id);
  }catch(e){escapeError(e.message);}
}
async function poll(id){
  if(polling)return;polling=true;
  try{
    while(true){
      const job=await api('/api/job?id='+encodeURIComponent(id));updateJob(job);
      if(['completed','failed','cancelled'].includes(job.status)){
        sessionStorage.removeItem('secops-job');sessionHistory.unshift({id:job.id,status:job.status,asset:job.asset,action:job.action,mode:job.mode});
        activeJob=null;$('job-actions').hidden=true;
        if($('approval-dialog').open)$('approval-dialog').close();
        await refresh();
        if(job.status==='failed'){escapeError(job.error||'La operación necesita revisión. Consulta el detalle.');addMessage('La operación necesita revisión. No se repetirá automáticamente.','system');}
        else if(job.status==='cancelled'){addMessage('Operación cancelada sin aprobar el procedimiento.','system');}
        else if(job.action==='chat'){addMessage(job.reply||'No se recibió texto.');}
        else if(job.action==='analyze'){
          const proposal=state.assets[asset].plan.proposal;
          if(proposal){addMessage(proposal.summary+'\n\n'+proposal.rationale+'\n\n'+(proposal.limitations||[]).map(x=>'• '+x).join('\n'), 'assistant',!!proposal.recommended_runbook&&state.assets[asset].assessment.status===CASES[asset].actionable);}
          else{addMessage('El estado actual no requiere el procedimiento de este caso. Puedes consultar la evidencia o preguntar por sus limitaciones.');}
          setFlow(2);
        }else if(job.action==='execute'){
          const success=state.assets[asset].assessment.status===CASES[asset].success;
          addMessage((mode==='demo'?'DEMO · ':'')+(success?(asset==='kernel'?'El kernel corregido está activo en este escenario.':'La autenticación por contraseña quedó deshabilitada. Esto es una mitigación; la imagen sigue sin parche permanente.'):'La consulta terminó sin confirmar una nueva remediación.'),'system');
          setFlow(4,success);
        }else{addMessage(mode==='demo'?'Se cargaron los datos del escenario de demostración.':'Evidencia recogida. Revisa los datos antes de solicitar un análisis.','system');setFlow(0);}
        renderMessages();render();break;
      }
      await new Promise(resolve=>setTimeout(resolve,850));
    }
  }catch(e){escapeError('Se perdió el seguimiento: '+e.message+'. No vuelvas a ejecutar sin revisar la operación.');}
  finally{polling=false;}
}
function openApproval(){
  if(!activeJob||activeJob.status!=='waiting_approval')return;
  const c=CASES[activeJob.asset], p=activeJob.plan?.proposal||{};
  $('approval-title').textContent=(activeJob.mode==='demo'?'Simular: ':'')+c.title;
  $('approval-impact').textContent=(activeJob.mode==='demo'?'DEMO: no modifica Oracle. ':'LABORATORIO REAL: ')+c.impact;
  $('approval-plan').textContent='Runbook: '+c.runbook+'\n\n'+(p.summary||'')+'\n\n'+(p.rationale||'')+'\n\n'+(p.limitations||[]).map(x=>'• '+x).join('\n');
  $('approval-label').textContent='Escribe exactamente: '+activeJob.phrase;
  $('approval-phrase').value='';$('approval-error').hidden=true;$('approval-dialog').showModal();$('approval-phrase').focus();
}
async function decision(cancel=false){
  if(!activeJob)return;
  try{
    const updated=await api(cancel?'/api/cancel':'/api/approve',{id:activeJob.id,approval_token:activeJob.approval_token,phrase:$('approval-phrase').value});
    if($('approval-dialog').open)$('approval-dialog').close();updateJob(updated);
  }catch(e){if($('approval-dialog').open){$('approval-error').textContent=e.message;$('approval-error').hidden=false;}else escapeError(e.message);}
}
function renderEvidence(){
  const root=$('evidence-content');root.replaceChildren();
  for(const [name,data] of Object.entries(state.assets)){
    const section=document.createElement('section');section.className='evidence-item';
    const h=document.createElement('h3');h.textContent=CASES[name].title;
    const small=document.createElement('small');small.textContent=mode==='demo'?'EJEMPLO SIMULADO':data.stale?'EVIDENCIA ANTIGUA O SIN VALIDAR':'ÚLTIMA RECOLECCIÓN: '+data.inventory.collected_at;
    const pre=document.createElement('pre');pre.textContent=JSON.stringify({inventory:data.inventory,assessment:data.assessment},null,2);
    section.append(h,small,pre);root.append(section);
  }
}
function renderHistory(){
  const root=$('history-content');root.replaceChildren();
  $('history-description').textContent=mode==='demo'?'Solo actividad simulada de esta sesión. No representa ejecuciones nuevas en Oracle.':'Registros locales del coordinador y actividad de esta sesión de la interfaz.';
  const items=[...sessionHistory.filter(j=>j.mode===mode).map(j=>({id:`${CASES[j.asset].title} · ${j.action} · sesión web`,status:j.status})),...(mode==='live'?state.audits:[])];
  if(!items.length){const p=document.createElement('p');p.className='empty-note';p.textContent='Aún no hay operaciones en esta vista. Selecciona un servidor para comenzar.';root.append(p);}
  for(const item of items){const row=document.createElement('div');row.className='history-row';const name=document.createElement('span');name.textContent=item.id;const status=document.createElement('span');status.textContent=({completed:'Completado',failed:'Revisar',cancelled:'Cancelado',requires_review:'Requiere revisión'})[item.status]||item.status;row.append(name,status);root.append(row);}
}
function view(name){document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===name));for(const v of ['operations','evidence','history'])$(v+'-view').hidden=v!==name;}
async function showReport(){
  try{
    if(mode==='live'){reportText=(await api('/api/report')).text;}
    else{reportText='# SecOps · DEMOSTRACIÓN SIMULADA\n\nSin conexiones a Oracle ni llamadas a Gemini.\n\n'+Object.entries(state.assets).map(([name,data])=>'## '+CASES[name].title+'\n'+(STATUS[data.assessment.status]||'Sin evaluar')).join('\n\n')+'\n\nLos estados pertenecen exclusivamente al ejemplo interactivo.';}
    $('report-text').textContent=reportText;$('report-mode').textContent=mode==='demo'?'DEMO · Reporte del escenario simulado':'Archivo local del coordinador. Consulta su fecha de generación.';$('report-dialog').showModal();
  }catch(e){escapeError(e.message);}
}
document.querySelectorAll('.asset-card,.server-object').forEach(el=>{el.addEventListener('click',()=>setAsset(el.dataset.asset));if(el.tagName.toLowerCase()==='g')el.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();setAsset(el.dataset.asset);}});});
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>view(b.dataset.view));
$('demo-mode').onclick=()=>setMode('demo').catch(e=>escapeError(e.message));$('live-mode').onclick=()=>setMode('live').catch(e=>escapeError(e.message));
$('collect-button').onclick=()=>start('status');$('analyze-button').onclick=()=>start('analyze');
$('chat-form').onsubmit=e=>{e.preventDefault();const text=$('question').value.trim();if(!text||activeJob)return;addMessage(text,'user');$('question').value='';start('chat',text);};
document.querySelectorAll('[data-question]').forEach(b=>b.onclick=()=>{addMessage(b.dataset.question,'user');start('chat',b.dataset.question);});
$('review-button').onclick=openApproval;$('cancel-button').onclick=()=>decision(true);
$('close-approval').onclick=()=>$('approval-dialog').close();$('approval-form').onsubmit=e=>{e.preventDefault();decision();};
$('report-button').onclick=showReport;$('close-report').onclick=()=>$('report-dialog').close();
$('download-report').onclick=()=>{const url=URL.createObjectURL(new Blob([reportText],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=mode==='demo'?'secops-demo.md':'secops-lab-report.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('refresh-evidence').onclick=()=>refresh().catch(e=>escapeError(e.message));
$('reset-demo').onclick=async()=>{try{await api('/api/demo-reset',{});messages.clear();setFlow(-1);$('job-stage').textContent='Listo para consultar';await refresh();renderMessages();}catch(e){escapeError(e.message);}};
(async()=>{try{token=(await (await fetch('/api/session')).json()).token;await refresh();renderMessages();const old=sessionStorage.getItem('secops-job');if(old){const job=await api('/api/job?id='+encodeURIComponent(old));mode=job.mode;asset=job.asset;await refresh();renderMessages();updateJob(job);poll(old);}}catch(e){sessionStorage.removeItem('secops-job');escapeError('No se pudo recuperar la sesión: '+e.message);}})();
