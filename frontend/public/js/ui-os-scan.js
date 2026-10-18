
const OS_DISTROS = [
  { id:'ubuntu', label:'Ubuntu' },
  { id:'debian', label:'Debian' },
  { id:'rhel',   label:'RHEL' },
  { id:'alpine', label:'Alpine' },
  { id:'suse',   label:'openSUSE' },
  { id:'sles',   label:'SLES' },
];

let osScans       = safeLoad('es_os', []);
let selOsDistro   = null;
let currentOsScan = null;
const saveOs      = () => safeSave('es_os', osScans);

function renderOsDistros(){
  document.getElementById('osDistroGrid').innerHTML = OS_DISTROS.map(d =>
    `<button class="eco-btn${selOsDistro===d.id?' on':''}" onclick="pickOsDistro('${d.id}')">
      <div class="eco-logo">${brandIcon(d.id)}</div><div class="eco-name">${d.label}</div>
    </button>`).join('');
}
function pickOsDistro(id){ selOsDistro=id; renderOsDistros(); }

function openOsModal(){
  selOsDistro=null;
  ['osDesc','osPkg','osPkgVer','osDistroVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('osmerr').hidden=true;
  setBtn('btnOsGo',false,'Scan');
  renderOsDistros();
  document.getElementById('osModal').hidden=false;
  setTimeout(()=>document.getElementById('osPkg').focus(),160);
}
function closeOsModal(){ document.getElementById('osModal').hidden=true; }

async function doOsScan(){
  const distro    = OS_DISTROS.find(d=>d.id===selOsDistro);
  const pkg       = document.getElementById('osPkg').value.trim();
  const pkgVer    = document.getElementById('osPkgVer').value.trim();
  const distroVer = document.getElementById('osDistroVer').value.trim();
  const desc      = document.getElementById('osDesc').value.trim();
  document.getElementById('osmerr').hidden=true;
  if(!distro) return showErr('osmerr','Select a distribution');
  if(!pkg)    return showErr('osmerr','Enter a package name');
  setBtn('btnOsGo',true);
  try{
    const r=await fetch('/api/osscan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:pkg,version:pkgVer||undefined,distro:distro.id,distroVersion:distroVer||undefined})});
    const data=await readJson(r);
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    const _ck = `os:${distro.id}:${distroVer||'latest'}:${pkg}:${pkgVer||'any'}`;
    const ckIdx = osScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) osScans.splice(ckIdx, 1);
    osScans.unshift({
      id:Date.now(), _cacheKey:_ck,
      pkg,pkgVer,distro:distro.id,distroLabel:distro.label,
      distroVer,desc,vulns:data.vulns||[],counts:data.counts||{},
      topSev:data.topSeverity||'NONE',scannedAt:data.scannedAt||new Date().toISOString(),
    });
    if(osScans.length>SCAN_HISTORY_MAX) osScans=osScans.slice(0,SCAN_HISTORY_MAX);
    saveOs();closeOsModal();updateOsBadge();navTo('os-list');
  }catch(e){ showErr('osmerr',e.message||'Scan failed'); }
  setBtn('btnOsGo',false,'Scan');
}

function updateOsBadge(){
  const b=document.getElementById('osBadge');
  if(osScans.length){b.hidden=false;b.textContent=osScans.length;}
  else b.hidden=true;
}

async function renderOsList(){
  updateOsBadge();
  const pg=paginate('os-list',osScans,renderOsList);
  const el=document.getElementById('osListContent');
  if(!osScans.length){
    el.innerHTML=`<div class="empty">${_emptyRadar()}
      <h2>No OS scans yet</h2>
      <p>Scan an OS package for known vulnerabilities across Ubuntu, Debian, RHEL, Alpine and SUSE — powered by Grype</p>
      <button class="btn-primary orange" onclick="openOsModal()">+ Add scan</button>
    </div>`;
    _initEmptyRadar();return;
  }
  el.innerHTML=`
    <div class="list-toolbar">
      <button class="btn-secondary" onclick="openOsModal()">+ Add scan</button>
      <button class="btn-secondary" onclick="if(confirm('Clear all OS scans?')){osScans=[];saveOs();updateOsBadge();renderOsList()}">Clear all</button>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Package</th><th>Description</th><th>Distribution</th><th>Version</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th class="col-del"></th></tr></thead>
      <tbody>${pg.rows.map(([s,i])=>{
        const counts=s.counts||{};
        const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>counts[sv])
          .map(sv=>`<span class="sev sm ${sv}">${counts[sv]} ${sv}</span>`).join(' ');
        const vulnLen=(s.vulns||[]).length;
        return`<tr class="row" onclick="navTo('os-detail',{scan:osScans[${i}]})">
          <td><div class="row-main">
            <span class="row-icon">${brandIcon(s.distro)}</span>
            <div class="row-name">${esc(s.pkg)}</div>
          </div></td>
          <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
          <td><span class="row-distro">${esc(s.distroLabel)}${s.distroVer?' <span>'+esc(s.distroVer)+'</span>':''}</span></td>
          <td><span class="row-ver">${s.pkgVer?'v'+esc(s.pkgVer):'any'}</span></td>
          <td><span class="sev ${esc(s.topSev)}">${esc(s.topSev)}</span></td>
          <td>${vulnLen===0?`<span class="row-clean">${icon('check')} clean</span>`:(pills||`<span class="row-count">${vulnLen}</span>`)}</td>
          <td class="row-date">${fmtDate(s.scannedAt)}</td>
          <td><button class="row-del" onclick="event.stopPropagation();osScans.splice(${i},1);saveOs();updateOsBadge();renderOsList()">${icon('x')}</button></td>
        </tr>`;
      }).join('')}
      </tbody>
    </table></div>${pg.html}`;
}

function renderOsDetail(scan){
  currentOsScan=scan;
  const el=document.getElementById('osDetailContent');
  const distroInfo=OS_DISTROS.find(d=>d.id===scan.distro)||{label:scan.distro};
  const vulns=scan.vulns||[];
  const counts=scan.counts||{};
  const chips=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>counts[sv])
    .map(sv=>`<span class="sev ${sv}">${counts[sv]} ${sv}</span>`).join('');
  const SEV_W={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  const groups=new Map();
  for(const v of vulns){
    const pkg=v.pkgName||scan.pkg;
    if(!groups.has(pkg)) groups.set(pkg,{vulns:[],topW:0,counts:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0}});
    const g=groups.get(pkg);
    g.vulns.push(v);
    const sev=(v.severity||'UNKNOWN').toUpperCase();
    if(sev in g.counts) g.counts[sev]++;
    g.topW=Math.max(g.topW,SEV_W[sev]||0);
  }
  const sorted=[...groups.entries()].sort((a,b)=>{
    if(b[1].topW!==a[1].topW) return b[1].topW-a[1].topW;
    return b[1].vulns.length-a[1].vulns.length;
  });
  for(const [,g] of sorted)
    g.vulns.sort((a,b)=>(SEV_W[b.severity]||0)-(SEV_W[a.severity]||0));

  const rerender=()=>keepOpenGroups(el,()=>renderOsDetail(scan));
  const groupPage=paginate('os-groups',sorted,rerender,scan);
  let gvi=0;
  const groupHtml=groupPage.rows.map(([[pkgName,g]])=>{
    const topSevG=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s=>g.counts[s])||'UNKNOWN';
    const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>g.counts[sv])
      .map(sv=>`<span class="sev xs ${sv}">${g.counts[sv]}</span>`).join('');
    const pkgVerSpan=g.vulns[0]?.pkgVersion?`<span class="pkg-group-ver">v${esc(g.vulns[0].pkgVersion)}</span>`:'';
    const fixedVer=g.vulns.find(v=>v.fix)?.fix;
    const fixTag=fixedVer?`<span class="fix-tag">${icon('arrow-right')} ${esc(fixedVer)}</span>`:'';
    const cardPage=paginate('os-cards:'+pkgName,g.vulns,rerender,scan);
    const cards=cardPage.rows.map(([v])=>osVulnCardHtml(v,gvi++)).join('')+cardPage.html;
    return`<div class="pkg-group" data-group="${esc(pkgName)}">
      <div class="pkg-group-hdr" onclick="togglePkgGroup(this)">
        <div class="vbar ${topSevG}"></div>
        <div class="pkg-group-title"><span class="pkg-group-name">${esc(pkgName)}</span>${pkgVerSpan}${fixTag}</div>
        <div class="pkg-group-stats">${pills}<span class="pkg-group-count">${g.vulns.length} CVE${g.vulns.length>1?'s':''}</span><span class="pkg-chev">${icon('chevron-down')}</span></div>
      </div>
      <div class="pkg-group-body">${cards}</div>
    </div>`;
  }).join('');

  window._lastOsScan = scan;
  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon orange">${brandIcon(scan.distro)}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(scan.pkg)}${scan.pkgVer?` <span class="detail-ver">v${esc(scan.pkgVer)}</span>`:''}</div>
        <div class="detail-sub">${esc(distroInfo.label)}${scan.distroVer?' '+esc(scan.distroVer):''}${scan.desc?' · '+esc(scan.desc):''} · ${vulns.length} vulnerabilit${vulns.length===1?'y':'ies'} across ${sorted.length} package${sorted.length!==1?'s':''} · scanned ${fmtDate(scan.scannedAt)}</div>
      </div>
      <div class="detail-chips">${chips||`<span class="sev NONE">${icon('check')} CLEAN</span>`}</div>
      <div class="detail-actions">${exportBtnHtml('os','__OS_SCAN__')}</div>
    </div>
    ${vulns.length===0?`<div class="detail-empty">${icon('shield-check')} No vulnerabilities found — this package is clean!</div>`:groupHtml+groupPage.html}`;

  el.querySelector('.pkg-group')?.classList.add('open');
}

function osVulnCardHtml(v,vi){
  const sev=(v.severity||'UNKNOWN').toUpperCase();
  const cveId=v.id||'';
  const title=v.summary||v.description||'No description';

  const cvss3=v.cvss?.cvss3;
  const cvssInline=cvss3?`<span class="sev xs ${cvssClass(cvss3.score)}">${cvss3.score}</span>`:'';
  let eb='';
  if(v.vex) eb+=`<span class="mark vex" title="VEX: ${esc(v.vex.label)}">VEX</span>`;
  if(v.vex) eb+=`<span class="sev xs vex-state ${esc(v.vex.cls)}" title="${esc(v.vex.source||'VEX')}: ${esc(v.vex.label)}">${esc(v.vex.label)}</span>`;
  if(v.inKev) eb+=`<span class="mark kev" title="CISA KEV">${icon('flame')} KEV</span>`;
  if((v.pocs||[]).length) eb+=`<span class="mark poc" title="${v.pocs.length} PoC(s)">${icon('bug')} PoC×${v.pocs.length}</span>`;
  const risk=v.risk;
  const riskBadge=risk?`<span class="sev xs risk ${esc(risk.label)}" title="Risk score">${icon('zap')}${Number(risk.score)||0}</span>`:'';

  return`<div class="vi" id="osvi-${vi}">
    <div class="vi-hdr" onclick="toggleOsVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">${esc(cveId)}</div>
      <div class="vi-sum">${esc(title.length>80?title.slice(0,80)+'…':title)}</div>
      <span class="enrich-badges">${eb}${cvssInline}${riskBadge}</span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">${icon('chevron-down')}</span>
    </div>
    <div class="vi-body" id="osvib-${vi}">
      <div class="vgrid">
        <span class="vk">CVE ID</span><span class="vv"><a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" rel="noopener">${esc(cveId)} ${icon('external-link')}</a></span>
        <span class="vk">Package</span><span class="vv strong">${esc(v.pkgName||'—')}</span>
        <span class="vk">Installed</span><span class="vv dim">${esc(v.pkgVersion||'—')}</span>
        ${v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">${icon('arrow-right')} ${esc(v.fix)}</span></span>`:''}
        ${v.description?`<span class="vk">Description</span><span class="vv prose" id="osdesc-${vi}">${esc(v.description.slice(0,480))}${v.description.length>480?`<button class="more-link" data-full="${esc(v.description)}" onclick="expandOsDesc(${vi},this)">… show more</button>`:''}</span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v.urls||[]).length?`<span class="vk">Reference</span><span class="vv"><a href="${esc(safeUrl(v.urls[0]))}" target="_blank" rel="noopener">${esc(v.urls[0].length>60?v.urls[0].slice(0,60)+'…':v.urls[0])}</a></span>`:''}
        <span class="vk">CVSS</span><span class="vv">${cvssHtml(v.cvss)}</span>
        <span class="vk">NVD Score</span><span class="vv">${_osNvdScoreHtml(v.cvss)}</span>
        <span class="vk">EPSS</span><span class="vv">${_osEpssHtml(v.epss)}</span>
        <span class="vk">Risk Score</span><span class="vv">${_osRiskHtml(v.risk)}</span>
        <span class="vk">CISA KEV</span><span class="vv">${kevBadge(v.inKev)}</span>
        <span class="vk">PoC (GitHub)</span><span class="vv">${pocBadge(v.pocs||[])}</span>
        ${v.vex?`<span class="vk">VEX Status</span><span class="vv">${_osVexHtml(v.vex)}</span>`:''}
      </div>
    </div>
  </div>`;
}

function _osNvdScoreHtml(cvss){
  if(!cvss?.cvss3) return NOT_IN_NVD;
  const s=cvss.cvss3.score;
  return`<span class="sev ${cvssClass(s)}">${s}</span><span class="text-note nvd-vector">${esc(cvss.cvss3.vector||'')}</span>`;
}
function _osEpssHtml(epss){
  if(!epss||!Number.isFinite(epss.epss)) return '<span class="text-note">not found</span>';
  const pct=(epss.epss*100).toFixed(2),cls=epss.epss>=.1?'hi':epss.epss>=.01?'mi':'';
  const pctl=Number.isFinite(epss.percentile)?`<span class="text-meta">${(epss.percentile*100).toFixed(0)}th pct</span>`:'';
  return`<div class="epss-row"><span class="epss-pct ${cls}">${pct}%</span><div class="epss-bar"><div class="epss-fill ${cls}" style="width:${Math.min(epss.epss*500,100)}%"></div></div>${pctl}</div>`;
}
function _osRiskHtml(risk){
  if(!risk) return '<span class="text-note">—</span>';
  const fill=['CRITICAL','HIGH','MEDIUM'].includes(risk.label)?risk.label:'LOW';
  const score=Number(risk.score)||0;
  return`<div class="epss-row"><span class="sev risk-score ${esc(risk.label)}">${score}/100</span><div class="epss-bar"><div class="epss-fill ${fill}" style="width:${score}%"></div></div><span class="text-meta">60% CVSS · 40% EPSS</span></div>`;
}

function toggleOsVI(vi){
  document.getElementById('osvi-'+vi)?.classList.toggle('open');
}
function expandOsDesc(vi,btn){
  const el=document.getElementById('osdesc-'+vi);
  if(el) el.textContent=btn.getAttribute('data-full');
}

function _osVexHtml(vex){
  if(!vex) return '<span class="text-note">—</span>';
  return`<span class="vex-tag ${esc(vex.cls)}">${esc(vex.label)}</span>`;
}

document.addEventListener('keydown',e=>{
  const m=document.getElementById('osModal');
  if(m&&!m.hidden){
    if(e.key==='Enter')  doOsScan();
  }
});
