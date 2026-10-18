const ECOS=[
  {id:'npm',      label:'npm',   logo:'📦',osv:'npm'},
  {id:'pypi',     label:'PyPI',  logo:'🐍',osv:'PyPI'},
  {id:'go',       label:'Go',    logo:'🐹',osv:'Go'},
  {id:'crates',   label:'Rust',  logo:'🦀',osv:'crates.io'},
  {id:'maven',    label:'Maven', logo:'☕',osv:'Maven'},
  {id:'rubygems', label:'Ruby',  logo:'💎',osv:'RubyGems'},
  {id:'nuget',    label:'NuGet', logo:'🔷',osv:'NuGet'},
  {id:'packagist',label:'PHP',   logo:'🐘',osv:'Packagist'},
];

const libStored=safeLoad('es_lib',[]);
let libScans=pruneLocalScans(libStored);
if(libScans.length!==libStored.length) safeSave('es_lib',libScans);
let selEco=null;
let libScanInFlight=false;
const saveLib=()=>safeSave('es_lib',libScans);

function renderEcos(){
  document.getElementById('ecoGrid').innerHTML=ECOS.map(e=>`
    <button class="eco-btn${selEco===e.id?' on':''}" onclick="pickEco('${e.id}')">
      <div class="eco-logo">${e.logo}</div><div class="eco-name">${e.label}</div>
    </button>`).join('');
}
function pickEco(id){selEco=id;renderEcos();}

function openLibModal(){
  selEco=null;['fDesc','fPkg','fVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('lmerr').hidden=true;
  setBtn('btnLibGo',false,'▶ Scan');renderEcos();
  document.getElementById('libModal').hidden=false;
  setTimeout(()=>document.getElementById('fPkg').focus(),160);
}
function closeLibModal(){document.getElementById('libModal').hidden=true;}

async function doLibScan(){
  const eco=ECOS.find(e=>e.id===selEco);
  const pkg=document.getElementById('fPkg').value.trim();
  const ver=document.getElementById('fVer').value.trim();
  const desc=document.getElementById('fDesc').value.trim();
  document.getElementById('lmerr').hidden=true;
  if(!eco) return showErr('lmerr','Select an ecosystem');
  if(!pkg) return showErr('lmerr','Enter a package name');
  if(libScanInFlight) return;
  libScanInFlight=true;
  setBtn('btnLibGo',true);
  try{
    const r=await fetch('/api/libscan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:pkg,ecosystem:eco.osv,version:ver||undefined})});
    const data=await readJson(r);
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    if(data.error) throw new Error(data.error);
    const vulns=(data.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]}));
    const _ck = `lib:${eco.osv||eco.id}:${data.package}:${data.version||'latest'}`;
    const ckIdx = libScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) libScans.splice(ckIdx, 1);
    libScans.unshift({
      id:Date.now(), _cacheKey:_ck,
      pkg:data.package,ver:data.version||'',
      eco:eco.id,ecoLabel:eco.label,ecoLogo:eco.logo,
      desc,vulns,toxic:data.toxic,topSev:data.topSeverity||'NONE',scannedAt:data.scannedAt,
    });
    saveLib();closeLibModal();updateLibBadge();navTo('lib-list');
  }catch(e){showErr('lmerr',e.message||'Request failed');}
  finally {
    libScanInFlight=false;
    setBtn('btnLibGo',false,'▶ Scan');
  }
}

function updateLibBadge(){
  const b=document.getElementById('libBadge');
  if(libScans.length){b.hidden=false;b.textContent=libScans.length;}
  else b.hidden=true;
}

async function renderLibList(){
  updateLibBadge();
  const pg=paginate('lib-list',libScans,renderLibList);
  const el=document.getElementById('libListContent');
  if(!libScans.length){
    el.innerHTML=`<div class="empty">${_emptyRadar()}<h2>No scans yet</h2><p>Add a library to check for known vulnerabilities via OSV database with EPSS enrichment</p><button class="btn-primary" onclick="openLibModal()">+ Add library</button></div>`;
    _initEmptyRadar();return;
  }
  el.innerHTML=`
    <div class="list-toolbar">
      <button class="btn-secondary" onclick="openLibModal()">+ Add library</button>
      <button class="btn-secondary" onclick="if(confirm('Clear all?')){libScans=[];saveLib();updateLibBadge();renderLibList()}">Clear all</button>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Package</th><th>Description</th><th>Version</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th class="col-del"></th></tr></thead>
      <tbody>${pg.rows.map(([s,i])=>{
        const cnt={};s.vulns.forEach(v=>{const sv=v._sev||v.severity||'UNKNOWN';cnt[sv]=(cnt[sv]||0)+1;});
        const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>cnt[sv])
          .map(sv=>`<span class="sev sm ${sv}">${cnt[sv]} ${sv}</span>`).join(' ');
        const isToxic=s.toxic?.found;
        return`<tr class="row" onclick="navTo('lib-detail',{scan:libScans[${i}]})">
          <td>
            <div class="row-name">${esc(s.pkg)}</div>
            <div class="row-meta">
              <div class="row-eco">${esc(s.ecoLogo)} ${esc(s.ecoLabel)}</div>
              ${isToxic?'<span class="pkg-flag toxic">☠ TOXIC</span>':''}
            </div>
          </td>
          <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
          <td><span class="row-ver">${s.ver?'v'+esc(s.ver):'any'}</span></td>
          <td><span class="sev ${esc(s.topSev)}">${esc(s.topSev)}</span></td>
          <td>${s.vulns.length===0?'<span class="row-clean">✓ clean</span>':(pills||`<span class="row-count">${s.vulns.length}</span>`)}</td>
          <td class="row-date">${fmtDate(s.scannedAt)}</td>
          <td><button class="row-del" onclick="event.stopPropagation();libScans.splice(${i},1);saveLib();updateLibBadge();renderLibList()">✕</button></td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>${pg.html}`;
}

function renderLibDetail(s){
  const vulnPage=paginate('lib-vulns',s.vulns,()=>renderLibDetail(s),s);
  const cnt={};s.vulns.forEach(v=>{const sv=v._sev||v.severity||'UNKNOWN';cnt[sv]=(cnt[sv]||0)+1;});
  const el=document.getElementById('libDetailContent');
  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon green">${esc(s.ecoLogo)}</div>
      <div class="detail-info">
        <div class="detail-name lg">${esc(s.pkg)}${s.ver?` <span class="detail-ver lg">${s.ver.startsWith('v') ? esc(s.ver) : 'v'+esc(s.ver)}</span>`:''}</div>
        <div class="detail-sub">${esc(s.ecoLabel)} · ${esc(s.desc||'No description')} · scanned ${fmtDate(s.scannedAt)}</div>
        <div class="detail-badges">
          ${_toxicBadgeHtml(s.toxic)}
          <div id="activityBadge"><span class="activity-pending">⏳ Checking activity…</span></div>
        </div>
      </div>
      <div class="detail-chips stacked">
        <div class="chip-row">
          ${s.vulns.length===0?'<span class="sev NONE">✅ CLEAN</span>':['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>cnt[sv]).map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('')}
        </div>
        ${exportBtnHtml('lib',{name:s.pkg,ecosystem:s.eco,version:s.ver||'',desc:s.desc||'',ecoLabel:s.ecoLabel||'',ecoLogo:s.ecoLogo||''})}
      </div>
    </div>
    ${s.vulns.length===0
      ?'<div class="detail-empty">🛡️ No vulnerabilities found — this package version is clean!</div>'
      :`<div id="vulnCards">${vulnPage.rows.map(([v,vi])=>vulnCardHtml(s,v,vi)).join('')}</div>${vulnPage.html}`}`;
  if(s.vulns.length) renderStoredEnrichment(s.vulns,'lib');
  checkActivity('activityBadge',s.pkg,s.ecoLabel);
}

function vulnCardHtml(s,v,vi){
  const cveId=[...(v._aliases||v.aliases||[]),(v.cve||v.id)].find(x=>x?.startsWith('CVE-'))||v.id;
  const sev=v._sev||v.severity||'UNKNOWN';
  return`<div class="vi" id="vi-${vi}">
    <div class="vi-hdr" onclick="toggleVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">
        ${cveId.startsWith('CVE-')?`<a class="vi-cve lg" href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()">${esc(cveId)} ↗</a><span class="vi-cve-sep lg">/</span>`:''}
        <span class="vi-alt-id lg">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="cvss-hdr-lib-${cveId}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="eb-lib-${cveId}"></span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="vib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} ↗</a></span>
        <span class="vk">CVSS</span><span class="vv" id="cvss-lib-${cveId}"></span>
        <span class="vk">NVD Score</span><span class="vv" id="nvd-lib-${cveId}"><span class="text-note">loading…</span></span>
        <span class="vk">EPSS</span><span class="vv" id="epss-lib-${cveId}"></span>
        ${v.details?`<span class="vk">Details</span><span class="vv prose" id="det-${vi}">${esc(v.details.slice(0,480))}${v.details.length>480?`<span id="det-dots-${vi}"> <button class="more-link" data-full="${esc(v.details)}" onclick="expandDet(${vi},this)">… show more</button></span>`:''}</span>`:''}
        ${(v._fix||v.fix)?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v._fix||v.fix)}</span></span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v._refs||v.refs||[]).length?`<span class="vk">References</span><span class="vv links">${(v._refs||v.refs).slice(0,4).map(u=>`<a href="${esc(safeUrl(u))}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'…':u)}</a>`).filter(Boolean).join('<br/>')}</span>`:''}
        <span class="vk">CISA KEV</span><span class="vv" id="kev-lib-${cveId}"></span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="poc-lib-${cveId}"></span>
      </div>
    </div>
  </div>`;
}

function expandDet(vi,btn){
  const el=document.getElementById('det-'+vi);
  const dots=document.getElementById('det-dots-'+vi);
  if(!el||!dots)return;
  dots.remove();el.textContent=btn.getAttribute('data-full');
}
function toggleVI(vi){
  document.getElementById('vi-'+vi)?.classList.toggle('open');
}

document.addEventListener('keydown',e=>{
  if(e.key==='Enter' && !document.getElementById('libModal').hidden) doLibScan();
});
