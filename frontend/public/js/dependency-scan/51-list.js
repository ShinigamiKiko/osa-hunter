
async function renderDepList(){
  updateDepBadge();
  const pg=paginate('dep-list',depScans,renderDepList);
  const el=document.getElementById('depListContent');
  if(!depScans.length){
    el.innerHTML=`<div class="empty">
      ${_emptyRadar()}
      <h2>No dependency scans yet</h2>
      <p>Scan a package to map its full dependency tree and check every dep for vulnerabilities, toxic repos and EPSS scores</p>
      <button class="btn-primary purple" onclick="openDepModal()">+ Add scan</button>
    </div>`;
    _initEmptyRadar();
    return;
  }
  el.innerHTML=`
    <div class="list-toolbar">
      <button class="btn-secondary" onclick="openDepModal()">+ Add scan</button>
      <button class="btn-secondary" onclick="if(confirm('Clear all dep scans?')){depScans=[];saveDep();updateDepBadge();renderDepList()}">Clear all</button>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr>
        <th>Package</th><th>Description</th><th>System</th>
        <th>Version</th><th>Deps</th><th>Vulnerabilities</th><th>Toxic</th><th>Scanned</th><th class="col-del"></th>
      </tr></thead>
      <tbody>
        ${pg.rows.map(([s,i])=>{
          markDependencyCompleteness(s);
          const sysInfo=DEP_SYSTEMS.find(x=>x.id===s.system)||{logo:'📦',label:s.system};
          const _sum={ ...s.summary };
          if (Array.isArray(s.deps) && s.deps.length)
            Object.assign(_sum, findingCounts(s.deps.flatMap(d => d.vulns || [])));
          const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>_sum[sv])
            .map(sv=>`<span class="sev sm ${sv}">${_sum[sv]} ${sv}</span>`).join(' ');
          const legacyVulnerabilityCount = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
            .reduce((total,sev)=>total+Number(_sum[sev]||0),0);
          const dependencyVulnerabilityCount = Array.isArray(s.deps)
            ? s.deps.reduce((total,d)=>total+(d.vulns||[]).length,0)
            : 0;
          const vulnerabilityCount = _sum.vulnerabilityCount ??
            (dependencyVulnerabilityCount || legacyVulnerabilityCount);
          const hasVulnerabilities = vulnerabilityCount>0 || Number(_sum.withVulns||0)>0;
          const vulnCell  = s.complete === false
            ? '<span class="sev UNKNOWN">RESCAN REQUIRED</span>'
            : !hasVulnerabilities
            ? '<span class="row-clean">&#10003; clean</span>'
            : (pills||`<span class="row-count">${vulnerabilityCount||'?'}</span>`);
          const toxicCell = _sum.toxic>0 ? `<span class="row-toxic">&#9760; ${_sum.toxic}</span>` : '<span class="row-clean">&#10003;</span>';
          const toxicFlag = s.toxic?.found ? '<div class="row-meta"><span class="pkg-flag toxic">&#9760; TOXIC</span></div>' : '';
          return `<tr class="row" onclick="currentDepScan=depScans[${i}];navTo('dep-detail',{scan:depScans[${i}]})">
            <td><div class="row-main">
              <span class="row-icon sm">${esc(sysInfo.logo)}</span>
              <div><div class="row-name">${esc(s.package)}</div>${toxicFlag}</div>
            </div></td>
            <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
            <td><span class="row-system">${esc(sysInfo.label)}</span></td>
            <td><span class="row-ver">${esc(s.resolvedVersion||'—')}</span></td>
            <td><span class="row-deps">${_sum.totalDeps||'?'}</span>
                <span class="row-deps-sub"> (${_sum.directDeps||'?'} direct)</span></td>
            <td>${vulnCell}</td>
            <td>${toxicCell}</td>
            <td class="row-date">${fmtDate(s.scannedAt)}</td>
            <td><button class="row-del" onclick="event.stopPropagation();depScans.splice(${i},1);saveDep();renderDepList()">&#10005;</button></td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>${pg.html}`;
}

function toggleDepSection(key){
  document.getElementById('depsec-'+key)?.classList.toggle('collapsed');
}

function toggleDepCard(depIdx){
  const card=document.getElementById('dcard-'+depIdx);
  if(!card) return;
  const open=card.classList.toggle('open');
  if(open && card.dataset.enriched!=='1'){
    card.dataset.enriched='1';
    const dep=window._currentDepScanDeps?.[depIdx];
    if(dep?.vulns?.length) _enrichDepCardVulns(dep.vulns, depIdx);
  }
}

function toggleDepVI(depIdx, vi){
  document.getElementById('dvi-'+depIdx+'-'+vi)?.classList.toggle('open');
}

function _enrichDepCardVulns(vulns, depIdx){
  vulns.forEach((v,vi)=>{
    const cvssVEl=document.getElementById('dvicvssv-'+depIdx+'-'+vi);
    if(cvssVEl) cvssVEl.innerHTML=cvssHtml(v.cvss);
    const cvssHEl=document.getElementById('dvicvss-'+depIdx+'-'+vi);
    if(cvssHEl&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score;
      cvssHEl.innerHTML=`<span class="sev xs ${cvssClass(s)}">${s}</span>`;
    }
    const epssEl=document.getElementById('dviepss-'+depIdx+'-'+vi);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);
    const kevEl=document.getElementById('dvikev-'+depIdx+'-'+vi);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);
    const pocEl=document.getElementById('dvipoc-'+depIdx+'-'+vi);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
    const eb=document.getElementById('dvieb-'+depIdx+'-'+vi);
    if(eb){
      let hb='';
      if(v.inKev)    hb+='<span class="mark kev" title="CISA KEV">&#128293; KEV</span>';
      if(v.pocs?.length) hb+=`<span class="mark poc" title="${v.pocs.length} PoC(s)">&#128165; PoC&#215;${v.pocs.length}</span>`;
      eb.innerHTML=hb;
    }
  });
}
