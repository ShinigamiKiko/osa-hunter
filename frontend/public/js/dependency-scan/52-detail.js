
function renderDepDetail(scan){
  markDependencyCompleteness(scan);
  window._lastDepScan=scan;
  currentDepScan=scan;
  const el=document.getElementById('depDetailContent');
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===scan.system)||{label:scan.system};
  const sm={ ...scan.summary };
  if (Array.isArray(scan.deps) && scan.deps.length)
    Object.assign(sm, findingCounts(scan.deps.flatMap(d => d.vulns || [])));
  const chips=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>sm[sv])
    .map(sv=>`<span class="sev ${sv}">${sm[sv]} ${sv}</span>`).join('');

  const allDeps  = Array.isArray(scan.deps) ? scan.deps : [];
  const rootDep  = allDeps.find(d=>d.relation==='ROOT') || null;
  const rootName = rootDep?.name || scan.package;
  const direct   = allDeps.filter(d=>d.relation==='DIRECT'   && d.name!==rootName);
  const indirect = allDeps.filter(d=>d.relation==='INDIRECT'  && d.name!==rootName);

  const directCount     = direct.length;
  const transitiveCount = indirect.length;
  const totalCount      = directCount + transitiveCount;

  function depMiniVulnRow(v, vi, depIdx){
    const cveId=[...(v.aliases||[]),v.id].find(x=>x&&x.startsWith('CVE-'))||v.id||'';
    const sev=v.severity||'UNKNOWN';
    const cveLink=cveId.startsWith('CVE-')
      ?`<a class="vi-cve" href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()">${esc(cveId)} ${icon('external-link')}</a><span class="vi-cve-sep">/</span>`
      :'';
    const fixRow=v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">${icon('arrow-right')} ${esc(v.fix)}</span></span>`:'';
    const descText = v.details||v.summary||'';
    const detRow=descText?`<span class="vk">Description</span><span class="vv prose">${esc(descText.slice(0,500))}${descText.length>500?'&#8230;':''}</span>`:'';
    const nvdScore = v.cvss?.cvss3?.score||null;
    const nvdRow   = nvdScore ? `<span class="vk">NVD Score</span><span class="vv"><span class="sev nvd-score ${cvssClass(nvdScore)}">${nvdScore}</span> <span class="text-meta">${esc(v.cvss.cvss3.vector||'')}</span></span>` : '';
    return`<div class="vi" id="dvi-${depIdx}-${vi}">
      <div class="vi-hdr" onclick="toggleDepVI(${depIdx},${vi})">
        <div class="vbar ${sev}"></div>
        <div class="vi-id">
          ${cveLink}
          <span class="vi-alt-id">${esc(v.id)}</span>
          <span id="dvicvss-${depIdx}-${vi}"></span>
        </div>
        <div class="vi-sum">${esc(v.summary||'No summary')}</div>
        <span class="enrich-badges" id="dvieb-${depIdx}-${vi}"></span>
        <span class="vi-sev ${sev}">${sev}</span>
        <span class="vi-chev">${icon('chevron-down')}</span>
      </div>
      <div class="vi-body">
        <div class="vgrid">
          <span class="vk">CVSS</span><span class="vv" id="dvicvssv-${depIdx}-${vi}">${v.cvss?cvssHtml(v.cvss):'—'}</span>
          ${nvdRow}
          <span class="vk">EPSS</span><span class="vv" id="dviepss-${depIdx}-${vi}">${v.epss?epssHtml(v.epss):'—'}</span>
          ${fixRow}${detRow}
          <span class="vk">CISA KEV</span><span class="vv" id="dvikev-${depIdx}-${vi}">${kevBadge(v.inKev)}</span>
          <span class="vk">PoC</span><span class="vv" id="dvipoc-${depIdx}-${vi}">${pocBadge(v.pocs||[])}</span>
        </div>
      </div>
    </div>`;
  }

  function depPkgCard(dep, depIdx){
    const isToxic =dep.toxic?.found;
    const topSev  =dep.topSeverity||(['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s=>(dep.counts||{})[s])||'NONE');
    const pills   =['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(k=>(dep.counts||{})[k])
      .map(k=>`<span class="sev xs ${k}">${dep.counts[k]}</span>`).join('');
    const fixVer  =dep.vulns?.find(v=>v.fix)?.fix;
    const cveCount=dep.vulns?.length||0;

    const cleanBadge =`<span class="sev xs NONE">${icon('check')}</span>`;
    const noCvesDiv  =`<div class="card-note">${icon('check')} No vulnerabilities found</div>`;
    const toxicBadge =isToxic?`<span class="pkg-flag toxic">${icon('skull')} TOXIC</span>`:'';
    const fixBadge   =fixVer?`<span class="fix-tag">${icon('arrow-right')} ${esc(fixVer)}</span>`:'';
    const cveLabel   =cveCount?`<span class="pkg-group-count">${cveCount} CVE${cveCount>1?'s':''}</span>`:'';
    const vulnsBody  =cveCount?(dep.vulns||[]).map((v,vi)=>depMiniVulnRow(v,vi,depIdx)).join(''):noCvesDiv;
    const sysId      =esc(scan.system);
    const depName    =esc(dep.name);
    const depVer     =esc(dep.version||'');

    return`<div class="pkg-group compact" id="dcard-${depIdx}">
      <div class="pkg-group-hdr" onclick="toggleDepCard(${depIdx})">
        <div class="vbar ${topSev}"></div>
        <div class="pkg-group-title">
          <a class="pkg-link" href="#" data-open-lib data-system="${sysId}" data-name="${depName}" data-version="${depVer}">${esc(dep.name)}</a>
          <span class="pkg-group-ver lg">${esc(dep.version)}</span>
          ${fixBadge}${toxicBadge}
        </div>
        <div class="pkg-group-stats">
          ${cveCount?pills:cleanBadge}
          ${cveLabel}
          <span class="pkg-chev">${icon('chevron-down')}</span>
        </div>
      </div>
      <div class="pkg-group-body">${vulnsBody}</div>
    </div>`;
  }

  // One collapsible section: own vulnerabilities, direct or transitive deps.
  function sectionHtml({ key, kind, tag, label, count, right, body }){
    return`<div class="dep-section ${kind}" id="depsec-${key}">
      <div class="dep-section-head" onclick="toggleDepSection('${key}')">
        <span class="dep-section-tag">${tag}</span>
        <span class="dep-section-label">${esc(label)}</span>
        <span class="dep-section-count">(${count})</span>
        <span class="dep-section-right">${right}<span class="dep-section-chev">${icon('chevron-down')}</span></span>
      </div>
      <div class="dep-section-body">${body}</div>
    </div>`;
  }

  function depSection(deps, label, isTransitive, key){
    const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
    deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=(v.severity||'').toUpperCase();if(s in cnt)cnt[s]++;}));
    const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(k=>cnt[k])
      .map(k=>`<span class="sev xs ${k}">${cnt[k]}</span>`).join('');
    const clean=`<span class="dep-section-note ok">${icon('check')} all clean</span>`;
    const body = deps.length ? (()=>{
      const page=paginate('dep-section:'+key,deps,()=>renderDepDetail(scan),scan);
      return page.rows.map(([d])=>depPkgCard(d,allDeps.indexOf(d))).join('')+page.html;
    })() : `<div class="dep-section-empty">No ${isTransitive?'transitive':'direct'} dependencies found</div>`;
    return sectionHtml({
      key, kind: isTransitive?'transitive':'direct',
      tag: isTransitive?`${icon('arrow-down')} Transitive`:`${icon('arrow-up')} Direct`, label, count: deps.length,
      right: deps.length ? (pills||clean) : '<span class="dep-section-note">&mdash; empty</span>',
      body,
    });
  }

  const rootVulns = rootDep?.vulns||[];
  const rootCnt   = rootDep?.counts||{};
  const rootChips = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>rootCnt[sv])
    .map(sv=>`<span class="sev ${sv}">${rootCnt[sv]} ${sv}</span>`).join('');

  const chipsHtml = scan.complete === false ? '<span class="sev UNKNOWN">RESCAN REQUIRED</span>'
    : chips||rootChips||`<span class="sev NONE">${icon('check')} CLEAN</span>`;
  const exportBtn      =(typeof exportBtnHtml==='function')?exportBtnHtml('dep','__DEP_SCAN__'):'';

  const rootPills = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(k=>rootCnt[k])
    .map(k=>`<span class="sev xs ${k}">${rootCnt[k]}</span>`).join('');
  const rootIsClean  = rootVulns.length === 0;
  const rootVulnsHtml = sectionHtml({
    key: 'root', kind: rootIsClean?'clean':'vulnerable',
    tag: `${rootIsClean?icon('check'):icon('triangle-alert')} Own Vulnerabilities`, label: scan.package, count: rootVulns.length,
    right: rootIsClean ? `<span class="dep-section-note ok">${icon('check')} clean</span>` : rootPills,
    body: rootIsClean
      ? `<div class="card-note">${icon('check')} No own vulnerabilities found</div>`
      : rootVulns.map((v,vi)=>depMiniVulnRow(v,vi,-1)).join(''),
  });

  const legacyVulnerabilityCount = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
    .reduce((total,sev)=>total+Number(sm[sev]||0),0);
  const dependencyVulnerabilityCount = Array.isArray(scan.deps)
    ? scan.deps.reduce((total,d)=>total+(d.vulns||[]).length,0)
    : 0;
  const vulnCount = sm.vulnerabilityCount ??
    (dependencyVulnerabilityCount || legacyVulnerabilityCount);
  const hasVulnerabilities = vulnCount>0 || Number(sm.withVulns||0)>0;
  const noVulnsHtml    =scan.complete === false
    ? '<span class="warn">Scan incomplete — rescan required</span>'
    : hasVulnerabilities
    ?`<span class="warn">${icon('triangle-alert')} ${sm.withVulns||'Some'} deps · ${vulnCount||'?'} vulnerabilities</span>`
    :`<span class="ok">${icon('check')} no vulns</span>`;
  const emptyHtml=(!direct.length&&!indirect.length)
    ?'<div class="detail-empty muted">No dependencies found in the graph.</div>'
    :'';

  el.innerHTML=`
    <div class="detail-header clickable" onclick="openDepPkg(-1)">
      <div class="detail-icon green">${brandIcon(scan.system)}</div>
      <div class="detail-info">
        <div class="detail-name lg">
          ${esc(scan.package)} <span class="detail-ver">${esc(scan.resolvedVersion)}</span>
          <span class="dep-hdr-stats">
            <span>${icon('package')} ${totalCount} total</span>
            <span class="direct">${icon('arrow-up')} ${directCount} direct</span>
            <span class="transitive">${icon('arrow-down')} ${transitiveCount} transitive</span>
            ${noVulnsHtml}
          </span>
        </div>
        <div class="detail-sub">${esc(sysInfo.label)} &middot; ${esc(scan.desc||'No description')} &middot; scanned ${fmtDate(scan.scannedAt)}</div>
        <div class="detail-badges" onclick="event.stopPropagation()">
          ${_toxicBadgeHtml(scan.toxic)}
          <div id="depDetailActivityBadge"><span class="activity-pending">${icon('loader-circle', 'spin')} Checking activity&#8230;</span></div>
        </div>
      </div>
      <div class="detail-chips stacked" onclick="event.stopPropagation()">
        <div class="chip-row">${chipsHtml}</div>
        ${exportBtn}
      </div>
    </div>
    ${rootVulnsHtml}
    ${depSection(direct,   'Direct Dependencies',    false,'direct')}
    ${depSection(indirect, 'Transitive Dependencies', true, 'transitive')}
     ${emptyHtml}`;

  el.querySelectorAll('[data-open-lib]').forEach(link => link.addEventListener('click', event => {
    event.preventDefault();
    event.stopPropagation();
    openLibFromDep(event, link.dataset.system, link.dataset.name, link.dataset.version);
  }));

  window._currentDepScanDeps=allDeps;
  window._currentDepScanRoot = rootDep || {
    name:scan.package, system:scan.system, version:scan.resolvedVersion,
    relation:'ROOT', toxic:scan.toxic||{found:false},
    topSeverity:['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s=>rootCnt[s]>0)||'NONE',
    vulnCount:(rootCnt.CRITICAL||0)+(rootCnt.HIGH||0)+(rootCnt.MEDIUM||0)+(rootCnt.LOW||0)+(rootCnt.UNKNOWN||0),
    counts:rootCnt,
    vulns:rootVulns,
  };
  checkActivity('depDetailActivityBadge', scan.package, scan.system);
}
