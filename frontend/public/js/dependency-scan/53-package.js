
function openDepPkg(idx){
  const dep=idx===-1?window._currentDepScanRoot:window._currentDepScanDeps[idx];
  if(!dep) return;
  navTo('dep-pkg',{dep,scan:currentDepScan,backScan:currentDepScan});
}

function renderDepPkg(dep, scan){
  const el=document.getElementById('depPkgContent');
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===(dep.system||scan?.system))||{label:dep.system||'Unknown'};
  const cnt=dep.counts||{};
  const chips=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>cnt[sv])
    .map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('');

  const chipsOrClean=dep.vulns?.length===0?`<span class="sev NONE">${icon('check')} CLEAN</span>`:chips;
  const relationHtml=(dep.relation&&dep.relation!=='ROOT')
    ?` &middot; <span class="${dep.relation==='DIRECT'?'relation-direct':'relation-other'}">${esc(dep.relation)}</span> &middot; from ${esc(scan?.package||'—')}`
    :'';
  const emptyMsg=dep.relation==='ROOT'
    ?`<div class="detail-empty">${icon('shield-check')} No vulnerabilities found in this library!</div>`
    :`<div class="detail-empty">${icon('shield-check')} No vulnerabilities found for this dependency!</div>`;
  const vulnsHtml=dep.vulns?.length===0
    ?emptyMsg
    :(()=>{
      const page=paginate('dep-pkg-vulns',dep.vulns||[],()=>renderDepPkg(dep,scan),dep);
      return `<div id="depPkgVulnCards">${page.rows.map(([v,vi])=>depVulnCardHtml(dep,v,vi)).join('')}</div>${page.html}`;
    })();

  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon purple">${brandIcon(dep.system||scan?.system)}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(dep.name)} <span class="detail-ver">${dep.version.startsWith('v') ? esc(dep.version) : 'v'+esc(dep.version)}</span></div>
        <div class="detail-sub">${esc(sysInfo.label)}${relationHtml}</div>
        <div class="detail-badges">
          <div>${_toxicBadgeHtml(dep.toxic)}</div>
          <div id="depPkgActivityBadge"><span class="activity-pending">${icon('loader-circle', 'spin')} Checking activity&#8230;</span></div>
        </div>
      </div>
      <div class="detail-chips">${chipsOrClean}</div>
    </div>
    ${vulnsHtml}`;

  if(dep.vulns?.length) enrichDepPkgVulns(dep.vulns);
  checkActivity('depPkgActivityBadge', dep.name, dep.system||scan?.system);
}

function depVulnCardHtml(dep,v,vi){
  const cveId=[...(v.aliases||[]),v.id].find(x=>x&&x.startsWith('CVE-'))||v.id||'';
  const cveLink=cveId.startsWith('CVE-')
    ?`<a class="vi-cve" href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()">${esc(cveId)} ${icon('external-link')}</a><span class="vi-cve-sep">/</span>`
    :'';
  const loading='<span class="text-note">loading&#8230;</span>';
  const fixRow =v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">${icon('arrow-right')} ${esc(v.fix)}</span></span>`:'';
  const descText2=v.details||v.summary||'';
  const detRow =descText2?`<span class="vk">Description</span><span class="vv prose">${esc(descText2.slice(0,500))}${descText2.length>500?'&#8230;':''}</span>`:'';
  const nvdScore2=v.cvss?.cvss3?.score||null;
  const nvdRow2  =nvdScore2?`<span class="vk">NVD Score</span><span class="vv"><span class="sev nvd-score ${cvssClass(nvdScore2)}">${nvdScore2}</span> <span class="text-meta">${esc(v.cvss.cvss3.vector||'')}</span></span>`:'';
  const pubRow =v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:'';
  const refsRow=(v.refs||[]).length
    ?`<span class="vk">References</span><span class="vv links">${v.refs.slice(0,4).map(u=>{const su=safeUrl(u);return su==='#'?'':`<a href="${esc(su)}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'&#8230;':u)}</a>`;}).filter(Boolean).join('<br/>')}</span>`
    :'';
  return`<div class="vi" id="dpvi-${vi}">
    <div class="vi-hdr" onclick="toggleDPVI(${vi})">
      <div class="vbar ${v.severity}"></div>
      <div class="vi-id">
        ${cveLink}
        <span class="vi-alt-id">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="dpvcvss-${vi}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="dpveb-${vi}"></span>
      <span class="vi-sev ${v.severity}">${v.severity}</span>
      <span class="vi-chev">${icon('chevron-down')}</span>
    </div>
    <div class="vi-body" id="dpvib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} ${icon('external-link')}</a></span>
        <span class="vk">CVSS</span><span class="vv" id="dpvcvssv-${vi}">${v.cvss?cvssHtml(v.cvss):loading}</span>
        ${nvdRow2}
        <span class="vk">EPSS</span><span class="vv" id="dpvepss-${vi}">${v.epss?epssHtml(v.epss):loading}</span>
        ${detRow}${fixRow}${pubRow}${refsRow}
        <span class="vk">CISA KEV</span><span class="vv" id="dpvkev-${vi}">${kevBadge(v.inKev)}</span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="dpvpoc-${vi}">${pocBadge(v.pocs||[])}</span>
      </div>
    </div>
  </div>`;
}
