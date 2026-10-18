let imgScans = safeLoad('es_img', []);
imgScans = Array.isArray(imgScans) ? imgScans.map(scan => normalizeImageScan(scan)) : [];
const saveImg = () => safeSave('es_img', imgScans);
const OS_PKG_TYPES = new Set(['debian','ubuntu','alpine','rhel','centos','oracle','amazon','rocky','fedora','suse','opensuse','photon','wolfi','chainguard','cbsl','cbl-mariner']);


function normalizeImageScan(data, metadata = {}) {
  const vulns = Array.isArray(data.Results)
    ? data.Results.flatMap(result => (result.Vulnerabilities || []).map(v => ({ ...v, _pkgType: result.Type || '' })))
    : (data.vulns || []).map(v => ({ ...v }));
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  for (const vuln of vulns) {
    const severity = String(vuln.Severity || vuln.severity || 'UNKNOWN').toUpperCase();
    vuln.Severity = Object.hasOwn(counts, severity) ? severity : 'UNKNOWN';
    counts[vuln.Severity]++;
  }
  vulns.sort((a,b) => SEV_ORD.indexOf(a.Severity) - SEV_ORD.indexOf(b.Severity));
  return {
    id: metadata.id ?? data.id ?? data._cacheKey ?? Date.now(),
    _cacheKey: metadata._cacheKey ?? data._cacheKey,
    image: metadata.image ?? data.image,
    tag: metadata.tag ?? data.tag ?? 'latest',
    desc: metadata.desc ?? data.desc ?? '',
    vulns, counts,
    scannedAt: data.scannedAt || data._cachedAt || new Date().toISOString(),
  };
}

async function doImageScan(){
  const image=document.getElementById('imgName').value.trim();
  const tag  =document.getElementById('imgTag').value.trim()||'latest';
  const desc =document.getElementById('imgDesc').value.trim();
  document.getElementById('imgErr').hidden=true;
  if(!image){ showErr('imgErr','Enter an image name'); return; }
  setBtn('btnImgScan',true);
  try{
    const r=await fetch('/api/trivy/scan',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({image,tag,desc})});
    const data=await readJson(r);
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    const _ck = `img:${image}:${tag}`;
    const ckIdx = imgScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) imgScans.splice(ckIdx, 1);
    const scan=normalizeImageScan(data, { id:Date.now(), _cacheKey:_ck, image,tag,desc });
    imgScans.unshift(scan);
    if(imgScans.length>SCAN_HISTORY_MAX) imgScans=imgScans.slice(0,SCAN_HISTORY_MAX);
    saveImg(); navTo('img-list');
  }catch(e){ showErr('imgErr',e.message||'Scan failed. Is Trivy running?'); }
  setBtn('btnImgScan',false,'Scan Image');
}

async function renderImgList(){
  const el=document.getElementById('imgListContent');
  const pg=paginate('img-list',imgScans,renderImgList);
  if(!imgScans.length){
    el.innerHTML=`<div class="empty">
      <div class="empty-rings"><div class="ering"></div><div class="ering"></div><div class="ering"></div><div class="ering-c">${brandIcon('docker')}</div></div>
      <h2>No image scans yet</h2>
      <p>Scan a Docker image to see vulnerability results</p>
      <button class="btn-primary blue-btn" onclick="navTo('img-form')">+ New scan</button>
    </div>`; return;
  }
  el.innerHTML=`
    <div class="list-toolbar">
      <button class="btn-secondary" onclick="navTo('img-form')">+ New scan</button>
      <button class="btn-secondary" onclick="if(confirm('Clear all image scans?')){imgScans=[];saveImg();renderImgList()}">Clear all</button>
    </div>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Image</th><th>Description</th><th>Tag</th>
          <th>Top Severity</th><th>Findings</th><th>Scanned</th><th class="col-del"></th>
        </tr></thead>
        <tbody>
          ${pg.rows.map(([s,i])=>{
            const _c=s.counts||{}; const _v=s.vulns||[];
            const topS=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(sv=>_c[sv])||'NONE';
            const pills=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>_c[sv])
              .map(sv=>`<span class="sev sm ${sv}">${_c[sv]} ${sv}</span>`).join(' ');
            return`<tr class="row" onclick="navTo('img-detail',{scan:imgScans[${i}]})">
              <td><div class="row-main">
                <span class="row-icon lg">${brandIcon('docker')}</span>
                <div class="row-name">${esc(s.image)}</div>
              </div></td>
              <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
              <td><span class="row-ver">${esc(s.tag)}</span></td>
              <td><span class="sev ${topS}">${topS}</span></td>
              <td>${_v.length===0
                ?`<span class="row-clean">${icon('check')} clean</span>`
                :(pills||`<span class="row-count">${_v.length}</span>`)}</td>
              <td class="row-date">${fmtDate(s.scannedAt)}</td>
              <td><button class="row-del" onclick="event.stopPropagation();imgScans.splice(${i},1);saveImg();renderImgList()">${icon('x')}</button></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>${pg.html}`;
}

function renderImgDetail(s){
  const el=document.getElementById('imgDetailContent');
  const chips=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>s.counts[sv])
    .map(sv=>`<span class="sev ${sv}">${s.counts[sv]} ${sv}</span>`).join('');

  const SEV_W = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  const groups = new Map();
  for(const v of (s.vulns||[])){
    const pkg = v.PkgName||'unknown';
    if(!groups.has(pkg)) groups.set(pkg, {vulns:[], topW:0, counts:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0}});
    const g = groups.get(pkg);
    g.vulns.push(v);
    const sev = (v.Severity||'UNKNOWN').toUpperCase();
    if(sev in g.counts) g.counts[sev]++;
    g.topW = Math.max(g.topW, SEV_W[sev]||0);
  }

  const sorted = [...groups.entries()].sort((a,b)=>{
    if(b[1].topW !== a[1].topW) return b[1].topW - a[1].topW;
    return b[1].vulns.length - a[1].vulns.length;
  });

  for(const [,g] of sorted)
    g.vulns.sort((a,b)=>(SEV_W[(b.Severity||'UNKNOWN').toUpperCase()]||0) - (SEV_W[(a.Severity||'UNKNOWN').toUpperCase()]||0));

  const rerender = () => keepOpenGroups(el, () => renderImgDetail(s));
  const groupPage = paginate('img-groups', sorted, rerender, s);
  let globalVi = 0;
  const groupHtml = groupPage.rows.map(([[pkgName, g]])=>{
    const topSev = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s=>g.counts[s])||'UNKNOWN';
    const pills = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(sv=>g.counts[sv])
      .map(sv=>`<span class="sev xs ${sv}">${g.counts[sv]}</span>`).join('');
    const pkgVer = g.vulns[0]?.InstalledVersion ? `<span class="pkg-group-ver">v${esc(g.vulns[0].InstalledVersion)}</span>` : '';
    const fixedVer= g.vulns.find(v=>v.FixedVersion)?.FixedVersion;
    const fixTag  = fixedVer ? `<span class="fix-tag">${icon('arrow-right')} ${esc(fixedVer)}</span>` : '';
    const _pt = (g.vulns[0]?._pkgType||'').toLowerCase();
    const debTag = OS_PKG_TYPES.has(_pt) ? `<span class="pkg-type-tag">${_pt==='debian'||_pt==='ubuntu'?'deb':esc(_pt)}</span>` : '';

    const cardPage = paginate('img-cards:'+pkgName, g.vulns, rerender, s);
    const cardsHtml = cardPage.rows.map(([v])=>{
      const vi = globalVi++;
      return imgVulnCardHtml(v, vi);
    }).join('') + cardPage.html;

    return `<div class="pkg-group" data-group="${esc(pkgName)}">
      <div class="pkg-group-hdr" onclick="togglePkgGroup(this)">
        <div class="vbar ${topSev}"></div>
        <div class="pkg-group-title">
          <span class="pkg-group-name">${esc(pkgName)}</span>${debTag}
          ${pkgVer}${fixTag}
        </div>
        <div class="pkg-group-stats">
          ${pills}
          <span class="pkg-group-count">${g.vulns.length} CVE${g.vulns.length>1?'s':''}</span>
          <span class="pkg-chev">${icon('chevron-down')}</span>
        </div>
      </div>
      <div class="pkg-group-body">
        ${cardsHtml}
      </div>
    </div>`;
  }).join('');

  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon blue">${brandIcon('docker')}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(s.image)}:${esc(s.tag)}</div>
        <div class="detail-sub">${s.vulns.length} vulnerabilit${s.vulns.length===1?'y':'ies'} across ${sorted.length} package${sorted.length!==1?'s':''}${s.desc?' · '+esc(s.desc):''}  ·  scanned ${fmtDate(s.scannedAt)}</div>
      </div>
      <div class="detail-chips stacked">
        <div class="chip-row">
          ${chips||`<span class="sev NONE">${icon('check')} CLEAN</span>`}
        </div>
        ${exportBtnHtml('img', {image:s.image,tag:s.tag||'latest',desc:s.desc||''})}
      </div>
    </div>
    ${s.vulns.length===0
      ?`<div class="detail-empty">${brandIcon('docker')} No vulnerabilities found — this image is clean!</div>`
      :groupHtml + groupPage.html}`;

  el.querySelector('.pkg-group')?.classList.add('open');

  if(s.vulns.length){
    s.vulns.forEach(v=>{
      if(!v.id) v.id = v.VulnerabilityID || '';
      if(!v.aliases) v.aliases = [v.VulnerabilityID].filter(Boolean);
      if(!v.cvss && v.CVSS){
        const nvd = v.CVSS.nvd || v.CVSS.NVD || Object.values(v.CVSS)[0] || {};
        const cvss = {};
        if(nvd.V3Score != null) cvss.cvss3 = { score: nvd.V3Score, vector: nvd.V3Vector || '', version: '3' };
        if(nvd.V2Score != null) cvss.cvss2 = { score: nvd.V2Score, vector: nvd.V2Vector || '' };
        if(cvss.cvss3 || cvss.cvss2) v.cvss = cvss;
      }
    });
    renderStoredEnrichment(s.vulns, 'img');
  }
}

function imgVulnCardHtml(v,vi){
  const sev=(v.Severity||'UNKNOWN').toUpperCase();
  const cveId=v.VulnerabilityID||'';
  const title=v.Title||v.Description||'No description';
  return`<div class="vi" id="ivi-${vi}">
    <div class="vi-hdr" onclick="toggleIVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">
        ${cveId.startsWith('CVE-')?`<a class="vi-cve" href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()">${esc(cveId)} ${icon('external-link')}</a>`:`<span class="vi-alt-id">${esc(cveId)}</span>`}
        <span class="vi-cvss-inline" id="cvss-hdr-img-${cveId}"></span>
      </div>
      <div class="vi-sum">${esc(title.length>80?title.slice(0,80)+'…':title)}</div>
      <span class="enrich-badges" id="eb-img-${cveId}"></span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">${icon('chevron-down')}</span>
    </div>
    <div class="vi-body" id="ivib-${vi}">
      <div class="vgrid">
        <span class="vk">CVE ID</span><span class="vv"><a href="https://avd.aquasec.com/nvd/${esc(cveId.toLowerCase())}" target="_blank">${esc(cveId)} ${icon('external-link')}</a></span>
        <span class="vk">Package</span><span class="vv strong">${esc(v.PkgName||'—')}</span>
        <span class="vk">Installed</span><span class="vv dim">${esc(v.InstalledVersion||'—')}</span>
        ${v.FixedVersion?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">${icon('arrow-right')} ${esc(v.FixedVersion)}</span></span>`:''}
        ${v.Title?`<span class="vk">Title</span><span class="vv">${esc(v.Title)}</span>`:''}
        ${v.Description?`<span class="vk">Description</span><span class="vv prose" id="idesc-${vi}">${esc(v.Description.slice(0,480))}${v.Description.length>480?`<span id="idesc-dots-${vi}"> <button class="more-link" data-full="${esc(v.Description)}" onclick="expandIDesc(${vi},this)">… show more</button></span>`:''}</span>`:''}
        ${v.PublishedDate?`<span class="vk">Published</span><span class="vv">${new Date(v.PublishedDate).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${v.PrimaryURL?`<span class="vk">Reference</span><span class="vv"><a href="${esc(safeUrl(v.PrimaryURL))}" target="_blank" rel="noopener noreferrer">${esc(v.PrimaryURL.length>60?v.PrimaryURL.slice(0,60)+'…':v.PrimaryURL)}</a></span>`:''}
        <span class="vk">CVSS</span><span class="vv" id="cvss-img-${cveId}"><span class="text-note">loading…</span></span>
        <span class="vk">NVD Score</span><span class="vv" id="nvd-img-${cveId}"><span class="text-note">loading…</span></span>
        <span class="vk">EPSS</span><span class="vv" id="epss-img-${cveId}"><span class="text-note">loading…</span></span>
        <span class="vk">CISA KEV</span><span class="vv" id="kev-img-${cveId}"><span class="text-note">loading…</span></span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="poc-img-${cveId}"><span class="text-note">loading…</span></span>
      </div>
    </div>
  </div>`;
}

function expandIDesc(vi,btn){
  const el=document.getElementById('idesc-'+vi);
  const dots=document.getElementById('idesc-dots-'+vi);
  if(!el||!dots) return;
  dots.remove(); el.textContent=btn.getAttribute('data-full');
}

function toggleIVI(vi){
  document.getElementById('ivi-'+vi)?.classList.toggle('open');
}
