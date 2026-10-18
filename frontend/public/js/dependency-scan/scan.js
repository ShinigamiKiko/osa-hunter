async function openLibFromDep(ev, systemId, name, version){
  try{
    if(ev) ev.stopPropagation();
    const map = {
      'NPM':      { ecoId:'npm',      osv:'npm',        label:'npm' },
      'PYPI':     { ecoId:'pypi',     osv:'PyPI',       label:'PyPI' },
      'GO':       { ecoId:'go',       osv:'Go',         label:'Go' },
      'CARGO':    { ecoId:'crates',   osv:'crates.io',  label:'Rust' },
      'MAVEN':    { ecoId:'maven',    osv:'Maven',      label:'Maven' },
      'NUGET':    { ecoId:'nuget',    osv:'NuGet',      label:'NuGet' },
      'RUBYGEMS': { ecoId:'rubygems', osv:'RubyGems',   label:'RubyGems' },
      'COMPOSER': { ecoId:'composer', osv:'Packagist',  label:'Composer' },
    };
    const eco = map[systemId] || map[(systemId||'').toUpperCase()];
    if(!eco) throw new Error('Unknown ecosystem for lib jump: '+systemId);
    const r = await fetch('/api/libscan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name, ecosystem: eco.osv, version: (version||'').trim() })
    });
    const data = await readJson(r);
    if(!r.ok) throw new Error(data?.error || 'libscan failed');
    const vulns = (data.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]}));
    const _ck = `lib:${eco.osv}:${data.package}:${data.version||'latest'}`;
    const existing = libScans.findIndex(s => s._cacheKey === _ck);
    if(existing !== -1) libScans.splice(existing, 1);
    libScans.unshift({
      id:Date.now(), pkg:data.package, ver:data.version||'',
      eco:eco.ecoId, ecoLabel:eco.label, desc:'',
      _cacheKey:_ck, vulns, toxic:data.toxic, topSev:data.topSeverity||'NONE', scannedAt:data.scannedAt,
    });
    if(libScans.length>SCAN_HISTORY_MAX) libScans=libScans.slice(0,SCAN_HISTORY_MAX);
    saveLib();
    updateLibBadge();
    navTo('lib-detail', { scan: libScans[0] });
  }catch(e){
    console.error(e);
    alert(e.message || 'Failed to open library');
  }
}

function renderDepEcos(){
  document.getElementById('depEcoGrid').innerHTML=DEP_SYSTEMS.map(e=>`
    <button class="eco-btn${selDepSys===e.id?' on':''}" onclick="pickDepSys('${e.id}')">
      <div class="eco-logo">${brandIcon(e.id)}</div><div class="eco-name">${e.label}</div>
    </button>`).join('');
}
function pickDepSys(id){ selDepSys=id; renderDepEcos(); }

function openDepModal(){
  selDepSys=null;
  ['dDesc','dPkg','dVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('dmerr').hidden=true;
  setBtn('btnDepGo',false,'Scan');
  renderDepEcos();
  document.getElementById('depModal').hidden=false;
  setTimeout(()=>document.getElementById('dPkg').focus(),160);
}
function closeDepModal(){ document.getElementById('depModal').hidden=true; }


function markDependencyCompleteness(scan) {
  if (scan.system !== 'COMPOSER' && scan.complete !== true && Number(scan.summary?.totalDeps) >= 500)
    scan.complete = false;
  return scan;
}

function normalizeComposerScan(data) {
    if (data.deps && !Array.isArray(data.deps)) {
      const normDeps=(list,relation)=>(list||[]).map(d=>{
        const epssMap = d.epss||{};
        const cvssMap = d.cvss||{};
        const pocsMap = d.pocs||{};
        const kevSet  = new Set(d.kev||[]);

        const vulns=(d.vulns||[]).map(v=>{
          const cveId=[...(v.aliases||[]),v.id].find(x=>x&&x.startsWith('CVE-'))||null;
          return {
            ...v,
            fix     : v.fixed||v.fix||null,
            severity: v.severity||'UNKNOWN',
            aliases : v.aliases||[],
            refs    : v.refs||[],
            epss    : cveId ? (epssMap[cveId]||null) : null,
            cvss    : cveId ? (cvssMap[cveId]||null) : null,
            pocs    : cveId ? (pocsMap[cveId]||[])   : [],
            inKev   : cveId ? kevSet.has(cveId)       : false,
          };
        });
        const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
        vulns.forEach(v=>{const s=(v.severity||'UNKNOWN').toUpperCase();if(s in cnt)cnt[s]++;});
        const topSev=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s=>cnt[s]>0)||'NONE';
        return{...d,relation,vulns,counts:cnt,topSeverity:topSev,system:data.system||'COMPOSER',toxic:d.toxic||{found:false}};
      });
      console.log('[dep-scan] raw deps from server:', {
        hasRoot: !!data.deps.root,
        directCount: (data.deps.direct||[]).length,
        transitiveCount: (data.deps.transitive||[]).length,
        transitiveNames: (data.deps.transitive||[]).map(d=>d.name).slice(0,5),
      });
      const rootNorm = data.deps.root ? normDeps([data.deps.root], 'ROOT') : [];
      data.deps=[
        ...rootNorm,
        ...normDeps(data.deps.direct,     'DIRECT'),
        ...normDeps(data.deps.transitive,  'INDIRECT'),
      ];
      console.log('[dep-scan] after normalize:', data.deps.map(d=>d.name+':'+d.relation));
      const sevTotals={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
      data.deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=(v.severity||'').toUpperCase();if(s in sevTotals)sevTotals[s]++;}));
      const toxicCount=data.deps.filter(d=>d.toxic?.found).length;
      const sm=data.summary||{};
      data.summary={
        ...sm,
        totalDeps : sm.total   ??sm.totalDeps  ??data.deps.length,
        directDeps: sm.direct  ??sm.directDeps ??data.deps.filter(d=>d.relation==='DIRECT').length,
        CRITICAL  : sevTotals.CRITICAL,
        HIGH      : sevTotals.HIGH,
        MEDIUM    : sevTotals.MEDIUM,
        LOW       : sevTotals.LOW,
        UNKNOWN   : sevTotals.UNKNOWN,
        toxic     : toxicCount,
        withVulns : data.deps.filter(d=>(d.vulns||[]).length>0).length,
        vulnerabilityCount: data.deps.reduce((total,d)=>(total+(d.vulns||[]).length),0),
      };
    }
  return data;
}

async function doDepScan(){
  const sys  = selDepSys;
  const pkg  = document.getElementById('dPkg').value.trim();
  const ver  = document.getElementById('dVer').value.trim();
  const desc = document.getElementById('dDesc').value.trim();
  document.getElementById('dmerr').hidden=true;
  if(!sys) return showErr('dmerr','Select a package system');
  if(!pkg) return showErr('dmerr','Enter a package name');
  if(depScanInFlight) return;
  depScanInFlight=true;
  setBtn('btnDepGo',true,'Scanning…');
  try{
    const ep = (sys==='COMPOSER') ? '/api/composerscan' : '/api/depscan';
    const payload = (sys==='COMPOSER')
      ? { name:pkg, version:ver||undefined }
      : { name:pkg, system:sys, version:ver||undefined };
    const r=await fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await readJson(r);
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    if (sys === 'COMPOSER') normalizeComposerScan(data);
    const _ck = `dep:${(data.system||'').toUpperCase()}:${data.package||''}:${data.resolvedVersion||data.version||'latest'}`;
    const ckIdx = depScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) depScans.splice(ckIdx, 1);
    const scan={...data,desc,id:Date.now(),_cacheKey:_ck};
    depScans.unshift(scan);
    if(depScans.length>SCAN_HISTORY_MAX) depScans=depScans.slice(0,SCAN_HISTORY_MAX);
    saveDep(); closeDepModal(); updateDepBadge();
    navTo('dep-detail',{scan});
  }catch(e){ showErr('dmerr',e.message||'Scan failed'); }
  finally {
    depScanInFlight=false;
    setBtn('btnDepGo',false,'Scan');
  }
}

document.addEventListener('keydown',e=>{
  if(e.key==='Enter' &&!document.getElementById('depModal').hidden) doDepScan();
});
