async function openLibFromDep(ev, systemId, name, version){
  try{
    if(ev) ev.stopPropagation();
    const map = {
      'NPM':      { ecoId:'npm',      osv:'npm',        label:'npm',       logo:'📦' },
      'PYPI':     { ecoId:'pypi',     osv:'PyPI',       label:'PyPI',      logo:'🐍' },
      'GO':       { ecoId:'go',       osv:'Go',         label:'Go',        logo:'🐹' },
      'CARGO':    { ecoId:'crates',   osv:'crates.io',  label:'Rust',      logo:'🦀' },
      'MAVEN':    { ecoId:'maven',    osv:'Maven',      label:'Maven',     logo:'☕' },
      'NUGET':    { ecoId:'nuget',    osv:'NuGet',      label:'NuGet',     logo:'💠' },
      'RUBYGEMS': { ecoId:'rubygems', osv:'RubyGems',   label:'RubyGems',  logo:'💎' },
      'COMPOSER': { ecoId:'composer', osv:'Packagist',  label:'Composer',  logo:'🐘' },
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
      eco:eco.ecoId, ecoLabel:eco.label, ecoLogo:eco.logo, desc:'',
      _cacheKey:_ck, vulns, toxic:data.toxic, topSev:data.topSeverity||'NONE', scannedAt:data.scannedAt,
    });
    if(libScans.length>50) libScans=libScans.slice(0,50);
    saveLib();
    updateLibBadge();
    navTo('lib-detail', { scan: libScans[0] });
  }catch(e){
    console.error(e);
    alert(e.message || 'Failed to open library');
  }
}
