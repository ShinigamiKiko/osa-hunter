
async function checkActivity(badgeId, pkgName, ecosystem){
  const el=document.getElementById(badgeId);
  if(!el) return;
  try{
    const r=await fetch('/api/activity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:pkgName,ecosystem})});
    const d=await readJson(r);
    if(!d.found||!d.lastCommit){ el.innerHTML='<span class="activity">Activity: unknown</span>'; return; }
    const date=new Date(d.lastCommit);
    const days=Math.floor((Date.now()-date)/86400000);
    const years=Math.floor(days/365);
    const age=days<1?'today':days<7?`${days}d ago`:days<60?`${Math.floor(days/7)}w ago`:years>=1?`${years}y ago`:`${Math.floor(days/30)}mo ago`;
    const stale=years>=2;
    const label=stale?'⚠ Possibly stale':'● Active';
    const link=d.repoUrl?` <a class="activity-link" href="${esc(safeUrl(d.repoUrl))}" target="_blank" rel="noopener">↗ repo</a>`:'';
    el.innerHTML=`<span class="activity ${stale?'stale':'active'}">${label} · last commit ${age}${link}</span>`;
  }catch{
    el.innerHTML='<span class="activity">Activity: error</span>';
  }
}
