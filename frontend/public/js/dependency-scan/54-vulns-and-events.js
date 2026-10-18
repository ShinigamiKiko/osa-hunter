
function toggleDPVI(vi){
  document.getElementById('dpvi-'+vi)?.classList.toggle('open');
}

function enrichDepPkgVulns(vulns){
  vulns.forEach((v,vi)=>{
    const cvssEl=document.getElementById('dpvcvssv-'+vi);
    if(cvssEl) cvssEl.innerHTML=cvssHtml(v.cvss);
    const cvssHdrEl=document.getElementById('dpvcvss-'+vi);
    if(cvssHdrEl&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score;
      cvssHdrEl.innerHTML=`<span class="sev xs ${cvssClass(s)}">${s}</span>`;
    }
    const epssEl=document.getElementById('dpvepss-'+vi);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);
    const kevEl=document.getElementById('dpvkev-'+vi);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);
    const pocEl=document.getElementById('dpvpoc-'+vi);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
    const eb=document.getElementById('dpveb-'+vi);
    if(eb){
      let hb='';
      if(v.inKev)    hb+='<span class="mark kev" title="CISA Known Exploited">&#128293; KEV</span>';
      if(v.pocs?.length) hb+=`<span class="mark poc" title="${v.pocs.length} PoC(s)">&#128165; PoC&#215;${v.pocs.length}</span>`;
      eb.innerHTML=hb;
    }
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Enter' &&!document.getElementById('depModal').hidden) doDepScan();
});
