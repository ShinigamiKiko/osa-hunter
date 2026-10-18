
const NOT_IN_NVD='<span class="text-note">not in NVD</span>';
const cvssClass=s=>s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';

function cvssHtml(entry){
  if(!entry||(!entry.cvss3&&!entry.cvss2)) return NOT_IN_NVD;
  let out='';
  if(entry.cvss3){
    const s=entry.cvss3.score,cls=cvssClass(s);
    out+=`<span class="sev md cvss-score ${cls}">${s} ${esc(entry.cvss3.severity||cls)}</span><span class="text-meta cvss-version">CVSSv${esc(entry.cvss3.version||3)}</span>`;
  }
  if(entry.cvss2){
    const s=entry.cvss2.score,cls=s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
    out+=`<span class="sev md cvss-score v2 ${cls}">${s}</span><span class="text-meta">CVSSv2</span>`;
  }
  return out;
}

function epssHtml(score){
  if(!score) return '<span class="text-note">not found</span>';
  const pct=(score.epss*100).toFixed(2);
  const cls=score.epss>=.1?'hi':score.epss>=.01?'mi':'';
  return `<div class="epss-row">
    <span class="epss-pct ${cls}">${pct}%</span>
    <div class="epss-bar"><div class="epss-fill ${cls}" style="width:${Math.min(score.epss*500,100)}%"></div></div>
    <span class="text-meta">${(score.percentile*100).toFixed(0)}th pct</span>
  </div>`;
}

function kevBadge(found){
  if(found) return `<span class="flag bad">${icon('flame')} Found in CISA KEV — actively exploited</span>`;
  return `<span class="flag good">${icon('check')} Not in CISA KEV</span>`;
}

function pocBadge(pocs){
  if(!pocs||!pocs.length) return `<span class="flag good">${icon('check')} No public PoC found</span>`;
  return pocs.map(p=>
    `<a class="poc-link" href="${esc(safeUrl(p.url))}" target="_blank" rel="noopener noreferrer">${icon('bug')} ${esc(p.name)} ${icon('star')}${Number(p.stars)||0}</a>`
  ).join('');
}

function renderStoredEnrichment(vulns, scope){
  for(const v of vulns){
    const cveId=[...(v._aliases||v.aliases||[]),(v._sev?v.id:v.cve)||v.id].find(x=>x?.startsWith('CVE-'))||v.cve||v.id;

    const cvssHdr=document.getElementById(`cvss-hdr-${scope}-${cveId}`);
    if(cvssHdr&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score;
      cvssHdr.innerHTML=`<span class="sev xs ${cvssClass(s)}">${s}</span>`;
    }

    const eb=document.getElementById(`eb-${scope}-${cveId}`);
    if(eb){
      let h='';
      if(v.inKev) h+=`<span class="mark kev" title="CISA Known Exploited">${icon('flame')} KEV</span>`;
      if((v.pocs||[]).length) h+=`<span class="mark poc" title="${v.pocs.length} PoC(s)">${icon('bug')} PoC×${v.pocs.length}</span>`;
      eb.innerHTML=h;
    }

    const cvssEl=document.getElementById(`cvss-${scope}-${cveId}`);
    if(cvssEl) cvssEl.innerHTML=cvssHtml(v.cvss);

    const nvdEl=document.getElementById(`nvd-${scope}-${cveId}`);
    if(nvdEl){
      if(v.cvss?.cvss3){
        const s=v.cvss.cvss3.score;
        nvdEl.innerHTML=`<span class="sev nvd-score ${cvssClass(s)}">${s}</span><span class="text-meta nvd-vector">${esc(v.cvss.cvss3.vector||'')}</span>`;
      } else {
        nvdEl.innerHTML=NOT_IN_NVD;
      }
    }

    const epssEl=document.getElementById(`epss-${scope}-${cveId}`);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);

    const kevEl=document.getElementById(`kev-${scope}-${cveId}`);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);

    const pocEl=document.getElementById(`poc-${scope}-${cveId}`);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
  }
}
