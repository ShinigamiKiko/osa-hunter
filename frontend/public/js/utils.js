const SEV_ORD = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];

function findingCounts(vulns) {
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  for (const v of vulns) {
    const severity = String(v.Severity || v._sev || v.severity || 'UNKNOWN').toUpperCase();
    counts[Object.hasOwn(counts, severity) ? severity : 'UNKNOWN']++;
  }
  return counts;
}

function esc(s){ return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function safeUrl(u){ try{ const p=new URL(u); return['http:','https:'].includes(p.protocol)?u:'#'; }catch{ return '#'; } }
function fmtDate(iso){ if(!iso)return'—'; const d=new Date(iso); return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); }
function showErr(id,msg){ const e=document.getElementById(id); if(e){ e.textContent=msg; e.hidden=false; } }
function setBtn(id, loading, label) {
  const button = document.getElementById(id);
  if (!button) return;
  button.disabled = loading;
  button.setAttribute('aria-busy', String(loading));
  const caption = loading ? 'Scanning…' : (label || 'Scan');
  button.innerHTML = icon(loading ? 'loader-circle' : 'play', loading ? 'spin' : '') + ' ' + esc(caption);
}
function safeLoad(key,def){ try{ const v=localStorage.getItem(key); return v?JSON.parse(v):def; }catch{ return def; } }
// Scan lists keep up to 150 entries. When the browser's storage quota is full,
// keep the newest entries that fit instead of silently saving nothing.
function safeSave(key,val){
  let list=val;
  for(;;){
    try{ localStorage.setItem(key,JSON.stringify(list)); return; }
    catch{ if(!Array.isArray(list)||list.length<=1) return; list=list.slice(0,Math.floor(list.length/2)); }
  }
}
const SCAN_HISTORY_MAX=150;
function pruneLocalScans(list){
  const cutoff=Date.now()-24*60*60*1000;
  return Array.isArray(list)?list.filter(s=>{
    const ts=Date.parse(s?.scannedAt||s?._cachedAt||'');
    return !Number.isFinite(ts)||ts>=cutoff;
  }):[];
}

// Collapsible blocks: the clicked header opens or closes its container.
function togglePkgGroup(hdr){ hdr.closest('.pkg-group')?.classList.toggle('open'); }
function toggleCard(hdr){ hdr.closest('.vi')?.classList.toggle('open'); }
function toggleFinding(hdr){ hdr.closest('.finding')?.classList.toggle('open'); }
// "… show more": the button carries the full text of the cell it sits in.
function showFullText(btn){ btn.parentElement.textContent=btn.dataset.full; }

// Parse a fetch() response as JSON, but fail with a readable message when the
// body isn't JSON — e.g. nginx returns an HTML error page (504/502/413) when a
// scan exceeds the proxy timeout or the payload is too large. Without this the
// caller's `await r.json()` throws "Unexpected token '<'".
async function readJson(r){
  const ct=(r.headers.get('content-type')||'').toLowerCase();
  if(ct.includes('application/json')) return r.json();
  const map={504:'Request timed out — the scan took too long. Try again.',
             502:'Backend is unavailable. Please try again shortly.',
             503:'Backend is unavailable. Please try again shortly.',
             413:'Request too large for the server to accept.'};
  throw new Error(map[r.status]||`Unexpected server response (HTTP ${r.status})`);
}

function _toxicBadgeHtml(toxic){
  if(!toxic?.found)
    return `<span class="toxic-badge clean">${icon('check')} Not in toxic-repos</span>`;
  const LABELS={ddos:'DDoS tool',hostile_actions:'Hostile actions',political_slogan:'Political slogan',malware:'Malware',ip_blocking:'IP blocking'};
  const label=LABELS[toxic.problem_type]||toxic.problem_type||'Toxic';
  const full=toxic.description||'';
  const preview=full.length>60?full.slice(0,60):full;
  const more=full.length>60
    ?`<button class="toxic-more" onclick="this.parentElement.classList.add('expanded');this.remove()">…</button><span class="toxic-full">${esc(full.slice(60))}</span>`:'';
  return `<span class="toxic-badge found">${icon('skull')} <strong>Toxic: ${esc(label)}</strong>${full?' — '+esc(preview)+more:''}</span>`;
}

// Pagination
// Every long list shows 50, 100 or 150 rows at a time. The chosen size is kept
// per list; the page resets when the list's owner (e.g. the open scan) changes.
const PAGE_SIZES=[50,100,150];
const _pagers=new Map();

function pageState(key,owner){
  let st=_pagers.get(key);
  if(!st){
    let size=PAGE_SIZES[0];
    try{ const saved=Number(localStorage.getItem('osa.pageSize.'+key)); if(PAGE_SIZES.includes(saved)) size=saved; }catch{}
    st={page:1,size,owner,rerender:null};
    _pagers.set(key,st);
  }
  if(owner!==undefined&&st.owner!==owner){ st.owner=owner; st.page=1; }
  return st;
}

// Show the page that holds row `index` (e.g. a rule opened from Proxy activity).
function pageReveal(key,index){
  const st=pageState(key);
  if(index>=0) st.page=Math.floor(index/st.size)+1;
}

// The visible slice as [item, absoluteIndex] pairs, so row handlers keep
// addressing the full list, plus the pager markup for below the list.
function paginate(key,items,rerender,owner){
  const st=pageState(key,owner);
  st.rerender=rerender;
  const total=items.length;
  const pages=Math.max(1,Math.ceil(total/st.size));
  st.page=Math.min(Math.max(1,st.page),pages);
  const from=(st.page-1)*st.size;
  const rows=items.slice(from,from+st.size).map((item,i)=>[item,from+i]);
  return {rows,html:pagerHtml(key,{page:st.page,pages,total,size:st.size})};
}

function pagerHtml(key,{page,pages,total,size}){
  // Everything fits at the smallest size: no controls to read past.
  if(total<=PAGE_SIZES[0]) return '';
  const from=(page-1)*size+1, to=Math.min(page*size,total);
  const btn=(n,label,{current=false,disabled=false,aria=''}={})=>
    `<button type="button" class="pager-btn${current?' current':''}" data-pager-page="${n}"${disabled?' disabled':''}${current?' aria-current="page"':''}${aria?` aria-label="${aria}"`:''}>${label}</button>`;
  const nums=[];
  const lo=Math.max(1,page-2), hi=Math.min(pages,page+2);
  if(lo>1){ nums.push(btn(1,'1')); if(lo>2) nums.push('<span class="pager-gap" aria-hidden="true">…</span>'); }
  for(let i=lo;i<=hi;i++) nums.push(btn(i,String(i),{current:i===page,aria:`Page ${i}`}));
  if(hi<pages){ if(hi<pages-1) nums.push('<span class="pager-gap" aria-hidden="true">…</span>'); nums.push(btn(pages,String(pages),{aria:`Page ${pages}`})); }
  return `<nav class="pager" data-pager="${esc(key)}" aria-label="Pages">
    <label class="pager-size">Rows
      <select data-pager-size>${PAGE_SIZES.map(n=>`<option value="${n}"${n===size?' selected':''}>${n}</option>`).join('')}</select>
    </label>
    <span class="pager-range">${from}–${to} of ${total}</span>
    ${pages>1?`<div class="pager-pages">${btn(page-1,'‹',{disabled:page<=1,aria:'Previous page'})}${nums.join('')}${btn(page+1,'›',{disabled:page>=pages,aria:'Next page'})}</div>`:''}
  </nav>`;
}

function _pagerRerender(key){
  const st=_pagers.get(key);
  if(!st?.rerender) return;
  st.rerender();
  // Land on the first row of the new page, not on the pager at the bottom.
  const nav=document.querySelector(`[data-pager="${CSS.escape(key)}"]`);
  const top=nav?.parentElement;
  if(top&&top.getBoundingClientRect().top<0) top.scrollIntoView({block:'start'});
}

// Paging a grouped detail view re-renders it; keep the groups the reader
// opened open instead of folding everything back to the first group.
function keepOpenGroups(container,render){
  const open=new Set(container?[...container.querySelectorAll('.pkg-group.open[data-group]')]
    .map(g=>g.dataset.group):[]);
  render();
  if(!container) return;
  container.querySelectorAll('.pkg-group[data-group]').forEach(g=>{
    if(open.has(g.dataset.group)) g.classList.add('open');
  });
}

document.addEventListener('click',event=>{
  const button=event.target.closest?.('[data-pager-page]');
  const nav=button?.closest('[data-pager]');
  if(!nav||button.disabled) return;
  event.stopPropagation();
  pageState(nav.dataset.pager).page=Number(button.dataset.pagerPage);
  _pagerRerender(nav.dataset.pager);
});
document.addEventListener('change',event=>{
  const select=event.target.closest?.('[data-pager-size]');
  const nav=select?.closest('[data-pager]');
  if(!nav) return;
  const key=nav.dataset.pager, st=pageState(key);
  const first=(st.page-1)*st.size;
  st.size=Number(select.value);
  st.page=Math.floor(first/st.size)+1;  // keep the first visible row on screen
  try{ localStorage.setItem('osa.pageSize.'+key,String(st.size)); }catch{}
  _pagerRerender(key);
});
