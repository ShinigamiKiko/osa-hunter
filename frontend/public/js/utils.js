const SEV_ORD = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function safeUrl(u){ try{ const p=new URL(u); return['http:','https:'].includes(p.protocol)?u:'#'; }catch{ return '#'; } }
function fmtDate(iso){ if(!iso)return'—'; const d=new Date(iso); return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); }
function showErr(id,msg){ const e=document.getElementById(id); if(e){ e.textContent=msg; e.style.display='block'; } }
function setBtn(id,loading,label){ const b=document.getElementById(id); if(!b)return; b.disabled=loading; if(label)b.textContent=loading?'⏳ Scanning…':label; }
function safeLoad(key,def){ try{ const v=localStorage.getItem(key); return v?JSON.parse(v):def; }catch{ return def; } }
function safeSave(key,val){ try{ localStorage.setItem(key,JSON.stringify(val)); }catch{} }

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
    return `<span style="display:inline-flex;align-items:center;gap:5px;font-size:10px;background:rgba(52,199,89,.1);color:#34c759;border:1px solid rgba(52,199,89,.3);padding:2px 9px;border-radius:12px">✅ Not in toxic-repos</span>`;
  const LABELS={ddos:'DDoS tool',hostile_actions:'Hostile actions',political_slogan:'Political slogan',malware:'Malware',ip_blocking:'IP blocking'};
  const label=LABELS[toxic.problem_type]||toxic.problem_type||'Toxic';
  const full=toxic.description||'';
  const preview=full.length>60?full.slice(0,60):full;
  const more=full.length>60
    ?`<button onclick="this.parentElement.querySelector('.toxic-full').style.display='inline';this.remove()" style="background:none;border:none;color:inherit;opacity:.75;cursor:pointer;font-size:10px;padding:0;text-decoration:underline;margin-left:2px">…</button><span class="toxic-full" style="display:none">${esc(full.slice(60))}</span>`:'';
  return `<span style="display:inline-flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:10px;background:rgba(255,59,48,.12);color:#ff3b30;border:1px solid rgba(255,59,48,.35);padding:3px 10px;border-radius:12px">☠ <strong>Toxic: ${esc(label)}</strong>${full?' — '+esc(preview)+more:''}</span>`;
}
