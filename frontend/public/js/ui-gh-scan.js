
let ghScans = safeLoad('es_gh', []);
const saveGh = () => safeSave('es_gh', ghScans);

function updateGhBadge(){
  const b = document.getElementById('ghBadge');
  if(!b) return;
  if(ghScans.length){ b.hidden=false; b.textContent=ghScans.length; }
  else b.hidden=true;
}

async function doGhScan(){
  const url  = document.getElementById('ghUrl').value.trim();
  const desc = document.getElementById('ghDesc').value.trim();
  document.getElementById('ghErr').hidden=true;

  if(!url) return showErr('ghErr','Enter a GitHub repository URL');
  if(!/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(url))
    return showErr('ghErr','Only public GitHub repositories are supported (https://github.com/owner/repo)');

  setBtn('btnGhScan', true);
  try {
    const r = await fetch('/api/ghscan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ url, desc }),
    });
    const data = await readJson(r);
    if(!r.ok) throw new Error(data.error || `Error ${r.status}`);

    const _repo = data.repo || url.replace('https://github.com/','');
    const _ck = `sast:${_repo}`;
    const ckIdx = ghScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) ghScans.splice(ckIdx, 1);
    ghScans.unshift({
      id: Date.now(), _cacheKey: _ck,
      url, desc,
      repo:      _repo,
      findings:  data.findings  || [],
      counts:    data.counts    || {},
      topSev:    data.topSev    || 'NONE',
      toxic:     data.toxic     || { found: false },
      complete:  data.complete === true,
      errors:    Number(data.errors) || 0,
      errorSamples: Array.isArray(data.errorSamples) ? data.errorSamples : [],
      scannedAt: data.scannedAt || new Date().toISOString(),
    });
    if(ghScans.length > SCAN_HISTORY_MAX) ghScans = ghScans.slice(0,SCAN_HISTORY_MAX);
    saveGh(); updateGhBadge(); navTo('gh-list');
  } catch(e) { showErr('ghErr', e.message || 'Scan failed'); }
  setBtn('btnGhScan', false, 'Scan Repository');
}

async function renderGhList(){
  updateGhBadge();
  const el = document.getElementById('ghListContent');
  if(!ghScans.length){
    el.innerHTML='<div class="empty">'+_emptyRadar()+
      '<h2>No GitHub scans yet</h2>'+
      '<p>Paste a public GitHub repository URL to scan for security vulnerabilities with Semgrep</p>'+
      '<button class="btn-primary purple" onclick="navTo(\'gh-form\')">+ New scan</button>'+
      '</div>';
    _initEmptyRadar(); return;
  }
  var pg = paginate('gh-list', ghScans, renderGhList);
  var rows = pg.rows.map(function(pair){
    var s = pair[0], i = pair[1];
    var counts = s.counts||{};
    var pills = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(function(sv){return counts[sv];})
      .map(function(sv){return '<span class="sev sm '+sv+'">'+counts[sv]+' '+sv+'</span>';}).join(' ');
    var total = (s.findings||[]).length;
    return '<tr class="row" onclick="navTo(\'gh-detail\',{scan:ghScans['+i+']})">' +
      '<td><div class="row-main"><span class="row-icon sm">'+icon('file-search')+'</span><div>' +
      '<div class="row-name">'+esc(s.repo)+'</div>' +
      '<div class="row-sub">'+esc(s.url)+'</div>' +
      '<div class="row-flag">'+_toxicBadgeHtml(s.toxic)+'</div>' +
      '</div></div></td>' +
      '<td><div class="row-desc">'+esc(s.desc||'—')+'</div></td>' +
      '<td><span class="sev '+(s.complete === true ? esc(s.topSev) : 'UNKNOWN')+'">'+(s.complete === true ? esc(s.topSev) : 'RESCAN')+'</span></td>' +
      '<td>'+(total===0 ? (s.complete === true ? '<span class="row-clean">'+icon('check')+' clean</span>' : '<span class="text-note">Not verified</span>') : (pills||'<span class="row-count">'+total+'</span>'))+'</td>' +
      '<td class="row-date">'+fmtDate(s.scannedAt)+'</td>' +
      '<td><button class="row-del" onclick="event.stopPropagation();ghScans.splice('+i+',1);saveGh();updateGhBadge();renderGhList()">'+icon('x')+'</button></td>' +
      '</tr>';
  }).join('');
  el.innerHTML =
    '<div class="list-toolbar">' +
    '<button class="btn-secondary" onclick="navTo(\'gh-form\')">+ New scan</button>' +
    '<button class="btn-secondary" onclick="if(confirm(\'Clear all GitHub scans?\')){ghScans=[];saveGh();updateGhBadge();renderGhList()}">Clear all</button></div>' +
    '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
    '<th>Repository</th><th>Description</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th class="col-del"></th>' +
    '</tr></thead><tbody>'+rows+'</tbody></table></div>'+pg.html;
}

function parseCweId(cweArr) {
  var raw = (cweArr || [])[0] || '';
  var m = raw.match(/CWE-(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

function cweToLabel(cweArr) {
  var id = parseCweId(cweArr);
  if (!id) return null;
  var map = {
    89:   { label: 'SQL Injection' },
    79:   { label: 'XSS' },
    78:   { label: 'Command Injection' },
    94:   { label: 'Code Injection' },
    95:   { label: 'Eval Injection' },
    22:   { label: 'Path Traversal' },
    73:   { label: 'Path Traversal' },
    798:  { label: 'Hardcoded Secret' },
    259:  { label: 'Hardcoded Secret' },
    321:  { label: 'Hardcoded Secret' },
    918:  { label: 'SSRF' },
    611:  { label: 'XXE' },
    502:  { label: 'Insecure Deserialization' },
    601:  { label: 'Open Redirect' },
    352:  { label: 'CSRF' },
    942:  { label: 'CORS Misconfiguration' },
    347:  { label: 'JWT Issue' },
    327:  { label: 'Weak Cryptography' },
    328:  { label: 'Weak Cryptography' },
    117:  { label: 'Log Injection' },
    1321: { label: 'Prototype Pollution' },
    338:  { label: 'Weak Randomness' },
    1004: { label: 'Insecure Cookie' },
    400:  { label: 'DoS / ReDoS' },
    200:  { label: 'Information Exposure' },
    209:  { label: 'Information Exposure' },
    116:  { label: 'Improper Encoding' },
    434:  { label: 'Unrestricted Upload' },
    285:  { label: 'Improper Authorization' },
    284:  { label: 'Improper Authorization' },
    306:  { label: 'Missing Authentication' },
    307:  { label: 'Brute Force' },
    287:  { label: 'Improper Authentication' },
    190:  { label: 'Integer Overflow' },
    476:  { label: 'Null Dereference' },
    416:  { label: 'Use After Free' },
    125:  { label: 'Out-of-bounds Read' },
    787:  { label: 'Out-of-bounds Write' }
  };
  return map[id] || { label: 'CWE-'+id };
}

function ruleIdToLabel(ruleId) {
  var r = (ruleId || '').toLowerCase();
  if (/sql.?inject|sqli/.test(r))                                       return { label: 'SQL Injection' };
  if (/xss|cross.site.script|html.inject/.test(r))                      return { label: 'XSS' };
  if (/command.inject|cmd.inject|shell.inject/.test(r))                 return { label: 'Command Injection' };
  if (/eval|exec.inject|rce/.test(r))                                   return { label: 'Code Injection' };
  if (/path.travers|directory.travers|lfi|rfi/.test(r))                 return { label: 'Path Traversal' };
  if (/secret|hardcode|api.key|token|password|credential|private.key/.test(r)) return { label: 'Hardcoded Secret' };
  if (/ssrf|server.side.request/.test(r))                               return { label: 'SSRF' };
  if (/xxe|xml.inject|xml.external/.test(r))                            return { label: 'XXE' };
  if (/deserializ|unsafe.deserial/.test(r))                             return { label: 'Insecure Deserialization' };
  if (/open.redirect/.test(r))                                          return { label: 'Open Redirect' };
  if (/csrf|cross.site.request/.test(r))                                return { label: 'CSRF' };
  if (/\bcors\b/.test(r))                                               return { label: 'CORS Misconfiguration' };
  if (/jwt|token.verif/.test(r))                                        return { label: 'JWT Issue' };
  if (/crypto|weak.hash|md5|sha1/.test(r))                              return { label: 'Weak Cryptography' };
  if (/prototype.pollu/.test(r))                                        return { label: 'Prototype Pollution' };
  if (/\bcookie\b/.test(r))                                             return { label: 'Insecure Cookie' };
  if (/\bdos\b|redos/.test(r))                                          return { label: 'DoS / ReDoS' };
  if (/debug|stack.trace|info.leak/.test(r))                            return { label: 'Information Exposure' };
  return { label: 'Security Issue' };
}

function ghVulnType(finding) {
  if (typeof finding === 'string') return ruleIdToLabel(finding);
  var fromCwe = cweToLabel(finding.cwe);
  return fromCwe || ruleIdToLabel(finding.ruleId);
}

function renderGhDetail(scan){
  var el = document.getElementById('ghDetailContent');
  var findings = scan.findings || [];
  var counts   = scan.counts   || {};
  var chips = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(function(sv){return counts[sv];})
    .map(function(sv){return '<span class="sev '+sv+'">'+counts[sv]+' '+sv+'</span>';}).join('');

  var SEV_W = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  var byGroup = new Map();
  findings.forEach(function(f){
    var vtype = ghVulnType(f);
    var cweId = parseCweId(f.cwe);
    var key = cweId ? 'cwe-'+cweId : vtype.label;
    if(!byGroup.has(key)) byGroup.set(key, { vtype: vtype, items: [] });
    byGroup.get(key).items.push(f);
  });

  var sortedGroups = Array.from(byGroup.values()).sort(function(a,b){
    var topA = Math.max.apply(null, a.items.map(function(f){return SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0;}));
    var topB = Math.max.apply(null, b.items.map(function(f){return SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0;}));
    return topB - topA;
  });

  var rerender = function(){ keepOpenGroups(el, function(){ renderGhDetail(scan); }); };
  var groupPage = paginate('gh-groups', sortedGroups, rerender, scan);
  var gvi = 0;
  var groupHtml = groupPage.rows.map(function(pair){
    var group = pair[0];
    var vtype = group.vtype;
    var items = group.items;
    items.sort(function(a,b){
      return (SEV_W[(b.severity||'UNKNOWN').toUpperCase()]||0)-(SEV_W[(a.severity||'UNKNOWN').toUpperCase()]||0);
    });
    var topSev = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(function(s){
      return items.some(function(f){return (f.severity||'').toUpperCase()===s;});
    })||'UNKNOWN';
    var sevCounts = {};
    items.forEach(function(f){var s=(f.severity||'UNKNOWN').toUpperCase();sevCounts[s]=(sevCounts[s]||0)+1;});
    var pills = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].filter(function(sv){return sevCounts[sv];})
      .map(function(sv){return '<span class="sev xs '+sv+'">'+sevCounts[sv]+'</span>';}).join('');

    var filePage = paginate('gh-files:'+vtype.label, items, rerender, scan);
    var fileRows = filePage.rows.map(function(filePair){
      var f = filePair[0];
      var vi = gvi++;
      var sev = (f.severity||'UNKNOWN').toUpperCase();
      var fname = f.path ? (f.path.length > 70 ? '…'+f.path.slice(-67) : f.path) : 'unknown';
      var lineStr = f.line ? ':'+f.line : '';
      return '<div class="finding" id="ghfi-'+vi+'">' +
        '<div class="finding-hdr" onclick="toggleGhVI('+vi+')">' +
        '<span class="vbar '+sev+'"></span>' +
        '<span class="finding-path">'+esc(fname)+'<span class="finding-line">'+esc(lineStr)+'</span></span>' +
        '<span class="sev xs '+sev+'">'+sev+'</span>' +
        (f.isBlocking?'<span class="finding-blocking">BLOCKING</span>':'') +
        '<span class="finding-chev">'+icon('chevron-right')+'</span>' +
        '</div>' +
        '<div class="finding-body">'+ghFindingBodyHtml(f)+'</div>' +
        '</div>';
    }).join('');

    return '<div class="pkg-group attached" data-group="'+esc(vtype.label)+'">' +
      '<div class="pkg-group-hdr" onclick="togglePkgGroup(this)">' +
      '<div class="vbar '+topSev+'"></div>' +
      '<span class="pkg-group-label">'+esc(vtype.label)+'</span>' +
      '<div class="pkg-group-stats">'+pills+
      '<span class="pkg-group-count">'+items.length+' finding'+(items.length>1?'s':'')+'</span>' +
      '<span class="pkg-chev">'+icon('chevron-down')+'</span>' +
      '</div></div>' +
      '<div class="pkg-group-body">'+fileRows+filePage.html+'</div>' +
      '</div>';
  }).join('');

  window._lastSastScan = scan;
  var fileCount = new Set(findings.map(function(f){return f.path;}).filter(Boolean)).size;
  el.innerHTML =
    '<div class="detail-header">' +
    '<div class="detail-icon purple"><img src="/assets/osa.png" alt=""/></div>' +
    '<div class="detail-info">' +
    '<div class="detail-name">'+esc(scan.repo)+'</div>' +
    '<div class="detail-sub"><a href="'+esc(safeUrl(scan.url))+'" target="_blank" rel="noopener">'+esc(scan.url)+' '+icon('external-link')+'</a>'+(scan.desc?' · '+esc(scan.desc):'')+' · '+findings.length+' finding'+(findings.length!==1?'s':'')+' in '+fileCount+' file'+(fileCount!==1?'s':'')+' · '+sortedGroups.length+' vuln type'+(sortedGroups.length!==1?'s':'')+' · scanned '+fmtDate(scan.scannedAt)+'</div>' +
    '<div class="detail-badges">'+_toxicBadgeHtml(scan.toxic)+'</div>' +
    '</div>' +
    '<div class="detail-chips">'+(chips||(scan.complete === true ? '<span class="sev NONE">'+icon('check')+' CLEAN</span>' : '<span class="sev UNKNOWN">RESCAN REQUIRED</span>'))+'</div>' +
    '<div class="detail-actions">'+exportBtnHtml('sast','__SAST_SCAN__')+'</div>' +
    '</div>' +
    _ghCompletenessHtml(scan) +
    (findings.length===0 ? (scan.complete === true ? '<div class="detail-empty">'+icon('check')+' No findings — this repository looks clean!</div>' : '') : groupHtml + groupPage.html);

  el.querySelector('.pkg-group')?.classList.add('open');
}

function ghFindingBodyHtml(f){
  var ruleId = f.ruleId || '';
  var msg    = f.message || 'No description';
  var cwe    = (f.cwe||[]).join(', ');
  var owasp  = (f.owasp||[]).join(', ');
  var refs   = f.references || [];
  var tech   = (f.technology||[]).join(', ');

  var codeHtml = '';
  if(f.codeSnippet){
    var startLine = f.snippetStart || f.line || 1;
    var lines = f.codeSnippet.split('\n');
    var gutterW = String(startLine + lines.length - 1).length;
    var rows = lines.map(function(l, i){
      var ln = String(startLine + i).padStart(gutterW, ' ');
      return '<span class="code-ln">'+esc(ln)+'</span>'+esc(l);
    }).join('\n');
    codeHtml = '<span class="vk">Code</span><span class="vv"><pre class="code-block">'+rows+'</pre></span>';
  }

  return '<div class="vgrid">' +
    '<span class="vk">Description</span><span class="vv prose">'+esc(msg)+'</span>' +
    codeHtml +
    (f.fix?'<span class="vk">Suggested Fix</span><span class="vv"><pre class="code-block fix">'+esc(f.fix)+'</pre></span>':'') +
    '<span class="vk">Rule</span><span class="vv code-id">'+esc(ruleId)+'</span>' +
    (f.language?'<span class="vk">Language</span><span class="vv note">'+esc(f.language)+'</span>':'') +
    (f.category?'<span class="vk">Category</span><span class="vv">'+esc(f.category)+'</span>':'') +
    (f.likelihood||f.impact||f.confidence?
      '<span class="vk">Risk Factors</span><span class="vv chips">' +
      (f.likelihood?'<span class="risk-chip">Likelihood: '+esc(f.likelihood)+'</span>':'') +
      (f.impact?'<span class="risk-chip">Impact: '+esc(f.impact)+'</span>':'') +
      (f.confidence?'<span class="risk-chip">Confidence: '+esc(f.confidence)+'</span>':'') +
      '</span>':'') +
    (cwe?'<span class="vk">CWE</span><span class="vv meta">'+esc(cwe)+'</span>':'') +
    (owasp?'<span class="vk">OWASP</span><span class="vv meta">'+esc(owasp)+'</span>':'') +
    (tech?'<span class="vk">Technology</span><span class="vv meta">'+esc(tech)+'</span>':'') +
    (refs.length?'<span class="vk">References</span><span class="vv">'+refs.slice(0,3).map(function(r){
      return '<a class="ref-link" href="'+esc(safeUrl(r))+'" target="_blank" rel="noopener">'+esc(r.length>70?r.slice(0,70)+'…':r)+'</a>';
    }).join('')+'</span>':'') +
    '</div>';
}

function toggleGhVI(vi){
  document.getElementById('ghfi-'+vi)?.classList.toggle('open');
}

document.addEventListener('keydown',function(e){
  if(document.getElementById('page-gh-form')&&document.getElementById('page-gh-form').classList.contains('active'))
    if(e.key==='Enter') doGhScan();
});

// Semgrep skips files it cannot parse or times out on. Say how many and which,
// so a partial result is not read as a full one.
function _ghCompletenessHtml(scan){
  if (scan.complete === true) return '';
  var errors = Number(scan.errors) || 0;
  if (scan.complete !== false || !errors)
    return '<p role="status" class="scan-incomplete">Scan completeness is unknown. Rescan this repository to verify the results.</p>';
  var samples = (scan.errorSamples || []).map(function(e){
    return '<li><code>'+esc(e.path || '—')+'</code> · '+esc(e.type || 'Error')+(e.message ? ' — '+esc(e.message) : '')+'</li>';
  }).join('');
  return '<div role="status" class="scan-incomplete">Scan incomplete: Semgrep reported '+errors+' analysis error'+(errors!==1?'s':'')+
    '. Findings in the affected files may be missing; rescan to retry.'+
    (samples ? '<ul>'+samples+'</ul>' : '')+'</div>';
}
