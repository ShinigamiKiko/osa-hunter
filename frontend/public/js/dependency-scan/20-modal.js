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

