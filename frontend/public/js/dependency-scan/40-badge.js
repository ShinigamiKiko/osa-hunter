function updateDepBadge(){
  const b=document.getElementById('depBadge');
  if(depScans.length){ b.hidden=false; b.textContent=depScans.length; }
  else b.hidden=true;
}

