const DEP_SYSTEMS = [
  { id:'NPM',      label:'npm',      logo:'📦', hint:'express, lodash…' },
  { id:'PYPI',     label:'PyPI',     logo:'🐍', hint:'django, requests…' },
  { id:'GO',       label:'Go',       logo:'🐹', hint:'github.com/gin-gonic/gin' },
  { id:'CARGO',    label:'Rust',     logo:'🦀', hint:'tokio, serde…' },
  { id:'MAVEN',    label:'Maven',    logo:'☕', hint:'com.google.guava:guava' },
  { id:'NUGET',    label:'NuGet',    logo:'🔷', hint:'Newtonsoft.Json…' },
  { id:'COMPOSER', label:'Composer', logo:'🐘', hint:'monolog/monolog' },
];

const depStored = safeLoad('es_dep', []);
let depScans  = pruneLocalScans(depStored);
if(depScans.length!==depStored.length) safeSave('es_dep',depScans);
let selDepSys = null;
let currentDepScan = null;
let depScanInFlight = false;
const saveDep = () => safeSave('es_dep', depScans);
