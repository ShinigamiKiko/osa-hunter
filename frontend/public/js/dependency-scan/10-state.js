const DEP_SYSTEMS = [
  { id:'NPM',      label:'npm', hint:'express, lodash…' },
  { id:'PYPI',     label:'PyPI', hint:'django, requests…' },
  { id:'GO',       label:'Go', hint:'github.com/gin-gonic/gin' },
  { id:'CARGO',    label:'Rust', hint:'tokio, serde…' },
  { id:'MAVEN',    label:'Maven', hint:'com.google.guava:guava' },
  { id:'NUGET',    label:'NuGet', hint:'Newtonsoft.Json…' },
  { id:'COMPOSER', label:'Composer', hint:'monolog/monolog' },
];

const depStored = safeLoad('es_dep', []);
let depScans  = pruneLocalScans(depStored);
if(depScans.length!==depStored.length) safeSave('es_dep',depScans);
let selDepSys = null;
let currentDepScan = null;
let depScanInFlight = false;
const saveDep = () => safeSave('es_dep', depScans);
