'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Gate policy: turns the facts of a single package scan into an allow/deny/warn
// decision. Kept as plain JS so it ships with zero new deps; the shape is
// deliberately declarative so it can be swapped for a YAML loader later without
// touching decide.js.
//
// A rule is { id, action, when(facts) -> bool, detail(facts) -> string }.
// Resolution order (in decide.js): denylist > allowlist > rules > default.
// Among rules, any matched `deny` wins over any `warn`.

const BUILTIN_POLICY = {
  // Manual overrides. Format: "<ecosystem>/<name>@<version>" (version optional).
  deny: [
    // 'npm/event-stream@3.3.6',
  ],
  allow: [
    // 'npm/lodash@4.17.21',
  ],

  rules: [
    {
      id: 'toxic',
      action: 'deny',
      when: f => !!(f.toxic && f.toxic.found),
      detail: f => `toxic repo: ${f.toxic.problem_type || 'malicious code'}`,
    },
    {
      id: 'kev',
      action: 'deny',
      when: f => f.kev > 0,
      detail: f => `${f.kev} CVE(s) in CISA KEV (actively exploited)`,
    },
    {
      id: 'critical-hot',
      action: 'deny',
      when: f => f.counts.CRITICAL > 0 && f.epssMax >= 0.5,
      detail: f => `critical vuln with EPSS ${f.epssMax.toFixed(2)} (likely exploit)`,
    },
    {
      id: 'critical',
      action: 'deny',
      when: f => f.counts.CRITICAL > 0,
      detail: f => `${f.counts.CRITICAL} critical vuln(s)`,
    },
    {
      id: 'high',
      action: 'warn',
      when: f => f.counts.HIGH > 0,
      detail: f => `${f.counts.HIGH} high vuln(s)`,
    },
    {
      id: 'has-poc',
      action: 'warn',
      when: f => f.pocCount > 0,
      detail: f => `${f.pocCount} CVE(s) with public PoC`,
    },
  ],

  // Verdict when no rule matches.
  default: 'allow',
};

const POLICY_FILE = process.env.OSA_POLICY_FILE || path.join(__dirname, '../../../policy.yaml');

function readPath(value, key) {
  return key.split('.').reduce((current, part) => current == null ? undefined : current[part], value);
}

function parseBool(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    if (['yes', 'true', 'on', 'y'].includes(s)) return true;
    if (['no', 'false', 'off', 'n'].includes(s)) return false;
  }
  return null;
}

function compare(actual, expected) {
  if (typeof expected !== 'string') return actual === expected;
  // Boolean-style match: `kev: yes` / `kev: no` (also true/false/on/off).
  // Truthiness is checked, so a count fact like kev=2 counts as "yes".
  const bool = parseBool(expected);
  if (bool !== null) return bool ? !!actual : !actual;
  // Wildcard/glob: any `*` in the value makes it a pattern, e.g.
  // cves: "CVE-2026-*". `*` matches any run of characters; everything else is
  // literal. On arrays this means "any element matches the pattern".
  if (expected.includes('*')) {
    const re = '^' + expected.split('*')
      .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, m => '\\' + m))
      .join('.*') + '$';
    try { return new RegExp(re).test(String(actual)); } catch { return false; }
  }
  // Power-user escape hatch: `~ <regex>` for a full regular expression.
  const rx = expected.match(/^~\s*(.+)$/);
  if (rx) {
    try { return new RegExp(rx[1]).test(String(actual)); } catch { return false; }
  }
  const match = expected.match(/^(>=|<=|>|<|==|!=)\s*(.+)$/);
  if (!match) return String(actual) === expected;
  const [, op, raw] = match;
  const right = Number(raw);
  const left = Number(actual);
  if (!Number.isNaN(left) && !Number.isNaN(right)) {
    return ({ '>=': left >= right, '<=': left <= right, '>': left > right,
      '<': left < right, '==': left === right, '!=': left !== right })[op];
  }
  return ({ '==': actual === raw, '!=': actual !== raw })[op] || false;
}

function conditionMatches(condition, facts) {
  if (!condition || typeof condition !== 'object') return false;
  if (Array.isArray(condition.all)) return condition.all.every(c => conditionMatches(c, facts));
  if (Array.isArray(condition.any)) return condition.any.some(c => conditionMatches(c, facts));
  return Object.entries(condition).every(([key, expected]) => {
    const actual = readPath(facts, key);
    // List facts (cves, ids) match if ANY element satisfies the condition, so
    // `cves: CVE-2026-1234` means "this package carries that CVE".
    if (Array.isArray(actual)) return actual.some(item => compare(item, expected));
    return compare(actual, expected);
  });
}

function compilePolicy(source) {
  if (!source || typeof source !== 'object') throw new Error('Policy must be an object');
  const defaults = source.defaults || {};
  const rules = (source.rules || []).map(rule => {
    if (!rule.id || !['allow', 'warn', 'deny'].includes(rule.action)) {
      throw new Error('Each policy rule requires id and action (allow, warn or deny)');
    }
    return {
      id: rule.id,
      action: rule.action,
      when: facts => conditionMatches(rule.when, facts),
      detail: rule.detail || rule.id,
    };
  });
  return {
    deny: (source.exceptions?.deny || []).map(formatException),
    allow: (source.exceptions?.allow || []).map(formatException),
    rules,
    default: defaults.decision || 'allow',
    onGateError: defaults.on_gate_error || 'deny',
    version: String(source.version || 1),
  };
}

function formatException(item) {
  if (typeof item === 'string') return item;
  if (!item?.ecosystem || !item.name) throw new Error('Policy exception requires ecosystem and name');
  return `${item.ecosystem}/${item.name}${item.version ? '@' + item.version : ''}`;
}

function loadPolicy() {
  if (!fs.existsSync(POLICY_FILE)) {
    if (process.env.OSA_POLICY_FILE) throw new Error(`Configured policy file not found: ${POLICY_FILE}`);
    return BUILTIN_POLICY;
  }
  return compilePolicy(yaml.load(fs.readFileSync(POLICY_FILE, 'utf8')));
}

const DEFAULT_POLICY = loadPolicy();

// Evaluate every rule and collect the ones that fire.
function evalRules(policy, facts) {
  const hits = [];
  for (const rule of policy.rules || []) {
    let matched = false;
    try {
      matched = !!rule.when(facts);
    } catch {
      matched = false;
    }
    if (!matched) continue;
    let detail = rule.id;
    try {
      detail = typeof rule.detail === 'function' ? rule.detail(facts) : (rule.detail || rule.id);
    } catch {
      detail = rule.id;
    }
    hits.push({ rule: rule.id, action: rule.action, detail });
  }
  return hits;
}

module.exports = { DEFAULT_POLICY, evalRules, loadPolicy, compilePolicy, POLICY_FILE };
