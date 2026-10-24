'use strict';

// Count expanded values, not unique objects: YAML aliases can share a tiny
// graph whose evaluation and JSON/YAML serialization require exponential work.
function validatePolicyData(source) {
  let nodes = 0, bytes = 0;
  const ancestors = new WeakSet();
  function visit(value, depth) {
    if (++nodes > 10000 || depth > 48) throw new Error('Policy exceeds complexity limit');
    if (typeof value === 'string') bytes += Buffer.byteLength(value);
    if (bytes > 1024 * 1024) throw new Error('Policy exceeds expanded size limit');
    if (!value || typeof value !== 'object') return;
    if (ancestors.has(value)) throw new Error('Policy contains a cyclic alias');
    ancestors.add(value);
    for (const key of Object.keys(value)) {
      bytes += Buffer.byteLength(key);
      visit(value[key], depth + 1);
    }
    ancestors.delete(value);
  }
  visit(source, 0);
}

module.exports = { validatePolicyData };
