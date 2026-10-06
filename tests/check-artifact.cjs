'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '../clash-adult-guard.html'), 'utf8');
const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
for (const [index, match] of scripts.entries()) {
  if (match[1].includes('application/json')) JSON.parse(match[2]);
  else new vm.Script(match[2], { filename: 'embedded-script-' + index });
}
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
assert.equal(ids.length, new Set(ids).size, 'HTML ids must be unique');
assert.ok(!/__(?:YAML_LIB|CORE_JS|DEFAULT_PAYLOAD|SOURCE_META)__/.test(html), 'all source placeholders must be expanded');
assert.ok(!/<script[^>]+src=/i.test(html), 'single-file tool must not load external scripts');
assert.ok(html.includes("connect-src 'none'"), 'network connections must be disabled');
for (const source of ['../vendor/js-yaml.min.js', '../src/guard-core.js']) {
  assert.ok(html.includes('<script>' + fs.readFileSync(path.join(__dirname, source), 'utf8') + '</script>'), 'bundled script must preserve raw source bytes: ' + source);
}
console.log(JSON.stringify({ embeddedScripts: scripts.length, syntaxValid: true, idsUnique: true, externalScripts: 0, browserRenderingVerified: false }));
