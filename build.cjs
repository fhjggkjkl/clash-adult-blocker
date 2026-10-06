/* Build the single-file offline tool; no network access. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = __dirname;
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const yaml = require('./vendor/js-yaml.min.js');
const payload = yaml.load(read('rules/adult-domains.yaml')).payload;
if (!Array.isArray(payload) || payload.length < 1000 || payload.some(x => typeof x !== 'string')) {
  throw new Error('Adult domain snapshot is missing or invalid.');
}
const safeJson = value => JSON.stringify(value).replace(/</g, '\\u003c');
const meta = {
  sourceName: 'MetaCubeX / category-porn',
  sourceUrl: 'https://github.com/MetaCubeX/meta-rules-dat',
  date: '2026-10-04',
  commit: JSON.parse(read('rules/snapshot.json')).sourceCommit,
  count: payload.length,
  sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'rules/adult-domains.yaml'))).digest('hex')
};
let html = read('src/tool.template.html');
const replace = (key, value) => {
  if (!html.includes(key)) throw new Error('Missing template placeholder: ' + key);
  html = html.replaceAll(key, () => value);
};
replace('__YAML_LIB__', read('vendor/js-yaml.min.js'));
replace('__CORE_JS__', read('src/guard-core.js'));
replace('__DEFAULT_PAYLOAD__', safeJson(payload));
replace('__SOURCE_META__', safeJson(meta));
const notices = {
  source: meta,
  rulesLicense: read('rules/LICENSE-MetaCubeX.txt'),
  upstreamLicenses: [read('rules/LICENSE-v2fly-MIT.txt'), read('rules/LICENSE-Loyalsoldier-MIT.txt')],
  parserLicense: read('vendor/LICENSE-js-yaml'),
  provenance: read('rules/provenance.md')
};
html = html.replace('</body>', () => '<script type="application/json" id="bundled-license-notices">' + safeJson(notices) + '</script>\n</body>');
fs.writeFileSync(path.join(root, 'clash-adult-guard.html'), html, 'utf8');
fs.writeFileSync(path.join(root, 'LICENSE.txt'), notices.rulesLicense, 'utf8');
fs.writeFileSync(path.join(root, 'vendor/provenance.md'),
  '# YAML parser\n\njs-yaml 4.1.1, MIT license. Vendored from its official fixed release tag:\n\n' +
  '- https://raw.githubusercontent.com/nodeca/js-yaml/4.1.1/dist/js-yaml.min.js\n' +
  '- https://raw.githubusercontent.com/nodeca/js-yaml/4.1.1/LICENSE\n\n' +
  'SHA256: ' + crypto.createHash('sha256').update(read('vendor/js-yaml.min.js')).digest('hex') + '\n', 'utf8');
console.log(JSON.stringify({ output: path.join(root, 'clash-adult-guard.html'), domains: payload.length, bytes: Buffer.byteLength(html), sourceSha256: meta.sha256 }));
