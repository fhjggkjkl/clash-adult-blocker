'use strict';
// Compile newly assembled subscription routing with local fixtures, without fetching a provider.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('../src/guard-core.js');
const exe = process.argv[2];
if (!exe) throw new Error('Pass a local Mihomo executable path.');
const root = path.resolve(__dirname, '..');
const fixture = path.join(__dirname, '.kernel-fixture');
fs.mkdirSync(fixture, { recursive: true });
const proxy = { name: 'Test node', type: 'socks5', server: '127.0.0.1', port: 12345 };
fs.writeFileSync(path.join(fixture, 'test-provider.yaml'), yaml.dump({ proxies: [proxy] }));
const defaultsPayload = yaml.load(fs.readFileSync(path.join(root, 'rules/adult-domains.yaml'), 'utf8')).payload;
const inputs = {
  'nodes-only': { proxies: [proxy] },
  'providers-only': { 'proxy-providers': { Source: { type: 'file', path: './test-provider.yaml' } } }
};
for (const [name, input] of Object.entries(inputs)) {
  const prepared = guard.prepareSubscription({ yaml, text: yaml.dump(input) });
  const generated = guard.patch({ yaml, defaultsPayload, configText: prepared.text, sniff: true, safeTest: true });
  const config = path.join(fixture, name + '.yaml');
  fs.writeFileSync(config, generated.text);
  const result = spawnSync(exe, ['-t', '-d', fixture, '-f', config], { encoding: 'utf8', timeout: 10000, windowsHide: true });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, String(result.stdout) + String(result.stderr));
  console.log('PASS Mihomo accepts ' + name + ' subscription with generated routing and adult rules');
}
