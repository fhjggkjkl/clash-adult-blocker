'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('../src/guard-core.js');
const { createServer, subscriptionUrl } = require('../src/subscription-server.cjs');
const complete = { proxies: [{ name: 'Node', type: 'socks5', server: 'example.com', port: 443, password: 'fake-test-password' }], rules: ['MATCH,DIRECT'], dns: { enable: true, nameserver: ['https://dns.example/dns-query'] } };
test('Full subscription preserves original configuration', () => {
  const prepared = guard.prepareSubscription({ yaml, text: yaml.dump(complete) });
  assert.deepEqual(yaml.load(prepared.text), complete);
  assert.equal(prepared.notice, '');
});
test('Node-only subscription gains a selectable default route without changing DNS', () => {
  const original = { proxies: complete.proxies, dns: complete.dns, 'proxy-groups': [{ name: 'ADULT-GUARD-PROXY', type: 'select', proxies: ['Node'] }] };
  const prepared = guard.prepareSubscription({ yaml, text: yaml.dump(original) });
  const config = yaml.load(prepared.text);
  assert.deepEqual(config.proxies, original.proxies);
  assert.deepEqual(config.dns, original.dns);
  assert.deepEqual(config.rules, ['MATCH,ADULT-GUARD-PROXY-2']);
  assert.equal(config['proxy-groups'][1].name, 'ADULT-GUARD-PROXY-2');
  const patched = guard.patch({ yaml, configText: prepared.text, defaultsPayload: ['+.blocked.example'], safeTest: true });
  assert.equal(patched.config.mode, 'rule');
  assert.match(prepared.notice, /基础分流/);
});
test('Subscription format and private-address failures have actionable messages', () => {
  for (const text of ['<html>login</html>', 'vmess://encoded-node', Buffer.from('vmess://encoded-node').toString('base64')]) assert.throws(() => guard.prepareSubscription({ yaml, text }), /Clash \/ Mihomo/);
  for (const url of ['http://subscription.example/path', 'https://user:password@subscription.example/path', 'https://127.0.0.1/path', 'https://10.0.0.1/path', 'https://[::1]/path', 'https://[::ffff:127.0.0.1]/path', 'https://localhost/path']) assert.throws(() => subscriptionUrl(url));
  assert.equal(subscriptionUrl('https://subscription.example/path?token=fake-test-token').protocol, 'https:');
});

test('Provider-only subscription defaults to its supplied nodes', () => {
  const original = { 'proxy-providers': { Source: { type: 'inline', payload: complete.proxies } } };
  const config = yaml.load(guard.prepareSubscription({ yaml, text: yaml.dump(original) }).text);
  assert.deepEqual(config['proxy-groups'][0].use, ['Source']);
  assert.equal(config['proxy-groups'][0].proxies, undefined);
  assert.deepEqual(config['proxy-providers'], original['proxy-providers']);
});
test('Local service reads and prepares a subscription, refuses unauthorized callers, and stores nothing', async t => {
  let remoteCalls = 0;
  const server = createServer({ readRemote: async url => { remoteCalls++; assert.equal(url, 'https://subscription.example/path?token=fake-test-token'); return yaml.dump(complete); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const page = await fetch(base);
  const html = await page.text();
  assert.match(html, /connect-src 'self'/);
  const token = html.match(/name="local-subscription-token" content="([a-f0-9]+)"/)[1];
  const headers = { 'Content-Type': 'application/json', 'X-Guard-Token': token, Origin: base };
  const body = JSON.stringify({ url: 'https://subscription.example/path?token=fake-test-token' });
  const denied = await fetch(base + '/api/subscription', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  assert.equal(denied.status, 403);
  const crossOrigin = await fetch(base + '/api/subscription', { method: 'POST', headers: { ...headers, Origin: 'https://untrusted.example' }, body });
  assert.equal(crossOrigin.status, 403);
  const privateRequest = await fetch(base + '/api/subscription', { method: 'POST', headers, body: JSON.stringify({ url: 'https://127.0.0.1/path' }) });
  assert.equal(privateRequest.status, 400);
  assert.equal(remoteCalls, 0);
  const response = await fetch(base + '/api/subscription', { method: 'POST', headers, body });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.deepEqual(yaml.load(data.text), complete);
  assert.equal(remoteCalls, 1);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.ok(!html.includes('fake-test-token'));
  const originalFile = fs.readFileSync(path.join(__dirname, '../clash-adult-guard.html'), 'utf8');
  assert.ok(!originalFile.includes(token));
  assert.ok(originalFile.includes("connect-src 'none'"));
});
