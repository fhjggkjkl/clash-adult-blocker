'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const http = require('node:http');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('../src/guard-core.js');
const root = path.resolve(__dirname, '..');
const original = { proxies: [{ name: '中文节点', type: 'socks5', server: 'example.com', port: 443, password: '中文口令' }], dns: { enable: false }, rules: ['MATCH,中文节点'] };
const generated = guard.patch({ yaml, defaultsPayload: ['+.blocked.example'], configText: yaml.dump(original), safeTest: true });
const metadata = { userinfo: 'upload=100; download=2500; total=107374182400; expire=1800000000' };
function page(html, fetcher, clipboard, storage = new Map()) {
  const elements = new Map();
  for (const match of html.matchAll(/\bid="([^"]+)"/g)) {
    const callbacks = new Map();
    elements.set(match[1], { value: '', textContent: '', checked: false, hidden: false, disabled: false, files: [],
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(type, callback) { callbacks.set(type, callback); }, fire(type) { return callbacks.get(type)?.(); }
    });
  }
  elements.get('format').value = 'meta'; elements.get('sniff').checked = true; elements.get('safe-test').checked = true;
  const token = html.match(/name="local-subscription-token" content="([a-f0-9]+)"/)[1];
  const context = vm.createContext({ TextEncoder, URL, Blob, setTimeout, clearTimeout, location: { protocol: 'http:', hostname: '127.0.0.1' },
    navigator: { clipboard: { writeText: clipboard } }, fetch: fetcher,
    localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) },
    document: { getElementById: id => elements.get(id), querySelector: () => ({ content: token }) }
  });
  for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) if (!match[1].includes('application/json')) vm.runInContext(match[2], context);
  return elements;
}
test('Local webpage exports a downloadable subscription, updates the same link, and revokes it', async t => {
  const { createServer, fileStore } = await import('../src/web-server.mjs');
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-web-test-'));
  const store = fileStore(fixture), ownerToken = 'a'.repeat(64);
  let remoteCalls = 0;
  const server = createServer({ ownerToken, store, allowLocal: true, publicBaseUrl: 'http://192.168.1.4:17896',
    readRemote: async () => { remoteCalls++; return { text: yaml.dump(original), metadata }; }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const headers = { 'Content-Type': 'application/json', 'X-Guard-Token': ownerToken, Origin: base };
  const call = (route, method, body) => fetch(base + route, { method, headers, ...(body ? { body: JSON.stringify(body) } : {}) });
  assert.equal((await fetch(base)).status, 404);
  assert.equal((await fetch(base + '/api/exports', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ configText: generated.text }) })).status, 403);
  const pageResponse = await fetch(base + '/tool/' + ownerToken);
  const html = await pageResponse.text();
  assert.match(html, /connect-src 'self'/);
  assert.match(html, /导出订阅链接/);
  const subscription = await (await call('/api/subscription', 'POST', { url: 'https://subscription.example/fake' })).json();
  assert.deepEqual(yaml.load(subscription.text), original); assert.equal(remoteCalls, 1);
  assert.deepEqual(subscription.metadata, metadata);
  const exported = await (await call('/api/exports', 'POST', { configText: generated.text, metadata: subscription.metadata })).json();
  assert.match(exported.id, /^[a-f0-9]{64}$/);
  assert.equal(new URL(exported.url).hostname, '192.168.1.4');
  assert.ok(!exported.url.includes(ownerToken));
  const downloadPath = new URL(exported.url).pathname;
  const download = await fetch(base + downloadPath);
  assert.equal(download.headers.get('content-type'), 'application/yaml; charset=utf-8');
  assert.equal(download.headers.get('subscription-userinfo'), metadata.userinfo);
  assert.equal(download.headers.get('content-disposition'), 'attachment; filename=clash-adult-guard.yaml');
  assert.equal(await download.text(), generated.text);
  const head = await fetch(base + downloadPath, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('subscription-userinfo'), metadata.userinfo);
  assert.equal(await fileStore(fixture).get(exported.id), generated.text);
  assert.deepEqual((await fileStore(fixture).getRecord(exported.id)).metadata, metadata);
  const updatedText = generated.text.replace('blocked.example', 'second-blocked.example');
  const updated = await (await call('/api/exports', 'POST', { configText: updatedText, exportId: exported.id })).json();
  assert.equal(updated.url, exported.url);
  const updatedDownload = await fetch(base + downloadPath);
  assert.equal(updatedDownload.headers.get('subscription-userinfo'), null);
  assert.equal(await updatedDownload.text(), updatedText);
  assert.equal((await fetch(base + '/sub/' + '0'.repeat(64) + '.yaml')).status, 404);
  await call('/api/exports/' + exported.id, 'DELETE');
  assert.equal((await fetch(base + downloadPath)).status, 404);
  assert.equal(await store.get(exported.id), null);
});
test('Real HTML carries subscription information through generation and export, and clears it for manual configurations', async t => {
  const { createServer, fileStore } = await import('../src/web-server.mjs');
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-traffic-test-'));
  const ownerToken = 'd'.repeat(64);
  const server = createServer({ ownerToken, store: fileStore(fixture), allowLocal: true, publicBaseUrl: 'http://192.168.1.4:17896',
    readRemote: async () => ({ text: yaml.dump(original), metadata }) });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const html = await (await fetch(base + '/tool/' + ownerToken)).text();
  const elements = page(html, (route, options) => fetch(base + route, options), async () => {});
  elements.get('subscription').value = 'https://subscription.example/fake';
  await elements.get('read-subscription').fire('click');
  assert.match(elements.get('subscription-info').textContent, /已保留/);
  elements.get('extra').value = 'manual.example.com'; elements.get('extra').fire('input');
  await elements.get('generate').fire('click'); await elements.get('export-link').fire('click');
  const downloadPath = new URL(elements.get('subscription-output').value).pathname;
  assert.equal((await fetch(base + downloadPath)).headers.get('subscription-userinfo'), metadata.userinfo);
  const id = downloadPath.match(/([a-f0-9]{64})\.yaml$/)[1];
  assert.deepEqual((await fileStore(fixture).getRecord(id)).metadata, metadata);
  elements.get('config').value = yaml.dump(original); elements.get('config').fire('input');
  await elements.get('generate').fire('click'); await elements.get('export-link').fire('click');
  assert.match(elements.get('subscription-info').textContent, /没有订阅流量信息/);
  assert.equal((await fetch(base + downloadPath)).headers.get('subscription-userinfo'), null);
});
test('Existing YAML exports retain their links after upgrading the storage format', async () => {
  const { fileStore } = await import('../src/web-server.mjs');
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-upgrade-test-')), id = 'e'.repeat(64);
  await fs.writeFile(path.join(fixture, id + '.yaml'), generated.text, 'utf8');
  const store = fileStore(fixture);
  assert.equal(await store.get(id), generated.text);
  await store.put(id, generated.text, metadata);
  assert.deepEqual(await fileStore(fixture).getRecord(id), { text: generated.text, metadata });
  await store.delete(id);
  assert.equal(await store.get(id), null);
});

test('One click reads the upstream, adds manual blocks, and exports an internet link with quota', async t => {
  const { createServer, fileStore } = await import('../src/web-server.mjs');
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-one-click-'));
  const store = fileStore(fixture), ownerToken = 'f'.repeat(64), published = new Set();
  let reads = 0, starts = 0;
  const internetTunnel = { async ensure() { starts++; return 'https://oneclick.lhr.life'; }, publish(id) { published.add(id); }, unpublish(id) { published.delete(id); }, async close() {} };
  const server = createServer({ ownerToken, store, internetTunnel, allowLocal: true, publicBaseUrl: 'http://192.168.1.4:17896',
    readRemote: async () => { reads++; return { text: yaml.dump(original), metadata }; } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const html = await (await fetch(base + '/tool/' + ownerToken)).text();
  const elements = page(html, (route, options) => fetch(base + route, options), async () => {});
  elements.get('subscription').value = 'https://subscription.example/fake';
  elements.get('extra').value = 'manual.example.com';
  await elements.get('one-click').fire('click');
  assert.equal(reads, 1); assert.equal(starts, 1);
  const url = new URL(elements.get('subscription-output').value);
  assert.equal(url.origin, 'https://oneclick.lhr.life');
  assert.equal(elements.get('link-result').hidden, false);
  const id = url.pathname.match(/([a-f0-9]{64})\.yaml$/)[1];
  assert.ok(published.has(id));
  const record = await store.getRecord(id), config = yaml.load(record.text);
  assert.deepEqual(record.metadata, metadata);
  assert.deepEqual(config.proxies, original.proxies);
  assert.equal(config.rules[0], 'DOMAIN-SUFFIX,manual.example.com,REJECT');
  assert.match(elements.get('link-help').textContent, /流量或其他 Wi-Fi/);
  assert.equal(elements.get('one-click').disabled, false);
});

test('The page rejects a LAN URL when an old service ignores an internet export request', async () => {
  const ownerToken = 'a'.repeat(64);
  const html = (await fs.readFile(path.join(root, 'clash-adult-guard.html'), 'utf8')).replace('</head>', '<meta name="local-subscription-token" content="' + ownerToken + '"></head>');
  const elements = page(html, async () => new Response(JSON.stringify({ id: 'b'.repeat(64), url: 'http://192.168.1.4:17896/sub/' + 'b'.repeat(64) + '.yaml' })), async () => {});
  elements.get('config').value = yaml.dump(original);
  await elements.get('generate').fire('click');
  await elements.get('export-internet').fire('click');
  assert.equal(elements.get('link-result').hidden, true);
  assert.match(elements.get('status').textContent, /旧版服务/);
});
test('The real HTML export and copy buttons produce a valid subscription and Clash import URI', async t => {
  const { createServer } = await import('../src/web-server.mjs');
  const records = new Map(), ownerToken = 'b'.repeat(64);
  const store = { get: async id => records.get(id) ?? null, put: async (id, text) => records.set(id, text), delete: async id => records.delete(id) };
  const server = createServer({ ownerToken, store, allowLocal: true, publicBaseUrl: 'http://192.168.1.4:17896' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const html = await (await fetch(base + '/tool/' + ownerToken)).text();
  let clipboard = '';
  const storage = new Map();
  const elements = page(html, (route, options) => fetch(base + route, options), async text => { clipboard = text; }, storage);
  elements.get('config').value = yaml.dump(original);
  await elements.get('generate').fire('click');
  await elements.get('export-link').fire('click');
  assert.equal(elements.get('link-result').hidden, false);
  const url = elements.get('subscription-output').value;
  await elements.get('copy-link').fire('click'); assert.equal(clipboard, url);
  await elements.get('copy-import').fire('click');
  const importUrl = new URL(clipboard);
  assert.equal(importUrl.protocol, 'clash:');
  assert.equal(importUrl.searchParams.get('url'), url);
  const retrieved = await (await fetch(base + new URL(url).pathname)).text();
  const config = yaml.load(retrieved);
  assert.deepEqual(config.proxies, original.proxies);
  assert.deepEqual(config.dns, original.dns);
  assert.equal(config.rules[0], 'DOMAIN,guard-check.example.com,REJECT');
  elements.get('extra').value = 'manual.example.com'; elements.get('extra').fire('input');
  await elements.get('generate').fire('click'); await elements.get('export-link').fire('click');
  assert.equal(elements.get('subscription-output').value, url);
  assert.match(await (await fetch(base + new URL(url).pathname)).text(), /DOMAIN-SUFFIX,manual\.example\.com,REJECT/);
  const reopened = page(html, (route, options) => fetch(base + route, options), async text => { clipboard = text; }, storage);
  reopened.get('config').value = yaml.dump(original);
  await reopened.get('generate').fire('click'); await reopened.get('export-link').fire('click');
  assert.equal(reopened.get('subscription-output').value, url);
  assert.equal(records.size, 1);
  await reopened.get('revoke-link').fire('click');
  assert.equal(reopened.get('link-result').hidden, true);
  assert.equal(storage.size, 0);
  assert.equal((await fetch(base + new URL(url).pathname)).status, 404);
});
test('Network selection prefers the physical connection and filters loopback and VPN fake-IP addresses', async () => {
  const { lanAddresses } = await import('../src/web-server.mjs');
  assert.deepEqual(lanAddresses({ TUN: [{ address: '198.18.0.1', family: 'IPv4', internal: false }], Loopback: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
    Adapter: [{ address: '172.20.1.2', family: 'IPv4', internal: false }], WLAN: [{ address: '192.168.1.4', family: 'IPv4', internal: false }] }), ['192.168.1.4', '172.20.1.2']);
});
test('The actual launcher server starts, is reused on reopening, and stops from the page API', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-cli-test-'));
  const children = [];
  t.after(() => { for (const child of children) if (child.exitCode === null) child.kill(); });
  function start() {
    const child = spawn(process.execPath, [path.join(root, 'src/web-server.mjs')], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, HOST: '127.0.0.1', PORT: '0', GUARD_DATA_DIR: directory, GUARD_ADMIN_TOKEN: 'c'.repeat(64) }
    });
    children.push(child);
    const closed = new Promise((resolve, reject) => { child.on('close', resolve); child.on('error', reject); });
    const ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error('Server startup timed out')); }, 8000);
      const lines = readline.createInterface({ input: child.stdout });
      lines.once('line', line => { clearTimeout(timer); try { resolve(JSON.parse(line)); } catch (error) { reject(error); } });
      child.once('exit', code => { if (code !== 0) { clearTimeout(timer); reject(new Error('Server startup failed')); } });
    });
    return { child, ready, closed };
  }
  const first = start(), one = await first.ready;
  assert.equal(one.ready, true);
  assert.equal((await fetch(one.localUrl)).status, 200);
  const second = start(), two = await second.ready;
  assert.equal(two.reused, true);
  assert.equal(two.localUrl, one.localUrl);
  assert.equal(await second.closed, 0);
  const stop = await fetch(new URL('/api/stop', one.localUrl), { method: 'POST', headers: { 'X-Guard-Token': 'c'.repeat(64) } });
  assert.equal(stop.status, 200);
  assert.equal(await first.closed, 0);
});

test('Reopening the launcher replaces its owned old service and retains saved configuration files', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-old-service-'));
  const ownerToken = 'd'.repeat(64);
  const exportPath = path.join(directory, 'saved-fixture.yaml');
  await fs.writeFile(exportPath, generated.text, 'utf8');
  let stopped = 0;
  const old = http.createServer((request, response) => {
    if (request.url === '/tool/' + ownerToken) {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('<meta name="local-subscription-token" content="' + ownerToken + '">');
    } else if (request.url === '/api/stop' && request.headers['x-guard-token'] === ownerToken) {
      stopped++;
      response.writeHead(200, { 'Content-Type': 'application/json' }); response.end('{"stopped":true}');
      setTimeout(() => { old.closeAllConnections(); old.close(); }, 25);
    } else { response.writeHead(404); response.end(); }
  });
  await new Promise(resolve => old.listen(0, '127.0.0.1', resolve));
  await fs.writeFile(path.join(directory, 'server.json'), JSON.stringify({ port: old.address().port }), 'utf8');
  t.after(() => { old.closeAllConnections(); old.close(); });
  const child = spawn(process.execPath, [path.join(root, 'src/web-server.mjs')], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, HOST: '127.0.0.1', PORT: '0', GUARD_DATA_DIR: directory, GUARD_ADMIN_TOKEN: ownerToken }
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Owned service upgrade timed out')), 8000);
    readline.createInterface({ input: child.stdout }).once('line', line => { clearTimeout(timer); resolve(JSON.parse(line)); });
    child.once('error', reject);
  });
  assert.equal(stopped, 1);
  const html = await (await fetch(ready.localUrl)).text();
  assert.match(html, /local-service-version" content="0\.3\.0/);
  assert.equal(await fs.readFile(exportPath, 'utf8'), generated.text);
  const closed = new Promise(resolve => child.once('close', resolve));
  await fetch(new URL('/api/stop', ready.localUrl), { method: 'POST', headers: { 'X-Guard-Token': ownerToken } });
  assert.equal(await closed, 0);
});
