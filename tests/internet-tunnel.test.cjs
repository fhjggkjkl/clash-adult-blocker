'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');

const id = 'a'.repeat(64), otherId = 'b'.repeat(64);
const fixture = 'proxies:\n  - name: Dummy\n    type: socks5\n    server: 127.0.0.1\n    port: 12345\nrules:\n  - MATCH,DIRECT\n';
const metadata = { userinfo: 'upload=10; download=20; total=1000; expire=2000000000' };
function memoryStore() {
  const records = new Map([[id, { text: fixture, metadata }], [otherId, { text: fixture, metadata }]]);
  return { getRecord: async key => records.get(key) ?? null, get: async key => records.get(key)?.text ?? null,
    put: async (key, text, info) => records.set(key, { text, metadata: info }), delete: async key => records.delete(key) };
}
function fakeSsh({ fail = false, silent = false } = {}) {
  const children = [];
  let localBase;
  const spawnProcess = (_executable, args, options) => {
    assert.equal(options.windowsHide, true);
    assert.ok(args.includes('IdentityAgent=none'));
    const forward = args[args.indexOf('-R') + 1];
    assert.match(forward, /^80:127\.0\.0\.1:\d+$/);
    localBase = 'http://127.0.0.1:' + forward.split(':').at(-1);
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.exitCode = null;
    child.kill = () => { if (child.exitCode !== null) return; child.exitCode = 0; queueMicrotask(() => child.emit('close', 0)); };
    children.push(child);
    if (fail) queueMicrotask(() => { child.exitCode = 255; child.emit('close', 255); });
    else if (!silent) queueMicrotask(() => child.stdout.write('https://session' + children.length + '.lhr.life\n'));
    return child;
  };
  return { spawnProcess, children, localBase: () => localBase,
    fetchPublic: (url, options) => fetch(localBase + new URL(url).pathname, options) };
}

test('Tunnel URL parsing accepts service domains and rejects unrelated or misleading hosts', async () => {
  const { tunnelOrigin } = await import('../src/internet-tunnel.mjs');
  assert.equal(tunnelOrigin('Banner https://admin.localhost.run then https://sample123.lhr.life\n'), 'https://sample123.lhr.life');
  assert.equal(tunnelOrigin('{"url":"https://sample123.lhr.life"}'), 'https://sample123.lhr.life');
  for (const invalid of ['https://localhost.run', 'https://sample.lhr.life.evil.test', 'https://sample.lhr.life@evil.test',
    'http://sample.lhr.life', 'https://unrelated.test', 'https://sample.lhr.life:8080']) assert.equal(tunnelOrigin(invalid), null);
});

test('Public bridge exposes only published subscriptions and keeps real quota headers', async t => {
  const { createDownloadBridge } = await import('../src/internet-tunnel.mjs');
  const store = memoryStore(), publishedIds = new Set([id]);
  const bridge = createDownloadBridge({ store, publishedIds });
  await new Promise(resolve => bridge.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { bridge.closeAllConnections(); bridge.close(resolve); }));
  const base = 'http://127.0.0.1:' + bridge.address().port;
  const download = await fetch(base + '/sub/' + id + '.yaml');
  assert.equal(await download.text(), fixture);
  assert.equal(download.headers.get('subscription-userinfo'), metadata.userinfo);
  const head = await fetch(base + '/sub/' + id + '.yaml', { method: 'HEAD' });
  assert.equal(head.status, 200); assert.equal(await head.text(), '');
  assert.equal(head.headers.get('content-length'), String(Buffer.byteLength(fixture)));
  assert.equal(head.headers.get('subscription-userinfo'), metadata.userinfo);
  for (const route of ['/', '/api/subscription', '/api/exports', '/tool/' + id, '/sub/' + otherId + '.yaml']) {
    assert.equal((await fetch(base + route)).status, 404);
  }
  assert.equal((await fetch(base + '/sub/' + id + '.yaml', { method: 'POST' })).status, 404);
  await store.delete(id);
  assert.equal((await fetch(base + '/sub/' + id + '.yaml')).status, 404);
});

test('Concurrent exports share a verified tunnel, reconnect after loss, and stop its listener', async t => {
  const { createInternetTunnel } = await import('../src/internet-tunnel.mjs');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-tunnel-'));
  const transport = fakeSsh();
  const tunnel = createInternetTunnel({ store: memoryStore(), directory, ...transport });
  t.after(() => tunnel.close());
  const origins = await Promise.all([tunnel.ensure(), tunnel.ensure()]);
  assert.deepEqual(origins, ['https://session1.lhr.life', 'https://session1.lhr.life']);
  assert.equal(transport.children.length, 1);
  transport.children[0].stdout.write('request logged https://unrelated.lhr.life/sub/unknown\n');
  assert.equal(await tunnel.ensure(), 'https://session1.lhr.life');
  tunnel.publish(id);
  const base = transport.localBase();
  assert.equal(await (await fetch(base + '/sub/' + id + '.yaml')).text(), fixture);
  transport.children[0].kill();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(await tunnel.ensure(), 'https://session2.lhr.life');
  assert.equal(transport.children.length, 2);
  tunnel.unpublish(id);
  assert.equal((await fetch(transport.localBase() + '/sub/' + id + '.yaml')).status, 404);
  const finalBase = transport.localBase();
  await tunnel.close();
  assert.equal(transport.children[1].exitCode, 0);
  await assert.rejects(fetch(finalBase));
  await assert.rejects(tunnel.ensure(), /已停止/);
});

test('Failed or unverified tunnels never produce a usable-looking export', async t => {
  const { createInternetTunnel } = await import('../src/internet-tunnel.mjs');
  for (const failure of ['ssh', 'probe', 'timeout']) {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-tunnel-fail-'));
    const transport = fakeSsh({ fail: failure === 'ssh', silent: failure === 'timeout' });
    const tunnel = createInternetTunnel({ store: memoryStore(), directory, ...transport,
      startupTimeoutMs: 40, ...(failure === 'probe' ? { fetchPublic: async () => new Response('wrong endpoint') } : {}) });
    t.after(() => tunnel.close());
    await assert.rejects(tunnel.ensure(), /失败|未连通|超时/);
    await assert.rejects(fetch(transport.localBase()));
    assert.notEqual(transport.children[0].exitCode, null);
  }
});

test('Internet export works without a LAN address, retains metadata, and revokes access', async t => {
  const { createServer } = await import('../src/web-server.mjs');
  const { createInternetTunnel } = await import('../src/internet-tunnel.mjs');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'adult-guard-internet-export-'));
  const store = memoryStore(), transport = fakeSsh(), ownerToken = 'c'.repeat(64);
  const internetTunnel = createInternetTunnel({ store, directory, ...transport });
  const server = createServer({ ownerToken, store, internetTunnel, allowLocal: true, publicBaseUrl: () => { throw new Error('No LAN'); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await internetTunnel.close(); await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }); });
  const base = 'http://127.0.0.1:' + server.address().port;
  const headers = { 'Content-Type': 'application/json', 'X-Guard-Token': ownerToken };
  const response = await fetch(base + '/api/exports', { method: 'POST', headers, body: JSON.stringify({ configText: fixture, metadata, access: 'internet' }) });
  assert.equal(response.status, 200);
  const exported = await response.json();
  assert.equal(exported.access, 'internet'); assert.equal(exported.temporary, true);
  assert.equal(new URL(exported.url).origin, 'https://session1.lhr.life');
  const download = await fetch(transport.localBase() + new URL(exported.url).pathname);
  assert.equal(await download.text(), fixture); assert.equal(download.headers.get('subscription-userinfo'), metadata.userinfo);
  const revoked = await fetch(base + '/api/exports/' + exported.id, { method: 'DELETE', headers });
  assert.equal(revoked.status, 200);
  assert.equal((await fetch(transport.localBase() + new URL(exported.url).pathname)).status, 404);
});
