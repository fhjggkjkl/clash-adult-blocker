/* Isolated loopback-only integration: no system proxy, TUN, or Internet requests. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('../src/guard-core.js');
const root = path.resolve(__dirname, '..');
const exe = process.argv[2];
if (!exe) throw new Error('Pass a local Mihomo executable path.');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});
const upstreamHosts = [];
const sockets = new Set();
const upstream = net.createServer(socket => {
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  let stage = 0, data = Buffer.alloc(0);
  socket.on('data', chunk => {
    data = Buffer.concat([data, chunk]);
    if (stage === 0) {
      if (data.length < 2 || data.length < 2 + data[1]) return;
      assert.equal(data[0], 5);
      data = data.subarray(2 + data[1]);
      stage = 1;
      socket.write(Buffer.from([5, 0]));
    }
    if (stage === 1 && data.length >= 5) {
      const end = data[3] === 3 ? 7 + data[4] : data[3] === 1 ? 10 : 22;
      if (data.length < end) return;
      assert.equal(data[3], 3, 'upstream should receive a domain without DNS resolution');
      upstreamHosts.push(data.subarray(5, 5 + data[4]).toString('utf8'));
      data = data.subarray(end);
      stage = 2;
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
    }
    if (stage === 2 && data.length) {
      data = Buffer.alloc(0);
      socket.write('guard-local-ok');
    }
  });
});
function connectViaProxy(port, host) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    let stage = 0, data = Buffer.alloc(0), settled = false;
    const finish = result => { if (!settled) { settled = true; socket.destroy(); resolve(result); } };
    socket.setTimeout(4000, () => { socket.destroy(); reject(new Error('Proxy response timed out.')); });
    socket.on('error', reject);
    socket.on('close', () => { if (!settled) finish({ accepted: false, closed: true }); });
    socket.on('connect', () => socket.write(Buffer.from([5, 1, 0])));
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      if (stage === 0 && data.length >= 2) {
        assert.deepEqual(Array.from(data.subarray(0, 2)), [5, 0]);
        data = data.subarray(2);
        stage = 1;
        const domain = Buffer.from(host);
        socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, domain.length]), domain, Buffer.from([1, 187])]));
      }
      if (stage === 1 && data.length >= 5) {
        if (data[1] !== 0) return finish({ accepted: false, status: data[1] });
        const end = data[3] === 3 ? 7 + data[4] : data[3] === 1 ? 10 : 22;
        if (data.length < end) return;
        data = data.subarray(end);
        stage = 2;
        socket.write('guard-local-ping');
      }
      if (stage === 2 && data.toString().includes('guard-local-ok')) finish({ accepted: true });
    });
  });
}
async function main() {
  const upstreamPort = await listen(upstream);
  const reservation = net.createServer();
  const port = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  const fixtureDir = path.join(root, 'tests', '.kernel-fixture');
  fs.mkdirSync(fixtureDir, { recursive: true });
  const input = {
    'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': false,
    mode: 'rule', 'log-level': 'silent', dns: { enable: false },
    proxies: [{ name: 'TEST-UPSTREAM', type: 'socks5', server: '127.0.0.1', port: upstreamPort, udp: false }]
  };
  const payload = yaml.load(fs.readFileSync(path.join(root, 'rules/adult-domains.yaml'), 'utf8')).payload;
  const subscription = guard.prepareSubscription({ yaml, text: yaml.dump(input) });
  const output = guard.patch({ yaml, defaultsPayload: payload, configText: subscription.text, extraBlock: 'manual-block.invalid', safeTest: true, legacy: false, sniff: false });
  const configPath = path.join(fixtureDir, 'config.yaml');
  fs.writeFileSync(configPath, output.text);
  const child = spawn(exe, ['-d', fixtureDir, '-f', configPath], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', data => { logs += data; });
  child.stderr.on('data', data => { logs += data; });
  child.on('error', error => { logs += error.message; });
  try {
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
      ready = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1');
        socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => resolve(false));
      });
      if (!ready) await delay(100);
    }
    assert.ok(ready, 'Isolated proxy did not start: ' + logs);
    const benign = await connectViaProxy(port, 'normal-site.example.com');
    assert.equal(benign.accepted, true, 'normal domain must reach the local stub');
    assert.deepEqual(upstreamHosts, ['normal-site.example.com']);
    for (const blocked of ['guard-check.example.com', 'manual-block.invalid', 'probe.adult']) {
      const result = await connectViaProxy(port, blocked);
      assert.equal(result.accepted, false, 'blocked domain must be rejected');
    }
    assert.deepEqual(upstreamHosts, ['normal-site.example.com'], 'blocked hosts must never reach an upstream');
    console.log(JSON.stringify({ passed: true, normalRouted: 1, rejected: 3, externalConnections: 0, dnsEnabled: false, fixture: configPath }));
  } finally {
    child.kill();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => upstream.close(resolve));
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
