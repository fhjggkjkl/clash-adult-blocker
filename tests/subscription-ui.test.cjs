'use strict';
// Exercise the shipped page's real button handlers with a minimal DOM, without a browser.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const yaml = require('../vendor/js-yaml.min.js');
const { createServer } = require('../src/subscription-server.cjs');
const input = { proxies: [{ name: 'Test node', type: 'socks5', server: 'example.com', port: 443 }], rules: ['MATCH,Test node'] };
const html = fs.readFileSync(path.join(__dirname, '../clash-adult-guard.html'), 'utf8');

function page(source, options = {}) {
  const elements = new Map();
  for (const match of source.matchAll(/\bid="([^"]+)"/g)) {
    const listeners = new Map();
    elements.set(match[1], { value: '', textContent: '', checked: false, disabled: false, hidden: false, files: [],
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(type, callback) { listeners.set(type, callback); },
      fire(type) { return listeners.get(type)?.(); }
    });
  }
  elements.get('format').value = 'meta';
  elements.get('sniff').checked = true;
  elements.get('safe-test').checked = true;
  const token = source.match(/name="local-subscription-token" content="([a-f0-9]+)"/)?.[1];
  const context = vm.createContext({ TextEncoder, URL, Blob, setTimeout, clearTimeout,
    location: options.location || { protocol: 'file:', hostname: '' },
    navigator: {}, fetch: options.fetch || (() => { throw new Error('Offline page must not fetch.'); }),
    document: { getElementById: id => elements.get(id), querySelector: () => token ? { content: token } : null }
  });
  for (const match of source.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (!match[1].includes('application/json')) vm.runInContext(match[2], context);
  }
  return elements;
}

test('Offline paste generates without a selected file and links give a launcher instruction', async () => {
  const elements = page(html);
  assert.equal(elements.get('read-subscription').disabled, true);
  elements.get('config').value = '```yaml\n' + yaml.dump(input) + '```';
  await elements.get('generate').fire('click');
  const config = yaml.load(elements.get('output').value);
  assert.deepEqual(config.proxies, input.proxies);
  assert.equal(config.rules[0], 'DOMAIN,guard-check.example.com,REJECT');
  assert.equal(elements.get('result').hidden, false);
  elements.get('config').value = 'https://subscription.example/path?token=fake-test-token';
  elements.get('config').fire('input');
  await elements.get('generate').fire('click');
  assert.equal(elements.get('result').hidden, true);
  assert.match(elements.get('status').textContent, /启动工具\.cmd/);
  assert.ok(!elements.get('status').textContent.includes('fake-test-token'));
});

test('Pasting a subscription URL in the original box reads and automatically generates via the local service', async t => {
  let remoteCalls = 0;
  const server = createServer({ readRemote: async url => { remoteCalls++; assert.equal(url, 'https://subscription.example/path?token=fake-test-token'); return yaml.dump(input); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = 'http://127.0.0.1:' + server.address().port;
  const source = await (await fetch(base)).text();
  const elements = page(source, { location: { protocol: 'http:', hostname: '127.0.0.1' }, fetch: (route, options) => fetch(base + route, options) });
  assert.equal(elements.get('read-subscription').disabled, false);
  elements.get('config').value = 'https://subscription.example/path?token=fake-test-token';
  await elements.get('generate').fire('click');
  assert.equal(remoteCalls, 1);
  assert.equal(elements.get('result').hidden, false);
  const config = yaml.load(elements.get('output').value);
  assert.deepEqual(config.proxies, input.proxies);
  assert.equal(config.rules[0], 'DOMAIN,guard-check.example.com,REJECT');
  assert.equal(config.rules.at(-1), input.rules[0]);
  assert.equal(config.mode, 'rule');
  assert.equal(elements.get('generate').disabled, false);
});

test('A response does not overwrite configuration edited while the subscription was loading', async () => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const source = html.replace('</head>', '<meta name="local-subscription-token" content="abcdef"></head>');
  const elements = page(source, { location: { protocol: 'http:', hostname: '127.0.0.1' }, fetch: () => pending });
  elements.get('subscription').value = 'https://subscription.example/path';
  const loading = elements.get('read-subscription').fire('click');
  elements.get('config').value = yaml.dump(input);
  elements.get('config').fire('input');
  release({ ok: true, json: async () => ({ text: yaml.dump({ ...input, rules: ['MATCH,DIRECT'] }) }) });
  await loading;
  assert.equal(elements.get('config').value, yaml.dump(input));
  assert.equal(elements.get('result').hidden, true);
  assert.match(elements.get('status').textContent, /保留当前输入/);
});
