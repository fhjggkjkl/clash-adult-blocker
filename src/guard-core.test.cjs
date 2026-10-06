'use strict';
// Offline semantic tests; run: node src/guard-core.test.cjs
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('./guard-core.js');
const realPayload = yaml.load(fs.readFileSync(path.join(__dirname, '../rules/adult-domains.yaml'), 'utf8')).payload;
const tinyPayload = ['+.blocked.example', 'exact.blocked.example', '+.adult', '+.porn', '+.blocked.example'];
function original() {
  return {
    mode: 'global',
    'mixed-port': 7890,
    proxies: [{ name: 'Node', type: 'socks5', server: '127.0.0.1', port: 1080 }],
    'proxy-groups': [{ name: 'Select', type: 'select', proxies: ['Node', 'DIRECT'] }],
    dns: { enable: true, 'enhanced-mode': 'fake-ip', nameserver: ['https://dns.example/dns-query'], 'fake-ip-filter': ['*.example.com'] },
    sniffer: { enable: false, 'skip-domain': ['safe.example.com'], 'override-destination': true, sniff: { TLS: { ports: [443], 'override-destination': false } } },
    rules: ['DOMAIN-SUFFIX,unrelated.example,Select', 'MATCH,Select']
  };
}
function patch(config = original(), options = {}) { return guard.patch({ yaml, defaultsPayload: tinyPayload, configText: yaml.dump(config), ...options }); }
let passed = 0;
function test(name, fn) { fn(); passed++; console.log('PASS ' + name); }

test('Meta injection preserves original DNS, nodes and routing suffix', () => {
  const before = original();
  const result = patch(before, { safeTest: true, sniff: true });
  assert.equal(result.config.mode, 'rule');
  assert.deepEqual(result.config.dns, before.dns);
  assert.deepEqual(result.config.proxies, before.proxies);
  assert.deepEqual(result.config['proxy-groups'], before['proxy-groups']);
  assert.deepEqual(result.config.rules.slice(-before.rules.length), before.rules);
  assert.equal(result.config.rules[0], 'DOMAIN,guard-check.example.com,REJECT');
  assert.equal(result.config['rule-providers']['local-adult-guard-v1'].type, 'inline');
  assert.equal(result.config['rule-providers']['local-adult-guard-v1'].payload.length, 4);
  assert.deepEqual(yaml.load(result.text), result.config);
});
test('Sniffer merge retains existing protocol options and skip-domain', () => {
  const before = original(), result = patch(before, { sniff: true });
  assert.equal(result.config.sniffer.enable, true);
  assert.equal(result.config.sniffer['parse-pure-ip'], true);
  assert.equal(result.config.sniffer['force-dns-mapping'], true);
  assert.deepEqual(result.config.sniffer.sniff.TLS, before.sniffer.sniff.TLS);
  assert.deepEqual(result.config.sniffer['skip-domain'], before.sniffer['skip-domain']);
  assert.equal(result.config.sniffer['override-destination'], true);
  assert.deepEqual(result.config.sniffer.sniff.QUIC.ports, [443, 8443]);
});
test('Legacy retains exact-versus-suffix semantics and omits new sniffer/provider', () => {
  const before = original(); delete before.sniffer;
  const result = patch(before, { legacy: true, sniff: true });
  assert.ok(result.config.rules.includes('DOMAIN,exact.blocked.example,REJECT'));
  assert.ok(result.config.rules.includes('DOMAIN-SUFFIX,blocked.example,REJECT'));
  assert.ok(result.config.rules.includes('DOMAIN-SUFFIX,adult,REJECT'));
  assert.equal(result.config['rule-providers'], undefined);
  assert.equal(result.config.sniffer, undefined);
});
test('Reapplying own output is idempotent, including a Meta-to-legacy switch', () => {
  const first = patch(original(), { safeTest: true, sniff: true });
  const second = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: first.text, safeTest: true, sniff: true });
  assert.deepEqual(second.config, first.config);
  const legacy = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: first.text, legacy: true });
  assert.equal(legacy.config['rule-providers'], undefined);
  assert.deepEqual(legacy.config.rules.slice(-2), original().rules);
});
test('Existing provider-name collision preserves the original provider', () => {
  const before = original();
  before['rule-providers'] = { 'local-adult-guard-v1': { type: 'inline', behavior: 'domain', payload: ['keep.example.com'] } };
  const result = patch(before);
  assert.deepEqual(result.config['rule-providers']['local-adult-guard-v1'], before['rule-providers']['local-adult-guard-v1']);
  assert.equal(result.config['x-local-adult-guard'].providerName, 'local-adult-guard-v1-2');
});
test('Manual domains accept IDN and URLs, deduplicate, and reject unsafe shapes', () => {
  const domains = guard.parseExtraDomains('Blocked.Example.com\nhttps://blocked.example.com/path\nhttps://例子.中国/path\n# a comment');
  assert.deepEqual(domains, ['blocked.example.com', 'xn--fsqu00a.xn--fiqs8s']);
  for (const invalid of ['127.0.0.1', '127.1', 'https://[::1]', '*.example.com', 'com', 'co.uk', 'example.com,REJECT', 'https://user:pass@example.com', 'http://example.com:8080']) assert.throws(() => guard.parseExtraDomains(invalid));
});
test('Tampered markers and generated rules fail rather than remove unrelated data', () => {
  const first = patch();
  first.config.rules[0] = 'DOMAIN,changed.example,DIRECT';
  assert.throws(() => patch(first.config), /修改/);
  const collision = original(); collision['x-local-adult-guard'] = { owner: 'somebody-else' };
  assert.throws(() => patch(collision), /标记/);
});
test('User references to an owned provider are refused before it is removed', () => {
  const output = patch();
  output.config.rules.splice(-1, 0, 'RULE-SET,local-adult-guard-v1,DIRECT');
  assert.throws(() => patch(output.config, { legacy: true }), /引用/);
  const subRule = patch();
  subRule.config['sub-rules'] = { local: ['RULE-SET,local-adult-guard-v1,DIRECT'] };
  assert.throws(() => patch(subRule.config, { legacy: true }), /引用/);
});
test('YAML duplicates, multiple documents, snippets and malformed providers fail', () => {
  for (const text of ['rules: []\nrules: []', '---\nfoo: 1\n---\nfoo: 2', 'payload:\n - +.example.com', 'proxies: []\nrules: []', 'proxies:\n - name: Node\nrules:\n - 123', 'proxies:\n - name: Node\nrules: []\nrule-providers:\n bad: nope']) assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: text }));
});
test('A provider-based complete config remains supported', () => {
  const result = patch({ 'proxy-providers': { Subscription: { type: 'http', url: 'https://subscription.example', path: './subscription.yaml' } }, rules: ['MATCH,DIRECT'] });
  assert.equal(result.config['proxy-providers'].Subscription.url, 'https://subscription.example');
});

test('Plain pasted YAML, CRLF and BOM produce the same config without a file', () => {
  const text = yaml.dump(original());
  const baseline = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: text });
  for (const pasted of [text, '\uFEFF' + text, text.replace(/\n/g, '\r\n'), '\n\n' + text + '\n']) {
    const result = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: pasted });
    assert.deepEqual(result.config, baseline.config);
  }
});

test('Pasted fenced YAML/JSON and a quoted document preserve field content', () => {
  const before = original();
  before.proxies[0].password = 'literal\\npassword';
  const text = yaml.dump(before);
  const baseline = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: text });
  for (const pasted of ['```yaml\n' + text + '```', '~~~yml\n' + text + '~~~', '```json\n' + JSON.stringify(before) + '\n```', JSON.stringify(text)]) {
    const result = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: pasted });
    assert.deepEqual(result.config, baseline.config);
    assert.equal(yaml.load(result.text).proxies[0].password, before.proxies[0].password);
  }
});

test('Subscription and node links get actionable errors without exposing their secrets', () => {
  const url = 'https://subscription.example/profile?token=private-example-token';
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: url }), error => /订阅链接/.test(error.message) && !error.message.includes('private-example-token'));
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: 'vmess://example-encoded-node' }), /节点分享链接/);
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: '- name: Node\n  type: socks5\n' }), /单独的列表/);
});
test('Full bundled source works in Meta and legacy with identical match count', () => {
  const meta = patch(original(), { defaultsPayload: realPayload });
  const legacy = patch(original(), { defaultsPayload: realPayload, legacy: true });
  assert.equal(meta.stats.defaults, new Set(realPayload).size);
  assert.equal(legacy.stats.generatedRules, meta.stats.defaults);
  assert.ok(meta.stats.defaults > 6000);
});
test('Oversized input is refused before YAML parsing', () => {
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: '#'.repeat(12 * 1024 * 1024 + 1) }), /12 MB/);
});
test('Ambiguous leading-zero and unsafe integers fail while quoted strings survive', () => {
  const base = yaml.dump(original());
  for (const spelling of ['0123', '-0123', '+0_123', '9007199254740993', '-9007199254740993']) assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nsecret: ' + spelling + '\n' }), /前导零数值或超出精确范围/);
  const octalPort = base.replace('port: 1080', 'port: 0123');
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: octalPort }), /端口写明实际十进制/);
  for (const spelling of ['0123', '9007199254740993']) {
    const result = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nsecret: "' + spelling + '"\n' });
    assert.equal(result.config.secret, spelling);
  }
  const zero = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nport: 0\n' });
  assert.equal(zero.config.port, 0);
});
test('Implicit timestamps and non-text credentials fail; quoted text remains exact', () => {
  const base = yaml.dump(original());
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nsecret: 2020-01-01\n' }), /日期或时间/);
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\ncreated: 2020-01-01T12:34:56Z\n' }), /日期或时间/);
  assert.throws(() => guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nsecret: 123\n' }), /凭据字段 secret/);
  const numericPassword = original(); numericPassword.proxies[0].password = 123;
  assert.throws(() => patch(numericPassword), /凭据字段 password/);
  for (const text of ['2020-01-01', '2020-01-01T12:34:56Z', '123']) {
    const result = guard.patch({ yaml, defaultsPayload: tinyPayload, configText: base + '\nsecret: "' + text + '"\n' });
    assert.equal(yaml.load(result.text).secret, text);
  }
});
console.log(`${passed} offline tests passed. No phone or network test performed.`);
