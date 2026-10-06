'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const zlib = require('node:zlib');
const { normalizeMetadata } = require('../src/subscription-metadata.cjs');
const { readRemoteDetails } = require('../src/subscription-server.cjs');
const info = 'upload=100; download=2500; total=107374182400; expire=1800000000';
test('Subscription information keeps exact integer values and rejects unsafe headers', () => {
  assert.deepEqual(normalizeMetadata({ userinfo: info }), { userinfo: info });
  assert.equal(normalizeMetadata({ userinfo: 'total=9007199254740993; download=0; upload=0001' }).userinfo, 'upload=1; download=0; total=9007199254740993');
  for (const raw of [info + '\r\nX-Injected: value', info + '; upload=3', 'upload=-1; download=2; total=3', 'upload=1; download=2; total=1e9', 'upload=1; download=2; total=9223372036854775808']) assert.deepEqual(normalizeMetadata({ userinfo: raw }), {});
  assert.deepEqual(normalizeMetadata(null), {});
});
test('The HTTPS reader preserves traffic information from the final compressed response', async () => {
  const addresses = [], config = 'proxies: []\nrules: [MATCH,DIRECT]\n';
  function transport(url, options, callback) {
    addresses.push(url.href);
    assert.equal(typeof options.lookup, 'function');
    const request = new EventEmitter(); request.destroy = () => {};
    setImmediate(() => {
      const response = new PassThrough();
      response.statusCode = addresses.length === 1 ? 302 : 200;
      response.headers = response.statusCode === 302 ? { location: '/final?token=fake-test-token', 'subscription-userinfo': 'upload=0; download=0; total=0' } : {
        'content-type': 'application/yaml; charset=utf-8', 'content-encoding': 'gzip', 'subscription-userinfo': info, 'set-cookie': ['secret=fake']
      };
      callback(response);
      response.end(response.statusCode === 200 ? zlib.gzipSync(config) : '');
    });
    return request;
  }
  const result = await readRemoteDetails('https://subscription.example/start', 0, Date.now() + 2000, transport);
  assert.equal(result.text, config);
  assert.deepEqual(result.metadata, { userinfo: info });
  assert.deepEqual(addresses, ['https://subscription.example/start', 'https://subscription.example/final?token=fake-test-token']);
  assert.ok(!JSON.stringify(result.metadata).includes('secret'));
});
