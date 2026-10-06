'use strict';
// Loopback-only subscription reader. No remote converter or configuration storage.
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const yaml = require('../vendor/js-yaml.min.js');
const guard = require('./guard-core.js');
const { decodeText } = require('./text-encoding.cjs');
const { normalizeMetadata } = require('./subscription-metadata.cjs');
const LIMIT = 12 * 1024 * 1024;

function privateAddress(address) {
  const value = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (value.startsWith('::ffff:')) {
    const mapped = value.slice(7);
    if (net.isIP(mapped) === 4) return privateAddress(mapped);
    const words = mapped.split(':');
    if (words.length !== 2 || words.some(word => !/^[0-9a-f]{1,4}$/.test(word))) return true;
    const [high, low] = words.map(word => parseInt(word, 16));
    return privateAddress([high >> 8, high & 255, low >> 8, low & 255].join('.'));
  }
  if (net.isIP(value) === 4) {
    const [a, b] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return value === '::' || value === '::1' || /^(?:fc|fd|fe[89ab])/i.test(value);
}
function subscriptionUrl(value) {
  if (typeof value !== 'string' || value.length > 8192) throw new Error('请填写有效的 https 订阅链接。');
  let url;
  try { url = new URL(value); } catch (_) { throw new Error('请填写有效的 https 订阅链接。'); }
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('请使用 https 订阅链接，账号密码应由订阅提供方的链接参数携带。');
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || (net.isIP(hostname) && privateAddress(hostname))) throw new Error('请使用订阅提供方的公开 https 地址，不能请求本机或内网地址。');
  url.hash = '';
  return url;
}
function publicLookup(hostname, options, callback) {
  const requested = typeof options === 'number' ? { family: options } : options || {};
  dns.lookup(hostname, { ...requested, all: true }, (error, records) => {
    if (error) return callback(error);
    if (!records.length || records.some(record => privateAddress(record.address))) return callback(new Error('Private network addresses are not allowed.'));
    if (requested.all) callback(null, records);
    else callback(null, records[0].address, records[0].family);
  });
}
function readRemoteDetails(value, hops = 0, deadline = Date.now() + 25000, transport = https.get) {
  const url = subscriptionUrl(value);
  if (hops > 4) return Promise.reject(new Error('订阅重定向次数过多，请使用最终订阅链接。'));
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return reject(new Error('读取订阅超时，请检查网络后重试。'));
    let settled = false;
    const finish = (error, text) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(text);
    };
    const request = transport(url, {
      lookup: publicLookup,
      headers: { 'User-Agent': 'ClashMeta/1.19.29', Accept: 'application/yaml, text/yaml, application/json, text/plain', 'Accept-Encoding': 'identity' }
    }, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        let next;
        try { next = subscriptionUrl(new URL(response.headers.location, url).href); }
        catch (error) { finish(error); return; }
        clearTimeout(timer); settled = true;
        readRemoteDetails(next.href, hops + 1, deadline, transport).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        finish(new Error('订阅提供方返回 HTTP ' + response.statusCode + '，请检查链接是否有效或已过期。'));
        return;
      }
      let stream = response;
      const encoding = String(response.headers['content-encoding'] || '').toLowerCase();
      if (encoding === 'gzip') stream = response.pipe(zlib.createGunzip());
      else if (encoding === 'deflate') stream = response.pipe(zlib.createInflate());
      else if (encoding === 'br') stream = response.pipe(zlib.createBrotliDecompress());
      const chunks = []; let size = 0;
      stream.on('data', chunk => {
        size += chunk.length;
        if (size > LIMIT) { finish(new Error('订阅配置超过 12 MB，无法导入。')); stream.destroy(); request.destroy(); return; }
        chunks.push(chunk);
      });
      stream.on('end', () => {
        try { finish(null, { text: decodeText(Buffer.concat(chunks), response.headers['content-type']).text, metadata: normalizeMetadata({ userinfo: response.headers['subscription-userinfo'] }) }); }
        catch (error) { finish(error); }
      });
      stream.on('error', () => finish(new Error('读取订阅响应失败，请检查网络后重试。')));
      response.on('error', () => finish(new Error('订阅连接中断，请重试。')));
    });
    const timer = setTimeout(() => { finish(new Error('读取订阅超时，请检查网络后重试。')); request.destroy(); }, remaining);
    request.on('error', () => finish(new Error('无法连接订阅提供方，请检查网络及订阅链接。')));
  });
}
async function readRemote(value) { return (await readRemoteDetails(value)).text; }
function createServer(options = {}) {
  const root = options.root || path.resolve(__dirname, '..');
  const reader = options.readRemote || readRemoteDetails;
  const token = crypto.randomBytes(24).toString('hex');
  const server = http.createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    const port = server.address().port;
    const hosts = ['127.0.0.1:' + port, 'localhost:' + port];
    const origin = request.headers.origin;
    const json = (status, body) => { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(body)); };
    if (!hosts.includes(request.headers.host)) return json(403, { error: '只允许本机访问。' });
    if (origin && !hosts.map(host => 'http://' + host).includes(origin)) return json(403, { error: '只允许本地工具页面发起请求。' });
    const route = new URL(request.url, 'http://127.0.0.1').pathname;
    if (request.method === 'GET' && (route === '/' || route === '/clash-adult-guard.html')) {
      try {
        let html = fs.readFileSync(path.join(root, 'clash-adult-guard.html'), 'utf8');
        html = html.replace("connect-src 'none'", "connect-src 'self'");
        html = html.replace('</head>', () => '<meta name="local-subscription-token" content="' + token + '">\n</head>');
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); response.end(html);
      } catch (_) { json(500, { error: '工具文件缺失，请解压完整工具包后重试。' }); }
      return;
    }
    if (route !== '/api/subscription') return json(404, { error: '不存在的页面。' });
    if (request.method !== 'POST') return json(405, { error: '请通过本地页面读取订阅。' });
    if (request.headers['x-guard-token'] !== token) return json(403, { error: '页面已过期，请刷新本地工具页面。' });
    if (!String(request.headers['content-type'] || '').startsWith('application/json')) return json(415, { error: '请求格式不正确。' });
    const chunks = []; let size = 0;
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 16384) return json(413, { error: '订阅链接过长。' });
        chunks.push(chunk);
      }
    } catch (_) { if (!response.destroyed) json(400, { error: '请求已中断，请重试。' }); return; }
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch (_) { return json(400, { error: '订阅链接格式不正确。' }); }
    let target;
    try { target = subscriptionUrl(input && input.url); }
    catch (error) { return json(400, { error: error.message }); }
    try {
      const remote = await reader(target.href);
      const text = typeof remote === 'string' ? remote : remote.text;
      const prepared = guard.prepareSubscription({ yaml, text });
      json(200, { ...prepared, metadata: normalizeMetadata(remote.metadata) });
    } catch (error) {
      // Parser snippets may contain a password. Keep those out of API errors/logs.
      const message = String(error.message || '读取失败，请重试。').split('\n')[0];
      json(422, { error: message });
    }
  });
  return server;
}
if (require.main === module) {
  const server = createServer();
  server.listen(0, '127.0.0.1', () => {
    const address = 'http://127.0.0.1:' + server.address().port + '/';
    console.log('订阅读取工具已启动：' + address);
    console.log('请保持此窗口打开；关闭窗口会停止本地服务。订阅和配置不会保存到服务器文件。');
    if (process.argv.includes('--open') && process.platform === 'win32') {
      require('node:child_process').spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "Start-Process -FilePath '" + address + "'"], { windowsHide: true, stdio: 'ignore' }).on('error', () => {});
    }
  });
  server.on('error', () => { console.error('启动失败，请确认 Node.js 可用后重试。'); process.exitCode = 1; });
}
module.exports = { createServer, subscriptionUrl, privateAddress, readRemote, readRemoteDetails };
