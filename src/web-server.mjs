import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import os from 'node:os';
import { createWebHandler, randomToken, SERVICE_VERSION } from './web-service.mjs';
import reader from './subscription-server.cjs';
import metadataHelpers from './subscription-metadata.cjs';
import { createInternetTunnel } from './internet-tunnel.mjs';
const { normalizeMetadata } = metadataHelpers;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function lanAddresses(interfaces = os.networkInterfaces()) {
  const addresses = [];
  for (const [name, records] of Object.entries(interfaces)) {
    for (const record of records || []) {
      if (record.internal || !['IPv4', 4].includes(record.family)) continue;
      if (!/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(record.address)) continue;
      addresses.push({ address: record.address, rank: /wlan|wi-?fi|ethernet|以太网|无线/i.test(name) ? 0 : 1 });
    }
  }
  return addresses.sort((a, b) => a.rank - b.rank).map(record => record.address);
}
export function fileStore(directory) {
  const filename = (token, extension = '.json') => {
    if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('无效的订阅标识。');
    return path.join(directory, token + extension);
  };
  const getRecord = async token => {
    try {
      const record = JSON.parse(await fs.readFile(filename(token), 'utf8'));
      if (typeof record.text !== 'string') throw new Error('保存的订阅配置无法读取，请重新生成并导出。');
      return { text: record.text, metadata: normalizeMetadata(record.metadata) };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      try { return { text: await fs.readFile(filename(token, '.yaml'), 'utf8'), metadata: {} }; }
      catch (legacyError) { if (legacyError.code === 'ENOENT') return null; throw legacyError; }
    }
  };
  return {
    getRecord,
    async get(token) { return (await getRecord(token))?.text ?? null; },
    async put(token, text, metadata = {}) {
      await fs.mkdir(directory, { recursive: true });
      const destination = filename(token), temporary = destination + '.' + randomToken() + '.tmp';
      try { await fs.writeFile(temporary, JSON.stringify({ text, metadata: normalizeMetadata(metadata) }), { encoding: 'utf8', mode: 0o600 }); await fs.rename(temporary, destination); }
      finally { await fs.unlink(temporary).catch(() => {}); }
    },
    async delete(token) { for (const extension of ['.json', '.yaml']) await fs.unlink(filename(token, extension)).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
  };
}
export function createServer(options) {
  let server;
  const onStop = () => setTimeout(async () => { await options.internetTunnel?.close(); server.closeAllConnections(); server.close(); }, 200).unref();
  const handler = createWebHandler({ ...options, onStop, html: options.html || (() => fs.readFile(path.join(root, 'clash-adult-guard.html'), 'utf8')), readRemote: options.readRemote || reader.readRemoteDetails });
  server = http.createServer(async (incoming, outgoing) => {
    try {
      if (!reader.privateAddress(incoming.socket.remoteAddress)) { outgoing.writeHead(403); outgoing.end(); return; }
      const address = 'http://' + (incoming.headers.host || '127.0.0.1') + incoming.url;
      const init = { method: incoming.method, headers: incoming.headers };
      if (!['GET', 'HEAD'].includes(incoming.method)) { init.body = incoming; init.duplex = 'half'; }
      const result = await handler(new Request(address, init));
      outgoing.writeHead(result.status, Object.fromEntries(result.headers));
      outgoing.end(Buffer.from(await result.arrayBuffer()));
    } catch (_) { outgoing.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' }); outgoing.end('服务处理失败，请重试。'); }
  });
  server.once('close', () => { void options.internetTunnel?.close(); });
  return server;
}
async function main() {
  const directory = path.resolve(process.env.GUARD_DATA_DIR || path.join(root, '.data'));
  await fs.mkdir(directory, { recursive: true });
  let ownerToken = process.env.GUARD_ADMIN_TOKEN;
  if (!ownerToken) {
    const secretPath = path.join(directory, 'admin-token');
    try { ownerToken = (await fs.readFile(secretPath, 'utf8')).trim(); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      ownerToken = randomToken();
      await fs.writeFile(secretPath, ownerToken, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    }
  }
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 17896);
  const statePath = path.join(directory, 'server.json');
  let previousService = null;
  try {
    const state = JSON.parse(await fs.readFile(statePath, 'utf8'));
    const localUrl = 'http://127.0.0.1:' + state.port + '/tool/' + ownerToken;
    const response = await fetch(localUrl, { signal: AbortSignal.timeout(1000) });
    const html = await response.text();
    if (response.ok && html.includes('content="' + ownerToken + '"')) {
      if (html.includes('name="local-service-version" content="' + SERVICE_VERSION + '"')) {
        process.stdout.write(JSON.stringify({ ready: true, url: localUrl, localUrl, reused: true }) + '\n'); return;
      }
      previousService = { localUrl, port: state.port };
    }
  } catch (_) {}
  if (previousService) {
    const base = 'http://127.0.0.1:' + previousService.port;
    const stopped = await fetch(base + '/api/stop', { method: 'POST', headers: { 'X-Guard-Token': ownerToken }, signal: AbortSignal.timeout(2000) });
    if (!stopped.ok) throw new Error('无法停止旧版服务，请在旧页面点击停止本地服务后重试。');
    let oldStillRunning = true;
    for (let attempt = 0; attempt < 30 && oldStillRunning; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      try {
        const response = await fetch(previousService.localUrl, { signal: AbortSignal.timeout(500) });
        oldStillRunning = response.ok && (await response.text()).includes('content="' + ownerToken + '"');
      } catch (_) { oldStillRunning = false; }
    }
    if (oldStillRunning) throw new Error('旧版服务尚未退出，请稍后重新打开工具。');
  }
  const store = fileStore(path.join(directory, 'exports'));
  const internetTunnel = createInternetTunnel({ store, directory });
  const server = createServer({ ownerToken, store, internetTunnel, allowLocal: true, publicBaseUrl: () => {
    const address = lanAddresses()[0];
    if (!address) throw new Error('未找到手机可访问的电脑地址，请先连接网络后再导出。');
    return 'http://' + address + ':' + server.address().port;
  } });
  const shutdown = async () => { await internetTunnel.close(); server.closeAllConnections(); server.close(); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  server.on('listening', async () => {
    const localUrl = 'http://127.0.0.1:' + server.address().port + '/tool/' + ownerToken;
    await fs.writeFile(statePath, JSON.stringify({ port: server.address().port }), 'utf8');
    process.stdout.write(JSON.stringify({ ready: true, url: localUrl, localUrl }) + '\n');
    if (process.argv.includes('--open') && process.platform === 'win32') spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "Start-Process -FilePath '" + localUrl + "'"], { windowsHide: true, stdio: 'ignore' }).on('error', () => {});
  });
  let fallback = false;
  server.on('error', error => {
    if (error.code === 'EADDRINUSE' && !fallback) { fallback = true; server.listen(0, host); return; }
    console.error('服务启动失败，请检查端口及文件夹权限。'); process.exitCode = 1;
  });
  server.listen(port, host);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => { console.error('启动失败，请确认数据目录可写，且已安装 Node.js。'); process.exitCode = 1; });
