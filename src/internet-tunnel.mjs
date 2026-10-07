import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { createWebHandler, randomToken } from './web-service.mjs';

const tokenPattern = /^[a-f0-9]{64}$/;
const startupError = () => new Error('外网通道连接失败，请检查电脑网络后重试。也可使用局域网链接。');

export function tunnelOrigin(output) {
  const clean = output.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
  const matches = clean.match(/https:\/\/[a-z0-9-]+\.(?:lhr\.life|localhost\.run)(?=[\s/"'\\]|$)/gi) || [];
  for (const match of matches.reverse()) {
    const url = new URL(match);
    if (/^(?:admin|docs)\./.test(url.hostname)) continue;
    return url.origin;
  }
  return null;
}

// This listener is separate from the management service and exposes downloads only.
export function createDownloadBridge({ store, publishedIds, healthToken = randomToken(), healthValue = 'adult-guard-ready' }) {
  const handler = createWebHandler({ ownerToken: randomToken(), store });
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://127.0.0.1');
      const readable = ['GET', 'HEAD'].includes(request.method);
      if (readable && url.pathname === '/health/' + healthToken) {
        response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(healthValue) });
        response.end(request.method === 'HEAD' ? '' : healthValue);
        return;
      }
      const download = url.pathname.match(/^\/sub\/([a-f0-9]{64})\.yaml$/);
      if (!readable || !download || !publishedIds.has(download[1])) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength('Not found') });
        response.end(request.method === 'HEAD' ? '' : 'Not found');
        return;
      }
      const result = await handler(new Request('http://127.0.0.1' + url.pathname, { method: 'GET' }));
      const bytes = Buffer.from(await result.arrayBuffer());
      response.writeHead(result.status, { ...Object.fromEntries(result.headers), 'Content-Length': bytes.length });
      response.end(request.method === 'HEAD' ? undefined : bytes);
    } catch (_) {
      response.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': Buffer.byteLength('Download unavailable') });
      response.end('Download unavailable');
    }
  });
}

export function createInternetTunnel(options) {
  const { store, directory } = options;
  const spawnProcess = options.spawnProcess || spawn;
  const fetchPublic = options.fetchPublic || fetch;
  const ssh = options.sshExecutable || (os.platform() === 'win32'
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'OpenSSH', 'ssh.exe') : 'ssh');
  const publishedIds = new Set();
  const sessions = new Set();
  let active = null;
  let pending = null;
  let closed = false;

  async function available(session) {
    if (!session?.alive || !session.origin || closed) return false;
    try {
      const response = await fetchPublic(session.origin + '/health/' + session.healthToken,
        { redirect: 'error', headers: { Connection: 'close' }, signal: AbortSignal.timeout(options.probeTimeoutMs || 10000) });
      return response.ok && await response.text() === session.healthValue && session.alive && !closed;
    } catch (_) { return false; }
  }

  async function connect() {
    await fs.mkdir(directory, { recursive: true });
    if (closed) throw new Error('本地服务已停止，请重新启动工具。');
    const healthToken = randomToken();
    const healthValue = randomToken();
    const bridge = createDownloadBridge({ store, publishedIds, healthToken, healthValue });
    bridge.requestTimeout = 15000;
    bridge.headersTimeout = 15000;
    const session = { bridge, child: null, origin: null, healthToken, healthValue, alive: true, cancel: null, disposal: null };
    sessions.add(session);
    session.dispose = () => {
      if (session.disposal) return session.disposal;
      session.alive = false;
      if (active === session) active = null;
      let complete;
      session.disposal = new Promise(resolve => { complete = resolve; });
      session.child?.kill();
      bridge.closeAllConnections();
      if (!bridge.listening) { sessions.delete(session); complete(); }
      else bridge.close(() => { sessions.delete(session); complete(); });
      return session.disposal;
    };
    try {
      await new Promise((resolve, reject) => {
        bridge.once('error', reject);
        bridge.listen(0, '127.0.0.1', resolve);
      });
      if (closed || !session.alive) {
        bridge.closeAllConnections();
        await new Promise(resolve => bridge.close(resolve));
        throw new Error('本地服务已停止，请重新启动工具。');
      }
      const knownHosts = path.join(directory, 'internet-known-hosts').replaceAll('\\', '/');
      const args = ['-F', os.platform() === 'win32' ? 'NUL' : '/dev/null', '-T',
        '-o', 'BatchMode=yes', '-o', 'IdentityAgent=none', '-o', 'IdentityFile=none',
        '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile="' + knownHosts + '"',
        '-o', 'ConnectTimeout=15', '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3', '-o', 'ExitOnForwardFailure=yes',
        '-R', '80:127.0.0.1:' + bridge.address().port, 'nokey@localhost.run', '--', '--output', 'json'];
      const child = spawnProcess(ssh, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      session.child = child;
      await new Promise((resolve, reject) => {
        let output = '';
        let finished = false;
        const finish = error => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          error ? reject(error) : resolve();
        };
        session.cancel = () => finish(new Error('本地服务已停止，请重新启动工具。'));
        const timer = setTimeout(() => finish(new Error('外网通道启动超时，请检查电脑网络后重新生成链接。')), options.startupTimeoutMs || 25000);
        const collect = bytes => {
          // Request logs must never replace the domain assigned during startup.
          if (finished) return;
          output = (output + bytes.toString('utf8')).slice(-32768);
          const origin = tunnelOrigin(output);
          if (origin) { session.origin = origin; active = session; finish(); }
        };
        child.stdout.on('data', collect);
        child.stderr.on('data', collect);
        child.once('error', error => {
          finish(error.code === 'ENOENT'
            ? new Error('未找到系统 SSH 客户端，请在 Windows 可选功能中启用 OpenSSH 客户端。无需下载额外 exe。') : startupError());
          void session.dispose();
        });
        child.once('close', () => { finish(startupError()); void session.dispose(); });
      });
      let verified = false;
      for (let attempt = 0; attempt < 2 && session.alive && !closed; attempt++) {
        verified = await available(session);
        if (verified) break;
      }
      if (!verified || closed || !session.alive) throw new Error('外网地址尚未连通，请稍后重新生成。未生成可用链接。');
      return session.origin;
    } catch (error) { await session.dispose(); throw error; }
  }

  return {
    async ensure() {
      if (closed) throw new Error('本地服务已停止，请重新启动工具。');
      if (pending) return pending;
      pending = (async () => {
        if (active?.alive && active.origin) {
          const session = active;
          if (await available(session)) return session.origin;
          await session.dispose();
        }
        return connect();
      })();
      try { return await pending; } finally { pending = null; }
    },
    publish(id) {
      if (!tokenPattern.test(id)) throw new Error('无效的订阅标识。');
      publishedIds.add(id);
    },
    unpublish(id) { publishedIds.delete(id); },
    async close() {
      closed = true;
      publishedIds.clear();
      for (const session of sessions) session.cancel?.();
      await Promise.all([...sessions].map(session => session.dispose()));
    }
  };
}
