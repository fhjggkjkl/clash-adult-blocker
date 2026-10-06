import metadataHelpers from './subscription-metadata.cjs';
const { normalizeMetadata } = metadataHelpers;
const LIMIT = 12 * 1024 * 1024;
const tokenPattern = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'
  } });
}
function authorized(value, expected) {
  if (typeof value !== 'string' || !expected || value.length !== expected.length) return false;
  let difference = 0;
  for (let i = 0; i < value.length; i++) difference |= value.charCodeAt(i) ^ expected.charCodeAt(i);
  return difference === 0;
}
export function randomToken() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export function publicOrigin(value, allowLocal = false) {
  let url;
  try { url = new URL(value); } catch (_) { throw new Error('本地服务地址无法读取，请重新启动工具后导出订阅链接。'); }
  const host = url.hostname;
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(host);
  if (url.username || url.password || (local && !allowLocal) || (url.protocol !== 'https:' && !(allowLocal && local && url.protocol === 'http:'))) {
    throw new Error('未找到可用于订阅链接的服务地址，请检查电脑网络连接。');
  }
  return url.origin;
}
async function inputJson(request) {
  if (!request.headers.get('content-type')?.startsWith('application/json')) throw new Error('请求格式不正确，请刷新工具页面。');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('请求内容为空。');
  const chunks = []; let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > LIMIT * 2) { await reader.cancel(); throw new Error('配置内容超过允许大小。'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch (_) { throw new Error('请求内容无法正确读取，请刷新页面后重试。'); }
  } finally { reader.releaseLock(); }
}
export function createWebHandler(options) {
  const { ownerToken, store, readRemote } = options;
  if (!tokenPattern.test(ownerToken)) throw new Error('服务管理密钥必须是 32 字节随机值。');
  return async function handle(request) {
    const url = new URL(request.url);
    const download = url.pathname.match(/^\/sub\/([a-f0-9]{64})\.yaml$/);
    if (download && ['GET', 'HEAD'].includes(request.method)) {
      const record = store.getRecord ? await store.getRecord(download[1]) : { text: await store.get(download[1]) };
      if (!record || record.text === null) return json({ error: '订阅链接不存在或已停用。' }, 404);
      const metadata = normalizeMetadata(record.metadata);
      return new Response(request.method === 'HEAD' ? null : record.text, { headers: {
        'Content-Type': 'application/yaml; charset=utf-8', 'Content-Disposition': 'attachment; filename=clash-adult-guard.yaml',
        ...(metadata.userinfo ? { 'Subscription-Userinfo': metadata.userinfo } : {}),
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'none'"
      } });
    }
    if (request.method === 'GET' && url.pathname === '/tool/' + ownerToken) {
      let html = typeof options.html === 'function' ? await options.html(request) : options.html;
      html = html.replace("connect-src 'none'", "connect-src 'self'");
      html = html.replace('</head>', () => '<meta name="local-subscription-token" content="' + ownerToken + '">\n</head>');
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' } });
    }
    if (!url.pathname.startsWith('/api/')) return json({ error: '请使用服务管理员提供的工具入口。' }, 404);
    if (!authorized(request.headers.get('x-guard-token'), ownerToken)) return json({ error: '工具入口无效，请重新打开管理员入口。' }, 403);
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) return json({ error: '请从工具页面发起操作。' }, 403);
    try {
      if (request.method === 'POST' && url.pathname === '/api/subscription') {
        const input = await inputJson(request);
        const remote = await readRemote(input.url);
        return json({ text: typeof remote === 'string' ? remote : remote.text, metadata: normalizeMetadata(remote.metadata), notice: '' });
      }
      if (request.method === 'POST' && url.pathname === '/api/exports') {
        const target = typeof options.publicBaseUrl === 'function' ? options.publicBaseUrl() : options.publicBaseUrl;
        const base = publicOrigin(target || url.origin, options.allowLocal === true);
        const input = await inputJson(request);
        if (typeof input.configText !== 'string' || !input.configText.trim() || encoder.encode(input.configText).length > LIMIT) throw new Error('请先生成有效的完整配置，再导出订阅链接。');
        if (!/^rules:/m.test(input.configText) || !/^(?:proxies|proxy-providers):/m.test(input.configText)) throw new Error('导出内容必须是包含节点和分流规则的完整配置。');
        let token;
        if (input.exportId !== undefined) {
          if (!tokenPattern.test(input.exportId) || await store.get(input.exportId) === null) return json({ error: '原链接已停用，请重新导出。' }, 404);
          token = input.exportId;
        } else { token = randomToken(); }
        await store.put(token, input.configText, normalizeMetadata(input.metadata));
        return json({ id: token, url: base + '/sub/' + token + '.yaml' });
      }
      const revoke = url.pathname.match(/^\/api\/exports\/([a-f0-9]{64})$/);
      if (request.method === 'DELETE' && revoke) { await store.delete(revoke[1]); return json({ revoked: true }); }
      if (request.method === 'POST' && url.pathname === '/api/stop' && options.onStop) { options.onStop(); return json({ stopped: true }); }
      return json({ error: '不支持的操作。' }, 404);
    } catch (error) {
      const message = String(error.message || '').split('\n')[0];
      return json({ error: /[\u3400-\u9fff]/.test(message) ? message : '服务处理失败，请检查配置、网络或服务设置后重试。' }, 422);
    }
  };
}
