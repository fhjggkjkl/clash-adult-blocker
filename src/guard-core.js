(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.LocalAdultGuard = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const MARKER = 'x-local-adult-guard';
  const OWNER = 'offline-clash-adult-guard';
  const LIMIT = 12 * 1024 * 1024;
  const RESERVED_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.kr', 'co.nz', 'com.hk', 'com.tw', 'com.sg', 'com.br']);
  const isMap = value => value !== null && Object.prototype.toString.call(value) === '[object Object]';
  function fail(message) { throw new Error(message); }
  function hash(strings) {
    let value = 2166136261;
    for (const string of strings) {
      for (let i = 0; i < string.length; i++) { value ^= string.charCodeAt(i); value = Math.imul(value, 16777619); }
      value ^= 10; value = Math.imul(value, 16777619);
    }
    return (value >>> 0).toString(16).padStart(8, '0');
  }
  function hostname(value, allowTld) {
    let host;
    try { host = new URL('https://' + value).hostname.toLowerCase().replace(/\.$/, ''); }
    catch (_) { fail('域名格式不正确：' + value); }
    const labels = host.split('.');
    if (host.length > 253 || (!allowTld && labels.length < 2) || /^\d+(?:\.\d+)*$/.test(host) || host.indexOf(':') !== -1 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) fail('请输入有效的完整域名，不支持 IP、通配符或单个顶级域名：' + value);
    if (!/^[a-z][a-z0-9-]*$/.test(labels[labels.length - 1])) fail('域名后缀不正确：' + value);
    return host;
  }
  function parseExtraDomains(text) {
    if (text == null || text === '') return [];
    if (typeof text !== 'string' || text.length > 65536) fail('额外域名内容过长，最多 64 KB。');
    const result = new Set();
    for (const [index, raw] of text.split(/\r?\n/).entries()) {
      const input = raw.trim();
      if (!input || input.charAt(0) === '#') continue;
      let value = input;
      if (/^https?:\/\//i.test(input)) {
        let parsed;
        try { parsed = new URL(input); } catch (_) { fail('第 ' + (index + 1) + ' 行网址格式不正确。'); }
        if (parsed.username || parsed.password || parsed.port) fail('第 ' + (index + 1) + ' 行不要填写账号密码或端口。');
        value = parsed.hostname;
      } else if (/[\s/:?#@,;=*+\\]/.test(input)) fail('第 ' + (index + 1) + ' 行请只填写域名或 http/https 网址。');
      const normalized = hostname(value, false);
      if (RESERVED_SUFFIXES.has(normalized)) fail('第 ' + (index + 1) + ' 行是公共后缀，请填写具体网站域名。');
      result.add(normalized);
    }
    return Array.from(result);
  }
  function normalizedPayload(payload) {
    if (!Array.isArray(payload) || !payload.length) fail('内置拦截名单缺失。');
    const unique = new Set();
    for (const entry of payload) {
      if (typeof entry !== 'string' || !entry || /[\s/:?#@,;=*\\]/.test(entry)) fail('内置名单中存在不支持的域名格式。');
      const suffix = entry.startsWith('+.');
      const domain = suffix ? entry.slice(2) : entry;
      if (domain.includes('+')) fail('内置名单中存在不支持的域名格式。');
      unique.add((suffix ? '+.' : '') + hostname(domain, suffix));
    }
    return Array.from(unique);
  }
  function validateProviderMap(config) {
    if (config['rule-providers'] === undefined) return;
    if (!isMap(config['rule-providers'])) fail('rule-providers 必须是名称到规则提供器的映射。');
    for (const [name, provider] of Object.entries(config['rule-providers'])) {
      if (!name || !isMap(provider) || !['http', 'file', 'inline'].includes(provider.type) || !['domain', 'ipcidr', 'classical'].includes(provider.behavior)) fail('规则提供器 ' + name + ' 的 type 或 behavior 不正确。');
      if (provider.payload !== undefined && (!Array.isArray(provider.payload) || provider.payload.some(item => typeof item !== 'string' || !item.trim()))) fail('规则提供器 ' + name + ' 的 payload 必须是文本列表。');
      if (provider.type === 'inline' && !Array.isArray(provider.payload)) fail('内嵌规则提供器 ' + name + ' 缺少 payload。');
    }
  }
  function validateConfig(config) {
    if (!isMap(config)) {
      if (typeof config === 'string' && /^https?:\/\/\S+$/i.test(config.trim())) fail('你粘贴的是订阅链接，请使用本地工具读取；也可以在 Clash 中导出完整 YAML 配置后粘贴文件内容。');
      if (typeof config === 'string' && /(?:^|\s)(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic):\/\//i.test(config)) fail('你粘贴的是节点分享链接。请先在 Clash 中导入节点并导出完整 YAML 配置，再粘贴配置文本。');
      if (Array.isArray(config)) fail('你粘贴的是单独的列表。请粘贴包含 proxies 或 proxy-providers，以及 rules 的完整 Clash 配置。');
      fail('没有识别到完整 Clash 配置。请粘贴包含 proxies 或 proxy-providers，以及 rules 的 YAML / JSON 文本；选择文件是可选的。');
    }
    if (!Array.isArray(config.rules) || config.rules.some(rule => typeof rule !== 'string' || !rule.trim())) fail('完整配置必须包含 rules 文本列表，不能只导入订阅链接或规则片段。');
    if (config.proxies !== undefined && (!Array.isArray(config.proxies) || config.proxies.some(proxy => !isMap(proxy) || typeof proxy.name !== 'string' || !proxy.name.trim()))) fail('proxies 必须是包含名称的节点列表。');
    if (config['proxy-providers'] !== undefined && (!isMap(config['proxy-providers']) || Object.entries(config['proxy-providers']).some(([name, provider]) => !name || !isMap(provider)))) fail('proxy-providers 必须是有效的提供器映射。');
    if (!(Array.isArray(config.proxies) && config.proxies.length) && !(isMap(config['proxy-providers']) && Object.keys(config['proxy-providers']).length)) fail('配置中没有 proxies 或 proxy-providers，请导入包含节点的完整配置。');
    function credentials(mapping, keys) {
      for (const key of keys) if (Object.prototype.hasOwnProperty.call(mapping, key) && typeof mapping[key] !== 'string') fail('凭据字段 ' + key + ' 必须用引号保存为文本，请先核实原值后重新导入。');
    }
    credentials(config, ['secret']);
    for (const proxy of config.proxies || []) credentials(proxy, ['password', 'uuid']);
    for (const provider of Object.values(config['proxy-providers'] || {})) if (Array.isArray(provider.payload)) for (const proxy of provider.payload) if (isMap(proxy)) credentials(proxy, ['password', 'uuid']);
    validateProviderMap(config);
  }
  function removePrevious(config) {
    if (!Object.prototype.hasOwnProperty.call(config, MARKER)) return;
    const marker = config[MARKER];
    if (!isMap(marker) || marker.owner !== OWNER || marker.version !== 1 || !Number.isInteger(marker.ruleCount) || marker.ruleCount < 1 || marker.ruleCount > 100000 || typeof marker.rulesHash !== 'string') fail('配置已有同名标记，或标记版本不支持；请导入生成前的原始配置。');
    if (config.rules.length < marker.ruleCount || hash(config.rules.slice(0, marker.ruleCount)) !== marker.rulesHash) fail('上次生成的拦截规则已被手动修改。请导入原始配置后重新生成，避免覆盖修改。');
    if (marker.providerName !== null) {
      const provider = config['rule-providers'] && config['rule-providers'][marker.providerName];
      if (typeof marker.providerName !== 'string' || !isMap(provider) || provider.type !== 'inline' || provider.behavior !== 'domain' || !Array.isArray(provider.payload) || Object.keys(provider).length !== 3 || hash(provider.payload) !== marker.payloadHash) fail('上次生成的规则提供器已被手动修改。请导入原始配置后重新生成。');
      const escapedName = marker.providerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const reference = new RegExp('(?:^|[,(])\\s*RULE-SET\\s*,\\s*' + escapedName + '\\s*(?:,|\\)|$)');
      function referencesOwnProvider(value) {
        if (typeof value === 'string') return reference.test(value);
        if (Array.isArray(value)) return value.some(referencesOwnProvider);
        if (isMap(value)) return Object.values(value).some(referencesOwnProvider);
        return false;
      }
      if (referencesOwnProvider(config.rules.slice(marker.ruleCount)) || referencesOwnProvider(config['sub-rules'])) fail('其他规则仍引用上次生成的拦截提供器。请导入原始配置后重新生成，避免留下失效引用。');
      delete config['rule-providers'][marker.providerName];
      if (marker.providerMapWasAbsent === true && Object.keys(config['rule-providers']).length === 0) delete config['rule-providers'];
    }
    config.rules.splice(0, marker.ruleCount);
    delete config[MARKER];
  }
  function enableSniffer(config) {
    if (config.sniffer !== undefined && !isMap(config.sniffer)) fail('sniffer 必须是配置映射，无法合并现有设置。');
    const sniffer = config.sniffer || (config.sniffer = {});
    if (sniffer.sniff !== undefined && !isMap(sniffer.sniff)) fail('sniffer.sniff 必须是协议配置映射。');
    sniffer.enable = true;
    sniffer['parse-pure-ip'] = true;
    sniffer['force-dns-mapping'] = true;
    if (sniffer['override-destination'] === undefined) sniffer['override-destination'] = false;
    const protocols = sniffer.sniff || (sniffer.sniff = {});
    for (const [name, ports] of [['HTTP', [80, '8080-8880']], ['TLS', [443, 8443]], ['QUIC', [443, 8443]]]) {
      if (protocols[name] === undefined) protocols[name] = { ports };
      else if (!isMap(protocols[name])) fail('sniffer.sniff.' + name + ' 必须是协议配置映射。');
    }
  }
  function preservationSchema(yaml) {
    const integer = yaml.types.int;
    const floating = yaml.types.float;
    const timestamp = yaml.types.timestamp;
    function ambiguousNumber(value, parsed) {
      if (/^[-+]?0[0-9_]+$/.test(value) || !Number.isSafeInteger(parsed)) fail('原配置包含有歧义的前导零数值或超出精确范围的整数，请先核实数值；端口写明实际十进制值，纯数字密码用引号。');
    }
    const guardedInteger = new yaml.Type(integer.tag, {
      kind: 'scalar', resolve: integer.resolve,
      construct(value) {
        const parsed = integer.construct(value);
        ambiguousNumber(value, parsed);
        return parsed;
      }
    });
    const guardedFloat = new yaml.Type(floating.tag, {
      kind: 'scalar', resolve: floating.resolve,
      construct(value) {
        const parsed = floating.construct(value);
        if (/^[-+]?[0-9][0-9_]*$/.test(value)) ambiguousNumber(value, parsed);
        return parsed;
      }
    });
    const guardedTimestamp = new yaml.Type(timestamp.tag, {
      kind: 'scalar', resolve: timestamp.resolve,
      construct() { fail('原配置包含未加引号的日期或时间，重新排版可能改变原值。请核实原文并用引号保存为文本后再导入。'); }
    });
    return yaml.DEFAULT_SCHEMA.extend({ implicit: [guardedInteger, guardedFloat, guardedTimestamp] });
  }
  function unwrapConfigText(text) {
    const trimmed = text.trim();
    // Only unwrap a fence surrounding the entire input. Do not discard YAML lines.
    const fenced = trimmed.match(/^(`{3,}|~{3,})[ \t]*(?:yaml|yml|json)?[ \t]*\r?\n([\s\S]*?)\r?\n\1[ \t]*$/i);
    return fenced ? fenced[2] : trimmed;
  }
  function readConfigText(yaml, text) {
    let source = unwrapConfigText(text);
    const schema = preservationSchema(yaml);
    let config;
    try {
      config = yaml.load(source, { schema });
      // Clipboard exports sometimes quote/escape the whole document as one string.
      // Decode only that document wrapper; never replace escapes inside YAML fields.
      if (typeof config === 'string' && /[\r\n]/.test(config)) {
        source = unwrapConfigText(config);
        config = yaml.load(source, { schema });
      }
    } catch (error) {
      if (error && error.name === 'YAMLException') {
        const place = error.mark ? '第 ' + (error.mark.line + 1) + ' 行，第 ' + (error.mark.column + 1) + ' 列。' : '';
        fail('配置文本解析失败：' + place + '请检查 YAML 缩进、冒号和引号，或 JSON 括号。');
      }
      fail('配置文本解析失败：' + (error.message || String(error)));
    }
    return config;
  }
  function prepareSubscription(options) {
    const yaml = options.yaml;
    if (typeof options.text !== 'string' || !options.text.trim()) fail('订阅返回了空内容，请检查链接是否有效。');
    if (new TextEncoder().encode(options.text).length > LIMIT) fail('订阅配置超过 12 MB，无法导入。');
    if (/^\s*(?:<!doctype\s+html|<html\b)/i.test(options.text)) fail('订阅返回了网页，请使用提供方的 Clash / Mihomo 订阅链接。');
    const config = readConfigText(yaml, options.text);
    if (typeof config === 'string' && (/^(?:[A-Za-z0-9+/_=-]+\s*)+$/.test(config) || /(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic):\/\//i.test(config))) fail('订阅返回的是编码内容或节点分享链接。请在订阅提供方选择 Clash / Mihomo 格式的订阅链接。');
    if (!isMap(config)) validateConfig(config);
    let notice = '';
    if (config.rules === undefined) {
      if (config.proxies !== undefined && !Array.isArray(config.proxies)) fail('订阅中的 proxies 必须是节点列表。');
      if (config['proxy-groups'] !== undefined && !Array.isArray(config['proxy-groups'])) fail('订阅中的 proxy-groups 必须是列表。');
      const names = new Set((config.proxies || []).map(proxy => proxy && proxy.name));
      for (const group of config['proxy-groups'] || []) names.add(group && group.name);
      let groupName = 'ADULT-GUARD-PROXY', suffix = 2;
      while (names.has(groupName)) groupName = 'ADULT-GUARD-PROXY-' + suffix++;
      const group = { name: groupName, type: 'select' };
      const nodeNames = (Array.isArray(config.proxies) ? config.proxies : []).map(proxy => proxy && proxy.name);
      // A provider-only selector must choose a supplied node rather than defaulting to DIRECT.
      if (nodeNames.length) group.proxies = nodeNames.concat('DIRECT');
      const providers = config['proxy-providers'];
      if (isMap(providers) && Object.keys(providers).length) group.use = Object.keys(providers);
      config['proxy-groups'] = (config['proxy-groups'] || []).concat(group);
      config.rules = ['MATCH,' + groupName];
      notice = '订阅只提供节点，已补充节点选择组和基础分流。需要保留自定义分流时，请导入当前完整配置。';
    }
    validateConfig(config);
    return { text: yaml.dump(config, { schema: yaml.DEFAULT_SCHEMA, noRefs: false, lineWidth: 120 }), notice };
  }
  function patch(options) {
    if (!options || !options.yaml || typeof options.yaml.load !== 'function' || typeof options.yaml.dump !== 'function') fail('本地 YAML 组件未加载，请重新打开完整工具文件。');
    const yaml = options.yaml;
    if (typeof options.configText !== 'string' || !options.configText.trim()) fail('请先选择或粘贴完整 Clash YAML 配置。');
    const bytes = typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(options.configText).length : options.configText.length;
    if (bytes > LIMIT) fail('配置超过 12 MB，请使用较小的完整 YAML 文件。');
    const config = readConfigText(yaml, options.configText);
    validateConfig(config);
    removePrevious(config);
    const defaults = normalizedPayload(options.defaultsPayload);
    const manual = parseExtraDomains(options.extraBlock || '');
    const generated = manual.map(domain => 'DOMAIN-SUFFIX,' + domain + ',REJECT');
    if (options.safeTest === true) generated.push('DOMAIN,guard-check.example.com,REJECT');
    let providerName = null;
    const providerMapWasAbsent = config['rule-providers'] === undefined;
    if (options.legacy === true) {
      for (const entry of defaults) generated.push((entry.startsWith('+.') ? 'DOMAIN-SUFFIX,' + entry.slice(2) : 'DOMAIN,' + entry) + ',REJECT');
    } else {
      const providers = config['rule-providers'] || (config['rule-providers'] = {});
      providerName = 'local-adult-guard-v1';
      let suffix = 2;
      while (Object.prototype.hasOwnProperty.call(providers, providerName)) providerName = 'local-adult-guard-v1-' + suffix++;
      providers[providerName] = { type: 'inline', behavior: 'domain', payload: defaults };
      generated.push('RULE-SET,' + providerName + ',REJECT');
      if (options.sniff === true) enableSniffer(config);
    }
    const rules = Array.from(new Set(generated));
    config.rules = rules.concat(config.rules);
    config.mode = 'rule';
    config[MARKER] = { owner: OWNER, version: 1, ruleCount: rules.length, rulesHash: hash(rules), providerName, providerMapWasAbsent, payloadHash: providerName ? hash(defaults) : null };
    const text = '# 本地生成的成人网站域名拦截配置；请在客户端启用规则模式并让 Chrome 流量经过它。\n' + yaml.dump(config, { schema: yaml.DEFAULT_SCHEMA, indent: 2, lineWidth: 120, noRefs: false, sortKeys: false });
    return { text, config, stats: { defaults: defaults.length, manual: manual.length, generatedRules: rules.length, safeTest: options.safeTest === true, legacy: options.legacy === true, sniffer: options.legacy !== true && options.sniff === true } };
  }
  return { patch, parseExtraDomains, prepareSubscription };
}));
