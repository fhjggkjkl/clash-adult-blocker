'use strict';
// Decode bytes without silently replacing Chinese names or passwords.
function decodeText(bytes, contentType = '') {
  const data = Buffer.from(bytes);
  let encoding;
  if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) encoding = 'utf-8';
  else if (data[0] === 0xff && data[1] === 0xfe) encoding = 'utf-16le';
  else if (data[0] === 0xfe && data[1] === 0xff) encoding = 'utf-16be';
  else {
    const declared = String(contentType).match(/charset\s*=\s*["']?([^\s;"']+)/i)?.[1]?.toLowerCase();
    if (declared) {
      if (/^(utf-?8|utf-?16le|utf-?16be)$/.test(declared)) encoding = declared;
      else if (/^(gbk|gb2312|gb18030|cp936)$/.test(declared)) encoding = 'gb18030';
      else if (/^(ascii|us-ascii)$/.test(declared)) encoding = 'utf-8';
      else throw new Error('配置使用了不支持的字符编码，请将原文件另存为 UTF-8 后导入。');
    }
  }
  let text;
  try {
    if (encoding) text = new TextDecoder(encoding, { fatal: true }).decode(data);
    else {
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(data); encoding = 'utf-8'; }
      catch (_) { text = new TextDecoder('gb18030', { fatal: true }).decode(data); encoding = 'gb18030'; }
    }
  } catch (_) { throw new Error('配置文件编码无法正确识别，请将原文件另存为 UTF-8 后导入，避免改变节点名称或密码。'); }
  if (text.includes('\u0000')) throw new Error('配置中包含无法读取的字符，请另存为 UTF-8 文本后导入。');
  return { text, encoding };
}
module.exports = { decodeText };
