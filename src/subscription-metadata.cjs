'use strict';
// Keep only the numeric subscription information understood by Clash clients.
function normalizeMetadata(value) {
  const raw = value?.userinfo;
  if (typeof raw !== 'string' || raw.length > 1024 || /[\r\n\x00]/.test(raw)) return {};
  const fields = new Map();
  for (const part of raw.split(';')) {
    const match = part.trim().match(/^(upload|download|total|expire)\s*=\s*(\d+)$/i);
    if (!match) continue;
    const key = match[1].toLowerCase();
    const number = BigInt(match[2]);
    if (number > 9223372036854775807n || fields.has(key)) return {};
    fields.set(key, number.toString());
  }
  if (!fields.has('upload') || !fields.has('download') || !fields.has('total')) return {};
  return { userinfo: ['upload', 'download', 'total', 'expire'].filter(key => fields.has(key)).map(key => key + '=' + fields.get(key)).join('; ') };
}
module.exports = { normalizeMetadata };
