// 鍵守 OTPコア: Base32 / HOTP / TOTP / otpauth / Google認証システム移行形式
// ブラウザとNodeの両方で動く純粋なESモジュール。通信は一切しない。

export const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];
const HASH_NAMES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const ERR_SECRET = '秘密鍵の形式が正しくありません';

// ---------- Base32 ----------

/** 保存用の正規化: 空白とハイフンと末尾の = を除き、大文字にする */
export function normalizeSecret(raw) {
  return String(raw ?? '')
    .replace(/[\s　\-‐‑–—ー]+/g, '')
    .replace(/=+$/, '')
    .toUpperCase();
}

/** 比較用: 0 は O、1 は I と読む */
export function canonicalSecret(raw) {
  return normalizeSecret(raw).replace(/0/g, 'O').replace(/1/g, 'I');
}

/** Base32 を生バイトにする。不正なら null */
export function base32Decode(raw) {
  const s = canonicalSecret(raw);
  if (!s) return null;
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (!out.length) return null;
  return Uint8Array.from(out);
}

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function isValidSecret(raw) {
  return base32Decode(raw) !== null;
}

// ---------- HOTP / TOTP ----------

function counterBytes(counter) {
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  const hi = Math.floor(counter / 4294967296);
  const lo = counter >>> 0;
  dv.setUint32(0, hi >>> 0, false); // ビッグエンディアン
  dv.setUint32(4, lo, false);
  return new Uint8Array(buf);
}

export async function hotp(secretBytes, counter, algorithm = 'SHA1', digits = 6) {
  const hash = HASH_NAMES[algorithm];
  if (!hash) throw new Error('未対応のアルゴリズムです');
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(counter)));
  const off = h[h.length - 1] & 0x0f;
  const bin =
    ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  const mod = digits === 8 ? 100000000 : 1000000;
  return String(bin % mod).padStart(digits, '0');
}

export function totpCounter(unixMs, period = 30) {
  return Math.floor(Math.floor(unixMs / 1000) / period);
}

export function totpRemaining(unixMs, period = 30) {
  return period - (Math.floor(unixMs / 1000) % period);
}

export async function totp(secretBytes, unixMs, algorithm = 'SHA1', digits = 6, period = 30) {
  return hotp(secretBytes, totpCounter(unixMs, period), algorithm, digits);
}

/** アカウントの現在のコード。秘密鍵が不正なら null */
export async function codeFor(account, unixMs = Date.now()) {
  const key = base32Decode(account.secret);
  if (!key) return null;
  if (account.type === 'hotp') {
    return hotp(key, account.counter, account.algorithm, account.digits);
  }
  return totp(key, unixMs, account.algorithm, account.digits, account.period);
}

/** 表示用: 6桁は「123 456」、8桁は「1234 5678」。桁数が3の倍数でない場合は半分で分ける */
export function formatCode(code) {
  if (!code) return '';
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  const h = Math.ceil(code.length / 2);
  return `${code.slice(0, h)} ${code.slice(h)}`;
}

// ---------- アカウント ----------

export function newId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

/**
 * 外部入力を検証して保存形式にする。不正なら Error を投げる。
 * 省略時は SHA1・6桁・30秒・カウンタ0。
 */
export function normalizeAccount(input) {
  const type = String(input.type ?? 'totp').toLowerCase();
  if (type !== 'totp' && type !== 'hotp') throw new Error('未対応の種類です（TOTPとHOTPだけ使えます）');

  const secret = normalizeSecret(input.secret);
  if (!isValidSecret(secret)) throw new Error(ERR_SECRET);

  const algorithm = String(input.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
  if (!ALGORITHMS.includes(algorithm)) throw new Error('未対応のアルゴリズムです');

  const digits = input.digits === undefined || input.digits === null || input.digits === '' ? 6 : Number(input.digits);
  if (digits !== 6 && digits !== 8) throw new Error('桁数は6か8にしてください');

  let period = 30;
  if (type === 'totp' && input.period !== undefined && input.period !== null && input.period !== '') {
    period = Number(input.period);
    if (!Number.isInteger(period) || period < 1) throw new Error('更新間隔は1秒以上の整数にしてください');
  }

  let counter = 0;
  if (type === 'hotp' && input.counter !== undefined && input.counter !== null && input.counter !== '') {
    counter = Number(input.counter);
    if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('カウンタは0以上の整数にしてください');
  }

  return {
    id: typeof input.id === 'string' && input.id ? input.id : newId(),
    type,
    issuer: String(input.issuer ?? '').trim(),
    name: String(input.name ?? '').trim(),
    secret,
    algorithm,
    digits,
    period: type === 'totp' ? period : 30,
    counter: type === 'hotp' ? counter : 0,
    pinned: input.pinned === true,
  };
}

export function displayLabel(a) {
  if (a.issuer && a.name) return `${a.issuer}:${a.name}`;
  return a.issuer || a.name || '（名前なし）';
}

// ---------- otpauth:// ----------

// URIはASCIIだけ（日本語はパーセントエンコードされる）。そうしないと直後の日本語の句読点や文章まで取り込んでしまう
const URI_RE = /otpauth(?:-migration)?:\/\/[\x21\x23-\x26\x28-\x3b\x3d\x3f-\x7e]+/gi;

/** 文中から otpauth:// と otpauth-migration:// のURIだけを取り出す */
export function extractUris(text) {
  const found = String(text ?? '').match(URI_RE) || [];
  return found.map((u) => u.replace(/[),.;、。]+$/, ''));
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

export function parseOtpauth(uri) {
  const m = /^otpauth:\/\/([a-z]+)\/([^?#]*)\??([^#]*)/i.exec(String(uri).trim());
  if (!m) throw new Error('otpauth:// の形式ではありません');
  const type = m[1].toLowerCase();
  if (type !== 'totp' && type !== 'hotp') throw new Error('未対応の種類です（TOTPとHOTPだけ使えます）');
  const label = safeDecode(m[2]);
  const params = new URLSearchParams(m[3]);

  let issuer = '';
  let name = label;
  const ci = label.indexOf(':');
  if (ci >= 0) {
    issuer = label.slice(0, ci).trim();
    name = label.slice(ci + 1).trim();
  }
  const issuerParam = params.get('issuer');
  if (issuerParam) issuer = issuerParam.trim();

  return normalizeAccount({
    type,
    issuer,
    name,
    secret: params.get('secret'),
    algorithm: params.get('algorithm') ?? undefined,
    digits: params.get('digits') ?? undefined,
    period: params.get('period') ?? undefined,
    counter: params.get('counter') ?? undefined,
  });
}

export function buildOtpauth(a) {
  const label = a.issuer
    ? `${encodeURIComponent(a.issuer)}:${encodeURIComponent(a.name)}`
    : encodeURIComponent(a.name);
  const q = [`secret=${a.secret}`];
  if (a.issuer) q.push(`issuer=${encodeURIComponent(a.issuer)}`);
  q.push(`algorithm=${a.algorithm}`, `digits=${a.digits}`);
  if (a.type === 'hotp') q.push(`counter=${a.counter}`);
  else q.push(`period=${a.period}`);
  return `otpauth://${a.type}/${label}?${q.join('&')}`;
}

// ---------- Google認証システム移行形式（protobuf） ----------

function readVarint(buf, pos) {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= buf.length) throw new Error('移行QRのデータが途中で切れています');
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7n;
    if (shift > 70n) throw new Error('移行QRのデータが壊れています');
  }
  return [result, pos];
}

function readFields(buf) {
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    let tag;
    [tag, pos] = readVarint(buf, pos);
    const num = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      let v;
      [v, pos] = readVarint(buf, pos);
      fields.push({ num, wire, value: v });
    } else if (wire === 2) {
      let len;
      [len, pos] = readVarint(buf, pos);
      const n = Number(len);
      if (pos + n > buf.length) throw new Error('移行QRのデータが途中で切れています');
      fields.push({ num, wire, value: buf.subarray(pos, pos + n) });
      pos += n;
    } else if (wire === 1) {
      pos += 8;
    } else if (wire === 5) {
      pos += 4;
    } else {
      throw new Error('移行QRのデータが壊れています');
    }
  }
  return fields;
}

function b64ToBytes(b64) {
  let s = b64.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

const utf8d = new TextDecoder();
const utf8e = new TextEncoder();

/**
 * otpauth-migration://offline?data=... を読む。
 * 戻り値: { accounts, skipped, batchSize, batchIndex, batchId, version }
 * 更新間隔は移行形式に無いので TOTP は必ず30秒になる。
 */
export function parseMigration(uri) {
  const m = /^otpauth-migration:\/\/[^?]*\?(.*)$/i.exec(String(uri).trim());
  if (!m) throw new Error('移行QRの形式ではありません');
  const data = new URLSearchParams(m[1]).get('data');
  if (!data) throw new Error('移行QRにデータがありません');
  const payload = b64ToBytes(data);

  const accounts = [];
  let skipped = 0;
  let version = 0;
  let batchSize = 1;
  let batchIndex = 0;
  let batchId = 0;

  for (const f of readFields(payload)) {
    if (f.num === 1 && f.wire === 2) {
      const p = { secret: null, name: '', issuer: '', algorithm: 0, digits: 0, type: 0, counter: 0n };
      for (const g of readFields(f.value)) {
        if (g.num === 1 && g.wire === 2) p.secret = g.value;
        else if (g.num === 2 && g.wire === 2) p.name = utf8d.decode(g.value);
        else if (g.num === 3 && g.wire === 2) p.issuer = utf8d.decode(g.value);
        else if (g.num === 4 && g.wire === 0) p.algorithm = Number(g.value);
        else if (g.num === 5 && g.wire === 0) p.digits = Number(g.value);
        else if (g.num === 6 && g.wire === 0) p.type = Number(g.value);
        else if (g.num === 7 && g.wire === 0) p.counter = g.value;
      }
      // アルゴリズム 1=SHA1 2=SHA256 3=SHA512。0（未指定）はSHA1扱い。MD5(4)などは飛ばす
      const algo = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' }[p.algorithm];
      if (!algo || !p.secret || !p.secret.length) {
        skipped++;
        continue;
      }
      const isHotp = p.type === 1;
      let name = p.name;
      let issuer = p.issuer;
      if (!issuer && name.includes(':')) {
        issuer = name.slice(0, name.indexOf(':')).trim();
        name = name.slice(name.indexOf(':') + 1).trim();
      } else if (issuer && name.startsWith(issuer + ':')) {
        name = name.slice(issuer.length + 1).trim();
      }
      try {
        accounts.push(
          normalizeAccount({
            type: isHotp ? 'hotp' : 'totp',
            issuer,
            name,
            secret: base32Encode(p.secret),
            algorithm: algo,
            digits: p.digits === 2 ? 8 : 6,
            period: 30,
            counter: isHotp ? Number(p.counter) : 0,
          }),
        );
      } catch {
        skipped++;
      }
    } else if (f.wire === 0) {
      if (f.num === 2) version = Number(f.value);
      else if (f.num === 3) batchSize = Number(f.value);
      else if (f.num === 4) batchIndex = Number(f.value);
      else if (f.num === 5) batchId = Number(BigInt.asIntN(32, f.value));
    }
  }
  return { accounts, skipped, version, batchSize: batchSize || 1, batchIndex, batchId };
}

function varint(n) {
  let v = BigInt(n);
  if (v < 0n) v = BigInt.asUintN(64, v);
  const out = [];
  while (v > 0x7fn) {
    out.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  out.push(Number(v));
  return out;
}

function concat(parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function lenField(num, bytes) {
  return concat([Uint8Array.from(varint((num << 3) | 2)), Uint8Array.from(varint(bytes.length)), bytes]);
}

function varField(num, value) {
  return Uint8Array.from([...varint(num << 3), ...varint(value)]);
}

function encodeParams(a) {
  const parts = [lenField(1, base32Decode(a.secret))];
  const name = a.issuer ? `${a.issuer}:${a.name}` : a.name;
  parts.push(lenField(2, utf8e.encode(name)));
  if (a.issuer) parts.push(lenField(3, utf8e.encode(a.issuer)));
  parts.push(varField(4, { SHA1: 1, SHA256: 2, SHA512: 3 }[a.algorithm]));
  parts.push(varField(5, a.digits === 8 ? 2 : 1));
  parts.push(varField(6, a.type === 'hotp' ? 1 : 2));
  if (a.type === 'hotp') parts.push(varField(7, a.counter)); // HOTPだけカウンタを入れる
  return concat(parts);
}

function encodePayload(list, batchSize, batchIndex, batchId) {
  const parts = list.map((a) => lenField(1, encodeParams(a)));
  parts.push(varField(2, 1), varField(3, batchSize), varField(4, batchIndex), varField(5, batchId));
  return concat(parts);
}

export function migrationUri(list, batchSize, batchIndex, batchId) {
  const b64 = bytesToB64(encodePayload(list, batchSize, batchIndex, batchId));
  return `otpauth-migration://offline?data=${encodeURIComponent(b64)}`;
}

export const MIGRATION_MAX_CHARS = 900;

/** まとめ形式にできない理由（更新間隔が30秒でないTOTP）を持つ鍵 */
export function nonStandardPeriod(accounts) {
  return accounts.filter((a) => a.type === 'totp' && a.period !== 30);
}

/**
 * 移行形式のまとめQRを作る。1枚900文字以内に分割し、batch_size / batch_index を正しく入れる。
 * 30秒でないTOTPが含まれるときは例外にする（相手のコードがずれるため）。
 */
export function planMigration(accounts, batchId = (Math.random() * 0x7fffffff) | 0) {
  const bad = nonStandardPeriod(accounts);
  if (bad.length) {
    throw new Error('30秒でないTOTPが含まれるため、まとめ形式は使えません');
  }
  if (!accounts.length) return [];
  const groups = [];
  let cur = [];
  for (const a of accounts) {
    const trial = cur.concat([a]);
    // batch_size は1バイトのvarintに収まる範囲で仮置きして長さを測る
    const len = migrationUri(trial, 1, 0, batchId).length;
    if (cur.length && len > MIGRATION_MAX_CHARS) {
      groups.push(cur);
      cur = [a];
    } else {
      cur = trial;
    }
  }
  if (cur.length) groups.push(cur);
  return groups.map((g, i) => migrationUri(g, groups.length, i, batchId));
}

// ---------- 取り込み ----------

/**
 * テキストや読み取り結果から取り込み候補を作る。
 * 戻り値: { items:[{account, source:'otpauth'|'migration'}], notes:[{kind,...}], errors:[string] }
 */
export function parseInput(text) {
  const uris = extractUris(text);
  const items = [];
  const notes = [];
  const errors = [];
  if (!uris.length) errors.push('otpauth:// のリンクが見つかりませんでした');
  for (const uri of uris) {
    try {
      if (/^otpauth-migration:/i.test(uri)) {
        const r = parseMigration(uri);
        for (const a of r.accounts) items.push({ account: a, source: 'migration' });
        notes.push({
          kind: 'migration',
          skipped: r.skipped,
          batchSize: r.batchSize,
          batchIndex: r.batchIndex,
          batchId: r.batchId,
          count: r.accounts.length,
        });
      } else {
        items.push({ account: parseOtpauth(uri), source: 'otpauth' });
      }
    } catch (e) {
      errors.push(e.message || '読み取れませんでした');
    }
  }
  return { items, notes, errors };
}
