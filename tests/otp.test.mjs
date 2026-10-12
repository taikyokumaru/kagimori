import assert from 'node:assert/strict';
import {
  base32Decode, base32Encode, normalizeSecret, canonicalSecret, isValidSecret, hotp, totp, codeFor, formatCode,
  normalizeAccount, parseOtpauth, buildOtpauth, extractUris, parseMigration, planMigration, migrationUri,
  parseInput, totpRemaining, MIGRATION_MAX_CHARS,
} from '../otp.js';
import { parseVault, serializeVault, mergeAccounts, addedMessage, loadVault, saveVault, VAULT_KEY } from '../vault.js';

let n = 0;
const t = async (name, fn) => { await fn(); n++; console.log('ok', name); };
const ascii = (s) => Uint8Array.from(Buffer.from(s, 'ascii'));

await t('RFC 4226 HOTP vectors', async () => {
  const exp = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let i = 0; i < 10; i++) assert.equal(await hotp(ascii('12345678901234567890'), i, 'SHA1', 6), exp[i]);
});

await t('RFC 6238 TOTP vectors (SHA1/256/512, 8 digits)', async () => {
  const k1 = ascii('12345678901234567890');
  const k2 = ascii('12345678901234567890123456789012');
  const k3 = ascii('1234567890123456789012345678901234567890123456789012345678901234');
  const rows = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t0, a, b, c] of rows) {
    assert.equal(await totp(k1, t0 * 1000, 'SHA1', 8, 30), a, 'sha1 ' + t0);
    assert.equal(await totp(k2, t0 * 1000, 'SHA256', 8, 30), b, 'sha256 ' + t0);
    assert.equal(await totp(k3, t0 * 1000, 'SHA512', 8, 30), c, 'sha512 ' + t0);
  }
});

await t('counter > 2^32 is 8-byte big endian', async () => {
  // 20000000000/30 = 666666666 (<2^32) so force a large counter and compare against a manual HMAC
  const { createHmac } = await import('node:crypto');
  const key = ascii('12345678901234567890');
  const counter = 4294967296 * 3 + 12345;
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', key).update(buf).digest();
  const o = h[19] & 15;
  const exp = String(((h[o] & 0x7f) << 24 | h[o+1] << 16 | h[o+2] << 8 | h[o+3]) % 1000000).padStart(6, '0');
  assert.equal(await hotp(key, counter, 'SHA1', 6), exp);
});

await t('base32', () => {
  assert.equal(base32Encode(ascii('foobar')), 'MZXW6YTBOI');
  assert.deepEqual([...base32Decode('MZXW6YTBOI======')], [...ascii('foobar')]);
  assert.equal(base32Encode(base32Decode('JBSWY3DPEHPK3PXP')), 'JBSWY3DPEHPK3PXP');
  assert.equal(normalizeSecret('jbsw y3dp-ehpk 3pxp=='), 'JBSWY3DPEHPK3PXP');
  // 0→O, 1→I
  assert.equal(canonicalSecret('JBSWY3DPEHPK3PXP'.replace('O','0')), canonicalSecret('JBSWY3DPEHPK3PXP'));
  assert.deepEqual([...base32Decode('A0A1')], [...base32Decode('AOAI')]);
  assert.equal(isValidSecret('8888'), false);
  assert.equal(isValidSecret('abc!'), false);
  assert.equal(isValidSecret(''), false);
  assert.throws(() => normalizeAccount({ secret: '8!9' }), /秘密鍵の形式が正しくありません/);
});

await t('formatCode', () => {
  assert.equal(formatCode('123456'), '123 456');
  assert.equal(formatCode('12345678'), '1234 5678');
});

await t('defaults and validation', () => {
  const a = normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', name: 'x' });
  assert.deepEqual([a.type, a.algorithm, a.digits, a.period, a.counter], ['totp', 'SHA1', 6, 30, 0]);
  assert.throws(() => normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', digits: 7 }));
  assert.throws(() => normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', period: 0 }));
  assert.throws(() => normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', period: 1.5 }));
  assert.throws(() => normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', counter: -1 }));
  assert.throws(() => normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', algorithm: 'MD5' }));
  assert.equal(normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', period: 1 }).period, 1);
});

await t('otpauth parse / build / roundtrip', () => {
  const a = parseOtpauth('otpauth://totp/Example%3Aalice%40google.com?secret=jbsw y3dp&issuer=Example&algorithm=SHA256&digits=8&period=60'.replace(' ', ''));
  assert.equal(a.issuer, 'Example'); assert.equal(a.name, 'alice@google.com');
  assert.equal(a.algorithm, 'SHA256'); assert.equal(a.digits, 8); assert.equal(a.period, 60);
  const h = parseOtpauth('otpauth://hotp/ACME:bob?secret=JBSWY3DPEHPK3PXP&counter=7');
  assert.equal(h.type, 'hotp'); assert.equal(h.counter, 7); assert.equal(h.issuer, 'ACME'); assert.equal(h.name, 'bob');
  const u = buildOtpauth(a);
  const b = parseOtpauth(u);
  for (const k of ['type','issuer','name','secret','algorithm','digits','period','counter']) assert.equal(b[k], a[k], k);
  assert.match(buildOtpauth(h), /counter=7/); assert.doesNotMatch(buildOtpauth(h), /period=/);
  assert.doesNotMatch(buildOtpauth(a), /counter=/);
  const jp = normalizeAccount({ issuer: '鍵 守&?', name: 'ユーザー:1', secret: 'JBSWY3DPEHPK3PXP' });
  const jp2 = parseOtpauth(buildOtpauth(jp));
  assert.equal(jp2.issuer, '鍵 守&?'); assert.equal(jp2.name, 'ユーザー:1');
  assert.throws(() => parseOtpauth('otpauth://totp/x?secret=!!!'), /秘密鍵の形式が正しくありません/);
  assert.throws(() => parseOtpauth('otpauth://steam/x?secret=JBSWY3DPEHPK3PXP'));
});

await t('extractUris from prose', () => {
  const s = '見てください「otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A」と otpauth-migration://offline?data=AAAA。以上';
  const u = extractUris(s);
  assert.equal(u.length, 2);
  assert.equal(u[0], 'otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A');
  assert.equal(u[1], 'otpauth-migration://offline?data=AAAA');
});

await t('migration: hand-built protobuf', () => {
  const secret = Buffer.concat([Buffer.from('Hello!'), Buffer.from([0xde,0xad,0xbe,0xef])]);
  const name = Buffer.from('Example:alice@google.com'); const issuer = Buffer.from('Example');
  const params = Buffer.concat([
    Buffer.from([0x0a, secret.length]), secret, Buffer.from([0x12, name.length]), name,
    Buffer.from([0x1a, issuer.length]), issuer, Buffer.from([0x20,1, 0x28,2, 0x30,1, 0x38,5]),
  ]);
  // 2件目: SHA512 / 8桁 / TOTP、3件目: MD5(4) は飛ばす
  const p2 = Buffer.concat([Buffer.from([0x0a,3,1,2,3, 0x12,1,0x78, 0x20,3, 0x28,2, 0x30,2])]);
  const p3 = Buffer.concat([Buffer.from([0x0a,3,1,2,3, 0x12,1,0x79, 0x20,4, 0x28,1, 0x30,2])]);
  const wrap = (p) => Buffer.concat([Buffer.from([0x0a, p.length]), p]);
  const payload = Buffer.concat([wrap(params), wrap(p2), wrap(p3), Buffer.from([0x10,1, 0x18,2, 0x20,1, 0x28,7])]);
  const uri = 'otpauth-migration://offline?data=' + encodeURIComponent(payload.toString('base64'));
  const r = parseMigration(uri);
  assert.equal(r.accounts.length, 2); assert.equal(r.skipped, 1);
  assert.equal(r.batchSize, 2); assert.equal(r.batchIndex, 1); assert.equal(r.batchId, 7); assert.equal(r.version, 1);
  const a = r.accounts[0];
  assert.equal(a.type, 'hotp'); assert.equal(a.counter, 5); assert.equal(a.period, 30);
  assert.equal(a.issuer, 'Example'); assert.equal(a.name, 'alice@google.com');
  assert.equal(a.secret, base32Encode(secret));
  const b = r.accounts[1];
  assert.equal(b.type, 'totp'); assert.equal(b.algorithm, 'SHA512'); assert.equal(b.digits, 8); assert.equal(b.period, 30);
});

await t('migration: export plan splits <=900 chars with correct batch fields', () => {
  const list = [];
  for (let i = 0; i < 25; i++) {
    list.push(normalizeAccount({
      type: i % 5 === 0 ? 'hotp' : 'totp', counter: i, issuer: 'サービス' + i, name: 'user' + i + '@example.com',
      secret: base32Encode(Uint8Array.from({ length: i % 3 === 0 ? 64 : 20 }, (_, k) => (k * 7 + i) & 255)),
      algorithm: ['SHA1','SHA256','SHA512'][i % 3], digits: i % 2 ? 8 : 6,
    }));
  }
  const uris = planMigration(list, 1234567);
  assert.ok(uris.length > 1);
  const back = [];
  uris.forEach((u, i) => {
    assert.ok(u.length <= MIGRATION_MAX_CHARS, 'len ' + u.length);
    const r = parseMigration(u);
    assert.equal(r.batchSize, uris.length); assert.equal(r.batchIndex, i); assert.equal(r.batchId, 1234567);
    back.push(...r.accounts);
  });
  assert.equal(back.length, list.length);
  list.forEach((a, i) => {
    for (const k of ['type','issuer','name','secret','algorithm','digits','period','counter']) assert.equal(back[i][k], a[k], `${i}.${k}`);
  });
  // 1件だけなら 1/1
  const one = planMigration(list.slice(0, 1));
  assert.equal(parseMigration(one[0]).batchSize, 1);
  assert.deepEqual(planMigration([]), []);
});

await t('migration: non-30s TOTP is refused, HOTP is fine', () => {
  const odd = normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', period: 60 });
  const h = normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', period: 60 });
  assert.throws(() => planMigration([odd]), /30秒でない/);
  assert.doesNotThrow(() => planMigration([h]));
});

await t('parseInput mixes uris and reports migration notes', () => {
  const a = normalizeAccount({ secret: 'JBSWY3DPEHPK3PXP', issuer: 'A', name: 'b' });
  const [m] = planMigration([a], 9);
  const r = parseInput(`first ${buildOtpauth(a)} then ${m} and junk otpauth://totp/x?secret=!!`);
  assert.equal(r.items.length, 2);
  assert.equal(r.notes[0].kind, 'migration');
  assert.equal(r.errors.length, 1);
  assert.equal(parseInput('なにもない').errors.length, 1);
});

await t('vault: parse skips broken, dedupes, normalizes; merge dedupes by secret', () => {
  const text = JSON.stringify({ v: 1, hidden: true, accounts: [
    { type: 'totp', issuer: 'A', name: 'a', secret: 'jbsw y3dp ehpk 3pxp==' },
    null, 5, { secret: '!!!' },
    { type: 'totp', issuer: 'B', name: 'b', secret: 'JBSWY3DPEHPK3PXP' },
    { type: 'hotp', name: 'c', secret: 'MZXW6YTBOI', counter: 3 },
  ]});
  const v = parseVault(text);
  assert.equal(v.accounts.length, 2); assert.equal(v.hidden, true);
  assert.equal(v.accounts[0].secret, 'JBSWY3DPEHPK3PXP');
  assert.deepEqual(parseVault('{broken').accounts, []);
  assert.deepEqual(parseVault(null).accounts, []);
  const inc = [
    normalizeAccount({ name: 'dup', secret: 'jbswy3dpehpk3pxp' }),
    normalizeAccount({ name: 'new', secret: 'GEZDGNBVGY3TQOJQ' }),
    normalizeAccount({ name: 'new2', secret: 'GEZD-GNBV GY3TQOJQ' }),
  ];
  const m = mergeAccounts(v.accounts, inc);
  assert.equal(m.added, 1); assert.equal(m.skipped, 2); assert.equal(m.accounts.length, 3);
  assert.equal(addedMessage(1, 2), '1件追加しました。2件は同じ秘密鍵がすでにあるので足していません');
  const mem = { d: {}, getItem(k) { return this.d[k] ?? null; }, setItem(k, v) { this.d[k] = v; } };
  assert.ok(saveVault(mem, { accounts: m.accounts, hidden: true }));
  assert.deepEqual(Object.keys(mem.d), [VAULT_KEY]);
  assert.equal(loadVault(mem).accounts.length, 3);
  assert.equal(saveVault({ setItem() { throw new Error('quota'); } }, { accounts: [] }), false);
});

await t('codeFor / remaining', async () => {
  const a = normalizeAccount({ secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', digits: 8 });
  assert.equal(await codeFor(a, 59000), '94287082');
  assert.equal(totpRemaining(59000, 30), 1);
  assert.equal(totpRemaining(60000, 30), 30);
  const h = normalizeAccount({ type: 'hotp', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: 1 });
  assert.equal(await codeFor(h), '287082');
});

console.log(`\n${n} test groups passed`);
