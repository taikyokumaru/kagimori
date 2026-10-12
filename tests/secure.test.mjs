import assert from 'node:assert/strict';
import { deriveKey, encryptJson, decryptJson, newSalt, passwordProblem, checkIter, AAD_VAULT, b64e } from '../crypto.js';
import { makeBackup, inspectBackup, readBackup, backupFileName } from '../backup.js';
import { parseVault, serializeEncrypted, openEncrypted, saltBytes, serializeVault } from '../vault.js';
import { normalizeAccount } from '../otp.js';
let n = 0; const t = async (name, fn) => { await fn(); n++; console.log('ok', name); };
const accts = [
  normalizeAccount({ issuer: '鍵守', name: 'サンプル', secret: 'JBSWY3DPEHPK3PXP', pinned: true }),
  normalizeAccount({ issuer: 'A', name: 'b', secret: 'GEZDGNBVGY3TQOJQ', type: 'hotp', counter: 9, digits: 8, algorithm: 'SHA512' }),
  normalizeAccount({ issuer: 'C', name: 'd', secret: 'MZXW6YTBOI', period: 60 }),
];
const ITER = 100000; // テストは速くするため下限で

await t('encrypt/decrypt roundtrip; wrong key and tamper fail', async () => {
  const salt = newSalt(); const k = await deriveKey('correct horse', salt, ITER); const bad = await deriveKey('wrong horse', salt, ITER);
  const { iv, ct } = await encryptJson(k, { a: 1, jp: '日本語' }, AAD_VAULT);
  assert.deepEqual(await decryptJson(k, iv, ct, AAD_VAULT), { a: 1, jp: '日本語' });
  assert.equal(await decryptJson(bad, iv, ct, AAD_VAULT), null);
  assert.equal(await decryptJson(k, iv, ct, 'other-aad'), null);
  const raw = Buffer.from(ct, 'base64'); raw[3] ^= 1;
  assert.equal(await decryptJson(k, iv, raw.toString('base64'), AAD_VAULT), null);
  // IVは毎回違う
  assert.notEqual((await encryptJson(k, {}, AAD_VAULT)).iv, (await encryptJson(k, {}, AAD_VAULT)).iv);
});

await t('NFKC: full-width password opens the same key', async () => {
  const salt = newSalt(); const a = await deriveKey('ＡＢＣｄｅｆ１２３４', salt, ITER); const b = await deriveKey('ABCdef1234', salt, ITER);
  const { iv, ct } = await encryptJson(a, { x: 1 }, 'z'); assert.deepEqual(await decryptJson(b, iv, ct, 'z'), { x: 1 });
});

await t('password rules / iter limits', () => {
  assert.ok(passwordProblem('short')); assert.ok(passwordProblem('aaaaaaaaaa')); assert.equal(passwordProblem('ながいパスワード123'), '');
  assert.throws(() => checkIter(10)); assert.throws(() => checkIter(1e9)); assert.equal(checkIter(600000), 600000);
});

await t('encrypted vault: no secrets in storage text; reopen; plaintext flags stay outside', async () => {
  const salt = newSalt(); const key = await deriveKey('pw-pw-pw-pw', salt, ITER);
  const text = await serializeEncrypted({ accounts: accts, hidden: true, backedUpAt: 1234 }, { key, salt, iter: ITER });
  for (const a of accts) assert.ok(!text.includes(a.secret), 'secret leaked');
  assert.ok(!text.includes('鍵守'));
  const st = parseVault(text);
  assert.ok(st.enc); assert.equal(st.accounts.length, 0); assert.equal(st.hidden, true); assert.equal(st.backedUpAt, 1234);
  const k2 = await deriveKey('pw-pw-pw-pw', saltBytes(st.enc), st.enc.iter);
  const r = await openEncrypted(st.enc, k2);
  assert.equal(r.accounts.length, 3); assert.equal(r.accounts[0].pinned, true); assert.equal(r.accounts[1].counter, 9);
  assert.equal(await openEncrypted(st.enc, await deriveKey('nope-nope', saltBytes(st.enc), st.enc.iter)), null);
});

await t('plain vault keeps backedUpAt and pinned; old v1 data still loads', () => {
  const st = parseVault(serializeVault({ accounts: accts, hidden: false, backedUpAt: 77 }));
  assert.equal(st.backedUpAt, 77); assert.equal(st.accounts[0].pinned, true); assert.equal(st.enc, null);
  assert.equal(parseVault(JSON.stringify({ v: 1, hidden: true, accounts: [{ secret: 'JBSWY3DPEHPK3PXP', name: 'x' }] })).accounts.length, 1);
});

await t('backup: password-encrypted roundtrip, no leaks, wrong password', async () => {
  const text = await makeBackup(accts, { mode: 'password', password: 'backup-pass-1' });
  for (const a of accts) assert.ok(!text.includes(a.secret));
  const info = inspectBackup(text); assert.equal(info.encrypted, true);
  const r = await readBackup(info, 'backup-pass-1');
  assert.equal(r.accounts.length, 3); assert.equal(r.skipped, 0);
  for (const [i, a] of accts.entries()) for (const k of ['type','issuer','name','secret','algorithm','digits','period','counter','pinned']) assert.equal(r.accounts[i][k], a[k], `${i}.${k}`);
  assert.equal(await readBackup(info, 'wrong-pass-1'), null);
});

await t('backup: key mode (same salt) opens with the app password', async () => {
  const salt = newSalt(); const key = await deriveKey('app-password-1', salt, ITER);
  const text = await makeBackup(accts, { mode: 'key', key, salt, iter: ITER });
  const r = await readBackup(inspectBackup(text), 'app-password-1'); assert.equal(r.accounts.length, 3);
});

await t('backup: plain, junk, broken entries, file name', async () => {
  const text = await makeBackup(accts, { mode: 'plain' }); const info = inspectBackup(text);
  assert.equal(info.encrypted, false); assert.equal((await readBackup(info)).accounts.length, 3);
  const obj = JSON.parse(text); obj.accounts.push({ secret: '!!!' }, 5, null); 
  const r = await readBackup(inspectBackup(JSON.stringify(obj))); assert.equal(r.accounts.length, 3); assert.equal(r.skipped, 3);
  assert.throws(() => inspectBackup('{bad'), /JSON/); assert.throws(() => inspectBackup('{"app":"x"}'), /鍵守の/);
  assert.throws(() => inspectBackup(JSON.stringify({ app: 'kagimori', format: 1, encrypted: true, salt: 'a', iv: 'b', ct: 'c', iter: 5 })), /暗号化の設定/);
  assert.match(backupFileName(false, new Date(2026, 9, 11)), /^kagimori-backup-20261011-PLAIN\.json$/); assert.match(backupFileName(true, new Date(2026, 9, 11)), /^kagimori-backup-20261011\.json$/);
});
console.log(`\n${n} secure test groups passed`);
