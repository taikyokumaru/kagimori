// 鍵守 バックアップファイル。端末のファイルとして書き出し・読み込みするだけで、どこにも送らない。
import { AAD_BACKUP, KDF_ITER, b64e, b64d, checkIter, decryptJson, deriveKey, encryptJson, newSalt } from './crypto.js';
import { normalizeAccount } from './otp.js';

const APP = 'kagimori';
const FORMAT = 1;

const slim = (a) => ({
  type: a.type, issuer: a.issuer, name: a.name, secret: a.secret,
  algorithm: a.algorithm, digits: a.digits, period: a.period, counter: a.counter, pinned: !!a.pinned,
});

export function backupFileName(encrypted, d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`;
  return `kagimori-backup-${stamp}${encrypted ? '' : '-PLAIN'}.json`;
}

/**
 * バックアップの中身（JSON文字列）を作る。
 *  mode 'plain'    : 平文。秘密鍵がそのまま読める
 *  mode 'password' : 指定パスワードで暗号化（新しい salt）
 *  mode 'key'      : すでにメモリにある鍵で暗号化（アプリの暗号化パスワードと同じ。salt と iter を引き継ぐ）
 */
export async function makeBackup(accounts, opt, now = new Date()) {
  const list = accounts.map(slim);
  const head = { app: APP, format: FORMAT, exportedAt: now.toISOString(), count: list.length };
  if (opt.mode === 'plain') return JSON.stringify({ ...head, encrypted: false, accounts: list }, null, 2);
  let key;
  let salt;
  let iter;
  if (opt.mode === 'key') {
    ({ key, salt, iter } = opt);
  } else {
    salt = newSalt();
    iter = KDF_ITER;
    key = await deriveKey(opt.password, salt, iter);
  }
  const { iv, ct } = await encryptJson(key, { accounts: list }, AAD_BACKUP);
  return JSON.stringify({ ...head, encrypted: true, kdf: 'pbkdf2-sha256', iter, salt: b64e(salt), iv, ct }, null, 2);
}

/** ファイルの文字列を調べる。鍵守のバックアップでなければ例外 */
export function inspectBackup(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error('バックアップファイルを読めませんでした（JSONではありません）');
  }
  if (!obj || obj.app !== APP || obj.format !== FORMAT) throw new Error('鍵守のバックアップファイルではありません');
  if (obj.encrypted) {
    if (!obj.salt || !obj.iv || !obj.ct) throw new Error('バックアップファイルが壊れています');
    checkIter(obj.iter);
    return { encrypted: true, obj };
  }
  if (!Array.isArray(obj.accounts)) throw new Error('バックアップファイルが壊れています');
  return { encrypted: false, obj };
}

function toAccounts(list) {
  const accounts = [];
  let skipped = 0;
  for (const raw of Array.isArray(list) ? list : []) {
    try {
      accounts.push(normalizeAccount({ ...raw, id: undefined }));
    } catch {
      skipped++;
    }
  }
  return { accounts, skipped };
}

/** 平文ならそのまま、暗号化されていれば password で開く。パスワード違いは null */
export async function readBackup(info, password) {
  if (!info.encrypted) return toAccounts(info.obj.accounts);
  const key = await deriveKey(password, b64d(info.obj.salt), info.obj.iter);
  const data = await decryptJson(key, info.obj.iv, info.obj.ct, AAD_BACKUP);
  if (!data) return null;
  return toAccounts(data.accounts);
}
