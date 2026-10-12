// 鍵守 保存まわり。localStorage の kagimori.vault.v1 だけを使う。サーバーへは何も送らない。
// 形式は2つ。
//  v1: 平文（既定）。{ v:1, hidden, backedUpAt, accounts:[…] }
//  v2: 暗号化（任意）。{ v:2, hidden, backedUpAt, kdf, iter, salt, iv, ct }。アカウント一覧は ct の中だけにある
// 「コードを隠す」設定と最終バックアップ日時は秘密ではないので、暗号化していても外に置く（ロック中も触れる）。
import { normalizeAccount, canonicalSecret } from './otp.js';
import { AAD_VAULT, b64d, b64e, checkIter, decryptJson, encryptJson } from './crypto.js';

export const VAULT_KEY = 'kagimori.vault.v1';

function cleanList(list) {
  const accounts = [];
  const seen = new Set();
  let dropped = 0;
  for (const item of Array.isArray(list) ? list : []) {
    try {
      if (!item || typeof item !== 'object') throw new Error('bad');
      const a = normalizeAccount(item);
      const key = canonicalSecret(a.secret);
      if (seen.has(key)) {
        dropped++;
        continue;
      }
      seen.add(key);
      accounts.push(a);
    } catch {
      dropped++;
    }
  }
  return { accounts, dropped };
}

const meta = (raw) => ({
  hidden: !!raw && !Array.isArray(raw) && raw.hidden === true,
  backedUpAt: raw && Number.isFinite(raw.backedUpAt) ? raw.backedUpAt : 0,
});

/** 保存文字列を読む。壊れた項目は読み飛ばし、同じ秘密鍵の重複も捨てる。暗号化されていれば enc に封筒を入れて返す */
export function parseVault(text) {
  const state = { accounts: [], hidden: false, backedUpAt: 0, dropped: 0, enc: null };
  if (!text) return state;
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    return state;
  }
  Object.assign(state, meta(raw));
  if (raw && !Array.isArray(raw) && raw.v === 2 && raw.salt && raw.iv && raw.ct) {
    try {
      checkIter(raw.iter);
      state.enc = { salt: raw.salt, iter: raw.iter, iv: raw.iv, ct: raw.ct };
    } catch {
      /* 壊れた暗号化データは空として扱う（上書きしない限り元の文字列は残る） */
    }
    return state;
  }
  const list = Array.isArray(raw) ? raw : raw && Array.isArray(raw.accounts) ? raw.accounts : [];
  const c = cleanList(list);
  state.accounts = c.accounts;
  state.dropped = c.dropped;
  return state;
}

export function serializeVault(state) {
  return JSON.stringify({ v: 1, hidden: !!state.hidden, backedUpAt: state.backedUpAt || 0, accounts: state.accounts });
}

/** 暗号化して保存する文字列にする。key は deriveKey の結果、salt は b64 の元バイト列 */
export async function serializeEncrypted(state, enc) {
  const { iv, ct } = await encryptJson(enc.key, { accounts: state.accounts }, AAD_VAULT);
  return JSON.stringify({
    v: 2, hidden: !!state.hidden, backedUpAt: state.backedUpAt || 0,
    kdf: 'pbkdf2-sha256', iter: enc.iter, salt: b64e(enc.salt), iv, ct,
  });
}

/** 封筒と鍵から一覧を取り出す。鍵が違えば null */
export async function openEncrypted(env, key) {
  const data = await decryptJson(key, env.iv, env.ct, AAD_VAULT);
  if (!data) return null;
  return cleanList(data.accounts);
}

export const saltBytes = (env) => b64d(env.salt);

export function loadVault(storage) {
  try {
    return parseVault(storage.getItem(VAULT_KEY));
  } catch {
    return { accounts: [], hidden: false, backedUpAt: 0, dropped: 0, enc: null, unavailable: true };
  }
}

/** 文字列を書く。書けたら true */
export function writeVault(storage, text) {
  try {
    storage.setItem(VAULT_KEY, text);
    return true;
  } catch {
    return false;
  }
}

/** 平文で保存する（v1） */
export function saveVault(storage, state) {
  return writeVault(storage, serializeVault(state));
}

/** 同じ秘密鍵は名前が違っても足さない */
export function splitDuplicates(existing, incoming) {
  const seen = new Set(existing.map((a) => canonicalSecret(a.secret)));
  const fresh = [];
  const dup = [];
  for (const a of incoming) {
    const key = canonicalSecret(a.secret);
    if (seen.has(key)) dup.push(a);
    else {
      seen.add(key);
      fresh.push(a);
    }
  }
  return { fresh, dup };
}

export function mergeAccounts(existing, incoming) {
  const { fresh, dup } = splitDuplicates(existing, incoming);
  return { accounts: existing.concat(fresh), added: fresh.length, skipped: dup.length };
}

export function addedMessage(added, skipped) {
  if (!skipped) return `${added}件追加しました`;
  return `${added}件追加しました。${skipped}件は同じ秘密鍵がすでにあるので足していません`;
}
