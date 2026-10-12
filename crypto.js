// 鍵守 暗号部品。Web Crypto だけを使う（PBKDF2-SHA256 で鍵を作り、AES-GCM で暗号化）。
// パスワードも鍵も保存しない。復号した鍵は画面を開いている間だけメモリに置く。

const te = new TextEncoder();
const td = new TextDecoder();

export const KDF_ITER = 600000; // OWASP の PBKDF2-HMAC-SHA256 の推奨値
const ITER_MIN = 100000;
const ITER_MAX = 5000000; // 細工されたファイルで固まらないようにする上限

export function b64e(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export function b64d(s) {
  const bin = atob(String(s));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function newSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export function checkIter(iter) {
  const n = Number(iter);
  if (!Number.isInteger(n) || n < ITER_MIN || n > ITER_MAX) throw new Error('暗号化の設定が正しくありません');
  return n;
}

/** パスワードから鍵を作る。全角・半角の違いで開けなくならないよう NFKC にそろえる */
export async function deriveKey(password, salt, iter = KDF_ITER) {
  const base = await crypto.subtle.importKey('raw', te.encode(String(password).normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: checkIter(iter), hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // 鍵そのものは取り出せない
    ['encrypt', 'decrypt'],
  );
}

export async function encryptJson(key, obj, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 毎回新しい値
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, te.encode(JSON.stringify(obj)));
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

/** パスワードが違う、またはデータが書き換えられているときは null */
export async function decryptJson(key, iv, ct, aad) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(iv), additionalData: te.encode(aad) }, key, b64d(ct));
    return JSON.parse(td.decode(pt));
  } catch {
    return null;
  }
}

export const AAD_VAULT = 'kagimori.vault.v2';
export const AAD_BACKUP = 'kagimori.backup.v1';

export const MIN_PASSWORD = 8;

/** パスワードの最低条件。弱すぎるものを断る（強さの保証ではない） */
export function passwordProblem(pw) {
  const s = String(pw ?? '').normalize('NFKC');
  if ([...s].length < MIN_PASSWORD) return `パスワードは${MIN_PASSWORD}文字以上にしてください`;
  if (new Set(s).size < 4) return '同じ文字ばかりのパスワードは使えません';
  return '';
}
