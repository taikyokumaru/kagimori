// 鍵守 画面。鍵は端末の localStorage にだけ置き、どこへも送らない。
import {
  buildOtpauth, codeFor, displayLabel, formatCode, normalizeAccount, nonStandardPeriod,
  parseInput, parseMigration, planMigration, totpCounter, totpRemaining,
} from './otp.js';
import { qrSvg } from './qr.js';
import {
  VAULT_KEY, addedMessage, loadVault, mergeAccounts, openEncrypted, saltBytes, serializeEncrypted, serializeVault,
  splitDuplicates, writeVault,
} from './vault.js';
import { KDF_ITER, MIN_PASSWORD, deriveKey, newSalt, passwordProblem } from './crypto.js';
import { backupFileName, inspectBackup, makeBackup, readBackup } from './backup.js';

// ---------- 小さな道具 ----------
const $ = (sel, root = document) => root.querySelector(sel);
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v; // 自前の固定SVGだけ。利用者やQR由来の文字列は絶対に入れない
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el && typeof v !== 'object' && !k.includes('-')) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  const add = (list) => {
    for (const c of list) {
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) add(c);
      else el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
  };
  add(kids);
  return el;
}

const svg = (inner) => `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">${inner}</svg>`;
const ICONS = {
  eye: svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
  eyeOff: svg('<path d="M3 3l18 18"/><path d="M10.6 5.1A10.6 10.6 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.7C3.9 8.5 2 12 2 12s3.5 7 10 7c1.7 0 3.2-.4 4.5-1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>'),
  transfer: svg('<path d="M5 8h13m0 0-3-3m3 3-3 3"/><path d="M19 16H6m0 0 3-3m-3 3 3 3"/>'),
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  camera: svg('<path d="M4 8h3l1.5-2h7L17 8h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>'),
  image: svg('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.6"/><path d="M21 16l-5-5-8 8"/>'),
  link: svg('<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1-1"/>'),
  keyboard: svg('<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>'),
  play: svg('<circle cx="12" cy="12" r="9"/><path d="M10 8.5l5 3.5-5 3.5z"/>'),
  copy: svg('<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>'),
  x: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  lock: svg('<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>'),
  chevron: svg('<path d="M9 6l6 6-6 6"/>'),
  file: svg('<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4M10 13h5M10 17h5"/>'),
  pin: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M9 3h6l-1 6 3 3v2h-4v7l-1 1-1-1v-7H7v-2l3-3z"/></svg>',
};

const SUBTITLE_ONLINE = 'この端末の中だけで、確認コードを出します。';
const SUBTITLE_OFFLINE = 'オフラインです。この端末に保存した鍵でコードを出します';
const SAMPLE = { type: 'totp', issuer: '鍵守', name: 'サンプル', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 };
const NO_ENGINE_MSG = 'QRの読み取り部品（jsQR）を読み込めませんでした。otpauth のリンクを貼り付けるか、手入力で追加してください。';

// ---------- 状態と保存 ----------
let storage = null;
try {
  storage = window.localStorage;
  storage.getItem(VAULT_KEY);
} catch {
  storage = null;
}
const memoryStore = { v: null, getItem() { return this.v; }, setItem(_k, v) { this.v = v; } };
const store = storage || memoryStore;

// enc: 暗号化が有効でロック解除中のとき { key, salt, iter }。パスワードそのものは持たない
// envelope: ロック中に、暗号化された保存データの外側（salt・iv・ct）を持つ
const state = { accounts: [], hidden: false, backedUpAt: 0, query: '', locked: false, enc: null, envelope: null };
let saveWarned = false;
let writeChain = Promise.resolve();

function warnSave() {
  if (saveWarned) return;
  saveWarned = true;
  toast('この環境では保存できませんでした。ブラウザを閉じると鍵が消えます', { error: true });
}

/** 保存を順番に行う（暗号化は非同期なので、書き込みが前後しないように一列に並べる）。ロック中は何も書かない */
function persist() {
  if (state.locked) return writeChain;
  const snap = { accounts: state.accounts.map((a) => ({ ...a })), hidden: state.hidden, backedUpAt: state.backedUpAt };
  const enc = state.enc;
  writeChain = writeChain.then(async () => {
    let text = null;
    try {
      text = enc ? await serializeEncrypted(snap, enc) : serializeVault(snap);
    } catch { /* 下で警告 */ }
    if (text === null || !writeVault(store, text)) warnSave();
  });
  return writeChain;
}

function applyLoaded(v) {
  state.hidden = v.hidden;
  state.backedUpAt = v.backedUpAt;
  state.enc = null;
  if (v.enc) {
    state.locked = true;
    state.envelope = v.enc;
    state.accounts = [];
  } else {
    state.locked = false;
    state.envelope = null;
    state.accounts = v.accounts;
  }
  codeCache.clear();
  nextCache.clear();
}

async function storagePersisted() {
  try {
    if (navigator.storage && navigator.storage.persisted) return await navigator.storage.persisted();
  } catch { /* 不明 */ }
  return null;
}

/** 「消えにくい保存」を頼む。ブラウザが自動で決めることもあり、断られることもある */
async function requestPersist() {
  try {
    if (navigator.storage && navigator.storage.persist) return await navigator.storage.persist();
  } catch { /* 無視 */ }
  return false;
}

// ---------- トースト ----------
function toast(message, { error = false, action = null, ms = 0 } = {}) {
  let el = null;
  const dismiss = () => {
    if (!el || !el.isConnected) return;
    if (reduceMotion()) return el.remove();
    el.classList.add('out');
    setTimeout(() => el.remove(), 220);
  };
  el = h(
    'div',
    { class: 'toast' + (error ? ' error' : ''), role: 'status' },
    h('span', { text: message }),
    action ? h('button', { type: 'button', class: 'toast-action', text: action.label, onclick: () => { dismiss(); action.fn(); } }) : null,
  );
  const box = $('#toasts');
  box.append(el);
  while (box.children.length > 3) box.firstElementChild.remove(); // 重なりすぎないよう、古いものから消す
  setTimeout(dismiss, ms || Math.min(7000, 2400 + message.length * 45));
}

// ---------- シート ----------
let current = null;

function focusables(root) {
  return [...root.querySelectorAll('button, [href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])')].filter(
    (e) => !e.disabled && !e.closest('[hidden]') && e.offsetParent !== null,
  );
}

function openSheet(title, build) {
  if (current) closeSheet(true);
  const ctrl = { cleanups: [], live: new Set(), onHide: null, title };
  ctrl.onClose = (fn) => ctrl.cleanups.push(fn);
  ctrl.close = () => closeSheet();
  const body = h('div', { class: 'sheet-body' });
  const sheet = h(
    'div',
    { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, tabindex: '-1' },
    h('div', { class: 'sheet-grab', 'aria-hidden': 'true' }),
    h('div', { class: 'sheet-head' }, h('h2', { text: title }), h('button', { type: 'button', class: 'icon-btn', 'aria-label': '閉じる', html: ICONS.x, onclick: () => closeSheet() })),
    body,
  );
  const scrim = h('div', { class: 'scrim' }, sheet);
  let downOnScrim = false;
  scrim.addEventListener('pointerdown', (e) => { downOnScrim = e.target === scrim; });
  scrim.addEventListener('click', (e) => { if (e.target === scrim && downOnScrim) closeSheet(); });
  ctrl.scrim = scrim;
  ctrl.sheet = sheet;
  ctrl.body = body;
  ctrl.prevFocus = document.activeElement;
  build(ctrl, body);
  $('#sheet-root').append(scrim);
  document.body.classList.add('sheet-open');
  sheet.focus({ preventScroll: true });
  current = ctrl;
  return ctrl;
}

function closeSheet(immediate = false) {
  const c = current;
  if (!c) return;
  current = null;
  for (const fn of c.cleanups.splice(0)) {
    try { fn(); } catch { /* 後始末の失敗は無視 */ }
  }
  const done = () => {
    c.scrim.remove();
    if (!current) {
      document.body.classList.remove('sheet-open');
      try { c.prevFocus?.focus?.({ preventScroll: true }); } catch { /* noop */ }
    }
  };
  if (immediate || reduceMotion()) done();
  else {
    c.scrim.classList.add('closing');
    setTimeout(done, 190);
  }
}

document.addEventListener('keydown', (e) => {
  if (!current) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    closeSheet();
  } else if (e.key === 'Tab') {
    const list = focusables(current.sheet);
    if (!list.length) return;
    const first = list[0];
    const last = list[list.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === current.sheet)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
});

// ---------- コード計算と表示 ----------
const codeCache = new Map(); // id -> { key, code }

function cacheKey(a, now) {
  return a.type === 'hotp' ? `h${a.counter}` : `t${totpCounter(now, a.period)}`;
}

async function ensureCode(a, now = Date.now()) {
  const key = cacheKey(a, now);
  const hit = codeCache.get(a.id);
  if (hit && hit.key === key) return hit.code;
  const code = await codeFor(a, now);
  codeCache.set(a.id, { key, code });
  return code;
}

const dots = (n) => formatCode('•'.repeat(n));
const RING_C = 2 * Math.PI * 18;

function makeRing() {
  const el = h('div', {
    class: 'ring',
    html: `<svg viewBox="0 0 44 44" aria-hidden="true"><circle class="track" cx="22" cy="22" r="18"/><circle class="bar" cx="22" cy="22" r="18" stroke-dasharray="${RING_C.toFixed(2)}" stroke-dashoffset="0"/></svg><span class="sec"></span>`,
  });
  const bar = $('.bar', el);
  const sec = $('.sec', el);
  return {
    el,
    set(now, period) {
      const ms = period * 1000;
      const remainMs = ms - (now % ms);
      const secs = totpRemaining(now, period);
      bar.style.strokeDashoffset = String((RING_C * (1 - remainMs / ms)).toFixed(2));
      if (sec.textContent !== String(secs)) sec.textContent = String(secs);
      el.classList.toggle('low', period > 10 && secs <= 5);
      el.setAttribute('role', 'img');
      el.setAttribute('aria-label', `次の更新まで${secs}秒`);
    },
  };
}

const nextCache = new Map(); // 次のコードの予告用（今のコードのキャッシュとは別にする）
async function ensureNext(a, now) {
  const t = now + a.period * 1000;
  const key = `t${totpCounter(t, a.period)}`;
  const hit = nextCache.get(a.id);
  if (hit && hit.key === key) return hit.code;
  const code = await codeFor(a, t);
  nextCache.set(a.id, { key, code });
  return code;
}

/** コードと残り秒の表示を毎回の刻みで更新する関数を作る。隠しているときは数字をDOMに置かない */
function makeLive(getAccount, codeEl, ring, nextEl) {
  let busy = false;
  let lastCode;
  let lastText = null;
  return async (now) => {
    if (busy) return;
    busy = true;
    try {
      const a = getAccount();
      if (!a) return;
      if (a.type === 'totp' && ring) ring.set(now, a.period);
      const code = await ensureCode(a, now);
      if (code === null) {
        if (lastText !== '!') { codeEl.textContent = '鍵が不正です'; lastText = '!'; }
        return;
      }
      const text = state.hidden ? dots(a.digits) : formatCode(code);
      codeEl.classList.toggle('is-hidden', state.hidden);
      codeEl.setAttribute('aria-label', state.hidden ? 'コードは隠れています。表示してからコピーできます' : `コード ${code.split('').join(' ')}。押すとコピーします`);
      if (text !== lastText) {
        const codeChanged = lastCode !== undefined && lastCode !== code;
        codeEl.textContent = text;
        if (codeChanged && !state.hidden && !reduceMotion()) {
          codeEl.classList.remove('fade');
          void codeEl.offsetWidth;
          codeEl.classList.add('fade');
        }
        lastText = text;
      }
      lastCode = code;
      if (nextEl) {
        // 切り替わる直前（残り5秒以下）だけ、次のコードを小さく見せる。隠しているときは出さない
        let show = false;
        if (a.type === 'totp' && !state.hidden && a.period > 10 && totpRemaining(now, a.period) <= 5) {
          const nc = await ensureNext(a, now);
          if (nc) {
            const t = `次 ${formatCode(nc)}`;
            if (nextEl.textContent !== t) nextEl.textContent = t;
            show = true;
          }
        }
        nextEl.classList.toggle('show', show);
      }
    } finally {
      busy = false;
    }
  };
}

async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch { /* フォールバックへ */ }
  try {
    const ta = h('textarea', { value: text, readOnly: true, 'aria-hidden': 'true', tabindex: '-1' });
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;';
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

async function copyCode(a) {
  if (state.hidden) {
    toast('表示してからコピーしてください');
    return;
  }
  const code = await ensureCode(a);
  if (!code) return;
  toast((await writeClipboard(code)) ? 'コピーしました' : 'コピーできませんでした', {});
}

// ---------- 一覧 ----------
const liveRows = new Set();
const norm = (s) => String(s).normalize('NFKC').toLowerCase();

function metaText(a) {
  const parts = [];
  if (a.type === 'hotp') parts.push(`カウンタ ${a.counter}`);
  else if (a.period !== 30) parts.push(`${a.period}秒ごと`);
  if (a.algorithm !== 'SHA1') parts.push(a.algorithm);
  if (a.digits !== 6) parts.push(`${a.digits}桁`);
  return parts.join(' ・ ');
}

let backupDismissed = false;

function renderAll() {
  const locked = state.locked;
  $('#lock-view').hidden = !locked;
  $('#vault-view').hidden = locked;
  $('#appbar-actions').hidden = locked;
  if (locked) {
    liveRows.clear();
    $('#list').replaceChildren();
    return;
  }
  const none = state.accounts.length === 0;
  $('#empty').hidden = !none;
  $('#btn-delete-all').hidden = none;
  $('#btn-transfer').hidden = none;
  $('#btn-lock').hidden = !state.enc;
  const many = state.accounts.length >= 5;
  $('#search-box').hidden = !many;
  if (!many && state.query) {
    state.query = '';
    $('#search').value = '';
  }
  renderBackupNote();
  renderToggle();
  renderList();
}

function renderBackupNote() {
  const days = state.backedUpAt ? Math.floor((Date.now() - state.backedUpAt) / 864e5) : null;
  const need = state.accounts.length > 0 && !backupDismissed && (days === null || days >= 30);
  $('#backup-note').hidden = !need;
  if (need) {
    $('#backup-note-text').textContent = days === null
      ? 'まだバックアップがありません。ブラウザのデータが消えると、鍵も消えます。暗号化したファイルに書き出しておくと安心です。'
      : `最後のバックアップから${days}日たっています。鍵を足したときは、取り直してください。`;
  }
}

function renderToggle() {
  const b = $('#btn-toggle');
  b.innerHTML = state.hidden ? ICONS.eyeOff : ICONS.eye;
  b.setAttribute('aria-pressed', String(state.hidden));
  b.setAttribute('aria-label', state.hidden ? 'コードを表示する' : 'コードを隠す');
}

function orderedAccounts() {
  // 固定した鍵を上に。それぞれの中は保存順
  return state.accounts.filter((a) => a.pinned).concat(state.accounts.filter((a) => !a.pinned));
}

function neighborIndex(id, dir) {
  const i = state.accounts.findIndex((a) => a.id === id);
  if (i < 0) return -1;
  const pinned = !!state.accounts[i].pinned;
  let j = i + dir;
  while (j >= 0 && j < state.accounts.length && !!state.accounts[j].pinned !== pinned) j += dir;
  return j >= 0 && j < state.accounts.length ? j : -1;
}

function moveAccount(id, dir) {
  const j = neighborIndex(id, dir);
  if (j < 0) return false;
  const i = state.accounts.findIndex((a) => a.id === id);
  [state.accounts[i], state.accounts[j]] = [state.accounts[j], state.accounts[i]];
  return true;
}

function renderList() {
  liveRows.clear();
  const list = $('#list');
  list.replaceChildren();
  const q = norm(state.query.trim());
  const shown = orderedAccounts().filter((a) => !q || norm(`${a.issuer} ${a.name}`).includes(q));
  $('#no-hit').hidden = !(q && state.accounts.length && !shown.length);
  for (const a of shown) {
    const id = a.id;
    const get = () => state.accounts.find((x) => x.id === id);
    const codeEl = h('button', { type: 'button', class: 'code', text: '------', onclick: () => copyCode(get()) });
    const nextEl = h('span', { class: 'next', 'aria-hidden': 'true' });
    const ring = a.type === 'totp' ? makeRing() : null;
    const meta = metaText(a);
    const pin = a.pinned ? h('span', { class: 'pin', html: ICONS.pin, title: '固定' }) : null;
    const li = h(
      'li',
      { class: 'row' },
      h(
        'div',
        { class: 'row-body' },
        h(
          'button',
          { type: 'button', class: 'row-main', 'aria-label': `${displayLabel(a)} の詳細を開く`, onclick: () => openDetail(id) },
          a.issuer || pin ? h('span', { class: 'row-issuer' }, pin, a.issuer) : null,
          h('span', { class: 'row-name', text: a.name || (a.issuer ? '' : '（名前なし）') }),
        ),
        codeEl,
        nextEl,
        meta ? h('span', { class: 'row-meta', text: meta }) : null,
      ),
      h(
        'div',
        { class: 'row-side' },
        ring ? ring.el : h('span', { class: 'hotp-badge', text: 'HOTP' }),
        h('button', { type: 'button', class: 'icon-btn', 'aria-label': `${displayLabel(a)} の詳細を開く`, html: ICONS.chevron, onclick: () => openDetail(id) }),
      ),
    );
    list.append(li);
    const live = makeLive(get, codeEl, ring, nextEl);
    liveRows.add(live);
    live(Date.now());
  }
}

// ---------- 時計・ネットワーク状態 ----------
function formatClock(now) {
  const d = new Date(now);
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '−';
  const hh = Math.floor(Math.abs(off) / 60);
  const mm = Math.abs(off) % 60;
  const tz = `UTC${sign}${hh}${mm ? ':' + String(mm).padStart(2, '0') : ''}`;
  const date = d.toLocaleDateString('ja-JP', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' });
  const time = d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  return `${date} ${time}（${tz}）`;
}

function updateNet() {
  const off = !navigator.onLine;
  const s = $('#subtitle');
  s.textContent = off ? SUBTITLE_OFFLINE : SUBTITLE_ONLINE;
  s.classList.toggle('offline', off);
}

let lastClockSec = -1;
let lastActive = Date.now();
let hiddenAt = 0;
let locking = false;
const IDLE_MS = 5 * 60 * 1000; // 暗号化しているとき、5分操作がなければロック
const AWAY_MS = 60 * 1000; // 画面を離れて1分たったらロック

function tick() {
  const now = Date.now();
  if (!state.locked) {
    for (const u of liveRows) u(now);
    if (current) for (const u of current.live) u(now);
    if (state.enc && now - lastActive > IDLE_MS) lockNow();
  }
  const s = Math.floor(now / 1000);
  if (s !== lastClockSec) {
    lastClockSec = s;
    $('#clock').textContent = formatClock(now);
  }
}

async function lockNow() {
  if (!state.enc || state.locked || locking) return;
  locking = true;
  try {
    await writeChain; // 書き込み中のものを待つ
    const env = loadVault(store).enc;
    if (!env) return;
    closeSheet(true);
    state.accounts = [];
    state.enc = null;
    state.envelope = env;
    state.locked = true;
    state.query = '';
    $('#search').value = '';
    codeCache.clear();
    nextCache.clear();
    renderAll();
    setTimeout(() => $('#lock-pw').focus({ preventScroll: true }), 50);
  } finally {
    locking = false;
  }
}

async function unlock(password) {
  const env = state.envelope;
  if (!env) return false;
  let key;
  let r;
  try {
    key = await deriveKey(password, saltBytes(env), env.iter);
    r = await openEncrypted(env, key);
  } catch {
    return false;
  }
  if (!r) return false;
  state.accounts = r.accounts;
  state.enc = { key, salt: saltBytes(env), iter: env.iter };
  state.envelope = null;
  state.locked = false;
  lastActive = Date.now();
  renderAll();
  return true;
}

// ---------- 追加 ----------
function addAccounts(list) {
  const { fresh, dup } = splitDuplicates(state.accounts, list);
  state.accounts.push(...fresh);
  persist();
  renderAll();
  toast(addedMessage(fresh.length, dup.length));
  if (fresh.length) requestPersist(); // 消えにくい保存を頼む（利用者の操作の直後に）
  return { added: fresh.length, skipped: dup.length };
}

function openAddMenu() {
  const item = (icon, title, sub, fn) =>
    h('button', { type: 'button', class: 'menu-item', onclick: fn }, h('span', { html: ICONS[icon], style: 'display:contents' }), h('span', { class: 'menu-text' }, h('span', { text: title }), sub ? h('span', { class: 'menu-sub', text: sub }) : null));
  openSheet('鍵を追加', (_c, body) => {
    body.append(
      h(
        'div',
        { class: 'menu' },
        item('camera', 'カメラで読み取る', 'サービスの画面のQRをかざします', () => openScanner()),
        item('image', '画像から読み取る', 'スクリーンショットや写真を選びます（ドラッグ＆ドロップ、貼り付けも可）', () => pickImage()),
        item('link', 'otpauthリンクを貼り付ける', 'otpauth:// で始まるリンク', () => openPaste()),
        item('keyboard', '手入力', 'サービス名と秘密鍵を入力します', () => openManual()),
        item('file', 'バックアップファイル', '書き出したJSONから読み込みます', () => pickBackup()),
        item('play', 'サンプル', '動作を見るための練習用の鍵を足します', () => addSample()),
      ),
    );
  });
}

function addSample() {
  closeSheet();
  addAccounts([normalizeAccount(SAMPLE)]);
}

function openPaste() {
  openSheet('リンクを貼り付ける', (c, body) => {
    const ta = h('textarea', { placeholder: 'otpauth://totp/… または otpauth-migration://offline?data=…', autocomplete: 'off', autocapitalize: 'off', spellcheck: false, 'aria-label': 'otpauthリンク' });
    const err = h('p', { class: 'error-text', role: 'alert', hidden: true });
    const go = () => {
      const res = parseInput(ta.value);
      if (!res.items.length) {
        err.textContent = res.errors[0] || '読み取れませんでした';
        err.hidden = false;
        return;
      }
      openConfirm(res, { viaImage: false });
    };
    body.append(
      h('p', { class: 'hint', text: '文章の中に混ざっていても、otpauth:// のリンク部分だけを取り出します。' }),
      ta,
      err,
      h('button', { type: 'button', class: 'btn btn-primary', text: '内容を確認する', onclick: go }),
    );
    setTimeout(() => ta.focus({ preventScroll: true }), 50);
  });
}

function openManual() {
  openSheet('手入力で追加', (c, body) => {
    const field = (label, input, id) => h('div', { class: 'field' }, h('label', { for: id, text: label }), input);
    const typeSel = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': '種類' },
      h('label', {}, h('input', { type: 'radio', name: 'otp-type', value: 'totp', checked: true }), '時間ごと（TOTP）'),
      h('label', {}, h('input', { type: 'radio', name: 'otp-type', value: 'hotp' }), '回数ごと（HOTP）'),
    );
    const issuer = h('input', { type: 'text', id: 'm-issuer', autocomplete: 'off', placeholder: '例: GitHub' });
    const name = h('input', { type: 'text', id: 'm-name', autocomplete: 'off', placeholder: '例: you@example.com' });
    const secret = h('input', { type: 'text', id: 'm-secret', autocomplete: 'off', autocapitalize: 'characters', spellcheck: false, placeholder: 'JBSW Y3DP EHPK 3PXP', class: 'mono' });
    const algo = h('select', { id: 'm-algo' }, ...['SHA1', 'SHA256', 'SHA512'].map((x) => h('option', { value: x, text: x })));
    const digits = h('select', { id: 'm-digits' }, h('option', { value: '6', text: '6桁' }), h('option', { value: '8', text: '8桁' }));
    const period = h('input', { type: 'number', id: 'm-period', inputmode: 'numeric', min: '1', step: '1', value: '30' });
    const counter = h('input', { type: 'number', id: 'm-counter', inputmode: 'numeric', min: '0', step: '1', value: '0' });
    const periodField = field('更新間隔（秒）', period, 'm-period');
    const counterField = field('カウンタ', counter, 'm-counter');
    counterField.hidden = true;
    typeSel.addEventListener('change', () => {
      const hotp = typeSel.querySelector('input:checked').value === 'hotp';
      periodField.hidden = hotp;
      counterField.hidden = !hotp;
    });
    const err = h('p', { class: 'error-text', role: 'alert', hidden: true });
    const submit = () => {
      try {
        const type = typeSel.querySelector('input:checked').value;
        const a = normalizeAccount({ type, issuer: issuer.value, name: name.value, secret: secret.value, algorithm: algo.value, digits: Number(digits.value), period: period.value, counter: counter.value });
        if (!a.issuer && !a.name) throw new Error('サービス名かアカウント名のどちらかを入れてください');
        closeSheet();
        addAccounts([a]);
      } catch (e) {
        err.textContent = e.message || '入力を確認してください';
        err.hidden = false;
      }
    };
    body.append(
      typeSel,
      field('サービス名', issuer, 'm-issuer'),
      field('アカウント名', name, 'm-name'),
      field('秘密鍵（Base32）', secret, 'm-secret'),
      h('details', { class: 'adv' }, h('summary', { text: '詳しい設定' }), h('div', { class: 'adv-grid' }, field('アルゴリズム', algo, 'm-algo'), field('桁数', digits, 'm-digits'), periodField, counterField)),
      err,
      h('button', { type: 'button', class: 'btn btn-primary', text: '追加する', onclick: submit }),
    );
  });
}

// ---------- 取り込みの確認 ----------
function describe(a) {
  const parts = [a.type === 'hotp' ? 'HOTP' : 'TOTP', a.algorithm, `${a.digits}桁`];
  parts.push(a.type === 'hotp' ? `カウンタ ${a.counter}` : `${a.period}秒`);
  return parts.join(' ・ ');
}

function openConfirm(res, { viaImage = false } = {}) {
  const accounts = res.items.map((i) => i.account);
  const { fresh, dup } = splitDuplicates(state.accounts, accounts);
  const dupSet = new Set(dup);
  const migrations = res.notes.filter((n) => n.kind === 'migration');
  openSheet('取り込む鍵の確認', (c, body) => {
    const notes = [];
    notes.push(h('p', { text: '表示されている名前は、QRを作った側が決めた文言です。見覚えのないサービス名のときは追加しないでください。' }));
    if (viaImage) notes.push(h('p', { text: '画像から読み取りました。取り込んだら、元の写真やスクリーンショットは端末から削除してください。秘密鍵が写っています。' }));
    body.append(h('div', { class: 'note' }, notes));
    for (const n of res.notes.filter((x) => x.kind === 'backup')) {
      const b = [h('p', { text: 'バックアップファイルから読み込みます。同じ秘密鍵がすでにある鍵は足しません。' })];
      if (!n.encrypted) b.push(h('p', { text: 'このファイルは暗号化されていません。取り込んだら、不要なコピーは削除してください。' }));
      if (n.skipped) b.push(h('p', { text: `読み込めない項目が${n.skipped}件あったので飛ばしました。` }));
      body.append(h('div', { class: 'note' + (n.encrypted ? '' : ' warn') }, b));
    }
    if (migrations.length) {
      const m = [h('p', { text: '移行用のQRには更新間隔の情報がありません。TOTPはすべて30秒として取り込みます。30秒ではないサービスのコードは合わなくなるので、取り込んだあとに使えるか確かめてください。' })];
      for (const n of migrations) {
        if (n.batchSize > 1) m.push(h('p', { text: `このQRは${n.batchSize}枚中${n.batchIndex + 1}枚目です。残りも読み取らないと、その鍵は入りません` }));
        if (n.skipped) m.push(h('p', { text: `未対応の形式の鍵が${n.skipped}件あったので飛ばしました。` }));
      }
      body.append(h('div', { class: 'note warn' }, m));
    }
    if (res.errors.length) body.append(h('div', { class: 'note danger' }, res.errors.map((e) => h('p', { text: `読み取れなかったものがあります: ${e}` }))));
    if (accounts.length) {
      body.append(
        h('div', { class: 'check-list' }, accounts.map((a) =>
          h('div', { class: 'item' + (dupSet.has(a) ? ' is-dup' : '') },
            h('div', { class: 'item-text' }, h('span', { class: 'item-title', text: displayLabel(a) }), h('span', { class: 'item-sub', text: describe(a) })),
            dupSet.has(a) ? h('span', { class: 'tag dup', text: 'すでにあります' }) : null,
          ),
        )),
      );
    }
    if (dup.length) body.append(h('p', { class: 'hint', text: `${dup.length}件は同じ秘密鍵がすでにあるので足しません。` }));
    body.append(
      h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn-secondary', text: 'やめる', onclick: () => closeSheet() }),
        h('button', { type: 'button', class: 'btn btn-primary', text: `${fresh.length}件を追加する`, disabled: fresh.length === 0, onclick: () => { closeSheet(); addAccounts(accounts); } }),
      ),
    );
  });
}

// ---------- QRの読み取り ----------
let jsQRPromise = null;
function loadJsQR() {
  if (typeof window.jsQR === 'function') return Promise.resolve(window.jsQR);
  jsQRPromise ??= new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = '/vendor/jsQR.js';
    s.onload = () => resolve(typeof window.jsQR === 'function' ? window.jsQR : null);
    s.onerror = () => resolve(null);
    document.head.append(s);
  });
  return jsQRPromise.then((q) => {
    if (!q) jsQRPromise = null; // 次回また試せるように
    return q;
  });
}

let decoderPromise = null;
/** canvas からQRの文字列を取り出す関数。jsQR が無いときだけ、ブラウザ標準の BarcodeDetector に頼る */
function getDecoder() {
  decoderPromise ??= (async () => {
    const q = await loadJsQR();
    if (q) {
      return async (canvas, both) => {
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const r = q(img.data, img.width, img.height, { inversionAttempts: both ? 'attemptBoth' : 'dontInvert' });
        return r ? r.data : null;
      };
    }
    if ('BarcodeDetector' in window) {
      try {
        const formats = await window.BarcodeDetector.getSupportedFormats();
        if (formats.includes('qr_code')) {
          const det = new window.BarcodeDetector({ formats: ['qr_code'] });
          return async (canvas) => {
            const r = await det.detect(canvas);
            return r.length ? r[0].rawValue : null;
          };
        }
      } catch { /* 使えない */ }
    }
    return null;
  })();
  return decoderPromise.then((d) => {
    if (!d) decoderPromise = null;
    return d;
  });
}

const cameraErrorMessage = (e) => {
  switch (e && e.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'カメラの使用が許可されていません。ブラウザの設定で許可するか、下の「画像から読み取る」「リンクを貼り付ける」から追加してください。';
    case 'NotFoundError':
    case 'OverconstrainedError':
      return 'カメラが見つかりません。下の「画像から読み取る」「リンクを貼り付ける」から追加してください。';
    case 'NotReadableError':
    case 'AbortError':
      return 'カメラを開けません。ほかのアプリが使っているかもしれません。閉じてからもう一度試すか、画像や貼り付けから追加してください。';
    default:
      return 'カメラを開けませんでした。画像や貼り付けから追加してください。';
  }
};

function openScanner() {
  let stream = null;
  let running = true;
  let lastHint = '';
  const video = h('video', { muted: true, autoplay: true, playsinline: true, 'aria-label': 'カメラの映像' });
  video.setAttribute('playsinline', '');
  video.muted = true;
  const overlay = h('div', { class: 'cam-msg', role: 'status', text: 'カメラを準備しています…' });
  const status = h('p', { class: 'scan-status', role: 'status', 'aria-live': 'polite' });
  const stop = () => {
    running = false;
    if (stream) stream.getTracks().forEach((t) => t.stop());
    stream = null;
    video.srcObject = null;
  };
  const fail = (msg) => {
    stop();
    overlay.textContent = msg;
    overlay.hidden = false;
    status.textContent = '';
  };

  const ctrl = openSheet('QRを読み取る', (c, body) => {
    body.append(
      h('div', { class: 'cam' }, video, h('div', { class: 'cam-frame', 'aria-hidden': 'true' }), overlay),
      status,
      h('p', { class: 'hint', text: 'カメラの映像はこの端末の中で処理するだけで、保存も送信もしません。' }),
      h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn-secondary', text: '画像から読み取る', onclick: () => pickImage() }),
        h('button', { type: 'button', class: 'btn btn-secondary', text: 'リンクを貼り付ける', onclick: () => openPaste() }),
      ),
    );
  });
  ctrl.onClose(stop);

  (async () => {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      return fail(window.isSecureContext === false ? 'カメラはHTTPSで開いたときだけ使えます。下の「画像から読み取る」「リンクを貼り付ける」から追加してください。' : 'このブラウザではカメラを使えません。下の「画像から読み取る」「リンクを貼り付ける」から追加してください。');
    }
    const decoder = await getDecoder();
    if (!running) return;
    if (!decoder) return fail(NO_ENGINE_MSG);
    try {
      // 背面カメラを優先
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
    } catch (e1) {
      if (e1 && (e1.name === 'NotAllowedError' || e1.name === 'SecurityError')) return fail(cameraErrorMessage(e1));
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false }); // 制約なしで再試行
      } catch (e2) {
        return fail(cameraErrorMessage(e2));
      }
    }
    if (!running) {
      stream.getTracks().forEach((t) => t.stop());
      return;
    }
    video.srcObject = stream;
    try { await video.play(); } catch { /* 自動再生が止められても映像は出る */ }
    overlay.hidden = true;
    status.textContent = 'QRを枠に入れてください';

    const canvas = document.createElement('canvas');
    const startedAt = Date.now();
    let last = 0;
    let busy = false;
    const loop = async (ts) => {
      if (!running) return;
      if (!busy && ts - last > 140 && video.readyState >= 2 && video.videoWidth) {
        busy = true;
        last = ts;
        try {
          const scale = Math.min(1, 720 / Math.max(video.videoWidth, video.videoHeight));
          canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
          canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
          canvas.getContext('2d', { willReadFrequently: true }).drawImage(video, 0, 0, canvas.width, canvas.height);
          const text = await decoder(canvas, false);
          if (text && running) {
            const res = parseInput(text);
            if (res.items.length) {
              stop();
              openConfirm(res, { viaImage: false });
              return;
            }
            const hint = res.errors[0] && !/見つかりませんでした/.test(res.errors[0]) ? res.errors[0] : 'このQRは鍵守で使える鍵（otpauth）ではありません';
            if (hint !== lastHint) {
              lastHint = hint;
              status.textContent = hint;
            }
          } else if (!lastHint && Date.now() - startedAt > 10000) {
            status.textContent = 'QRが見つかりません。明るい場所で、QR全体が枠に入るように近づけてください。画像や貼り付けからも追加できます。';
          }
        } catch { /* 1フレームの失敗は無視 */ }
        busy = false;
      }
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  })();
  return ctrl;
}

async function loadBitmap(file) {
  if (window.createImageBitmap) {
    try { return await createImageBitmap(file); } catch { /* Image で再試行 */ }
  }
  const url = URL.createObjectURL(file);
  try {
    return await new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('decode'));
      img.src = url;
    });
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function decodeImageFile(file) {
  const decoder = await getDecoder();
  if (!decoder) throw new Error(NO_ENGINE_MSG);
  let bmp;
  try {
    bmp = await loadBitmap(file);
  } catch {
    throw new Error('この画像は開けませんでした。PNGやJPEGのスクリーンショットなどを選んでください。');
  }
  const w = bmp.width || bmp.naturalWidth;
  const hgt = bmp.height || bmp.naturalHeight;
  const canvas = document.createElement('canvas');
  for (const side of [1600, 1000, 600]) {
    const s = Math.min(1, side / Math.max(w, hgt));
    canvas.width = Math.max(1, Math.round(w * s));
    canvas.height = Math.max(1, Math.round(hgt * s));
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
    const text = await decoder(canvas, true);
    if (text) {
      if (bmp.close) bmp.close();
      return text;
    }
  }
  if (bmp.close) bmp.close();
  return null;
}

async function handleImageFile(file) {
  if (state.locked) return toast('先にロックを解除してください');
  toast('画像を読み取っています…');
  try {
    const text = await decodeImageFile(file);
    if (!text) return toast('画像からQRが見つかりませんでした。QRが大きく写った、ぶれていない画像を選んでください', { error: true });
    const res = parseInput(text);
    if (!res.items.length) return toast(res.errors[0] && !/見つかりませんでした/.test(res.errors[0]) ? res.errors[0] : 'このQRは鍵守で使える鍵（otpauth）ではありません', { error: true });
    openConfirm(res, { viaImage: true });
  } catch (e) {
    toast(e.message || '読み取れませんでした', { error: true });
  }
}

function pickImage() {
  const input = $('#file-input');
  input.value = '';
  input.onchange = () => {
    const file = input.files && input.files[0];
    input.value = '';
    if (file) handleImageFile(file);
  };
  input.click();
}

function pickBackup() {
  const input = $('#backup-input');
  input.value = '';
  input.onchange = () => {
    const file = input.files && input.files[0];
    input.value = '';
    if (file) importBackupFile(file);
  };
  input.click();
}

async function importBackupFile(file) {
  if (state.locked) return toast('先にロックを解除してください');
  if (file.size > 5 * 1024 * 1024) return toast('ファイルが大きすぎます。鍵守のバックアップファイルではありません', { error: true });
  let info;
  try {
    info = inspectBackup(await file.text());
  } catch (e) {
    return toast(e.message || '読み込めませんでした', { error: true });
  }
  if (!info.encrypted) return showBackupContents(info, null);
  openSheet('バックアップのパスワード', (c, body) => {
    const pw = h('input', { type: 'password', autocomplete: 'off', 'aria-label': 'バックアップのパスワード', placeholder: 'バックアップを作ったときのパスワード' });
    const err = h('p', { class: 'error-text', role: 'alert', hidden: true });
    const go = h('button', { type: 'button', class: 'btn btn-primary', text: '開く' });
    const run = async () => {
      if (!pw.value) return;
      go.disabled = true;
      go.textContent = 'ひらいています…';
      await new Promise((r) => setTimeout(r, 30));
      const ok = await showBackupContents(info, pw.value, err);
      if (!ok) {
        go.disabled = false;
        go.textContent = '開く';
      }
    };
    go.onclick = run;
    pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    body.append(h('p', { class: 'hint', text: `${file.name} は暗号化されています。書き出したときのパスワードを入れてください。` }), pw, err, go);
    setTimeout(() => pw.focus({ preventScroll: true }), 50);
  });
}

async function showBackupContents(info, password, errEl) {
  let r;
  try {
    r = await readBackup(info, password);
  } catch {
    r = null;
  }
  if (!r) {
    if (errEl) {
      errEl.textContent = 'パスワードが違うか、ファイルが壊れています';
      errEl.hidden = false;
    } else toast('バックアップを開けませんでした', { error: true });
    return false;
  }
  if (!r.accounts.length) {
    toast('バックアップに読み込める鍵がありませんでした', { error: true });
    return true;
  }
  openConfirm({ items: r.accounts.map((account) => ({ account, source: 'backup' })), notes: [{ kind: 'backup', encrypted: info.encrypted, skipped: r.skipped }], errors: [] });
  return true;
}

// ---------- 詳細 ----------
function openDetail(id) {
  const a = state.accounts.find((x) => x.id === id);
  if (!a) return;
  openSheet('鍵の詳細', (c, body) => {
    const get = () => state.accounts.find((x) => x.id === id);
    const codeEl = h('button', { type: 'button', class: 'code', text: '------', onclick: () => copyCode(get()) });
    const nextEl = h('span', { class: 'next', 'aria-hidden': 'true', style: 'padding:0' });
    const ring = a.type === 'totp' ? makeRing() : null;
    const live = makeLive(get, codeEl, ring, nextEl);
    c.live.add(live);
    live(Date.now());

    body.append(
      h('div', {},
        a.issuer ? h('p', { class: 'row-issuer', text: a.issuer }) : null,
        h('p', { text: a.name || '（名前なし）', style: 'overflow-wrap:anywhere' }),
      ),
      h('div', { class: 'detail-code' }, h('div', {}, codeEl, nextEl), ring ? ring.el : h('span', { class: 'hotp-badge', text: 'HOTP' })),
      h('button', { type: 'button', class: 'btn btn-secondary', html: `${ICONS.copy.replace('<svg ', '<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" ')}<span>コードをコピー</span>`, onclick: () => copyCode(get()) }),
    );

    if (a.type === 'hotp') {
      const counterEl = h('span', { class: 'counter', text: String(a.counter) });
      const back = h('button', { type: 'button', class: 'btn btn-secondary', text: '一つ戻す', disabled: a.counter <= 0 });
      const use = h('button', { type: 'button', class: 'btn btn-primary', text: '使用済みにする' });
      const sync = () => {
        const x = get();
        counterEl.textContent = String(x.counter);
        back.disabled = x.counter <= 0;
      };
      back.onclick = () => {
        const x = get();
        if (!x || x.counter <= 0) return;
        x.counter = Math.max(0, x.counter - 1);
        persist(); sync(); renderList(); live(Date.now());
      };
      use.onclick = () => {
        const x = get();
        if (!x) return;
        x.counter += 1;
        persist(); sync(); renderList(); live(Date.now());
      };
      body.append(
        h('div', { class: 'hotp-counter' }, h('span', { text: 'カウンタ' }), counterEl),
        h('div', { class: 'btn-row' }, back, use),
        h('p', { class: 'hint', text: 'サービスにコードを入れたら「使用済みにする」を押すと、次のコードに進みます。' }),
      );
    } else {
      body.append(h('p', { class: 'detail-meta', text: `${a.algorithm} ・ ${a.digits}桁 ・ ${a.period}秒ごとに切り替わります` }));
    }
    if (a.type === 'hotp') body.append(h('p', { class: 'detail-meta', text: `${a.algorithm} ・ ${a.digits}桁` }));

    // 並び順（固定・上へ・下へ）
    const pinBtn = h('button', { type: 'button', class: 'btn btn-secondary' });
    const upBtn = h('button', { type: 'button', class: 'btn btn-secondary', text: '上へ' });
    const downBtn = h('button', { type: 'button', class: 'btn btn-secondary', text: '下へ' });
    const syncOrder = () => {
      const x = get();
      if (!x) return;
      pinBtn.textContent = x.pinned ? '固定を外す' : '上に固定';
      upBtn.disabled = neighborIndex(id, -1) < 0;
      downBtn.disabled = neighborIndex(id, 1) < 0;
    };
    pinBtn.onclick = () => { const x = get(); if (!x) return; x.pinned = !x.pinned; persist(); renderList(); syncOrder(); };
    upBtn.onclick = () => { if (moveAccount(id, -1)) { persist(); renderList(); syncOrder(); } };
    downBtn.onclick = () => { if (moveAccount(id, 1)) { persist(); renderList(); syncOrder(); } };
    body.append(h('div', { class: 'divider' }), h('p', { class: 'section-title', text: '並び順' }), h('div', { class: 'btn-row' }, pinBtn, upBtn, downBtn));
    syncOrder();

    // 名前
    const issuerIn = h('input', { type: 'text', id: 'd-issuer', value: a.issuer, autocomplete: 'off', maxlength: '200' });
    const nameIn = h('input', { type: 'text', id: 'd-name', value: a.name, autocomplete: 'off', maxlength: '200' });
    body.append(
      h('div', { class: 'divider' }),
      h('p', { class: 'section-title', text: '名前' }),
      h('div', { class: 'field' }, h('label', { for: 'd-issuer', text: 'サービス名' }), issuerIn),
      h('div', { class: 'field' }, h('label', { for: 'd-name', text: 'アカウント名' }), nameIn),
      h('button', {
        type: 'button', class: 'btn btn-secondary', text: '名前を保存',
        onclick: () => {
          const x = get();
          if (!x) return;
          x.issuer = issuerIn.value.trim();
          x.name = nameIn.value.trim();
          persist();
          renderList();
          toast('名前を保存しました');
        },
      }),
    );

    // QRと秘密鍵（最初は隠す）
    const reveal = h('div', {});
    const showBtn = h('button', { type: 'button', class: 'btn btn-secondary', text: 'QRと秘密鍵を表示する' });
    const hide = () => {
      reveal.replaceChildren();
      showBtn.hidden = false;
    };
    c.onHide = hide;
    showBtn.onclick = () => {
      const x = get();
      if (!x) return;
      let qr;
      try {
        qr = qrSvg(buildOtpauth(x));
      } catch {
        toast('QRを作れませんでした', { error: true });
        return;
      }
      showBtn.hidden = true;
      reveal.replaceChildren(
        h('div', { class: 'qr-box' },
          h('div', { class: 'qr-frame', html: qr }),
          h('p', { class: 'qr-caption', text: '写真には残さないでください' }),
        ),
        h('div', { class: 'field', style: 'margin-top:12px' }, h('span', { class: 'label', text: '秘密鍵' }), h('p', { class: 'secret-text', text: x.secret.replace(/(.{4})/g, '$1 ').trim() })),
        h('div', { class: 'btn-row', style: 'margin-top:12px' },
          h('button', { type: 'button', class: 'btn btn-secondary', text: '秘密鍵をコピー', onclick: async () => toast((await writeClipboard(x.secret)) ? '秘密鍵をコピーしました。扱いに気をつけてください' : 'コピーできませんでした') }),
          h('button', { type: 'button', class: 'btn btn-secondary', text: '隠す', onclick: hide }),
        ),
      );
    };
    body.append(
      h('div', { class: 'divider' }),
      h('p', { class: 'section-title', text: 'QRと秘密鍵' }),
      h('p', { class: 'hint', text: '秘密鍵を知っている人は、あなたと同じコードを作れます。人目のない場所で表示してください。' }),
      showBtn,
      reveal,
    );

    // 削除（二段階）
    const delBox = h('div', {});
    const showDelete = () => {
      delBox.replaceChildren(
        h('div', { class: 'note danger' },
          h('p', { text: 'この端末からこの鍵を削除します。元に戻せません。' }),
          h('p', { text: 'サービス側の二段階認証は有効なままです。ほかの端末や、リカバリコードで入れることを確かめてから削除してください。' }),
        ),
        h('div', { class: 'btn-row', style: 'margin-top:10px' },
          h('button', { type: 'button', class: 'btn btn-secondary', text: 'やめる', onclick: resetDelete }),
          h('button', {
            type: 'button', class: 'btn btn-danger', text: '削除する',
            onclick: () => {
              const idx = state.accounts.findIndex((x) => x.id === id);
              const removed = state.accounts[idx];
              state.accounts = state.accounts.filter((x) => x.id !== id);
              codeCache.delete(id);
              nextCache.delete(id);
              persist();
              closeSheet();
              renderAll();
              toast('削除しました', {
                ms: 8000,
                action: {
                  label: '元に戻す',
                  fn: () => {
                    if (state.locked || !removed || splitDuplicates(state.accounts, [removed]).fresh.length === 0) return;
                    state.accounts.splice(Math.min(idx, state.accounts.length), 0, removed);
                    persist();
                    renderAll();
                    toast('元に戻しました');
                  },
                },
              });
            },
          }),
        ),
      );
    };
    const resetDelete = () => delBox.replaceChildren(h('button', { type: 'button', class: 'btn btn-text btn-danger-text', text: 'この鍵を削除…', onclick: showDelete }));
    resetDelete();
    body.append(h('div', { class: 'divider' }), delBox);
  });
}

// ---------- 引き継ぎ ----------
function openTransfer() {
  if (!state.accounts.length) return;
  const sel = new Set(state.accounts.map((a) => a.id)); // 最初は全選択
  let mode = 'single'; // 渡し方の初期値は「1件ずつ」
  let pages = [];
  let idx = 0;

  openSheet('別の端末へ引き継ぐ', (c, body) => {
    const panel = h('div', {});
    const showBtn = h('button', { type: 'button', class: 'btn btn-primary', text: 'QRを表示する' });
    const blocked = h('div', { class: 'note warn', hidden: true });
    const modeHint = h('p', { class: 'hint' });
    const allBtn = h('button', { type: 'button', class: 'btn btn-text btn-small', text: 'すべて外す' });

    const checks = state.accounts.map((a) => {
      const cb = h('input', { type: 'checkbox', checked: true });
      cb.addEventListener('change', () => {
        if (cb.checked) sel.add(a.id); else sel.delete(a.id);
        refresh();
      });
      return { a, cb, row: h('label', { class: 'item' }, cb, h('div', { class: 'item-text' }, h('span', { class: 'item-title', text: displayLabel(a) }), h('span', { class: 'item-sub', text: describe(a) }))) };
    });

    const single = h('input', { type: 'radio', name: 'tmode', value: 'single', checked: true });
    const bundle = h('input', { type: 'radio', name: 'tmode', value: 'bundle' });
    const seg = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': '渡し方' },
      h('label', {}, single, '1件ずつ'),
      h('label', {}, bundle, 'まとめて'),
    );
    seg.addEventListener('change', () => {
      mode = bundle.checked ? 'bundle' : 'single';
      refresh();
    });

    const selected = () => state.accounts.filter((a) => sel.has(a.id));

    function hideQr() {
      pages = [];
      idx = 0;
      panel.replaceChildren();
      showBtn.hidden = false;
    }

    function refresh() {
      const list = selected();
      const bad = nonStandardPeriod(list);
      bundle.disabled = bad.length > 0;
      if (bad.length && mode === 'bundle') {
        mode = 'single';
        single.checked = true;
      }
      blocked.hidden = bad.length === 0;
      if (bad.length) {
        blocked.replaceChildren(h('p', { text: `更新間隔が30秒でないTOTP（${bad.map((x) => displayLabel(x)).join('、')}）が含まれるため、まとめ形式は使えません。` }), h('p', { text: 'まとめ形式には更新間隔を入れられず、相手のコードがずれてしまいます。1件ずつのQRで渡してください。' }));
      }
      modeHint.textContent = mode === 'single'
        ? '標準のotpauth形式です。ほとんどの認証アプリで読み取れます。鍵の数だけQRが出ます。'
        : 'Google認証システムの「アカウントをエクスポート」と同じ形式です。複数の鍵を少ない枚数のQRにまとめます。';
      showBtn.disabled = list.length === 0;
      allBtn.textContent = list.length === state.accounts.length ? 'すべて外す' : 'すべて選ぶ';
      hideQr(); // 対象や形式を変えたらQRは隠す
    }

    function renderPage() {
      const p = pages[idx];
      let qr;
      try {
        qr = qrSvg(p.uri);
      } catch {
        panel.replaceChildren(h('p', { class: 'error-text', text: 'QRを作れませんでした（内容が長すぎます）。' }));
        return;
      }
      panel.replaceChildren(
        h('div', { class: 'qr-box' },
          h('div', { class: 'qr-frame', html: qr }),
          h('p', { class: 'qr-caption', text: p.caption }),
          pages.length > 1
            ? h('div', { class: 'qr-nav' },
                h('button', { type: 'button', class: 'btn btn-secondary btn-small', text: '前へ', disabled: idx === 0, onclick: () => { idx -= 1; renderPage(); } }),
                h('span', { class: 'count', text: `${idx + 1} / ${pages.length}` }),
                h('button', { type: 'button', class: 'btn btn-secondary btn-small', text: '次へ', disabled: idx === pages.length - 1, onclick: () => { idx += 1; renderPage(); } }))
            : null,
          mode === 'bundle' && pages.length > 1 ? h('p', { class: 'hint', text: `全部で${pages.length}枚です。受け取る側で、すべてのQRを読み取ってください。` }) : null,
          h('p', { class: 'qr-caption', text: '写真には残さないでください' }),
          h('div', { class: 'btn-row', style: 'width:100%' },
            h('button', { type: 'button', class: 'btn btn-secondary', text: 'リンクをコピー', onclick: async () => toast((await writeClipboard(p.uri)) ? 'コピーしました。このリンクには秘密鍵が入っています。送り先に気をつけてください' : 'コピーできませんでした') }),
            h('button', { type: 'button', class: 'btn btn-secondary', text: 'QRを隠す', onclick: hideQr }),
          ),
        ),
      );
    }

    showBtn.onclick = () => {
      const list = selected();
      if (!list.length) return;
      try {
        if (mode === 'single') {
          pages = list.map((a, i) => ({ uri: buildOtpauth(a), caption: list.length > 1 ? `${i + 1}/${list.length}件目: ${displayLabel(a)}` : displayLabel(a) }));
        } else {
          const uris = planMigration(list);
          pages = uris.map((u, i) => ({ uri: u, caption: `${i + 1}/${uris.length}枚目（${parseMigration(u).accounts.length}件）` }));
        }
      } catch (e) {
        toast(e.message || 'QRを作れませんでした', { error: true });
        return;
      }
      idx = 0;
      showBtn.hidden = true;
      renderPage();
    };

    allBtn.onclick = () => {
      const all = sel.size !== state.accounts.length;
      sel.clear();
      if (all) state.accounts.forEach((a) => sel.add(a.id));
      checks.forEach(({ a, cb }) => { cb.checked = sel.has(a.id); });
      refresh();
    };

    c.onHide = hideQr;
    body.append(
      h('div', { class: 'note warn' }, h('p', { text: 'QRにもリンクにも秘密鍵が入っています。新しい端末で読み取れたら、すぐに隠してください。写真やスクリーンショットには残さないでください。' })),
      h('div', { style: 'display:flex;align-items:center;justify-content:space-between;gap:8px' }, h('p', { class: 'section-title', text: '引き継ぐ鍵' }), allBtn),
      h('div', { class: 'check-list' }, checks.map((x) => x.row)),
      h('p', { class: 'section-title', text: '渡し方' }),
      seg,
      modeHint,
      blocked,
      showBtn,
      panel,
    );
    refresh();
  });
}

// ---------- 全削除 ----------
function openDeleteAll() {
  openSheet('すべての鍵を削除', (c, body) => {
    const input = h('input', { type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: false, placeholder: '削除', 'aria-label': '確認のため「削除」と入力' });
    const go = h('button', { type: 'button', class: 'btn btn-danger', text: `${state.accounts.length}件の鍵をすべて削除する`, disabled: true });
    const check = () => { go.disabled = input.value.trim() !== '削除'; };
    input.addEventListener('input', check);
    input.addEventListener('compositionend', check);
    go.onclick = () => {
      if (input.value.trim() !== '削除') return;
      const snapshot = state.accounts;
      state.accounts = [];
      state.query = '';
      codeCache.clear();
      nextCache.clear();
      persist();
      closeSheet();
      renderAll();
      toast('すべての鍵を削除しました', {
        ms: 8000,
        action: {
          label: '元に戻す',
          fn: () => {
            if (state.locked) return;
            state.accounts = mergeAccounts(snapshot, state.accounts).accounts;
            persist();
            renderAll();
            toast('元に戻しました');
          },
        },
      });
    };
    body.append(
      h('div', { class: 'note danger' },
        h('p', { text: 'この端末に保存した鍵をすべて削除します。元に戻せません。' }),
        h('p', { text: '消す前に「引き継ぎ」で別の端末へ移し、各サービスのリカバリコードも控えてあるか確かめてください。' }),
      ),
      h('div', { class: 'field' }, h('label', { text: '続けるには「削除」と入力してください' }), input),
      h('div', { class: 'btn-row' }, h('button', { type: 'button', class: 'btn btn-secondary', text: 'やめる', onclick: () => closeSheet() }), go),
    );
  });
}

// ---------- 設定・暗号化・バックアップ ----------
const fmtDate = (ts) => {
  const d = new Date(ts);
  return `${d.toLocaleDateString('ja-JP', { year: 'numeric', month: 'long', day: 'numeric' })} ${d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', hour12: false })}`;
};

function statusLine(label, value) {
  return h('div', { class: 'status-line' }, h('span', { text: label }), h('span', { class: 'v', text: value }));
}

function openSettings() {
  openSheet('設定・バックアップ', (c, body) => {
    const draw = async () => {
      const persisted = await storagePersisted();
      const kids = [];

      // 暗号化
      kids.push(h('p', { class: 'section-title', text: '暗号化' }));
      kids.push(statusLine('保存データ', state.enc ? '暗号化あり（AES-GCM）' : '暗号化なし（平文）'));
      if (state.enc) {
        kids.push(h('p', { class: 'hint', text: `パスワードから鍵を作り（PBKDF2、${KDF_ITER.toLocaleString('ja-JP')}回）、一覧を暗号化して保存しています。5分操作がないか、画面を1分離れるとロックします。` }));
        kids.push(
          h('div', { class: 'btn-row' },
            h('button', { type: 'button', class: 'btn btn-secondary', text: 'パスワードを変える', onclick: () => openPasswordSetup(true) }),
            h('button', { type: 'button', class: 'btn btn-secondary', text: '暗号化をやめる', onclick: openDisableEnc }),
          ),
        );
      } else {
        kids.push(h('p', { class: 'hint', text: 'いまは鍵が平文でこのブラウザに保存されています。パスワードで暗号化すると、端末を他人に触られても、パスワードなしでは鍵を読み出せません。ただし、パスワードを忘れると取り出せません。' }));
        kids.push(h('button', { type: 'button', class: 'btn btn-primary', text: 'パスワードで暗号化する', onclick: () => openPasswordSetup(false) }));
      }

      // バックアップ
      kids.push(h('div', { class: 'divider' }), h('p', { class: 'section-title', text: 'バックアップ' }));
      kids.push(statusLine('最後のバックアップ', state.backedUpAt ? fmtDate(state.backedUpAt) : 'まだありません'));
      kids.push(h('p', { class: 'hint', text: 'ブラウザのデータを消したり、端末を替えたりしたときのために、鍵をファイルに書き出せます。ファイルはこの端末に保存されるだけで、どこにも送りません。' }));
      kids.push(
        h('div', { class: 'btn-row' },
          h('button', { type: 'button', class: 'btn btn-secondary', text: '書き出す', disabled: state.accounts.length === 0, onclick: openExport }),
          h('button', { type: 'button', class: 'btn btn-secondary', text: '読み込む', onclick: () => pickBackup() }),
        ),
      );

      // 保存の保護
      kids.push(h('div', { class: 'divider' }), h('p', { class: 'section-title', text: '保存の保護' }));
      kids.push(statusLine('消えにくい保存', persisted === null ? 'このブラウザでは確認できません' : persisted ? '有効' : 'まだ有効ではありません'));
      kids.push(h('p', { class: 'hint', text: 'iPhone の Safari は、ホーム画面に追加していないサイトの保存データを、しばらく使わないと消すことがあります。ホーム画面に追加し、バックアップを取っておいてください。' }));
      if (persisted === false) {
        kids.push(h('button', { type: 'button', class: 'btn btn-secondary', text: '消えにくい保存を頼む', onclick: async () => {
          const ok = await requestPersist();
          toast(ok ? '消えにくい保存になりました' : 'ブラウザに断られました。バックアップを取っておいてください');
          draw();
        } }));
      }
      body.replaceChildren(...kids);
    };
    draw();
  });
}

function openPasswordSetup(change) {
  openSheet(change ? 'パスワードを変える' : 'パスワードで暗号化する', (c, body) => {
    const pw = h('input', { type: 'password', id: 'pw1', autocomplete: 'new-password', placeholder: `${MIN_PASSWORD}文字以上` });
    const pw2 = h('input', { type: 'password', id: 'pw2', autocomplete: 'new-password', placeholder: 'もう一度' });
    const ack = h('input', { type: 'checkbox', id: 'pw-ack' });
    const err = h('p', { class: 'error-text', role: 'alert', hidden: true });
    const go = h('button', { type: 'button', class: 'btn btn-primary', text: change ? '変更する' : '暗号化する' });
    const fail = (m) => { err.textContent = m; err.hidden = false; };
    go.onclick = async () => {
      err.hidden = true;
      const prob = passwordProblem(pw.value);
      if (prob) return fail(prob);
      if (pw.value !== pw2.value) return fail('確認用のパスワードが一致しません');
      if (!ack.checked) return fail('「忘れると取り出せない」ことを確かめてチェックしてください');
      go.disabled = true;
      go.textContent = '暗号化しています…';
      await new Promise((r) => setTimeout(r, 30));
      try {
        const salt = newSalt();
        const key = await deriveKey(pw.value, salt, KDF_ITER);
        state.enc = { key, salt, iter: KDF_ITER };
        await persist();
        if (!loadVault(store).enc) throw new Error('save');
      } catch {
        state.enc = null;
        await persist();
        go.disabled = false;
        go.textContent = change ? '変更する' : '暗号化する';
        return fail('保存できませんでした。この環境では暗号化を使えません');
      }
      lastActive = Date.now();
      closeSheet();
      renderAll();
      toast(change ? 'パスワードを変えました。前のパスワードで作ったバックアップは、前のパスワードで開きます' : '暗号化しました。パスワードは保存していません。忘れないでください', { ms: 6000 });
    };
    body.append(
      h('div', { class: 'note warn' },
        h('p', { text: 'パスワードは、この端末にも、どこにも保存しません。忘れると、保存した鍵は取り出せなくなります。' }),
        h('p', { text: '先にバックアップを書き出し、各サービスのリカバリコードも控えてください。' }),
      ),
      h('div', { class: 'field' }, h('label', { for: 'pw1', text: change ? '新しいパスワード' : 'パスワード' }), pw),
      h('div', { class: 'field' }, h('label', { for: 'pw2', text: '確認' }), pw2),
      h('label', { class: 'item', for: 'pw-ack' }, ack, h('span', { class: 'item-text' }, h('span', { class: 'item-title', text: '忘れると取り出せないことを理解しました' }))),
      err,
      go,
    );
    setTimeout(() => pw.focus({ preventScroll: true }), 50);
  });
}

function openDisableEnc() {
  openSheet('暗号化をやめる', (c, body) => {
    body.append(
      h('div', { class: 'note danger' }, h('p', { text: '保存データが平文に戻ります。この端末を他人が開けると、鍵を読み出せるようになります。' })),
      h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn-secondary', text: 'やめる', onclick: () => closeSheet() }),
        h('button', { type: 'button', class: 'btn btn-danger', text: '平文に戻す', onclick: async () => {
          state.enc = null;
          await persist();
          closeSheet();
          renderAll();
          toast('暗号化をやめました');
        } }),
      ),
    );
  });
}

function downloadText(name, text) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  a.style.display = 'none';
  document.body.append(a);
  a.click();
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 4000);
}

function openExport() {
  if (!state.accounts.length) return toast('書き出す鍵がありません');
  openSheet('バックアップを書き出す', (c, body) => {
    const modes = [];
    if (state.enc) modes.push({ v: 'key', t: 'このアプリのパスワードで暗号化', s: '開くときも、いまのパスワードを使います（推奨）' });
    modes.push({ v: 'password', t: '別のパスワードで暗号化', s: state.enc ? 'ファイル専用のパスワードを決めます' : 'ファイル専用のパスワードを決めます（推奨）' });
    modes.push({ v: 'plain', t: '暗号化しない', s: '秘密鍵がそのまま読めます。おすすめしません' });
    let mode = modes[0].v;
    const radios = modes.map((m, i) => {
      const r = h('input', { type: 'radio', name: 'bk-mode', value: m.v, checked: i === 0 });
      r.addEventListener('change', () => { mode = m.v; sync(); });
      return h('label', { class: 'item' }, r, h('div', { class: 'item-text' }, h('span', { class: 'item-title', text: m.t }), h('span', { class: 'item-sub', text: m.s })));
    });
    const pw = h('input', { type: 'password', id: 'bk-pw', autocomplete: 'new-password', placeholder: `${MIN_PASSWORD}文字以上` });
    const pw2 = h('input', { type: 'password', id: 'bk-pw2', autocomplete: 'new-password', placeholder: 'もう一度' });
    const pwBox = h('div', { class: 'field-group', style: 'display:grid;gap:10px' },
      h('div', { class: 'field' }, h('label', { for: 'bk-pw', text: 'バックアップ用のパスワード' }), pw),
      h('div', { class: 'field' }, h('label', { for: 'bk-pw2', text: '確認' }), pw2),
      h('p', { class: 'hint', text: 'このパスワードも保存しません。忘れるとバックアップは開けません。' }),
    );
    const ack = h('input', { type: 'checkbox', id: 'bk-ack' });
    const plainBox = h('div', {},
      h('div', { class: 'note danger' }, h('p', { text: 'ファイルを手に入れた人は、あなたと同じコードを作れます。クラウドやメールに置かないでください。' })),
      h('label', { class: 'item', for: 'bk-ack', style: 'margin-top:8px' }, ack, h('span', { class: 'item-text' }, h('span', { class: 'item-title', text: '平文で書き出すことを理解しました' }))),
    );
    const err = h('p', { class: 'error-text', role: 'alert', hidden: true });
    const go = h('button', { type: 'button', class: 'btn btn-primary', text: 'ファイルに書き出す' });
    const sync = () => {
      pwBox.hidden = mode !== 'password';
      plainBox.hidden = mode !== 'plain';
      err.hidden = true;
    };
    const fail = (m) => { err.textContent = m; err.hidden = false; };
    go.onclick = async () => {
      err.hidden = true;
      const list = state.accounts;
      try {
        if (mode === 'password') {
          const prob = passwordProblem(pw.value);
          if (prob) return fail(prob);
          if (pw.value !== pw2.value) return fail('確認用のパスワードが一致しません');
        }
        if (mode === 'plain' && !ack.checked) return fail('平文で書き出すことを確かめてチェックしてください');
        go.disabled = true;
        go.textContent = '書き出しています…';
        await new Promise((r) => setTimeout(r, 30));
        const opt = mode === 'plain' ? { mode: 'plain' } : mode === 'key' ? { mode: 'key', ...state.enc } : { mode: 'password', password: pw.value };
        const text = await makeBackup(list, opt);
        downloadText(backupFileName(mode !== 'plain'), text);
        state.backedUpAt = Date.now();
        backupDismissed = false;
        persist();
        closeSheet();
        renderAll();
        toast(mode === 'plain' ? '書き出しました。平文のファイルです。使い終わったら削除してください' : '書き出しました。ファイルとパスワードは別の場所に保管してください', { ms: 6000 });
      } catch {
        go.disabled = false;
        go.textContent = 'ファイルに書き出す';
        fail('書き出せませんでした');
      }
    };
    body.append(h('div', { class: 'radio-list' }, radios), pwBox, plainBox, err, go);
    sync();
  });
}

function openForgot() {
  openSheet('パスワードを忘れた', (c, body) => {
    const input = h('input', { type: 'text', autocomplete: 'off', autocapitalize: 'off', spellcheck: false, placeholder: '削除', 'aria-label': '確認のため「削除」と入力' });
    const go = h('button', { type: 'button', class: 'btn btn-danger', text: 'この端末の鍵をすべて消す', disabled: true });
    const check = () => { go.disabled = input.value.trim() !== '削除'; };
    input.addEventListener('input', check);
    input.addEventListener('compositionend', check);
    go.onclick = () => {
      if (input.value.trim() !== '削除') return;
      writeVault(store, serializeVault({ accounts: [], hidden: state.hidden, backedUpAt: 0 }));
      applyLoaded(loadVault(store));
      closeSheet();
      renderAll();
      toast('この端末の鍵を消しました。バックアップや引き継ぎQRから、もう一度追加してください');
    };
    body.append(
      h('div', { class: 'note danger' },
        h('p', { text: 'パスワードがないと、暗号化した鍵は取り出せません。取り戻す方法はありません。' }),
        h('p', { text: 'バックアップのファイルやほかの端末に鍵があるなら、この端末のデータを消して、そこから入れ直せます。' }),
      ),
      h('div', { class: 'field' }, h('label', { text: '続けるには「削除」と入力してください' }), input),
      h('div', { class: 'btn-row' }, h('button', { type: 'button', class: 'btn btn-secondary', text: 'やめる', onclick: () => closeSheet() }), go),
    );
  });
}

// ---------- 時刻のずれの目安 ----------
async function checkSkew() {
  const el = $('#clock-skew');
  if (!navigator.onLine) return;
  try {
    const t0 = Date.now();
    const res = await fetch('/', { method: 'HEAD', cache: 'no-store' });
    const t1 = Date.now();
    const date = res.headers.get('date');
    if (!res.ok || !date) return;
    const server = Date.parse(date) + Number(res.headers.get('age') || 0) * 1000;
    if (!Number.isFinite(server)) return;
    const skew = Math.round(((t0 + t1) / 2 - server) / 1000);
    if (Math.abs(skew) >= 15) {
      el.textContent = `この端末の時計は、このサイトの配信元の時刻より約${Math.abs(skew)}秒${skew > 0 ? '進んで' : '遅れて'}います（目安）。コードが拒否されるときは、日付と時刻を自動設定にしてください。`;
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  } catch { /* 確かめられないだけ。何も出さない */ }
}

// ---------- ドラッグ＆ドロップ・貼り付け・ショートカット ----------
function setupInputShortcuts() {
  let depth = 0;
  const hasFiles = (e) => e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
  const showDrop = (on) => { $('#drop-hint').hidden = !on; };
  window.addEventListener('dragenter', (e) => { if (hasFiles(e)) { depth++; showDrop(true); } });
  window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('dragleave', (e) => { if (hasFiles(e)) { depth = Math.max(0, depth - 1); if (!depth) showDrop(false); } });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    showDrop(false);
    const files = [...e.dataTransfer.files];
    const img = files.find((f) => f.type.startsWith('image/'));
    const json = files.find((f) => /\.json$/i.test(f.name) || f.type === 'application/json');
    if (img) handleImageFile(img);
    else if (json) importBackupFile(json);
    else toast('QRの画像か、鍵守のバックアップ（.json）を落としてください', { error: true });
  });

  document.addEventListener('paste', (e) => {
    const t = e.target;
    if (state.locked || (t && t.matches && t.matches('input, textarea, select')) || !e.clipboardData) return;
    const imgItem = [...e.clipboardData.items].find((i) => i.kind === 'file' && i.type.startsWith('image/'));
    if (imgItem) {
      e.preventDefault();
      const f = imgItem.getAsFile();
      if (f) handleImageFile(f);
      return;
    }
    const text = e.clipboardData.getData('text');
    if (/otpauth(-migration)?:\/\//i.test(text)) {
      const res = parseInput(text);
      if (res.items.length) {
        e.preventDefault();
        openConfirm(res, { viaImage: false });
      }
    }
  });

  document.addEventListener('keydown', (e) => {
    if (current || state.locked || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) return;
    const t = e.target;
    if (t && t.matches && t.matches('input, textarea, select, [contenteditable="true"]')) return;
    if (e.key === '/') {
      if (!$('#search-box').hidden) { e.preventDefault(); $('#search').focus(); }
    } else if (e.key === 'n') {
      e.preventDefault();
      openAddMenu();
    } else if (e.key === 'h') {
      e.preventDefault();
      $('#btn-toggle').click();
    } else if (e.key === 'l' && state.enc) {
      e.preventDefault();
      lockNow();
    }
  });
  $('#search').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.target.value = '';
      state.query = '';
      renderList();
      e.target.blur();
    }
  });
}

// ---------- 起動 ----------
function init() {
  applyLoaded(loadVault(store));
  const loadedInfo = loadVault(store);
  if (storage === null) toast('この環境では保存できません。ブラウザを閉じると鍵が消えます', { error: true });
  else if (loadedInfo.dropped) toast(`${loadedInfo.dropped}件の項目は壊れているか重複しているので読み飛ばしました`);

  $('#btn-transfer').innerHTML = ICONS.transfer;
  $('#btn-add').innerHTML = ICONS.plus;
  $('#btn-lock').innerHTML = ICONS.lock;
  $('#btn-toggle').addEventListener('click', () => {
    state.hidden = !state.hidden;
    persist();
    renderToggle();
    tick();
  });
  $('#btn-transfer').addEventListener('click', openTransfer);
  $('#btn-add').addEventListener('click', openAddMenu);
  $('#btn-lock').addEventListener('click', lockNow);
  $('#btn-settings').addEventListener('click', openSettings);
  $('#empty-camera').addEventListener('click', openScanner);
  $('#empty-more').addEventListener('click', openAddMenu);
  $('#empty-sample').addEventListener('click', addSample);
  $('#btn-delete-all').addEventListener('click', openDeleteAll);
  $('#backup-now').addEventListener('click', openExport);
  $('#backup-later').addEventListener('click', () => { backupDismissed = true; renderBackupNote(); });
  $('#search').addEventListener('input', (e) => {
    state.query = e.target.value;
    renderList();
  });

  $('#lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('#lock-pw');
    const err = $('#lock-err');
    const go = $('#lock-go');
    if (!input.value) return;
    err.hidden = true;
    go.disabled = true;
    go.textContent = 'ひらいています…';
    await new Promise((r) => setTimeout(r, 30));
    const ok = await unlock(input.value);
    go.disabled = false;
    go.textContent = 'ロックを解除';
    if (ok) input.value = '';
    else {
      err.textContent = 'パスワードが違います';
      err.hidden = false;
      input.select();
    }
  });
  $('#lock-forgot').addEventListener('click', openForgot);

  for (const ev of ['pointerdown', 'keydown', 'touchstart', 'wheel']) document.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true });
  window.addEventListener('online', () => { updateNet(); checkSkew(); });
  window.addEventListener('offline', updateNet);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      hiddenAt = Date.now();
      if (current && current.onHide) current.onHide();
    } else {
      if (state.enc && !state.locked && hiddenAt && Date.now() - hiddenAt > AWAY_MS) lockNow();
      tick();
    }
  });
  window.addEventListener('storage', (e) => {
    if (e.key !== VAULT_KEY) return;
    closeSheet(true);
    applyLoaded(loadVault(store));
    renderAll();
  });
  setupInputShortcuts();

  updateNet();
  // 保存を読んでから一覧を出す（空の一覧を先に見せない）
  renderAll();
  tick();
  setInterval(tick, 250);
  setTimeout(checkSkew, 1500);
  if (state.locked) setTimeout(() => $('#lock-pw').focus({ preventScroll: true }), 100);

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => { /* 失敗しても今ある控えは残る */ });
    });
  }
}

init();
