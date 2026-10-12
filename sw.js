// 鍵守 Service Worker
// 同一オリジンの画面・JS・CSS・マニフェスト・アイコンだけを控えに保存する。
// オンライン中はネットワーク優先で控えを更新し、失敗したら控えを返す。鍵や入力内容には一切触れない。
const VERSION = 'v2';
const PREFIX = 'kagimori-shell-';
const CACHE = PREFIX + VERSION;
const NETWORK_TIMEOUT_MS = 4000;

const REQUIRED = [
  '/', '/style.css', '/app.js', '/otp.js', '/qr.js', '/vault.js', '/crypto.js', '/backup.js',
  '/manifest.webmanifest', '/favicon.svg', '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png', '/apple-touch-icon.png',
];
// 無くてもインストールは成功させる（無いときは jsQR の代わりにブラウザ標準の読み取りを使う）
const OPTIONAL = ['/vendor/jsQR.js'];
const KNOWN = new Set([...REQUIRED, ...OPTIONAL, '/index.html']);

const OFFLINE_HTML = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101418"><title>鍵守</title></head><body style="margin:0;background:#101418;color:#f4f0e8;font:16px/1.8 'Hiragino Kaku Gothic ProN','Yu Gothic UI',Meiryo,sans-serif;display:grid;place-items:center;min-height:100vh;text-align:center;padding:24px"><div><h1 style="letter-spacing:.12em;margin:0 0 12px">鍵守</h1><p style="margin:0">電波があるときに一度開いてください。</p><p style="margin:8px 0 0;color:#9aa399;font-size:14px">一度開くと、以後は電波がなくても保存した鍵のコードを出せます。</p></div></body></html>`;

/** 控えに入れてよい応答か。HTMLをJSやCSSとして保存しないよう、種類を確かめる */
function okForCache(req, res) {
  if (!res || res.status !== 200 || res.type === 'opaque' || res.type === 'error') return false;
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  const path = new URL(req.url).pathname;
  if (req.mode === 'navigate' || req.destination === 'document' || path === '/' || path.endsWith('.html')) return ct.includes('text/html');
  if (req.destination === 'script' || /\.m?js$/.test(path)) return /javascript|ecmascript/.test(ct);
  if (req.destination === 'style' || path.endsWith('.css')) return ct.includes('text/css');
  if (path.endsWith('.webmanifest') || path.endsWith('.json')) return /json|manifest/.test(ct);
  if (/\.(png|svg|ico|jpe?g|webp)$/.test(path)) return ct.startsWith('image/');
  return false;
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // 1つでも失敗したら例外にしてインストールを失敗させる。古い控えと古いSWはそのまま残る（ここでは何も消さない）
      await Promise.all(
        REQUIRED.map(async (path) => {
          const req = new Request(path, { cache: 'reload' });
          const res = await fetch(req);
          if (!okForCache(req, res)) throw new Error('precache failed: ' + path);
          await cache.put(path, res);
        }),
      );
      for (const path of OPTIONAL) {
        try {
          const req = new Request(path, { cache: 'reload' });
          const res = await fetch(req);
          if (okForCache(req, res)) await cache.put(path, res);
        } catch { /* 任意のものは無くてよい */ }
      }
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      // 新しい版の控えがそろってから（=activate まで来てから）古い版だけを消す
      await Promise.all(names.filter((n) => n.startsWith(PREFIX) && n !== CACHE).map((n) => caches.delete(n)));
      await self.clients.claim();
    })(),
  );
});

async function networkFirst(event, key, req) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(key);
  const net = fetch(req).then((res) => {
    if (okForCache(req, res)) event.waitUntil(cache.put(key, res.clone()));
    return res;
  });
  if (!cached) return net; // 控えが無いときはネットワークの結果をそのまま（失敗は呼び出し側で処理）
  net.catch(() => {}); // 競争に負けても未処理の拒否にしない
  const timer = new Promise((resolve) => setTimeout(() => resolve('timeout'), NETWORK_TIMEOUT_MS));
  try {
    const res = await Promise.race([net, timer]);
    if (res === 'timeout') return cached; // 電波が弱いときは控えを先に返す。取得は裏で続けて控えを更新する
    if (res.status >= 500) return cached;
    return res;
  } catch {
    return cached;
  }
}

async function handleNavigation(event) {
  const req = event.request;
  const url = new URL(req.url);
  const isRoot = url.pathname === '/' || url.pathname === '/index.html';
  try {
    if (isRoot) return await networkFirst(event, '/', req);
    const res = await fetch(req);
    if (res.ok) return res;
    const fallback = await caches.match('/');
    return fallback || res;
  } catch {
    // 画面のリクエストは / の控えに戻す
    const fallback = await caches.match('/');
    if (fallback) return fallback;
    return new Response(OFFLINE_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  }
}

async function handleAsset(event, path) {
  const req = event.request;
  try {
    return await networkFirst(event, path, req);
  } catch {
    const cached = await caches.match(path);
    return cached || Response.error();
  }
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // 扱わないもの: sw.js 自身、/api/、install 付きのURL
  if (url.pathname === '/sw.js' || url.pathname.startsWith('/api/') || url.searchParams.has('install') || /install/i.test(url.pathname)) return;
  if (req.mode === 'navigate') {
    event.respondWith(handleNavigation(event));
    return;
  }
  if (!KNOWN.has(url.pathname)) return;
  event.respondWith(handleAsset(event, url.pathname === '/index.html' ? '/' : url.pathname));
});
