import { qrMatrix } from '../qr.js';
import { planMigration, normalizeAccount, base32Encode, buildOtpauth } from '../otp.js';
const cases = [];
for (const len of [5, 20, 60, 120, 200, 260, 261, 400, 600, 800, 900]) cases.push('x'.repeat(len - 3) + String(len).padStart(3,'0'));
cases.push('otpauth://totp/鍵守:サンプル?secret=JBSWY3DPEHPK3PXP&issuer=%E9%8D%B5%E5%AE%88&algorithm=SHA1&digits=6&period=30');
cases.push(buildOtpauth(normalizeAccount({ issuer: 'Example', name: 'a@b.c', secret: 'JBSWY3DPEHPK3PXP' })));
const list = Array.from({ length: 12 }, (_, i) => normalizeAccount({ issuer: 'S' + i, name: 'u' + i, secret: base32Encode(Uint8Array.from({ length: 20 }, (_, k) => k * 3 + i)) }));
cases.push(...planMigration(list, 42));
// 乱数風の長文も（バージョンの境目を広く踏む）
for (let n = 30; n <= 900; n += 37) cases.push(Array.from({ length: n }, (_, i) => String.fromCharCode(33 + ((i * 31 + n * 7) % 90))).join(''));
const out = cases.map((text) => { const q = qrMatrix(text); return { text, size: q.size, version: q.version, ecc: q.ecc, mask: q.mask, m: q.matrix.map((r) => r.map((v) => (v ? 1 : 0)).join('')) }; });
process.stdout.write(JSON.stringify(out));
