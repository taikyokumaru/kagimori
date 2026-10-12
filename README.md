# 鍵守

ビルド不要の静的サイトです。ドメイン直下（`/`）でHTTPS配信してください（start_url と scope が `/`、カメラと Service Worker に HTTPS が必要）。
外部への通信はありません（CSP で同一サイト以外を禁止）。

## jsQR（要対応）
作業環境から npm・CDN に届かず、jsQR を同梱できませんでした。次で置いてください。

    curl -o vendor/jsQR.js https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js

置かない場合は、ブラウザ標準の BarcodeDetector で代用し、使えない環境では日本語で理由を出して貼り付け・手入力へ誘導します。

## 保存と暗号化
- 既定は平文（localStorage `kagimori.vault.v1`）。「設定・バックアップ」で任意にパスワード暗号化（PBKDF2-SHA256 600,000回 → AES-GCM）。
- 暗号化中は、5分の無操作か、画面を1分離れるとロック。パスワードは保存しません。忘れると取り出せません。
- バックアップは JSON ファイル。暗号化（推奨）か平文を選べます。

## テスト
    node tests/otp.test.mjs
    node tests/secure.test.mjs
    # ブラウザ: node tests/serve.mjs . 8123 を起動して python3 tests/e2e2.py（Playwright）
