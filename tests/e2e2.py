import asyncio, json, os, re, datetime
from playwright.async_api import async_playwright
URL='http://127.0.0.1:8123/'
SHOT='/tmp/claude-0/-home-claude/69426174-383b-5a24-8b02-c38824be6d7d/scratchpad/'
SECRET='JBSWY3DPEHPK3PXP'
ok_all=True
def check(name, cond, extra=''):
    global ok_all
    ok_all = ok_all and bool(cond)
    print(('PASS ' if cond else 'FAIL ')+name, extra)
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path='/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell')
        ctx = await b.new_context(viewport={'width':390,'height':844}, accept_downloads=True)
        pg = await ctx.new_page(); errs=[]; reqs=[]
        pg.on('pageerror', lambda e: errs.append(str(e))); pg.on('request', lambda r: reqs.append(r.url))
        await pg.goto(URL); await pg.wait_for_selector('#empty:not([hidden])')
        await pg.click('#empty-sample'); await pg.wait_for_selector('.row'); await pg.wait_for_timeout(500)
        # タップコピー / 隠し中
        await pg.click('.row .code'); await pg.wait_for_timeout(100)
        check('tap code copies', 'コピーしました' in ' '.join([await t.inner_text() for t in await pg.query_selector_all('.toast')]) or 'コピーできませんでした' in ' '.join([await t.inner_text() for t in await pg.query_selector_all('.toast')]))
        await pg.click('#btn-toggle'); await pg.wait_for_timeout(300); await pg.click('.row .code')
        check('hidden copy refused', '表示してからコピーしてください' in ' '.join([await t.inner_text() for t in await pg.query_selector_all('.toast')]))
        check('hidden shows dots only', (await pg.inner_text('.row .code')).strip()=='••• •••')
        await pg.click('#btn-toggle')
        # 設定 → 暗号化
        PW='テスト-password-1'
        await pg.click('#btn-settings'); await pg.click('button:text-is("パスワードで暗号化する")')
        await pg.fill('#pw1', PW); await pg.fill('#pw2', PW)
        await pg.click('.sheet .btn-primary'); check('needs ack', 'チェック' in await pg.inner_text('.sheet .error-text'))
        await pg.check('#pw-ack'); await pg.click('.sheet .btn-primary'); await pg.wait_for_selector('.sheet', state='detached', timeout=15000)
        raw = await pg.evaluate("localStorage.getItem('kagimori.vault.v1')")
        check('stored text has no secret / issuer', SECRET not in raw and 'サンプル' not in raw and '"v":2' in raw.replace(' ',''))
        check('only one storage key', await pg.evaluate("Object.keys(localStorage)")==['kagimori.vault.v1'])
        check('lock button visible', await pg.locator('#btn-lock').is_visible())
        await pg.click('#btn-lock'); await pg.wait_for_selector('#lock-view:not([hidden])')
        check('locked: no rows, no codes in DOM', await pg.locator('.row').count()==0 and SECRET not in await pg.content())
        check('locked: appbar actions hidden', not await pg.locator('#appbar-actions').is_visible())
        await pg.screenshot(path=SHOT+'lock.png')
        await pg.fill('#lock-pw','wrong-password-x'); await pg.click('#lock-go'); await pg.wait_for_selector('#lock-err:not([hidden])', timeout=15000)
        check('wrong password rejected', 'パスワードが違います' in await pg.inner_text('#lock-err') and await pg.locator('.row').count()==0)
        await pg.fill('#lock-pw','ＴＥＳＴ'); # junk
        await pg.fill('#lock-pw',PW); await pg.click('#lock-go'); await pg.wait_for_selector('.row', timeout=15000)
        check('unlock shows rows', await pg.locator('.row').count()==1)
        # リロード→ロック
        await pg.reload(); await pg.wait_for_selector('#lock-view:not([hidden])')
        check('reload stays locked (no flash of list)', await pg.locator('.row').count()==0)
        await pg.fill('#lock-pw',PW); await pg.keyboard.press('Enter'); await pg.wait_for_selector('.row', timeout=15000)
        # バックアップ書き出し（アプリのパスワード）
        await pg.click('#btn-settings'); await pg.click('button:text-is("書き出す")')
        async with pg.expect_download() as dl: await pg.click('.sheet .btn-primary')
        d = await dl.value; path = SHOT+'backup_key.json'; await d.save_as(path)
        txt=open(path,encoding='utf-8').read()
        check('backup encrypted, no secret', SECRET not in txt and '"encrypted": true' in txt, d.suggested_filename)
        check('backedUpAt saved', (await pg.evaluate("JSON.parse(localStorage.getItem('kagimori.vault.v1')).backedUpAt"))>0)
        # 別パスワードの暗号化と平文の拒否条件
        await pg.click('#btn-settings'); await pg.click('button:text-is("書き出す")'); await pg.click('input[value=plain]')
        await pg.click('.sheet .btn-primary'); check('plain needs ack', 'チェック' in await pg.inner_text('.sheet .error-text'))
        await pg.keyboard.press('Escape'); await pg.wait_for_timeout(300)
        # 追加→固定→並べ替え
        for i,sec in enumerate(['GEZDGNBVGY3TQOJQ','MZXW6YTBOI','NBSWY3DPEB3W64TM']):
            await pg.keyboard.press('n'); await pg.click('.menu-item:has-text("手入力")'); await pg.fill('#m-issuer',f'S{i}'); await pg.fill('#m-name',f'u{i}'); await pg.fill('#m-secret',sec); await pg.click('.sheet .btn-primary'); await pg.wait_for_timeout(300)
        check('4 rows, search not yet', await pg.locator('.row').count()==4 and not await pg.locator('#search-box').is_visible())
        names=lambda: pg.evaluate("[...document.querySelectorAll('.row .row-name')].map(e=>e.textContent)")
        before=await names()
        await pg.locator('.row-main').nth(2).click(); await pg.click('text=上に固定'); await pg.keyboard.press('Escape'); await pg.wait_for_timeout(300)
        after=await names(); check('pinned moves to top', after[0]==before[2] and await pg.locator('.pin').count()==1, str(after))
        # 削除→元に戻す
        await pg.locator('.row-main').nth(1).click(); await pg.click('text=この鍵を削除…'); await pg.click('.btn-danger'); await pg.wait_for_timeout(300)
        check('deleted', await pg.locator('.row').count()==3)
        await pg.click('.toast-action'); await pg.wait_for_timeout(300)
        check('undo restores', await pg.locator('.row').count()==4)
        # 5件目で検索
        await pg.keyboard.press('n'); await pg.click('.menu-item:has-text("手入力")'); await pg.fill('#m-issuer','Zed'); await pg.fill('#m-name','z'); await pg.fill('#m-secret','ORSXG5DJNZTQ'); await pg.click('.sheet .btn-primary'); await pg.wait_for_timeout(300)
        check('search appears at 5', await pg.locator('#search-box').is_visible())
        await pg.keyboard.press('/'); await pg.keyboard.type('zed'); await pg.wait_for_timeout(200)
        check('search filters + / shortcut', await pg.locator('.row').count()==1)
        await pg.keyboard.press('Escape'); await pg.wait_for_timeout(200); check('Esc clears search', await pg.locator('.row').count()==5)
        # 貼り付け(otpauth)
        await pg.evaluate("""()=>{const dt=new DataTransfer();dt.setData('text','見て otpauth://totp/Paste:me?secret=KRSXG5CTMVRXEZLU&issuer=Paste');document.dispatchEvent(new ClipboardEvent('paste',{clipboardData:dt,bubbles:true}))}""")
        await pg.wait_for_selector('text=取り込む鍵の確認'); check('paste otpauth opens confirm', 'Paste' in await pg.inner_text('.sheet')); await pg.keyboard.press('Escape'); await pg.wait_for_timeout(300)
        # D&D（画像でもJSONでもない）
        await pg.evaluate("""()=>{const dt=new DataTransfer();dt.items.add(new File(['x'],'a.txt',{type:'text/plain'}));window.dispatchEvent(new DragEvent('drop',{dataTransfer:dt,bubbles:true,cancelable:true}))}""")
        await pg.wait_for_timeout(200); check('drop of other file refused', 'ドロップ' in ' '.join([await t.inner_text() for t in await pg.query_selector_all('.toast')]) or '落としてください' in ' '.join([await t.inner_text() for t in await pg.query_selector_all('.toast')]))
        # 全削除→バックアップから復元（パスワード違い→正しい）
        await pg.click('#btn-delete-all'); await pg.fill('.sheet input','削除'); await pg.click('.sheet .btn-danger'); await pg.wait_for_timeout(300)
        check('all deleted', await pg.locator('.row').count()==0)
        # ここで 'ドラッグ' 経由でJSONを取り込む
        await pg.set_input_files('#backup-input', path) if False else None
        await pg.click('#btn-settings'); 
        async with pg.expect_file_chooser() as fc: await pg.click('button:text-is("読み込む")')
        await (await fc.value).set_files(path)
        await pg.wait_for_selector('text=バックアップのパスワード')
        await pg.fill('.sheet input','bad-password-1'); await pg.click('.sheet .btn-primary'); await pg.wait_for_selector('.sheet .error-text:not([hidden])', timeout=15000)
        check('backup wrong password', 'パスワードが違う' in await pg.inner_text('.sheet .error-text'))
        await pg.fill('.sheet input',PW); await pg.click('.sheet .btn-primary'); await pg.wait_for_selector('text=取り込む鍵の確認', timeout=15000)
        check('backup confirm shows note', 'バックアップファイルから' in await pg.inner_text('.sheet'))
        await pg.click('.sheet .btn-primary'); await pg.wait_for_timeout(400)
        check('restored 1 row (the one backed up)', await pg.locator('.row').count()==1)
        # 暗号化をやめる
        await pg.click('#btn-settings'); await pg.click('button:text-is("暗号化をやめる")'); await pg.click('button:text-is("平文に戻す")'); await pg.wait_for_timeout(500)
        raw = await pg.evaluate("localStorage.getItem('kagimori.vault.v1')")
        check('back to plain v1', '"v":1' in raw.replace(' ','') and SECRET in raw and not await pg.locator('#btn-lock').is_visible())
        # 忘れた場合
        await pg.click('#btn-settings'); await pg.click('button:text-is("パスワードで暗号化する")'); await pg.fill('#pw1',PW); await pg.fill('#pw2',PW); await pg.check('#pw-ack'); await pg.click('.sheet .btn-primary'); await pg.wait_for_selector('.sheet', state='detached', timeout=15000)
        await pg.click('#btn-lock'); await pg.click('#lock-forgot'); await pg.fill('.sheet input','削除'); await pg.click('.sheet .btn-danger'); await pg.wait_for_selector('#empty:not([hidden])')
        check('forgot-password wipes and returns to empty', SECRET not in await pg.evaluate("localStorage.getItem('kagimori.vault.v1')||''"))
        # バックアップ案内バナー
        await pg.click('#empty-sample'); await pg.wait_for_selector('.row')
        check('backup banner shown when never backed up', await pg.locator('#backup-note').is_visible())
        await pg.click('#backup-later'); check('banner dismissable', not await pg.locator('#backup-note').is_visible())
        await pg.screenshot(path=SHOT+'main.png')
        ext=[u for u in reqs if not u.startswith(URL.rstrip('/')) and not u.startswith('blob:') and not u.startswith('data:')]
        check('no external requests', not ext, str(ext)); check('no page errors', not errs, str(errs))
        await b.close()
        # --- 次コード予告・自動ロック（時計を進める）
        b = await p.chromium.launch(executable_path='/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell')
        ctx = await b.new_context(viewport={'width':390,'height':844}); pg = await ctx.new_page()
        t = datetime.datetime(2026,10,11,12,0,26,tzinfo=datetime.timezone.utc)   # 30秒周期の26秒目 = 残り4秒
        await pg.clock.install(time=t)
        await pg.goto(URL); await pg.click('#empty-sample'); await pg.wait_for_selector('.row'); await pg.clock.run_for(600)
        check('next-code preview shows at <=5s', await pg.locator('.next.show').count()==1, await pg.inner_text('.next'))
        exp = await pg.evaluate("""async()=>{const m=await import('/otp.js');return 'nextcode '+m.formatCode(await m.totp(m.base32Decode('JBSWY3DPEHPK3PXP'),Date.now()+30000))}""")
        check('preview equals real next code', (await pg.inner_text('.next')).replace('次','nextcode')==exp, exp)
        await pg.clock.run_for(8000); check('preview hidden early in period', await pg.locator('.next.show').count()==0)
        # 暗号化→無操作5分でロック
        PW='idle-test-pass-1'
        await pg.click('#btn-settings'); await pg.click('button:text-is("パスワードで暗号化する")'); await pg.fill('#pw1',PW); await pg.fill('#pw2',PW); await pg.check('#pw-ack'); await pg.click('.sheet .btn-primary')
        await pg.wait_for_selector('.sheet', state='detached', timeout=20000)
        await pg.clock.run_for(4*60*1000); check('not locked after 4 min', not await pg.locator('#lock-view').is_visible())
        await pg.clock.run_for(70*1000); await pg.wait_for_timeout(300)
        check('auto-locked after 5 min idle', await pg.locator('#lock-view').is_visible() and await pg.locator('.row').count()==0)
        await b.close()
    print('ALL PASS' if ok_all else 'SOME FAILED')
asyncio.run(main())
