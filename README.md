# adguard-filter

## AdGuard 過濾規則（由 Surge 模組自動轉換）

GitHub Actions 每天自動抓取上游 Surge 模組，轉成 AdGuard 語法後提交到 `adguard/`。
上游沒變就不會產生新 commit。

| 訂閱網址 | 內容 | 需要 HTTPS 過濾 |
|---|---|---|
| `https://raw.githubusercontent.com/g91720/adguard-filter/main/adguard/LINE-ADs.txt` | 完整版：網域規則 + URL 路徑規則 | 是（URL 規則） |
| `https://raw.githubusercontent.com/g91720/adguard-filter/main/adguard/LINE-ADs-dns.txt` | 只有網域規則，DNS 層即可生效 | 否 |

上游來源：<https://raw.githubusercontent.com/jkgtw/Surge/master/Modules/LINE-ADs.sgmodule>（jkgtw/Surge，`LINE-ADs.sgmodule`）

### AdGuard for Android（rooted）設定

1. **加入訂閱**：設定 → 過濾 → 自訂過濾器 → 新增 → 貼上上面的完整版網址，開啟「自動更新」。
2. **開啟 HTTPS 過濾**：設定 → 過濾 → HTTPS 過濾 → 啟用，並安裝 AdGuard 憑證。
3. **把憑證放進系統憑證存放區**（root 的關鍵優勢）：Android 7 以上的 App 預設不信任使用者安裝的憑證，
   LINE 這類 App 的流量因此無法解密。已 root 的裝置可在 AdGuard 的 HTTPS 過濾設定中把憑證安裝到系統存放區
   （或用 Magisk 模組移動憑證），之後 LINE 的 HTTPS 請求才能套用 URL 路徑規則。
4. **確認 LINE 沒被排除**：HTTPS 過濾 → 應用程式 → LINE 要在過濾名單內；「不過濾的網域」裡不能有 `line.me`、`line-apps.com` 等。
5. Proxy 模式或 VPN 模式都可以，規則語法相同。

### 效果能否和 Surge 模組一樣？

| Surge 規則 | AdGuard 對應 | 條件 |
|---|---|---|
| `DOMAIN,host,REJECT` | `\|\|host^` | 不需 HTTPS 過濾，DNS 層就擋得掉 |
| `URL-REGEX,^https://host/path...,REJECT` | `\|\|host/path...` | 需要 HTTPS 過濾且 LINE 信任 AdGuard 憑證 |
| `REJECT-TINYGIF` | `$redirect=1x1-transparent.gif` | 回傳 1x1 透明圖，避免 App 顯示錯誤 |

- 上游模組的 `[MITM] hostname` 清單，就是 AdGuard 需要做 HTTPS 過濾的主機清單，已寫在產生檔案的檔頭註解。
- 上游規則是從 iOS 版 LINE 抓包整理的（部分路徑含 `/ios/`）。Android 版 LINE 的廣告 API 大多相同，
  但不保證 100% 一致；若某些廣告仍出現，需要另外抓 Android 的請求。
- 如果 LINE Android 對某些主機做了憑證綁定（certificate pinning），AdGuard 無法解密該主機流量，
  那些 URL 規則就不會生效，只剩網域規則有效。這是 MITM 類方案的共同限制，Surge 也一樣。

### 轉換規則摘要

`scripts/convert_sgmodule.py` 只用 Python 標準函式庫，轉換方式：

- `DOMAIN` / `DOMAIN-SUFFIX` → `||host^`；`DOMAIN-KEYWORD` → `||*kw*^`
- `URL-REGEX` 若只用到常見子集（`\d+`、`[^/]+`、`(?::443)?`、`(?:\?|$)`、`(?:a|b|c)` 等）→ 轉成 AdGuard 基本規則
  （`\d+` 變成 `*`，`(?:\?|$)` 變成 `^`，`(?:a|b|c)` 展開成多條規則）
- 其他複雜正則 → 原樣保留為 AdGuard 正則規則 `/regex/`
- `REJECT-TINYGIF` / `REJECT-IMG` → `$redirect=1x1-transparent.gif`；`REJECT-DICT` / `REJECT-ARRAY` → `$redirect=noopjson`
- 非 REJECT 的策略（DIRECT、PROXY）與不支援的規則類型會以註解標記 `[skipped]`
- 上游註解會保留為 `!` 註解，方便對照

### 新增其他模組

在 `sources.json` 的 `sources` 陣列加一筆：

```json
{
  "name": "Example",
  "title": "Example (AdGuard)",
  "url": "https://raw.githubusercontent.com/.../Example.sgmodule",
  "out": "adguard/Example.txt",
  "dns_out": "adguard/Example-dns.txt"
}
```

本機測試：

```bash
python3 scripts/convert_sgmodule.py                 # 下載並轉換
python3 scripts/convert_sgmodule.py --from-file x.sgmodule   # 用本機檔案測試
```

### 排程注意事項

- `schedule` 只會在預設分支（`main`）上執行，這個 repo 的工作流程檔已在 `main` 上，不需額外動作。
- GitHub 會在儲存庫 60 天沒有任何活動後自動停用排程；若上游長期沒更新，到 Actions 頁面按一次
  「Run workflow」即可重新啟用。
