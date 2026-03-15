# Windows Upgrade Requirements Scanner (WURS)

Windows 10環境で動作するElectronアプリです。  
PC・アプリ・ファイル・ZIPツールのWindows Upgradeの互換性をスキャンします。

---

## 機能

| 機能 | 説明 |
|------|------|
| **システム要件チェック** | CPU世代・RAM・TPM2.0・セキュアブート等をWindows 11要件と比較 |
| **インストール済みアプリスキャン** | レジストリから全インストールアプリを取得し互換性判定 |
| **ファイル/フォルダスキャン** | .exe/.msi/.bat/.com等の実行ファイルを再帰的にスキャン |
| **ZIP解析** | 配布ZIPの中身を解析し実行ファイル互換性をチェック |
| **ネット互換検索** | Google検索でアプリのWindows 11対応情報を自動収集 |
| **結果エクスポート** | JSON/CSV形式でスキャン結果を保存 |

---

## セットアップ方法

### 必要環境
- **Node.js** 18以上 (https://nodejs.org)
- **npm** (Node.jsに付属)
- Windows 10 / Windows 11

### 起動手順

RUN.batを開くだけでOK

## プロジェクト構成

```
win11-scanner/
├── src/
│   ├── main.js       # Electronメインプロセス（スキャンロジック）
│   ├── preload.js    # セキュアなIPC橋渡し
│   └── index.html    # UI（HTML/CSS/JS）
├── assets/
│   └── icon.ico      # アプリアイコン（任意）
├── package.json
└── README.md
```

---

## 互換性判定ロジック

### アプリ判定
AIによる確認を採用

### ファイル判定
AIによる確認を採用

### ネット検索
Googleの検索結果スニペットを取得し、"not compatible"や"supported"などのキーワードで  
自動判定を行います（参考情報、確定ではありません）。

---

## 注意事項

- システムスキャン（TPM・セキュアブート確認）は管理者権限が必要な場合があります
- ネット検索は実行時にインターネット接続が必要です
- 互換性判定は参考情報です。最終確認は各ソフトウェアの公式サイトでご確認ください

---

## ライセンス

MIT
