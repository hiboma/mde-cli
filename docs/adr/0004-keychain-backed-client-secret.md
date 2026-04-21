# ADR-0004: Keychain による client_secret の保管

## ステータス

採択（実装済み、PR #52）

## 日付

2026-04-21

## コンテキスト

`mde-cli` の OAuth2 client_secret は、これまで `~/.config/mde/credentials.toml`
に平文で保存されていました。`MDE_CLIENT_SECRET` 環境変数からも読み込めますが、
永続的な保管手段は事実上 toml ファイルのみでした。

### 脅威

平文ファイル保管には以下のリスクがあります。

1. **バックアップ経由の漏洩**: Time Machine、iCloud Drive、`tar -czf`
   など、ホームディレクトリ単位のバックアップに client_secret が
   そのまま含まれます。バックアップは複製・配布されやすく、いったん
   流出すると回収不可能です。
2. **同一ユーザー権限のプロセスからの読み取り**: ファイルパーミッション
   `0600` のみが防御層です。同じ uid で動く任意のマルウェア・スクリプト
   が無条件に読めます。macOS Keychain は ACL で「特定の署名済みアプリの
   み」に制限できます。
3. **dotfiles リポジトリへの誤コミット**: `.gitignore` の漏れや
   `git add -A` 経由で公開リポジトリに push される事故が起こりえます。
4. **AI エージェントによるコンテキスト汚染**: Claude Code 等の LLM
   エージェントが「設定確認のため」と称して `cat credentials.toml` を
   実行し、出力が会話履歴・PR 説明・サポートログに残るリスクが
   あります。

### 制約

- macOS 環境を主要ターゲットとします。Linux / Windows サポートは
  trait 設計で将来追加可能とします。
- 既存の toml 利用者がアップグレードしただけで挙動が変わらないこと
  （後方互換）。
- agent モード（ADR-0001）との整合性を保つこと。agent は親プロセスで
  解決した credentials を子プロセスのメモリに渡すため、Keychain への
  追加読み込みが per-request で発生してはなりません。
- CI / sandbox 環境（default keychain が無い）で resolve が破綻しない
  こと。

## 決定

### CredentialStore trait による抽象化

`src/config/credential_store.rs` に `CredentialStore` trait を定義し、
プラットフォーム固有の保管バックエンドを抽象化します。

```rust
pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}
```

実装は 3 種類です。

| 実装 | 用途 | 配置 |
|---|---|---|
| `KeychainStore` | macOS Keychain（本番） | `#[cfg(target_os = "macos")]` |
| `MemoryStore` | テスト用 in-memory | `#[cfg(test)]` |
| なし | 非 macOS ターゲット | `default_store()` が `None` を返す |

`KeychainStore` は `keyring` crate（`apple-native` feature）経由で
`Security.framework` の `SecItemAdd` / `SecItemCopyMatching` を
呼び出します。

### Keychain エントリの属性

| 属性 | 値 |
|---|---|
| Kind | `application password`（`kSecClassGenericPassword`） |
| Service | `dev.mde-cli` |
| Account | `client_secret` |
| Keychain | login（デフォルト） |

Service 名は bundle identifier 風の固定文字列です。Account 名は
`KEY_CLIENT_SECRET` 定数として `src/config/credential_store.rs` で
公開しています。

### Resolve の優先順位

`MdeCredentials::resolve()` は client_secret を以下の順で解決します。

```
MDE_CLIENT_SECRET (env) > Keychain > credentials.toml > None
```

tenant_id / client_id は機密性が低いため Keychain に格納せず、CLI args >
env > toml の従来順を維持します。

### StoreError の分類とフォールバック判断

`StoreError` を 2 variant に分けます。

| Variant | 意味 | resolve の挙動 |
|---|---|---|
| `Unavailable(msg)` | 保管バックエンドそのものが存在しない（非 macOS、CI sandbox の default keychain なし） | 静かに toml にフォールバック |
| `Backend(msg)` | バックエンドへのアクセスに失敗（ユーザーが prompt を Deny、Keychain daemon ダウン、ACL 不整合） | **toml にフォールバックしない**。stderr に強い警告を出して `None` を返す |

`Backend` 時に toml フォールバックを許可すると、Keychain に移行済みの
ユーザーが Deny した瞬間に古い toml の secret が黙って採用されます。
これは Keychain への移行という決定そのものを台無しにするため、
明示的な失敗を選びます。

`KeychainStore` は `keyring::Error` を `classify_keyring_err` で振り分け、
"no default keychain" 系のメッセージのみを `Unavailable` に分類します。

### `mde-cli credentials` サブコマンド

ユーザーが Keychain エントリを操作するためのサブコマンドを追加します。

| サブコマンド | 機能 |
|---|---|
| `set <field> [--stdin]` | 対話的または stdin 経由で保管 |
| `delete <field>` | 削除 |
| `status` | 各エントリの「stored / not stored」のみを表示（値は出さない） |
| `migrate [--dry-run]` | credentials.toml の client_secret を Keychain に移し、toml から削除 |

`get` サブコマンドは**意図的に提供しません**。理由は以下です。

- 値を取り出す正当なユースケースが存在しません。動作確認は `status`
  で十分です。バックアップは Azure portal で client_secret を再発行
  するのが正攻法です。
- AI エージェントが「デバッグのため」と称して `get` を実行し、出力が
  会話履歴・ログ・PR 説明に流出する事故を構造的に防ぎます。
- シェル履歴・端末スクロールバックへの汚染を防ぎます。

### Migrate の安全策

`migrate` は以下の順で実行します。

1. credentials.toml から client_secret を抽出（quoted basic string のみ
   サポート、literal / multi-line は明示エラー）
2. ユーザーに移行確認（default No）
3. **Keychain への書き込み**（toml 未変更のため失敗時の rollback 不要）
4. ユーザーに plaintext 処分方法を確認:
   - **default Yes**: tempfile + atomic rename で `client_secret` 行を
     完全削除。disk 上に plaintext は残らない
   - **No**: 0o600 backup を作成 + toml は新形式に書き換え + 多段の
     警告を表示
5. 失敗時は Keychain エントリを rollback し、plaintext がどこに残って
   いるかを明示

backup 作成を default にせず default 削除にしたのは、レビュー指摘に
よる方針変更です。backup を残す選択は意識的にしか取れず、取った場合
は強い警告を出します。

### Debug マスク

`MdeCredentials` の `Debug` 実装を手動化し、`client_secret` と
`access_token` を `***` でマスクします。`dbg!` / `{:?}` 経由の
偶発的な leak を防ぎます。

### ローカル平文の取り扱い

migrate で作成する backup ファイルは `OpenOptions::mode(0o600) +
create_new(true)` で書き出します。`fs::copy` は元ファイルの mode を
継承する（典型的には `0o644`）ため使いません。toml 本体の書き換えは
sibling tempfile への書き込み + `rename(2)` でアトミックに行います。

## 結果

### Positive

- client_secret がホームディレクトリのバックアップ・他プロセス・
  dotfiles リポジトリから完全に隔離されます
- macOS 標準の Keychain Access.app から GUI で監査・削除可能です
- trait 抽象化により Linux / Windows backend の追加コストが小さい
  です
- 既存 toml ユーザーは何もせずアップグレードしても挙動が変わらず、
  `migrate` で能動的に移行できます

### Negative

- 初回アクセスと `cargo install` 再ビルドのたびに Keychain ACL
  ダイアログが出ます。これは macOS の codesign ベース ACL に由来する
  挙動で、Homebrew bottle のような署名安定なバイナリ配布で緩和でき
  ます
- `keyring` crate の追加でサプライチェーン面積が増えます。`cargo
  audit` での監視を継続します
- 環境変数優先のため、`.env` 経由の `MDE_CLIENT_SECRET` 上書き攻撃は
  Keychain で防御できません（TODO.md に follow-up として記録）

## 代替案

### A. `security` コマンドのサブプロセス呼び出し

`/usr/bin/security add-generic-password` を `Command` で叩く方式です。
追加 crate は不要ですが、子プロセス起動コスト・シェルエスケープ・
ACL の細かい制御が課題です。`keyring` crate は `Security.framework` を
直接 FFI で呼ぶため、子プロセス不要・型安全です。

### B. `security-framework` crate を直接利用

最低レベルです。ACL を細かく制御できますが、コード量が増え、Linux /
Windows backend を将来追加する際に再抽象化が必要です。`keyring` crate
は最初から cross-platform 抽象化を持っています。

### C. tenant_id / client_id も Keychain に格納

これらは機密性が低く（公開可能な識別子）、Keychain に入れると ACL
ダイアログ頻度が増えるだけで便益が小さいため不採用としました。
toml に残します。

### D. backup を default で作成し続ける（PR 初版の挙動）

レビューで指摘されたとおり、backup ファイル自体が plaintext を持つ
ため移行の意図を裏切ります。「default は完全削除、backup は opt-in」
に変更しました。

## 先行事例

- **ssh-agent / gpg-agent**: 秘密鍵をプロセスメモリに保持する方式
  （ADR-0001 で採用済）
- **`gh` CLI**: Keychain / Secret Service / Credential Manager を抽象化
  して OAuth トークンを保管
- **Docker CLI**: `docker-credential-osxkeychain` 等の credential
  helper を介して registry credentials を Keychain に保管

## 影響範囲

- `Cargo.toml` — `keyring` crate を `target.cfg(target_os = "macos")` で
  追加
- `src/config/credential_store.rs` — trait と KeychainStore 実装
- `src/config/mod.rs` — `MdeCredentials::resolve()` の優先順位拡張、
  `Debug` の手動マスク化
- `src/cli/credentials.rs` — clap サブコマンド定義
- `src/commands/credentials.rs` — handler 実装
- `src/main.rs` — `credentials` / `completion` サブコマンドで
  resolve をスキップ
- `README.md` — Credential storage セクション追加

## セキュリティ考慮事項

- **codesign の安定性**: `cargo install` で再ビルドするたびに ACL が
  再評価され、ダイアログが再出します。本質的な解決には Homebrew bottle
  のような署名済みバイナリ配布が必要です
- **`MDE_CLIENT_SECRET` 環境変数の優先**: 攻撃者が cwd に malicious
  `.env` を置けば Keychain 値を上書き可能です。TODO.md に follow-up
  として記録、別 PR で対処予定
- **Keychain メモリダンプ**: root 権限による Keychain unlock 後の
  メモリスキャンは ADR-0003 のプロセス hardening の延長で緩和し、
  本 ADR のスコープ外とします
- **`keyring::Error` の locale 翻訳**: 日本語 macOS で `errSecNoDefault
  Keychain` のメッセージが翻訳されると `classify_keyring_err` の
  string match 漏れにより `Backend` 扱いになり、toml フォールバックが
  失われます。TODO.md に follow-up として記録
