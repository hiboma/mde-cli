# ADR-0003: Agent プロセスの環境変数サニタイズ

## ステータス

提案

## 日付

2026-03-19

## コンテキスト

mde-cli の agent プロセスは fork() で生成されるため、親プロセスの環境変数をすべて継承します。`op run --env-file=.env` 経由で起動すると、mde-cli が必要としない他サービスのトークン（Slack, GitHub など）も agent プロセスの環境に載ります。

### 脅威

1. **`/proc/[pid]/environ` 経由の漏洩（Linux）**: `/proc/[pid]/environ` は `execve(2)` 時点のスナップショットです。`std::env::remove_var()` を呼んでも反映されません。同一ユーザーの任意のプロセスが読み取り可能です。
2. **子プロセスへの伝搬**: agent プロセスが将来的に子プロセスを spawn する場合、不要な認証情報が伝搬します。
3. **最小権限の原則の違反**: agent が必要とするのは Microsoft Defender for Endpoint API の認証情報のみです。他サービスのトークンを保持する理由がありません。

### 制約

- `MDE_CLIENT_SECRET` は `fork()` 前に `Config` 構造体に読み込み済みで、fork 後は環境変数を再参照しません。
- agent プロセスは HTTP 通信（reqwest）と Unix ドメインソケット通信を行うため、プロキシ・TLS 関連の環境変数は保持する必要があります。
- メモリダンプ（root 権限）による漏洩は本 ADR のスコープ外とします。

## 決定

### ホワイトリスト方式による環境変数クリア

fork 直後にすべての環境変数をクリアし、以下のホワイトリストに含まれる変数のみを保持します。

| カテゴリ | 変数 | 用途 |
|---|---|---|
| パス解決 | `HOME`, `PATH`, `USER`, `TMPDIR` | ファイルシステム操作、外部コマンド |
| XDG | `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR` | セッションファイル、設定ファイル、ソケットパス |
| プロキシ | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` | reqwest による HTTP 通信 |
| プロキシ (小文字) | `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` | reqwest は小文字も参照する |
| TLS | `SSL_CERT_FILE`, `SSL_CERT_DIR` | カスタム CA 証明書 |
| ロケール | `LANG`, `LC_*` | 文字エンコーディング |
| デバッグ | `RUST_LOG`, `RUST_BACKTRACE` | ログ出力、パニック時のバックトレース |

### プロセス hardening

| プラットフォーム | 手法 | 効果 |
|---|---|---|
| Linux | `prctl(PR_SET_DUMPABLE, 0)` | コアダンプ・ptrace の拒否 |
| macOS | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | デバッガのアタッチ拒否 |
| 共通 | `setrlimit(RLIMIT_CORE, 0)` | コアダンプの無効化 |

macOS には `/proc/[pid]/environ` が存在しないため、`remove_var()` だけで環境変数は外部から読めなくなります。`ptrace(PT_DENY_ATTACH)` はデバッガ経由のメモリ読み取りを防ぐ追加の防御層です。

### 適用タイミング

- **デーモンモード（fork）**: fork 直後、ソケット listen の前に実行します
- **フォアグラウンドモード**: Config 構築前に実行します

## 代替案

### 1. ブラックリスト方式

既知の危険な変数（`SLACK_TOKEN`, `GITHUB_TOKEN` など）を個別に削除する方式です。未知の変数が漏れる可能性があるため不採用としました。

### 2. 全クリア

すべての環境変数を削除する方式です。`HOME` や `PATH` が消えるとソケットパスの解決や外部コマンドの実行が不能になるため不採用としました。

### 3. remove_var のみ

`std::env::remove_var` で個別に削除する方式です。Rust ランタイム上の環境変数は消えますが、`/proc/[pid]/environ` にはプロセス起動時の環境変数が残り続けるため不十分です。

## 先行事例

- **ssh-agent**: 環境変数を最小限に絞り、認証情報をメモリ上のみで管理します
- **gpg-agent**: 同様に環境を制限し、秘密鍵をプロセス内に隔離します

## 影響範囲

- `src/agent/mod.rs` — fork 処理と環境変数クリアの統合
- `src/agent/server.rs` — プロセス hardening の適用

## セキュリティ考慮事項

- **root 権限による迂回**: root ユーザーは `prctl` や `ptrace` の制限を迂回できます。これは OS レベルの制約であり、mde-cli の責任範囲外とします
- **Config 構造体のメモリ残存**: `MDE_CLIENT_SECRET` は環境変数から削除されますが、Config 構造体のフィールドとしてプロセスメモリ上に残存します。メモリスキャンによる読み取りは前述のプロセス hardening で緩和します
