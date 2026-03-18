# ADR-0002: Agent shared モードによる複数ターミナルからの利用

## ステータス

承認済み（実装完了）

## 日付

2026-03-18

## コンテキスト

mde-cli の agent は ssh-agent をモデルにしたセキュリティデザインを採用しています（ADR-0001 参照）。`eval "$(mde-cli agent start)"` でシェルに環境変数（`MDE_AGENT_SOCKET`, `MDE_AGENT_TOKEN`）を設定し、そのターミナルセッション内でのみ agent 経由のコマンド実行を可能にします。

この設計は単一ターミナルでの利用では堅牢ですが、以下の運用上の不便が生じています。

### 問題: 複数ターミナルからの利用ができない

- agent が返す環境変数は `eval` を実行したシェルにしか存在しません
- 別のターミナルから同じ agent を利用するには、ソケットパスとトークンを手動でコピーする必要があります
- tmux の複数ペイン、複数の iTerm2 タブなど、日常的なワークフローで不便です

### 既存の仕組み

- `resolve_socket_path()` はソケットディレクトリ内の `.sock` ファイルを探索する機能を持っています
- しかし、トークンの自動解決手段がないため、ソケットが見つかっても認証できません

## 決定

### `--shared` オプションの導入

`agent start` に `--shared` オプションを追加し、eval モードと排他的に使い分けます。

#### eval モード（現行）

```bash
eval "$(mde-cli agent start)"
```

- 環境変数を stdout に出力します
- session.json は作成しません
- watchdog がセッションリーダーの生存を監視します
- ターミナルを閉じると agent が停止します

#### shared モード（新規）

```bash
mde-cli agent start --shared
```

- stdout に eval 用の変数を出力しません
- `~/.local/share/mde-cli/session.json` にソケットパスとトークンを書き出します
- watchdog のセッションリーダー監視を無効化します（アイドルタイムアウトは維持）
- 別のターミナルから `mde-cli alerts list` 等を実行すると、session.json から自動検出して agent 経由で実行します

### session.json の仕様

保存先: `$XDG_DATA_HOME/mde-cli/session.json` (デフォルト: `~/.local/share/mde-cli/session.json`)

```json
{
  "socket_path": "/tmp/mde-agent/mde-12345.sock",
  "token": "abcdef0123456789...",
  "pid": 12345,
  "started_at": "2026-03-18T10:00:00Z"
}
```

- ファイルパーミッション: 0600
- 親ディレクトリのパーミッション: 0700

### コマンド実行時の優先順位

```
1. --no-agent フラグ          → direct mode を強制
2. MDE_AGENT_TOKEN 環境変数    → eval モードの agent 経由
3. session.json               → shared モードの agent 経由
4. MDE_CLIENT_ID 環境変数      → direct mode
```

環境変数による明示指定は session.json より常に優先します。

### agent stop の動作

- eval モード/shared モード共通で、ソケット/PID ファイルから agent を特定して停止します
- shared モードの agent 停止時は session.json も削除します
- watchdog によるアイドルタイムアウト停止時も session.json を削除します
- `agent stop --all` は全モードの agent を停止し、session.json も削除します

### --no-agent フラグ

session.json が存在しても agent 経由を抑制し、direct mode でコマンドを実行します。

```bash
mde-cli --no-agent alerts list --filter "status:'new'"
```

## 影響範囲

| ファイル | 変更内容 |
|----------|----------|
| `src/cli/agent.rs` | `AgentCommand::Start` に `--shared` フラグを追加 |
| `src/cli/mod.rs` | `Cli` に `--no-agent` フラグを追加 |
| `src/agent/session.rs` | `session_file_path()`, `write_session()`, `read_session()`, `remove_session()` を追加 |
| `src/agent/server.rs` | shared モード時の session.json 書き出し・削除。watchdog のセッションリーダー監視の条件分岐 |
| `src/agent/client.rs` | stop 時に session.json のクリーンアップ |
| `src/main.rs` | session.json フォールバックロジック、`--no-agent` の処理 |

## セキュリティに関する考慮事項

### リスク

- session.json にトークンがディスクに保存されます（eval モードではメモリのみ）
- session.json にアクセスできるプロセスは agent に接続できます

### 緩和策

- session.json のパーミッションは 0600 で、同一ユーザーのみ読み取り可能です
- 既存の UID 検証・ピアプロセス検証（コード署名）は引き続き適用されます
- agent 停止時・アイドルタイムアウト時に session.json を確実に削除します
- eval モードを選択すれば、従来通りディスクにトークンを書き出しません

### トレードオフ

利便性（複数ターミナル共有）とセキュリティ（トークンのディスク保存）のトレードオフを、ユーザーが `--shared` フラグで明示的に選択します。デフォルトの動作は変更しません。
