# ADR-0001: Agent Mode for Credential Isolation

## Status

Accepted (implemented)

## Context

`mde-cli` CLI は `MDE_ACCESS_TOKEN` 環境変数や OAuth2 認証情報（`MDE_TENANT_ID`, `MDE_CLIENT_ID`, `MDE_CLIENT_SECRET`）から API トークンを取得します。Claude Code のような LLM エージェントツールと組み合わせる場合、`op run -- claude` のように 1Password の子プロセスとして起動すると、API トークンが LLM エージェントのプロセス空間に平文で存在します。

これにより以下のリスクがあります:

1. Prompt injection により `env` コマンドが実行され、トークンが漏洩する
2. LLM エージェントが意図せずトークンをログや出力に含める
3. プロセスメモリ内の秘密情報が LLM のコンテキストウィンドウに流出する

## Decision

ssh-agent と同じモデルで、認証情報を別プロセスに隔離する agent モードを導入します。

### Architecture

```
LLM Agent --> mde-cli (client mode) --UDS--> mde-cli agent (op run 下で起動)
              セッショントークンのみ保持    API トークンを保持、API を実行
```

### CLI Interface

```bash
# Agent の起動 (ssh-agent パターン)
eval "$(op run --env-file .env.1password -- mde-cli agent start)"

# Agent の管理
mde-cli agent start [--socket PATH] [--config PATH] [--foreground]
mde-cli agent stop [--socket PATH] [--all]
mde-cli agent status [--socket PATH]
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `MDE_AGENT_SOCKET` | Unix domain socket path |
| `MDE_AGENT_TOKEN` | Session token for authentication |
| `MDE_AGENT_PID` | Agent process PID |

### Auto-detection

`MDE_AGENT_TOKEN` 環境変数が設定されている場合、通常のコマンドは自動的に agent 経由でルーティングされます。明示的なフラグは不要です。

### Socket Path Resolution

3段階の解決ロジック:

1. `MDE_AGENT_SOCKET` 環境変数（最優先）
2. ソケットディレクトリをスキャンし、ソケットが1つだけなら自動検出
3. デフォルトパスにフォールバック

PID ベースのソケットパス (`mde-<PID>.sock`) を使用し、複数インスタンスが共存できます。

### Security Layers

1. UDS パーミッション (socket `0600`, directory `0700`)
2. Peer UID verification (UCred)
3. Code signing verification (macOS) / path verification (Linux)
4. Session token (constant-time comparison)
5. Command name validation (alphanumeric, hyphen, underscore only)
6. Command whitelist (`agent.toml`)
7. Rate limiting (token bucket, default 60 req/min)
8. Request size limit (1 MiB)
9. Concurrent connection limit (64, Semaphore)
10. Audit log

### Watchdog

- `getsid(0)` でセッションリーダー（ログインシェル）を監視し、ターミナルが閉じたら agent を自動停止します
- 8時間のアイドルタイムアウトで放置された agent を自動停止します
- `getppid()` ではなく `getsid(0)` を使用する理由: Claude Code 経由で起動した場合、中間シェルが即座に終了して agent が誤停止するのを防ぐためです

### Process Model

`main()` を `#[tokio::main]` から通常の `fn main()` に変更します。`fork()` はシングルスレッドでないと安全に動作しないため、tokio runtime 作成前に fork を実行する必要があります。

## Consequences

### Positive

- API トークンが LLM エージェントのプロセス空間から完全に隔離されます
- ssh-agent と同じ使い慣れたパターンで利用できます
- 既存のコマンドインタフェースに変更はありません

### Negative

- `main()` の構造変更が必要です
- macOS 固有の依存関係（コード署名検証）が増えます
- Windows はサポート対象外になります（UDS 非対応）

## References

- [cloudapps-cli PR#8](https://github.com/hiboma/cloudapps-cli/pull/8) - 参照実装
- [falcon-cli PR#9](https://github.com/hiboma/falcon-cli/pull/9) - 初期参照実装
