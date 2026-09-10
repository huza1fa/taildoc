# taildoc

`taildoc` is a read-only CLI for understanding a Tailscale tailnet: inventory
what is there, explain why a connection is allowed or denied, and keep useful
snapshots of change over time. Collection, evaluation, diffs, and graph
rendering stay on your machine; taildoc never changes the tailnet or sends data
anywhere except the Tailscale API.

## Install

The install script fetches the latest GitHub release for Linux or macOS and
verifies its SHA-256 checksum and keyless Sigstore signature. Install
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) first:

```sh
curl -fsSL https://raw.githubusercontent.com/huza1fa/taildoc/master/install.sh | sh
```

Alternatively, download a platform archive from the
[releases page](https://github.com/huza1fa/taildoc/releases). Releases include
Linux, macOS, and Windows archives for amd64 and arm64, `checksums.txt`, and its
Sigstore certificate/signature. You can also use Go:

```sh
go install github.com/huza1fa/taildoc/cmd/taildoc@latest
```

To build locally:

```sh
git clone https://github.com/huza1fa/taildoc && cd taildoc
go build ./cmd/taildoc
```

## Start here

```sh
taildoc auth login       # choose an API key or OAuth client
taildoc inventory        # users, devices, tags, routes, and policy
taildoc audit            # practical operational and access findings
taildoc explain <src> <dst[:port]>
```

Create API keys at <https://login.tailscale.com/admin/settings/keys> (admin or
network-admin scope) or OAuth clients at
<https://login.tailscale.com/admin/settings/oauth>. For automation, set
`TS_ACCESS_TOKEN`; it takes precedence over stored credentials.

## Commands

| Command | What it does |
| --- | --- |
| `inventory` | Show normalized users, groups, devices, tag owners, grants, and routers. |
| `audit` | Run checks; supports `--output text\|json\|sarif\|markdown`, `--fail-on`, and `--snapshot`. |
| `explain <src> <dst[:port]>` | Trace the policy rule that allows or denies a connection. |
| `find <query>` / `show <resource>` | Quickly locate a resource, then drill into its ownership, routes, and related policy. Both support `--snapshot FILE` before the argument. |
| `snapshot` / `diff <old.json> [new.json]` | Save an inventory, then compare snapshots or one snapshot with live state. |
| `graph` | Render grant relationships as Mermaid or DOT (`--format`, `--output`, `--snapshot`). |
| `ui` | Browse findings, filter them, sort devices, and inspect grant relationships in a terminal dashboard. |
| `history` | Store and review findings over time in SQLite (`--record`, `--db`). |
| `doctor` / `watch` | Check local/API readiness without exposing credentials, or follow live inventory changes (`--interval`, `--once`). |
| `completion <bash\|zsh\|fish>` | Generate shell completion. |
| `auth login\|status\|logout` | Manage and verify local credentials. |

Exit codes: `0` success, `1` error, `2` usage error, and `3` when findings meet
the `audit --fail-on` threshold.

## CI

Use JSON, Markdown, or SARIF for automation. A minimal GitHub Actions gate:

```yaml
- run: go install github.com/huza1fa/taildoc/cmd/taildoc@v0.2.0
- name: Audit tailnet
  env:
    TS_ACCESS_TOKEN: ${{ secrets.TS_API_KEY }}
  run: taildoc audit --fail-on high
```

For code-scanning integration, create a SARIF file with
`taildoc audit --output sarif > taildoc.sarif` and upload it with
`github/codeql-action/upload-sarif`. Taildoc emits SARIF 2.1.0 and stable
SHA-256 partial fingerprints, so repeat findings deduplicate.

## Security

- Credentials are sent only to `api.tailscale.com` through the official SDK; no telemetry or third-party endpoints.
- Stored credentials default to `~/.config/taildoc/config.json` (or `TAILDOC_CONFIG`), with `0700` directory and `0600` file permissions.
- Credentials are checked with a read-only API call before saving. Interactive input is masked; scripts should pipe secrets to `--apikey-stdin` or `--oauth-client-secret-stdin`, never use command-line secrets.

## Development

```sh
go test ./...
go vet ./...
```

The implementation lives under `internal/`: `collector` builds a normalized
model, `policy` powers `explain`, `audit` renders findings, and `snapshot`,
`diff`, `graph`, and `history` provide the corresponding workflows. `cmd/taildoc`
is the binary entry point.

## License

MIT — see [LICENSE](LICENSE).
