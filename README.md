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
| `snapshot` / `diff [--impact] <old.json> [new.json]` | Save an inventory, compare snapshots, and explain gained/lost/uncertain packet access. |
| `plan --snapshot FILE --policy FILE` | Preview a complete replacement HuJSON policy offline, showing policy differences and gained/lost/uncertain device access without applying anything. |
| `graph` | Render grant relationships as Mermaid or DOT (`--format`, `--output`, `--snapshot`). |
| `ui` | Search and sort devices, explain access between selected devices, browse findings and grants, and refresh data. |
| `history` | Track new, ongoing, resolved, and reopened findings in SQLite; filter by status, severity, check, or time. |
| `doctor` / `watch` | Check local/API readiness without exposing credentials, or follow live inventory changes (`--interval`, `--once`). |
| `completion <bash\|zsh\|fish>` | Generate shell completion. |
| `auth login\|status\|logout` | Manage and verify local credentials. |

Exit codes: `0` success, `1` error, `2` usage error, and `3` when findings meet
the `audit --fail-on` threshold.

## Policy explanations and access impact

Legacy ACL destination ports, port lists/ranges, protocols, and source posture
are retained during collection. The evaluator supports user/group selectors,
tags, role selectors, IPs/CIDRs, host aliases, and named IP sets on either side.
Unsupported selectors, posture conditions, and `via` constraints produce a
`CANNOT DETERMINE` result when relevant. A separate certain allow path wins.
App-only grants do not grant packet access. Tagged devices use their tags
rather than inheriting their owner's user identity.

```sh
taildoc diff --impact before.json after.json
taildoc diff --impact --source laptop --destination db-prod --port 5432 --proto tcp before.json after.json
taildoc diff --impact --output json before.json after.json
```

Impact compares collected devices across TCP and UDP ports by default (SCTP is
optional). It partitions ports at rule boundaries and combines adjacent changed
ranges. Redundant rule changes do not appear as access changes. Uncertain paths
are labeled separately from gained/lost access. Self-pairs, service endpoints,
subnet destinations, and runtime connectivity are outside this comparison.
A one-million-evaluation limit prevents unexpectedly expensive comparisons;
use source/destination/port filters to narrow the scope.

`explain` accepts concrete destination IPs and host aliases as well as device
names. A tag destination evaluates the tag selector itself; specify a device
name to include its IP addresses and other tags. Omitting the port or protocol
asks whether any access is permitted, rather than whether all ports are open.
Snapshots from older versions cannot recover policy fields that were never
collected; collect a fresh snapshot for the most complete analysis.

## Preview policy changes before applying them

```sh
taildoc plan --snapshot current.json --policy proposed.hujson
taildoc plan --snapshot current.json --policy proposed.hujson --source laptop --destination db-prod --port 5432 --proto tcp
taildoc plan --snapshot current.json --policy proposed.hujson --output json
```

Both files are required. `plan` replaces **all policy sections** in memory, not
just grants, while keeping the snapshot's users, devices, tags, and enabled
routes fixed. A removed group or host alias is not inherited from the baseline.
Changes to tag owners and auto approvers do not simulate re-tagging or route
approval. The original files are never modified; no credentials or API calls
are needed, and the proposed policy is never sent anywhere.

Output includes the baseline collection time, normalized policy differences,
and access gained, lost, or made uncertain. TCP and UDP are compared by default;
`--proto` also accepts SCTP. Filters and the one-million-evaluation limit match
`diff --impact`. Older snapshots can lack policy information; use a recent,
trusted snapshot. Only distinct collected device pairs are compared, not future
devices, subnet/service destinations, SSH authorization, application capabilities,
or runtime connectivity. Posture, `via`, and unsupported selectors remain
unknown. Unknown evaluations are counted **even when unchanged**; no detected
changes is not proof that a policy is safe.

The loader accepts HuJSON comments and trailing commas, with a 4 MiB input limit
and a 128-level nesting limit. It rejects duplicate keys, null values, unknown
sections or packet-rule fields, and malformed packet-rule shapes rather than
silently discarding possible restrictions. Known out-of-scope sections such as
`ssh`, `tests`, `sshTests`, and `nodeAttrs` produce warnings and are not evaluated
or validated. Omitting both `acls` and `grants` uses the local evaluator's default
allow-all behavior and produces a warning; explicit empty rule arrays deny all.

**This is an offline estimate, not authoritative Tailscale policy validation or
a policy test runner.** Exit `0` means the preview completed, not that deployment
is safe. Continue using [Tailscale's validation and policy tests](https://tailscale.com/kb/1306/gitops-acls-github)
before deploying a policy.

## Finding history

```sh
taildoc history --record
taildoc history --limit 20 --status reopened
taildoc history --severity high --check broad-grants --output json
taildoc history --since 2026-10-01T00:00:00Z
taildoc history --record --snapshot saved.json
```

Each run is compared with its predecessor. Findings are **new** on first
appearance, **ongoing** while present, **resolved** when absent, and **reopened**
when they return after resolution. Built-in checks use stable identities, so
changing evidence or aggregate counts does not create a fresh issue. Aggregate
findings track the check category; they are not individual device issue tickets.
Existing databases are upgraded when opened. Older findings retain their legacy
identity until a fresh run establishes the new identities.

History shows the 10 most recent runs by default; `--limit 0` shows all. `--since`
filters run timestamps, and status/severity/check filters apply within the
selected runs. Classification still uses the actual predecessor even when it
falls outside the display limit or time window. Display filters cannot be used
with `--record`. Recording a snapshot audits it at its collection time and stores
the run at the current recording time.

## Terminal workflow and offline demo

In `taildoc ui`, use `/` to search devices by name, IP, owner, OS, or tag and `s`
to cycle sorting. Press `e` on a source device, select a destination, then press
Enter to choose a port and protocol. Tab switches fields; Enter evaluates; Esc
returns. Press `r` to refresh live data or reload the file passed to `--snapshot`.
Failed refreshes keep the previous data. The status bar displays the collection
timestamp, and snapshot expiry displays use that timestamp too.

The synthetic examples let you try everything without API credentials:

```sh
go run ./cmd/taildoc explain --snapshot examples/demo-before.json laptop db-prod:443
go run ./cmd/taildoc diff --impact examples/demo-before.json examples/demo-after.json
go run ./cmd/taildoc plan --snapshot examples/demo-before.json --policy examples/demo-policy.hujson
go run ./cmd/taildoc ui --snapshot examples/demo-after.json

go run ./cmd/taildoc history --db /tmp/taildoc-demo.db --record --snapshot examples/demo-before.json
go run ./cmd/taildoc history --db /tmp/taildoc-demo.db --record --snapshot examples/demo-after.json
go run ./cmd/taildoc history --db /tmp/taildoc-demo.db
```

## CI

Use JSON, Markdown, or SARIF for automation. A minimal GitHub Actions gate:

```yaml
- run: go install github.com/huza1fa/taildoc/cmd/taildoc@v1.3.0
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
`diff`, `plan`, `graph`, and `history` provide the corresponding workflows. `cmd/taildoc`
is the binary entry point.

## License

MIT — see [LICENSE](LICENSE).
