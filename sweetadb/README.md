# boarnet-sweetadb-adapter

Ship data from an existing [sweetADB](https://github.com/Womkirkie/sweetADB)
honeypot into the BoarNet threat-intelligence network **without
replacing or modifying sweetADB itself.**

You run sweetADB as you already do. You drop this binary alongside
it. The adapter tails sweetADB's `events.jsonl`, translates each
event into BoarNet's envelope format, and ships the stream to
`https://www.boarnet.io/api/ingest/v1/events` over authenticated
HTTPS. Payload drops (`./mimic/payloads/*.bin`) are SHA256'd and
shipped as `payload.dropped` envelopes.

No code changes to sweetADB required. No Docker required. Single
static Go binary, stdlib-only dependencies.

## What you get

- Your ADB attacker data joins a cross-sensor pivot graph with
  TLS / SSH / scan probes from the rest of the BoarNet fleet
- Per-IP enrichment (GeoIP, ASN, reputation, ThreatFox overlap)
  happens server-side — your adapter only ships raw observations
- Source IPs are peppered with an HMAC-SHA256 secret stored
  locally at `/var/lib/boarnet-sweetadb/pepper.secret`, never
  transmitted in plaintext. The pepper is per-sensor — other
  sensors in the network cannot correlate your IPs against theirs
  byte-for-byte (only the server, which sees every pepper, can)

## Prerequisites

- **OS**: Linux (sweetADB itself requires Linux). The adapter also
  builds cleanly on macOS and FreeBSD, but you'd only run it on the
  same host where sweetADB is writing its log.
- **Go 1.21 or newer** to build from source. **Check your version:**
  ```bash
  go version
  ```
  It must say `go1.21` or higher. Go versions older than 1.21 lack
  the `log/slog` package and will fail to compile with errors like
  `package log/slog is not in GOROOT`.

  **`apt install golang` on Debian/Ubuntu often pins an older
  version.** If `go version` reports anything below 1.21, uninstall
  the distro package and install a current toolchain instead:
  ```bash
  # Ubuntu / Debian — via Snap (simplest):
  sudo apt remove -y golang-go golang
  sudo snap install go --classic

  # Or manual — download the latest tarball from go.dev/dl/:
  curl -fsSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | \
    sudo tar -C /usr/local -xz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  source ~/.profile
  go version   # verify it now says 1.23+
  ```

  On macOS: `brew install go`. On Alpine: `apk add go`. On other
  distros: see [go.dev/doc/install](https://go.dev/doc/install).
- **A running sweetADB instance** writing to `./mimic/events.jsonl`.
- **Outbound HTTPS** to `www.boarnet.io` (no special firewall rules
  needed — the adapter makes only one kind of external connection).
- **Sudo access** only if you want to install the binary to
  `/usr/local/bin/` or run under systemd. Neither is required —
  the adapter works from any path, any user that can read the log.
- **If sweetADB writes its `events.jsonl` under a different user's
  home**, grant read access so the adapter process (running under
  a systemd-managed dynamic user by default) can reach it:
  ```bash
  sudo setfacl -m u:systemd-boarnet-sweetadb:rx /home/<sweetadb-user>
  sudo setfacl -R -m u:systemd-boarnet-sweetadb:r /home/<sweetadb-user>/sweetADB/mimic
  ```
  Or, more commonly, run sweetADB with `--log-dir /var/log/sweetadb`
  so its output lands in a system-level path the adapter can already
  reach via the shipped unit's `ReadOnlyPaths=/var/log/sweetadb`.

> No more `boarnet` user creation — the shipped systemd unit now
> uses `DynamicUser=true` + `StateDirectory=boarnet-sweetadb`,
> which allocates a transient UID at service start and persists
> the state directory across restarts. Eliminates the
> `status=217/USER` failure that hit early adopters who missed
> the manual `useradd` step.

## Install

1. **Mint an ingest token** at
   `https://www.boarnet.io/dashboard/sensors` → Mint new token.
   Copy the `bn_…` string once — it's not shown again.
2. **Pick a sensor id.** Convention: `mesh-<location>-adb-<nn>`,
   e.g. `mesh-fra1-adb-01`. Must be unique across your fleet.
3. **Build the adapter** (requires Go 1.21+):
   ```
   git clone https://github.com/Bino97/boarnet-adapters.git
   cd boarnet-adapters/sweetadb
   go build -o boarnet-sweetadb-adapter
   sudo install -m 0755 boarnet-sweetadb-adapter /usr/local/bin/
   ```

## Run (ad-hoc)

```bash
export BOARNET_TOKEN=bn_your_token_here
export BOARNET_SENSOR_ID=mesh-fra1-adb-01

boarnet-sweetadb-adapter \
  --events-log /home/you/sweetADB/mimic/events.jsonl \
  --payloads-dir /home/you/sweetADB/mimic/payloads \
  --data-dir /var/lib/boarnet-sweetadb
```

First run creates `/var/lib/boarnet-sweetadb/{pepper.secret,
events-tail.offset}`. Subsequent runs resume from the saved offset,
so restarts don't re-ship history.

## Run (systemd)

A unit template lives at `systemd/boarnet-sweetadb.service`. Wire
it up:

```bash
sudo cp systemd/boarnet-sweetadb.service /etc/systemd/system/
sudo mkdir -p /etc/boarnet
sudo install -m 0600 /dev/null /etc/boarnet/sweetadb.env
sudoedit /etc/boarnet/sweetadb.env     # paste BOARNET_TOKEN + BOARNET_SENSOR_ID
sudo systemctl daemon-reload
sudo systemctl enable --now boarnet-sweetadb
journalctl -u boarnet-sweetadb -f
```

Minimal `/etc/boarnet/sweetadb.env`:
```env
BOARNET_TOKEN=bn_your_token_here
BOARNET_SENSOR_ID=mesh-fra1-adb-01
```

The shipped unit defaults to reading from `/var/log/sweetadb/mimic/`.
If sweetADB is writing somewhere else, see below.

### Non-default log locations

The unit defaults assume sweetADB writes to
`/var/log/sweetadb/mimic/events.jsonl`. Two common deviations:

**(a) sweetADB writes to a system-level path you control** —
e.g. you ran sweetADB with `--log-dir /srv/sweetadb`. Set the
path in `/etc/boarnet/sweetadb.env`:
```env
SWEETADB_EVENTS_LOG=/srv/sweetadb/mimic/events.jsonl
SWEETADB_PAYLOADS_DIR=/srv/sweetadb/mimic/payloads
```
Then add a drop-in so the hardening lets the adapter read it:
```bash
sudo systemctl edit boarnet-sweetadb
```
Paste:
```ini
[Service]
ReadOnlyPaths=
ReadOnlyPaths=/srv/sweetadb
```
(The empty `ReadOnlyPaths=` clears the base unit's `/var/log/sweetadb`
entry; the second line adds the new path. Without the reset, both
paths would be listed — harmless but noisy.)

**(b) sweetADB writes inside `/root/`** — e.g. you run sweetADB
as root from `/root/` and it creates `/root/mimic/events.jsonl`
next to itself. Set the paths in `sweetadb.env`:
```env
SWEETADB_EVENTS_LOG=/root/mimic/events.jsonl
SWEETADB_PAYLOADS_DIR=/root/mimic/payloads
```
Then drop in the hardening override:
```bash
sudo systemctl edit boarnet-sweetadb
```
Paste:
```ini
[Service]
ProtectHome=read-only
BindReadOnlyPaths=/root/mimic
```
`ProtectHome=read-only` relaxes the base unit's `ProtectHome=true`
(which hides `/root/` entirely) to read-only visibility.
`BindReadOnlyPaths=` then makes `/root/mimic` specifically reachable
by the dynamic user. We don't widen to all of `/root/` — only the
one directory the adapter needs.

Reload and restart after any drop-in edit:
```bash
sudo systemctl daemon-reload
sudo systemctl restart boarnet-sweetadb
sudo journalctl -u boarnet-sweetadb -f
```
Within ~30s you should see `tailing events.jsonl path=... offset=...`
and then `batch sent count=N` once attacker traffic arrives.

## Flags / env

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--events-log` | `SWEETADB_EVENTS_LOG` | `./mimic/events.jsonl` | Path to sweetADB's JSONL |
| `--payloads-dir` | `SWEETADB_PAYLOADS_DIR` | `./mimic/payloads` | Binary payload drop directory |
| `--ingest-url` | `BOARNET_INGEST_URL` | `https://www.boarnet.io/api/ingest/v1/events` | BoarNet ingest endpoint |
| `--token` | `BOARNET_TOKEN` | *required* | `bn_…` token from /dashboard/sensors |
| `--sensor-id` | `BOARNET_SENSOR_ID` | *required* | Stable id, e.g. `mesh-fra1-adb-01` |
| `--fleet` | `BOARNET_FLEET` | `mesh` | `mesh` for partner-run; `core` reserved for BoarNet-operated |
| `--persona` | `BOARNET_PERSONA` | `sweetadb` | Dashboard grouping label |
| `--start-from` | `BOARNET_START_FROM` | `begin` | First-run behavior. `begin` ships the whole existing `events.jsonl` (backlog upload); `eof` starts at the tail and only ships events written from now forward. Subsequent runs always resume from the saved offset regardless. |
| `--data-dir` | `BOARNET_DATA_DIR` | `/var/lib/boarnet-sweetadb` | Writable dir for pepper + tail offset |
| `--pepper-key-id` | `BOARNET_PEPPER_KEY_ID` | `pepper-sweetadb-v1` | Stamp on envelope.encryption_hints.pepper_key_id |
| `--verbose` |  | off | Log every envelope at DEBUG |

Under the shipped systemd unit, `SWEETADB_EVENTS_LOG` and
`SWEETADB_PAYLOADS_DIR` default to `/var/log/sweetadb/mimic/...`
(set via `Environment=` in the unit). Values in
`/etc/boarnet/sweetadb.env` override those defaults — the unit
file itself does not need to be edited to change paths. See
**Non-default log locations** above for the two common override
recipes.

## Event mapping

sweetADB events translate to BoarNet envelope `event_type` as:

| sweetADB `event` | BoarNet `event_type` | Tags |
|---|---|---|
| `cnxn` | `adb.cnxn` | `adb`, `stack:sweetadb`, `probe-family:adb`, `adb-handshake` |
| `auth` | `adb.auth` | `…`, `adb-auth` |
| `shell_command` | `adb.cmd.exec` | `…`, `adb-shell` |
| `stream_open` / `stream_data` / `stream_close` | `adb.stream` | `…`, `adb-stream:open`/`data`/`close` |
| `sync_data` | `adb.stream` | `…`, `adb-sync` (payload file also shipped as `payload.dropped`) |
| `unknown_cmd` | `adb.stream` | `…`, `adb-unknown-cmd` |
| (forward-compat) | `adb.stream` | `…`, `adb-event:<name>` |

## What the adapter does NOT do

- **Does not modify sweetADB.** We only read its output files.
- **Does not ship session transcripts** (`mimic/sessions/*.txt`) —
  events.jsonl is the source of record; session files are lossy
  reformats of the same data.
- **Does not delete files after shipping.** Use `logrotate` if the
  `mimic/` directory is growing unbounded.
- **Does not make outbound connections to anything but
  `--ingest-url`.** Audit `main.go` if you want to verify.

## Troubleshooting

**"register 401: token_invalid"** — paste the token again; they're
shown once on mint and revocable from /dashboard/sensors.

**"register 401: missing_bearer"** — `--token` flag / env missing.

**`status=217/USER` in `journalctl -u boarnet-sweetadb`** — you're
running an older unit file that has `User=boarnet` baked in,
which requires a pre-created system user. Current unit files use
`DynamicUser=true` and don't need this step. Pull the latest
unit file:
```bash
sudo curl -fsSL -o /etc/systemd/system/boarnet-sweetadb.service \
  https://raw.githubusercontent.com/Bino97/boarnet-adapters/main/sweetadb/systemd/boarnet-sweetadb.service
sudo systemctl daemon-reload
sudo systemctl restart boarnet-sweetadb
```
If you're intentionally staying on the old `User=boarnet` variant,
create the user once with `sudo useradd --system --shell /usr/sbin/nologin
--home /var/lib/boarnet-sweetadb boarnet` and chown the data dir.

**`fleet_privilege_exceeded`** — you set `--fleet core` but your
ingest token was minted as `mesh`. Drop the flag (defaults to
`mesh`, which is correct for partner-run adapters) or mint a new
core token from a BoarNet account that's authorized to issue
them.

**"batch failed — ingest 400: invalid_event_type"** — means
BoarNet's ingest validator doesn't yet have `adb.*` types (your
adapter is newer than the server). Nothing to do locally — server
deploy pending.

**No events ever ship** — tail stays at offset 0. Check sweetADB
is actually writing to the configured `--events-log`. The adapter
logs `tailing events.jsonl path=... offset=...` at startup;
`offset > 0` after a few attacks means events are being consumed.

**`journalctl -u boarnet-sweetadb` shows the adapter starting
cleanly but `grep -E 'batch sent|batch failed'` returns nothing**
— the adapter is running but its file tail never opens. Almost
always a path mismatch between the unit and where sweetADB is
actually writing. Check what sweetADB wrote:
```bash
sudo find / -name events.jsonl 2>/dev/null
```
If the path isn't `/var/log/sweetadb/mimic/events.jsonl`, set
`SWEETADB_EVENTS_LOG`/`SWEETADB_PAYLOADS_DIR` in
`/etc/boarnet/sweetadb.env` and — if the new path lives outside
`/var/log/sweetadb` — add the drop-in from
**Non-default log locations** above. `ProtectHome=true` in the
base unit hides `/root/` and `/home/` entirely, so an adapter
pointed at `/root/mimic/events.jsonl` with no drop-in will fail
to open the file silently (the tail worker retries forever
without logging an error for each attempt).

## License

MIT. Same as sweetADB so downstream redistribution is friction-free.
