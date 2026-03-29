# Projects + Per-Project Broker URL

Statesman uses the control plane as the source of truth for project metadata.

## List / Inspect Projects

```bash
statesman projects list
statesman projects get <uuid|slug>
```

## Configure Broker URL Per Project

Set:

```bash
statesman projects set-broker-url <uuid|slug> https://broker.example.com
```

Clear:

```bash
statesman projects clear-broker-url <uuid|slug>
```

Notes:

- This is intended to replace relying on a single global `STATESMAN_BROKER_URL`.
- You can still temporarily override via CLI global `--broker-url ...` or env `STATESMAN_BROKER_URL=...`.

## How This Interacts With `statesman init`

- `statesman init` can connect a repo to a project via `--project <uuid|slug>`.
- When a project has `broker_url` set, `statesman init` prefers it.
- `statesman init` writes `statesman.toml` so future commands can infer `[project].id`.
