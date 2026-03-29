# noscope

noscope is a short-lived credential manager for agent subprocesses. Credentials are minted on start, refreshed on a timer, and revoked on exit, never touching disk, logs, or process arguments.

Agents and automated processes need credentials to interact with cloud providers, APIs, and infrastructure. Long-lived credentials are a liability: they get logged, leaked in stack traces, persisted in shell history, and forgotten in environment variables. When an agent process crashes, credentials often outlive the process that needed them.

noscope sits between the agent and the credential provider. The design calls for three safety layers: process-group termination, revoke-on-exit, and TTL expiry as a backstop. Today, only the TTL expiry layer is implemented (as a property of `ScopedToken`). The other two depend on the process lifecycle module, which hasn't been built yet.
