# SOYAL adapter

Standalone extraction of the SOYAL controller adapter for client verification.
The repository contains the adapter, protocol helpers, direct transport, test
simulator, CLI, and focused tests. It does not contain application integration,
deployment configuration, credentials, or site-specific runtime data.

## Adapter entrypoint

The adapter entrypoint is [`src/adapter.ts`](src/adapter.ts). It exposes
`SoyalAdapter`, the adapter result types, controller configuration, credential
operations, event pulling, discovery, commissioning, and clock operations.

`src/index.ts` re-exports the public modules for consumers that prefer a single
entrypoint. The adapter itself is still defined in `src/adapter.ts`.

When adding a new adapter, create `src/adapter.ts` and make sure that entrypoint
is correctly created and exported. Keep protocol and transport helpers in their
own modules, following the existing layout.

## Development

Requires [Bun](https://bun.sh/).

```sh
bun install
bun test
bun run typecheck
```

The local simulator can be started with:

```sh
bun run simulate -- --host 127.0.0.1 --port 5599
```

The CLI is available with:

```sh
bun run cli -- --help
```

Tests use the local simulator and loopback sockets. They do not require access
to a physical controller.

## Scope and licensing

This is a public verification snapshot. Public visibility does not by itself
grant permission to reuse the code; licensing or commercial-use terms should be
agreed separately with the repository owner.
