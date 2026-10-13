# Avanan (Check Point) MCP Server

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

A Model Context Protocol (MCP) server for Check Point Avanan (Harmony Email & Collaboration). Enables AI assistants to manage security events, investigate threats, and handle multi-tenant MSP operations across your email security environment.

This is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that connects Claude (or any MCP-compatible AI) to your Check Point Avanan environment.

> **Part of the [MSP Claude Plugins](https://github.com/WYRE-AI) ecosystem** — a growing suite of AI integrations for the MSP stack. Built by MSPs, for MSPs.

## Features

- **Interactive Security Event Card (MCP Apps)**: `hec_get_event` renders as a read-only interactive card in MCP Apps hosts (Claude Desktop/web) showing severity, state, platform, and remediation status; neutral by default, brandable via `window.__BRAND__` injection or `MCP_BRAND_*` env vars; plain-JSON behavior is unchanged in other hosts

## Installation

```bash
npm install @wyre-ai/avanan-mcp
```

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. Leave `CONDUIT_S2S_SECRET` empty in that file.

| Variable | Required | Description |
|----------|----------|-------------|
| `CHECKPOINT_CLIENT_ID` | For stdio and `AUTH_MODE=env` | Checkpoint/Avanan OAuth2 client ID |
| `CHECKPOINT_CLIENT_SECRET` | For stdio and `AUTH_MODE=env` | Checkpoint/Avanan OAuth2 client secret |
| `CHECKPOINT_REGION` | No | API region (`us`, `eu`, `au`, `in`). Auto-detected from the JWT when omitted. |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `AUTH_MODE` | No | `gateway` (Docker image and Compose default) or `env`. Gateway mode requires `X-Checkpoint-Client-Id` and `X-Checkpoint-Client-Secret` on each `/mcp` request and never falls back to `CHECKPOINT_*`. `env` uses those variables only after S2S auth succeeds. |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service HMAC secret. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `replace-with-a-real-secret`, `your-s2s-secret`, and the other public example values). `MCP_ALLOW_INSECURE_DEV=1` does not accept a placeholder. Compose will not start without it. Never commit a real value. The value is never logged. Generate one with `openssl rand -hex 32`. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` (including `0.0.0.0`) is overridden and the override is logged. |
| `MCP_HTTP_HOST` | No | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1`. A configured secret honors this value. The container image sets `0.0.0.0`. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |

`/health` stays unauthenticated. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### HTTP authentication

With `MCP_TRANSPORT=http` and a real `CONDUIT_S2S_SECRET`, every `/mcp` request must include `X-Gateway-S2S`. The header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header returns HTTP 401 before vendor credentials are read.

```bash
TS=$(date +%s)
SIG=$(printf 't=%s' "$TS" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "X-Gateway-S2S: t=${TS},v1=${SIG}" \
  -H 'X-Checkpoint-Client-Id: your-client-id' \
  -H 'X-Checkpoint-Client-Secret: your-client-secret' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway` (the image and Compose default), `/mcp` also requires `X-Checkpoint-Client-Id` and `X-Checkpoint-Client-Secret`. Those headers are the only credential source for that request. A request missing either one returns 401 and does not fall back to `CHECKPOINT_CLIENT_ID` / `CHECKPOINT_CLIENT_SECRET` in the process environment.

Single-tenant HTTP (`AUTH_MODE=env`) still requires a valid `X-Gateway-S2S` header, then uses `CHECKPOINT_CLIENT_ID` and `CHECKPOINT_CLIENT_SECRET` when the request does not carry those headers.

## Usage

### Running with Claude Desktop

Add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "avanan-mcp": {
      "command": "npx",
      "args": ["@wyre-ai/avanan-mcp"],
      "env": {
        "CHECKPOINT_CLIENT_ID": "your-checkpoint-client-id"
        "CHECKPOINT_CLIENT_SECRET": "your-checkpoint-client-secret"
      }
    }
  }
}
```

### Running with Claude Code (CLI)

```bash
claude mcp add avanan-mcp \
  -e CHECKPOINT_CLIENT_ID=your-value \
  -e CHECKPOINT_CLIENT_SECRET=your-value \
  -- npx -y @wyre-ai/avanan-mcp
```

### Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass a real S2S secret. In gateway mode, Checkpoint credentials arrive on each request as headers; they are not read from the environment.

```bash
docker build -t avanan-mcp .
docker run \
  -e CONDUIT_S2S_SECRET=your-s2s-secret \
  -p 127.0.0.1:8080:8080 \
  avanan-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, sets `AUTH_MODE=gateway`, does not inject `CHECKPOINT_CLIENT_ID` or `CHECKPOINT_CLIENT_SECRET`, and publishes `127.0.0.1:8080:8080`:

```bash
CONDUIT_S2S_SECRET=your-s2s-secret docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `CHECKPOINT_CLIENT_ID` and `CHECKPOINT_CLIENT_SECRET`. Keep that off the gateway Compose service:

```bash
docker run \
  -e CONDUIT_S2S_SECRET=your-s2s-secret \
  -e AUTH_MODE=env \
  -e CHECKPOINT_CLIENT_ID=your-value \
  -e CHECKPOINT_CLIENT_SECRET=your-value \
  -e CHECKPOINT_REGION=us \
  -p 127.0.0.1:8080:8080 \
  avanan-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` even when `MCP_HTTP_HOST` is `0.0.0.0` or `localhost`, and logs a warning. A known placeholder secret still refuses to start:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm start
```

## Available Domains

### Events
Security event retrieval and investigation

### Actions
Take action on threats (quarantine, release, etc.)

### Exceptions
Manage email exceptions and allowlists

### Search
Search across email security data


## Development

```bash
# Clone the repository
git clone https://github.com/WYRE-AI/avanan-mcp.git
cd avanan-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) if present, or open an issue to discuss changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
