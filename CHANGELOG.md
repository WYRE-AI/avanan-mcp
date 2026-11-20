# 1.0.0 (2026-04-07)


### Bug Fixes

* align package name to avanan-mcp convention ([a997b3b](https://github.com/wyre-technology/avanan-mcp/commit/a997b3bcf939d8f13959ba59b9f5da05668164d9))


### Features

* initial scaffold with lazy loading meta-tools support ([eda4480](https://github.com/wyre-technology/avanan-mcp/commit/eda4480f0d962093a35a658915d0c885da6051eb))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The HTTP transport no longer exits on a malformed request (WYREAI-741).** The request
  target was parsed against the client-supplied `Host` header, and a value that does not parse
  (or a target such as `//`) threw inside the request listener before authentication. The
  target is now parsed against a fixed base, so `Host` is no longer consulted, and a target
  that still cannot be parsed gets a `400` JSON response while the server keeps running.

### Security

- **Fixed a cross-tenant credential leak in gateway (multi-tenant) mode.** `src/utils/client.ts` cached the derived OAuth bearer token, scopes, and resolved base URL (fetched from Checkpoint's `/auth/external` and `/v1.0/scopes` endpoints) in module-level variables shared by the whole process. Raw per-request credentials were already correctly isolated per tenant via `AsyncLocalStorage`, but this *derived* layer was not: under concurrent multi-tenant load, one tenant's in-flight token refresh could be overwritten by another tenant's concurrent refresh before the first tenant's request read it back, causing that request to authenticate with — and receive data scoped to — a different tenant's credentials. Confirmed exploitable in production (this sidecar is live in `conduit-prod`).
  - Fix: the derived token/scopes/baseUrl cache now lives inside the same `AsyncLocalStorage` request context as the raw credentials (`src/utils/credential-store.ts`), via a new `runWithRequestCredentials()` helper used by the gateway HTTP handler. Each gateway request gets its own isolated cache; the stdio/env (single-tenant) code path keeps a lazily-initialized module-level fallback, since there's no concurrent multi-tenant traffic to race in that mode. No module-level mutable state holding tenant-derived secrets remains in the gateway request path.
  - Added a regression test (`src/utils/client.test.ts`) that deterministically forces two tenants' requests to interleave (via a manually-resolved deferred, not a timer) so tenant B's request runs to completion while tenant A's is still in flight, then asserts the actual token/base URL values each tenant's outbound API call used. The test fails against the pre-fix implementation and passes against the fix.

### Added

- **Interactive security event card via MCP Apps (SEP-1865).** `hec_get_event` results now render as an interactive card in MCP Apps hosts (Claude Desktop/web, and other hosts advertising the `io.modelcontextprotocol/ui` extension), instead of a wall of JSON. The card shows the event type, severity, state, confidence, SaaS platform, detection time, description, actions already taken, and available remediation. The card is **read-only** — remediation runs through the existing chat tools, never from the card. Non-App hosts are unaffected: the tool's payload is unchanged apart from a new `_card` field.
  - The card is **brand-neutral by default** (system fonts, neutral palette, no baked-in identity — this is a published server) and brandable without rebuilding: `MCP_BRAND_NAME`, `MCP_BRAND_LOGO_URL`, `MCP_BRAND_PRIMARY_COLOR`, `MCP_BRAND_ACCENT_COLOR`, `MCP_BRAND_BG`, and `MCP_BRAND_TEXT` env vars are injected as `window.__BRAND__` at serve time (a gateway can inject the same object per-org). A test pins the default bundle to zero brand identity and zero external fetches.
  - The renderable tool advertises the UI via `_meta` (`ui/resourceUri`, plus the nested `ui.resourceUri` form) pointing at a new `ui://avanan/security-event-card.html` resource served as `text/html;profile=mcp-app` from the newly added resources capability. The card HTML is a self-contained vite single-file bundle embedded at build time (`src/generated/event-card-html.ts`, committed), so plain `npm run build` and CI never need vite.

## [1.1.0] - 2026-03-10

### Added
- Lazy loading meta-tools mode as an alternative to decision-tree navigation
  - Enabled via `LAZY_LOADING=true` environment variable
  - `avanan_list_categories`: List all tool categories with descriptions and tool counts
  - `avanan_list_category_tools`: List full tool schemas for a given category
  - `avanan_execute_tool`: Execute any domain tool by name without navigating first
  - `avanan_router`: Natural-language intent routing that suggests the best tool(s)
- New `src/utils/categories.ts` module defining TOOL_CATEGORIES constant and helper functions

## [1.0.0] - 2026-03-10

### Added
- Initial release of Checkpoint Harmony Email & Collaboration (Avanan) MCP Server
- Decision-tree navigation architecture with nine domains:
  - `quarantine`: List, get details, release, and delete quarantined emails
  - `threats`: List threats, get threat details, IOCs, and threat timelines
  - `events`: List security events, get event details, and list active alerts
  - `policies`: List, get details, and enable/disable security policies (DLP, anti-phishing, anti-malware)
  - `users`: List users, get user details, and view user threat history
  - `reports`: Threat summary, email flow statistics, and protection effectiveness reports
  - `incidents`: List, get details, update status, and add notes to security incidents
  - `banners`: List, get details, and update Smart Banner configurations
  - `saas`: List SaaS applications, get protection status, and view security summaries
- OAuth2 client credentials authentication with automatic token refresh
- Dual transport support: stdio (Claude Desktop) and HTTP streaming (hosted deployment)
- Gateway auth mode: credentials injected via `X-Checkpoint-Client-Id` and `X-Checkpoint-Client-Secret` headers
- Health check endpoint at `/health`
- Docker image with non-root user and health check
- Structured stderr-only logging with configurable log level
- Elicitation support for interactive filtering and destructive action confirmation
- Comprehensive test suite with vitest
- MCPB manifest for Claude Desktop installation
