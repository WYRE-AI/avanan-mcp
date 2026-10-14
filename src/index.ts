#!/usr/bin/env node
/**
 * Checkpoint Harmony Email & Collaboration MCP Server
 *
 * Implements the HEC Smart API v1.50.
 *
 * Transports:
 *   - stdio (default): For local Claude Desktop / CLI usage
 *   - http: For hosted deployment via MCP gateway
 *
 * Auth modes:
 *   - env (default): Credentials from CHECKPOINT_CLIENT_ID and CHECKPOINT_CLIENT_SECRET
 *   - gateway: Credentials injected from X-Checkpoint-Client-Id / X-Checkpoint-Client-Secret headers.
 *     Gateway mode never falls back to CHECKPOINT_* env credentials.
 *
 * HTTP transport refuses to start unless CONDUIT_S2S_SECRET is a real secret.
 * Known placeholders are rejected even when MCP_ALLOW_INSECURE_DEV=1.
 * That flag is a local-only escape hatch for an empty secret: it logs a
 * warning, skips X-Gateway-S2S, and binds 127.0.0.1 only. A configured
 * secret keeps honoring MCP_HTTP_HOST (default 127.0.0.1 when unset).
 * /health stays unauthenticated. stdio does not use S2S auth.
 *
 * Regional base URL is auto-detected from the JWT region claim (eu/us/au/in).
 * Override with CHECKPOINT_REGION env var.
 */

import { createServer as createHttpServer, IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { logger } from "./utils/logger.js";
import { runWithRequestCredentials } from "./utils/credential-store.js";
import { registerResourceHandlers } from "./resources.js";
import { eventTools, handleEventTool } from "./tools/events.js";
import { searchTools, handleSearchTool } from "./tools/search.js";
import { actionTools, handleActionTool } from "./tools/actions.js";
import { exceptionTools, handleExceptionTool } from "./tools/exceptions.js";
import type { CallToolResult } from "./utils/types.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";

// Conduit service-to-service auth (gateway#377 parity). HTTP startup fails
// closed. An empty CONDUIT_S2S_SECRET refuses to boot unless
// MCP_ALLOW_INSECURE_DEV=1, and that bypass binds 127.0.0.1 only. A known
// placeholder secret always refuses to start. When a real secret is set,
// every /mcp request must carry a valid X-Gateway-S2S header. The secret
// value is never logged. See src/s2s-verify.ts.

/** Public example values. A copied placeholder must not verify as a real secret. */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
]);

const MISSING_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
  "Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), " +
  "or set MCP_ALLOW_INSECURE_DEV=1 for local development only.";

const PLACEHOLDER_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
  "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.";

const INSECURE_DEV_WARNING =
  "SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. " +
  "HTTP /mcp is not enforcing X-Gateway-S2S and listens on 127.0.0.1 only. " +
  "Do not use this outside local development.";

const LOOPBACK_HOST = "127.0.0.1";

function headerValue(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

/**
 * Secret for X-Gateway-S2S on /mcp. Read at HTTP startup, not module load.
 * Empty is fail-closed unless MCP_ALLOW_INSECURE_DEV=1. A known placeholder
 * always exits, so a copied example cannot forge a signature or widen the bind.
 * The secret value is never written to logs.
 */
function resolveHttpS2sSecret(): string {
  const raw = (process.env.CONDUIT_S2S_SECRET ?? "").trim();
  if (KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase())) {
    logger.error(PLACEHOLDER_S2S_SECRET_ERROR);
    process.exit(1);
  }
  if (raw) return raw;

  if (process.env.MCP_ALLOW_INSECURE_DEV === "1") {
    logger.error(INSECURE_DEV_WARNING);
    return "";
  }

  logger.error(MISSING_S2S_SECRET_ERROR);
  process.exit(1);
}

/**
 * No secret (insecure-dev bypass only) always binds loopback. A configured
 * secret honors MCP_HTTP_HOST, defaulting to 127.0.0.1 when that var is unset.
 */
function resolveListenHost(s2sSecret: string): string {
  const configured = (process.env.MCP_HTTP_HOST ?? "").trim();
  if (s2sSecret) return configured || LOOPBACK_HOST;

  if (configured && !isLoopbackHost(configured)) {
    logger.error(
      `WARNING: MCP_HTTP_HOST=${configured} is not a loopback address. ` +
        "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. " +
        `Binding ${LOOPBACK_HOST} only.`,
    );
  }
  return LOOPBACK_HOST;
}

const ALL_TOOLS = [...eventTools, ...searchTools, ...actionTools, ...exceptionTools];

// Pre-built map for O(1) tool dispatch instead of repeated Array.some() per request
type ToolHandler = (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
const TOOL_HANDLERS = new Map<string, ToolHandler>([
  ...eventTools.map((t) => [t.name, handleEventTool] as [string, ToolHandler]),
  ...searchTools.map((t) => [t.name, handleSearchTool] as [string, ToolHandler]),
  ...actionTools.map((t) => [t.name, handleActionTool] as [string, ToolHandler]),
  ...exceptionTools.map((t) => [t.name, handleExceptionTool] as [string, ToolHandler]),
]);

/**
 * Create a fresh MCP server instance with all handlers registered.
 * Called once for stdio, or per-request for HTTP transport.
 */
function createMcpServer(): Server {
  const server = new Server(
    { name: "mcp-server-checkpoint-harmony-email", version: "2.0.0" },
    { capabilities: { tools: {}, resources: {} } }
  );

  // MCP Apps (SEP-1865): serves the ui:// security event card.
  registerResourceHandlers(server);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: ALL_TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    logger.info("Tool call", { tool: name });

    try {
      const toolArgs = args as Record<string, unknown>;
      const handler = TOOL_HANDLERS.get(name);

      if (!handler) {
        return {
          content: [{ type: "text", text: `Unknown tool: '${name}'` }],
          isError: true,
        };
      }

      return await handler(name, toolArgs);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error("Tool call failed", { tool: name, error: message });
      return {
        content: [{ type: "text", text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Checkpoint Harmony Email MCP running on stdio");
}

export async function startHttpTransport(): Promise<HttpServer> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const s2sSecret = resolveHttpS2sSecret();
  const host = resolveListenHost(s2sSecret);
  const isGatewayMode = process.env.AUTH_MODE === "gateway";

  const httpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    if (url.pathname === "/health") {
      // Liveness probe: HTTP server is bound and accepting requests. Always
      // 200 as long as we got here. In gateway/multi-tenant mode the upstream
      // creds arrive per-request via headers, so the absence of process-env
      // creds is normal — gating liveness on them caused a crash-loop on
      // ACA (probe → 503 → kill → restart → repeat). The diagnostic value
      // of "are upstream env creds present?" is preserved as a separate
      // field that operators can inspect without it being load-bearing on
      // the probe.
      const hasEnvCreds = !!process.env.CHECKPOINT_CLIENT_ID && !!process.env.CHECKPOINT_CLIENT_SECRET;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          envCredentialsConfigured: hasEnvCreds,
          version: "2.0.0",
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname === "/mcp") {
      // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1;
      // startup refuses otherwise. A configured secret is always enforced,
      // before any credential extraction.
      if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
          })
        );
        return;
      }

      // Extract per-request credentials from headers (gateway mode).
      // Credentials are stored in AsyncLocalStorage so concurrent
      // requests are isolated — no process.env mutation.
      let gatewayCreds: { clientId: string; clientSecret: string } | null = null;

      if (isGatewayMode) {
        const clientId = headerValue(req.headers["x-checkpoint-client-id"]);
        const clientSecret = headerValue(req.headers["x-checkpoint-client-secret"]);

        if (!clientId || !clientSecret) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing credentials",
              required: ["X-Checkpoint-Client-Id", "X-Checkpoint-Client-Secret"],
            })
          );
          return;
        }

        gatewayCreds = { clientId, clientSecret };
      }

      const handleMcp = () => {
        // Create fresh server + transport per request (stateless)
        const server = createMcpServer();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });

        res.on("close", () => {
          transport.close();
          server.close();
        });

        server.connect(transport).then(() => {
          transport.handleRequest(req, res);
        });
      };

      if (gatewayCreds) {
        runWithRequestCredentials(gatewayCreds, handleMcp);
      } else {
        handleMcp();
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      logger.info(`Checkpoint Harmony Email MCP listening on http://${host}:${port}/mcp`);
      logger.info(`Auth mode: ${isGatewayMode ? "gateway" : "env"}`);
      resolve();
    });
  });

  return httpServer;
}

async function main() {
  const transport = process.env.MCP_TRANSPORT || "stdio";
  logger.info("Starting Checkpoint Harmony Email MCP", { transport });

  if (transport === "http") {
    const httpServer = await startHttpTransport();
    const shutdown = async () => {
      logger.info("Shutting down...");
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    await startStdioTransport();
  }
}

// Vitest imports this module to call startHttpTransport. Skip the CLI
// entrypoint there. `node dist/index.js` still starts stdio or HTTP.
if (process.env.VITEST !== "true") {
  main().catch((error) => {
    logger.error("Fatal startup error", {
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  });
}
