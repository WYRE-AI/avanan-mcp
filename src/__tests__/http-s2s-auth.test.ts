/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a real CONDUIT_S2S_SECRET. Known placeholders are rejected
 * even when MCP_ALLOW_INSECURE_DEV=1. That flag starts without a secret, logs
 * a warning, and binds 127.0.0.1 only. Gateway mode rejects /mcp requests
 * that omit vendor credential headers and must not fall back to CHECKPOINT_*.
 */

import { createHmac } from "node:crypto";
import { request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { startHttpTransport } from "../index.js";

const S2S_SECRET = "s2s-do-not-log-7f3a";
const ENV_CLIENT_ID = "env-client-id-must-not-be-used";
const ENV_CLIENT_SECRET = "env-secret-must-not-be-used";
const HEADER_CLIENT_ID = "header-client-id";
const HEADER_CLIENT_SECRET = "header-client-secret";

const ENV_KEYS = [
  "CONDUIT_S2S_SECRET",
  "MCP_ALLOW_INSECURE_DEV",
  "MCP_HTTP_PORT",
  "MCP_HTTP_HOST",
  "AUTH_MODE",
  "CHECKPOINT_CLIENT_ID",
  "CHECKPOINT_CLIENT_SECRET",
  "CHECKPOINT_REGION",
  "LOG_LEVEL",
  "MCP_TRANSPORT",
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];
const originalFetch = global.fetch;

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${hex}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "));
  });
  return {
    text: () => lines.join("\n"),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy(): ReturnType<typeof vi.spyOn> {
  return vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function listen(): Promise<{ port: number; address: string; server: Server }> {
  const server = await startHttpTransport();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === "string") {
    throw new Error("HTTP server did not bind a TCP port");
  }
  return { port: bound.port, address: bound.address, server };
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...extra,
  };
}

const toolsList = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/list",
});

const queryEvents = JSON.stringify({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/call",
  params: { name: "hec_query_events", arguments: {} },
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function assertNoSecrets(text: string, extra: string[] = []): void {
  expect(text).not.toContain(S2S_SECRET);
  expect(text).not.toContain(ENV_CLIENT_ID);
  expect(text).not.toContain(ENV_CLIENT_SECRET);
  expect(text).not.toContain(HEADER_CLIENT_SECRET);
  for (const value of extra) {
    expect(text).not.toContain(value);
  }
}

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = "0";
  process.env.MCP_HTTP_HOST = "127.0.0.1";
  process.env.LOG_LEVEL = "info";
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.CHECKPOINT_CLIENT_ID;
  delete process.env.CHECKPOINT_CLIENT_SECRET;
  delete process.env.CHECKPOINT_REGION;
});

afterEach(async () => {
  global.fetch = originalFetch;
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server) continue;
    await new Promise<void>((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
});

describe("HTTP startup", () => {
  it("refuses to start when CONDUIT_S2S_SECRET is empty", async () => {
    const logs = captureStderr();
    const exit = exitSpy();
    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("Refusing to start HTTP transport");
      expect(text).toContain("CONDUIT_S2S_SECRET is empty");
      expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
      assertNoSecrets(text);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("still refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1", async () => {
    process.env.CONDUIT_S2S_SECRET = "";
    process.env.MCP_ALLOW_INSECURE_DEV = "true";
    const logs = captureStderr();
    const exit = exitSpy();
    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      expect(logs.text()).toContain("Refusing to start HTTP transport");
      expect(logs.text()).toContain("CONDUIT_S2S_SECRET is empty");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each([
    "replace-with-a-real-secret",
    "changeme",
    "CHANGE-ME",
    "placeholder",
    "secret",
    "example",
    "replace-me",
    "s2s-secret",
    "your-secret",
    "your-s2s-secret",
  ])("refuses known placeholder %s and does not log it", async (placeholder) => {
    process.env.CONDUIT_S2S_SECRET = placeholder;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    const logs = captureStderr();
    const exit = exitSpy();
    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("known placeholder");
      expect(text).toContain("openssl rand -hex 32");
      const staticError =
        "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
        "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.";
      const redacted = text.split(staticError).join("");
      expect(redacted.toLowerCase()).not.toContain(placeholder.toLowerCase());
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1", async () => {
    process.env.CONDUIT_S2S_SECRET = "  Your-S2S-Secret  ";
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    const exit = exitSpy();
    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("known placeholder");
      expect(text).not.toContain("Your-S2S-Secret");
      expect(text).not.toContain("SECURITY WARNING");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("allows startup with a warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    delete process.env.MCP_HTTP_HOST;
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("127.0.0.1");
      const text = logs.text();
      expect(text).toContain("SECURITY WARNING");
      expect(text).toContain("CONDUIT_S2S_SECRET");
      expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
      expect(text).toContain("127.0.0.1");
      expect(text).not.toContain("not a loopback address");
      assertNoSecrets(text);
    } finally {
      logs.restore();
    }
  });

  it.each(["0.0.0.0", "10.1.2.3"])(
    "forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is %s",
    async (host) => {
      process.env.MCP_ALLOW_INSECURE_DEV = "1";
      process.env.MCP_HTTP_HOST = host;
      const logs = captureStderr();
      try {
        const server = await listen();
        expect(server.address).toBe("127.0.0.1");
        const text = logs.text();
        expect(text).toContain(`MCP_HTTP_HOST=${host} is not a loopback address`);
        expect(text).toContain("Binding 127.0.0.1 only");
        expect(text).toContain("SECURITY WARNING");
        assertNoSecrets(text);
      } finally {
        logs.restore();
      }
    },
  );

  it("forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is localhost", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "localhost";
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("127.0.0.1");
      expect(logs.text()).toContain("SECURITY WARNING");
      expect(logs.text()).not.toContain("not a loopback address");
    } finally {
      logs.restore();
    }
  });

  it("honors a non-loopback MCP_HTTP_HOST when CONDUIT_S2S_SECRET is set", async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe("0.0.0.0");
      expect(logs.text()).not.toContain("not a loopback address");
      assertNoSecrets(logs.text());
    } finally {
      logs.restore();
    }
  });

  it("binds 127.0.0.1 when MCP_HTTP_HOST is unset and a secret is set", async () => {
    delete process.env.MCP_HTTP_HOST;
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    const server = await listen();
    expect(server.address).toBe("127.0.0.1");
  });
});

describe("HTTP /mcp authentication", () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.AUTH_MODE = "gateway";
    process.env.CHECKPOINT_CLIENT_ID = ENV_CLIENT_ID;
    process.env.CHECKPOINT_CLIENT_SECRET = ENV_CLIENT_SECRET;
    process.env.CHECKPOINT_REGION = "eu";
  });

  it("returns 401 when the S2S header is missing or invalid and does not read credentials", async () => {
    const logs = captureStderr();
    const fetchMock = vi.fn(() => {
      throw new Error("fetch must not run when S2S auth fails");
    });
    global.fetch = fetchMock as typeof fetch;
    try {
      const server = await listen();
      const missing = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-checkpoint-client-id": HEADER_CLIENT_ID,
          "x-checkpoint-client-secret": HEADER_CLIENT_SECRET,
        }),
        body: toolsList,
      });
      const invalid = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader("wrong-secret"),
          "x-checkpoint-client-id": HEADER_CLIENT_ID,
          "x-checkpoint-client-secret": HEADER_CLIENT_SECRET,
        }),
        body: toolsList,
      });

      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain("X-Gateway-S2S");
      expect(invalid.body).toContain("X-Gateway-S2S");
      assertNoSecrets(missing.body);
      assertNoSecrets(invalid.body);
      assertNoSecrets(logs.text());
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      logs.restore();
    }
  });

  it("returns 401 in gateway mode without credential headers and does not use env credentials", async () => {
    const fetchMock = vi.fn(() => {
      throw new Error("fetch must not run when gateway credentials are missing");
    });
    global.fetch = fetchMock as typeof fetch;
    const server = await listen();

    const response = await sendHttp({
      port: server.port,
      method: "POST",
      path: "/mcp",
      headers: mcpHeaders({ "x-gateway-s2s": mintS2sHeader(S2S_SECRET) }),
      body: toolsList,
    });

    expect(response.status).toBe(401);
    expect(response.body).toContain("Missing credentials");
    expect(response.body).toContain("X-Checkpoint-Client-Id");
    expect(response.body).toContain("X-Checkpoint-Client-Secret");
    assertNoSecrets(response.body);
    expect(response.body).not.toContain("eu");
    expect(fetchMock).not.toHaveBeenCalled();

    const partial = await sendHttp({
      port: server.port,
      method: "POST",
      path: "/mcp",
      headers: mcpHeaders({
        "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
        "x-checkpoint-client-id": HEADER_CLIENT_ID,
      }),
      body: toolsList,
    });
    expect(partial.status).toBe(401);
    expect(partial.body).toContain("Missing credentials");
    assertNoSecrets(partial.body);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts a valid S2S header plus credential headers and uses those credentials", async () => {
    const logs = captureStderr();
    const authBodies: string[] = [];
    global.fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes("/auth/external")) {
        authBodies.push(typeof init?.body === "string" ? init.body : "");
        return jsonResponse(200, {
          success: true,
          data: { token: "mock-checkpoint-token", expiresIn: 1800 },
        });
      }
      if (url.includes("/v1.0/scopes")) {
        return jsonResponse(200, {
          responseEnvelope: { requestId: "scopes-req", responseCode: 200, responseText: "OK" },
          responseData: ["mt-prod-cp-1:acme-test"],
        });
      }
      return jsonResponse(200, {
        responseEnvelope: { requestId: "data-req", responseCode: 200, responseText: "OK" },
        responseData: [],
      });
    }) as typeof fetch;

    try {
      const server = await listen();
      const response = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
          "x-checkpoint-client-id": HEADER_CLIENT_ID,
          "x-checkpoint-client-secret": HEADER_CLIENT_SECRET,
        }),
        body: queryEvents,
      });

      expect(response.status).toBe(200);
      const payload = JSON.parse(response.body) as { result?: { isError?: boolean } };
      expect(payload.result?.isError).toBeFalsy();
      expect(authBodies).toHaveLength(1);
      const auth = JSON.parse(authBodies[0]) as { clientId?: string; accessKey?: string };
      expect(auth.clientId).toBe(HEADER_CLIENT_ID);
      expect(auth.accessKey).toBe(HEADER_CLIENT_SECRET);
      assertNoSecrets(response.body);
      assertNoSecrets(logs.text());
      expect(authBodies[0]).not.toContain(ENV_CLIENT_ID);
      expect(authBodies[0]).not.toContain(ENV_CLIENT_SECRET);
    } finally {
      logs.restore();
    }
  });

  it("serves /health without authentication and without echoing credentials", async () => {
    const fetchMock = vi.fn(() => {
      throw new Error("fetch must not run for /health");
    });
    global.fetch = fetchMock as typeof fetch;
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: "GET",
      path: "/health",
    });
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body) as { status?: string; authMode?: string };
    expect(body.status).toBe("ok");
    expect(body.authMode).toBe("gateway");
    assertNoSecrets(response.body);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
