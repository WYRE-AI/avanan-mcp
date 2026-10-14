/**
 * Instrumented call-counter probe for the S2S guard ordering invariant
 * (boss's ordering-catch rule, 2026-07-28 S2S rollout evidence report).
 *
 * A generic 4-case grant/deny test proves the guard rejects/accepts, but not
 * ORDERING — a sibling whose credential-read has a side effect (here: the
 * lazy Checkpoint OAuth exchange inside ensureAuth(), see src/utils/client.ts)
 * could still have that side effect fire on a rejected request if the guard
 * were ever moved after it. This test spins up the real HTTP handler
 * (src/index.ts) and asserts Checkpoint's `/auth/external` (refreshToken)
 * and `/v1.0/scopes` (refreshScopes) endpoints are hit exactly ZERO times
 * when the S2S guard rejects a request.
 *
 * SCOPE NOTE (approach (a), the strongest option offered): unlike blumira's
 * OAuth exchange (eager, called directly in the HTTP handler before
 * dispatch), avanan's OAuth call is *lazy* — ensureAuth() (client.ts:178)
 * only fires from inside apiRequest() (client.ts:216), which only runs when
 * an actual MCP tool handler executes. Neither ensureAuth() nor
 * refreshToken()/refreshScopes() are exported from client.ts, so they can't
 * be vi.mock()'d directly by name. Instead this test drives a REAL
 * `tools/call` for the lightest available tool (`hec_query_events`, which
 * takes no required arguments) through the actual HTTP server with valid
 * S2S + Checkpoint gateway-credential headers, and observes the sole
 * externally-visible side effect of refreshToken()/refreshScopes() firing:
 * outbound fetch() calls to Checkpoint's real `/auth/external` and
 * `/v1.0/scopes` paths (same substring-matching technique already used by
 * src/utils/client.test.ts's cross-tenant regression test). global.fetch is
 * mocked with a passthrough for calls to this test's own local HTTP server
 * (so the test's own request to /mcp is unaffected) and stubbed responses
 * for the two Checkpoint endpoints plus the underlying HEC data call — this
 * is a full, real MCP tools/call round-trip through the real SDK server,
 * not a bypassed unit call, so it counts as the strongest option (a) rather
 * than the (b) fallback.
 */
import { describe, it, expect, vi, beforeAll, afterEach } from "vitest";
import { createHmac } from "node:crypto";

const TEST_PORT = 47031;
const TEST_HOST = "127.0.0.1";
const TEST_SERVER_PREFIX = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_S2S_SECRET = "test-s2s-guard-ordering-secret-do-not-use-in-prod";

const originalFetch = global.fetch;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * A fresh fetch mock per test: passes real requests to this test's own
 * local HTTP server straight through to the real network, and stubs out
 * Checkpoint's auth/scopes/data endpoints — while counting calls to each so
 * tests can assert exactly how many times refreshToken()/refreshScopes()
 * fired (by way of their fetch() side effects).
 */
function createMockFetch() {
  const calls = { auth: 0, scopes: 0, dataApi: 0 };
  const fn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = input.toString();

    if (url.startsWith(TEST_SERVER_PREFIX)) {
      return originalFetch(input as never, init);
    }
    if (url.includes("/auth/external")) {
      calls.auth++;
      return jsonResponse(200, {
        success: true,
        data: { token: "mock-checkpoint-token", expiresIn: 1800 },
      });
    }
    if (url.includes("/v1.0/scopes")) {
      calls.scopes++;
      return jsonResponse(200, {
        responseEnvelope: { requestId: "scopes-req", responseCode: 200, responseText: "OK" },
        responseData: ["mt-prod-cp-1:acme-test"],
      });
    }
    calls.dataApi++;
    return jsonResponse(200, {
      responseEnvelope: { requestId: "data-req", responseCode: 200, responseText: "OK" },
      responseData: [],
    });
  });
  return { fn, calls };
}

function mintS2sHeader(secret: string, unixSeconds: number): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${hex}`;
}

async function postToMcp(headers: Record<string, string>, body: unknown): Promise<Response> {
  return fetch(`${TEST_SERVER_PREFIX}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Streamable HTTP transport (stateless mode) requires both
      // content types in Accept even for non-streaming JSON responses.
      Accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

const TOOLS_LIST_BODY = { jsonrpc: "2.0", method: "tools/list", id: 1 };
const QUERY_EVENTS_CALL_BODY = {
  jsonrpc: "2.0",
  method: "tools/call",
  params: { name: "hec_query_events", arguments: {} },
  id: 2,
};

async function waitForServerReady(): Promise<void> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      await originalFetch(`${TEST_SERVER_PREFIX}/health`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  throw new Error("test HTTP server did not become ready in time");
}

beforeAll(async () => {
  process.env.MCP_TRANSPORT = "http";
  process.env.AUTH_MODE = "gateway";
  process.env.MCP_HTTP_PORT = String(TEST_PORT);
  process.env.MCP_HTTP_HOST = TEST_HOST;
  process.env.CONDUIT_S2S_SECRET = TEST_S2S_SECRET;
  const { startHttpTransport } = await import("../index.js");
  await startHttpTransport();
  await waitForServerReady();
});

afterEach(() => {
  global.fetch = originalFetch;
});

describe("S2S guard ordering vs. lazy Checkpoint OAuth exchange", () => {
  it("does NOT reach Checkpoint auth/scopes when the S2S header is missing", async () => {
    const { fn, calls } = createMockFetch();
    global.fetch = fn;

    const res = await postToMcp(
      { "x-checkpoint-client-id": "test-client", "x-checkpoint-client-secret": "test-secret" },
      TOOLS_LIST_BODY
    );

    expect(res.status).toBe(401);
    expect(calls.auth).toBe(0);
    expect(calls.scopes).toBe(0);
  });

  it("does NOT reach Checkpoint auth/scopes when the S2S header is present but invalid", async () => {
    const { fn, calls } = createMockFetch();
    global.fetch = fn;

    const res = await postToMcp(
      {
        "x-gateway-s2s": mintS2sHeader("wrong-secret", Math.floor(Date.now() / 1000)),
        "x-checkpoint-client-id": "test-client",
        "x-checkpoint-client-secret": "test-secret",
      },
      TOOLS_LIST_BODY
    );

    expect(res.status).toBe(401);
    expect(calls.auth).toBe(0);
    expect(calls.scopes).toBe(0);
  });

  it("DOES reach Checkpoint auth/scopes once the S2S guard accepts and a real tool executes (negative control)", async () => {
    const { fn, calls } = createMockFetch();
    global.fetch = fn;

    const res = await postToMcp(
      {
        "x-gateway-s2s": mintS2sHeader(TEST_S2S_SECRET, Math.floor(Date.now() / 1000)),
        "x-checkpoint-client-id": "test-client",
        "x-checkpoint-client-secret": "test-secret",
      },
      QUERY_EVENTS_CALL_BODY
    );

    expect(res.status).toBe(200);
    const payload = (await res.json()) as { result?: { isError?: boolean } };
    // Proves the tool call actually completed successfully end-to-end
    // (not that it merely reached the server and errored out before
    // ensureAuth() could run) — otherwise a zero-calls-elsewhere false
    // negative could hide behind an early error path.
    expect(payload.result?.isError).toBeFalsy();

    // The proof this negative control exists for: the mock apparatus CAN
    // detect refreshToken()/refreshScopes() firing, so the zero-calls
    // assertions in the two tests above aren't vacuously true.
    expect(calls.auth).toBe(1);
    expect(calls.scopes).toBe(1);
    expect(calls.dataApi).toBe(1);
  });
});
