/**
 * Regression coverage for the S2S guard ordering invariant: a rejected
 * request must not reach lazy Datto OAuth token acquisition or API dispatch.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { createHmac } from "node:crypto";

const TEST_PORT = 47006;
const TEST_SECRET = "test-s2s-ordering-secret-do-not-use-in-prod";
const TEST_BACKEND_TOKEN = "test-backend-token-do-not-use-in-prod";
const DATTO_HOST = "https://concord-api.centrastage.net";

let tokenCalls = 0;
let sitesCalls = 0;
const realFetch = globalThis.fetch;

beforeAll(async () => {
  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url.startsWith(`${DATTO_HOST}/auth/oauth/token`)) {
      tokenCalls++;
      return new Response(
        JSON.stringify({
          access_token: "fake-access-token",
          token_type: "bearer",
          expires_in: 3600,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    if (url.startsWith(`${DATTO_HOST}/api/v2/`)) {
      sitesCalls++;
      return new Response(JSON.stringify({ items: [], pageDetails: { count: 0 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return realFetch(input, init);
  }) as typeof fetch;

  process.env.MCP_TRANSPORT = "http";
  process.env.AUTH_MODE = "gateway";
  process.env.MCP_HTTP_PORT = String(TEST_PORT);
  process.env.MCP_HTTP_HOST = "127.0.0.1";
  process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
  process.env.DATTO_BACKEND_TOKEN = TEST_BACKEND_TOKEN;

  await import("../index.js");
  await waitForServerReady();
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

function mintS2sHeader(secret: string, unixSeconds: number): string {
  const message = `t=${unixSeconds}`;
  const signature = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${signature}`;
}

async function waitForServerReady(): Promise<void> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const response = await realFetch(`http://127.0.0.1:${TEST_PORT}/health`);
      if (response.ok) return;
    } catch {
      // The listener may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Datto RMM MCP test HTTP server did not become ready in time");
}

async function callListSites(headers: Record<string, string>): Promise<Response> {
  return fetch(`http://127.0.0.1:${TEST_PORT}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "x-summit-datto-backend-token": TEST_BACKEND_TOKEN,
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "tools/call",
      params: { name: "datto_list_sites", arguments: {} },
      id: 1,
    }),
  });
}

const VALID_DATTO_HEADERS = {
  "x-datto-api-key": "test-api-key",
  "x-datto-api-secret": "test-api-secret",
};

describe("S2S guard ordering vs. lazy Datto OAuth acquisition", () => {
  it("does not call Datto OAuth when the S2S header is missing", async () => {
    tokenCalls = 0;
    sitesCalls = 0;
    const response = await callListSites(VALID_DATTO_HEADERS);

    expect(response.status).toBe(401);
    expect(tokenCalls).toBe(0);
    expect(sitesCalls).toBe(0);
  });

  it("does not call Datto OAuth when the S2S header is invalid", async () => {
    tokenCalls = 0;
    sitesCalls = 0;
    const response = await callListSites({
      "x-gateway-s2s": mintS2sHeader("wrong-secret", Math.floor(Date.now() / 1000)),
      ...VALID_DATTO_HEADERS,
    });

    expect(response.status).toBe(401);
    expect(tokenCalls).toBe(0);
    expect(sitesCalls).toBe(0);
  });

  it("allows a valid S2S request to reach Datto exactly once", async () => {
    tokenCalls = 0;
    sitesCalls = 0;
    const response = await callListSites({
      "x-gateway-s2s": mintS2sHeader(TEST_SECRET, Math.floor(Date.now() / 1000)),
      ...VALID_DATTO_HEADERS,
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { result?: { isError?: boolean } };
    expect(body.result?.isError).toBeFalsy();
    expect(tokenCalls).toBe(1);
    expect(sitesCalls).toBe(1);
  });
});
