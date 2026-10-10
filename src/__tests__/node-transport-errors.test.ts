import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Server as HttpServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { getServerRef } from "../utils/server-ref.js";

// Capture the real listener solely to choose an ephemeral port and close it.
// MCP dispatch, auth guards, Server, and HTTP transport all remain real.
const state = vi.hoisted(() => ({ server: undefined as HttpServer | undefined }));
vi.mock("node:http", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:http")>();
  return {
    ...actual,
    createServer: (...args: Parameters<typeof actual.createServer>) => {
      state.server = actual.createServer(...args);
      return state.server;
    },
  };
});

const BACKEND_TOKEN = "test-node-backend-token";
const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
const oldSignals = {
  SIGINT: process.listeners("SIGINT"),
  SIGTERM: process.listeners("SIGTERM"),
};
let endpoint: string;

beforeAll(async () => {
  vi.stubEnv("MCP_TRANSPORT", "http");
  vi.stubEnv("AUTH_MODE", "env");
  vi.stubEnv("MCP_HTTP_HOST", "127.0.0.1");
  vi.stubEnv("MCP_HTTP_PORT", "0");
  vi.stubEnv("CONDUIT_S2S_SECRET", "");
  vi.stubEnv("DATTO_BACKEND_TOKEN", BACKEND_TOKEN);
  process.on("unhandledRejection", onUnhandled);
  await import("../index.js");
  if (!state.server!.listening) {
    await new Promise<void>((resolve) => state.server!.once("listening", resolve));
  }
  const address = state.server!.address();
  if (!address || typeof address === "string") throw new Error("Missing test listener");
  endpoint = `http://127.0.0.1:${address.port}/mcp`;
});

afterEach(() => { vi.restoreAllMocks(); });
afterAll(async () => {
  state.server?.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    state.server!.close((error) => error ? reject(error) : resolve());
  });
  process.off("unhandledRejection", onUnhandled);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    for (const listener of process.listeners(signal)) {
      if (!oldSignals[signal].includes(listener)) process.off(signal, listener);
    }
  }
  vi.unstubAllEnvs();
});

function request() {
  return fetch(endpoint, {
    method: "POST",
    signal: AbortSignal.timeout(1500),
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "x-summit-datto-backend-token": BACKEND_TOKEN,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
}

describe("Node HTTP asynchronous transport failures", () => {
  it("catches a rejection after an await gap without an unhandled rejection", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const failure = new Error("synthetic-secret-must-not-be-logged");
    let boundContext = false;
    vi.spyOn(StreamableHTTPServerTransport.prototype, "handleRequest")
      .mockImplementationOnce(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        boundContext = getServerRef() !== null;
        throw failure;
      });

    const response = await request();
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      jsonrpc: "2.0", id: null,
      error: { code: -32603, message: "Internal error" },
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(boundContext).toBe(true);
    expect(unhandled).toEqual([]);
    expect(logged.mock.calls.flat().join(" ")).not.toContain(failure.message);
  });

  it("terminates a partial response on a late rejection without writing new headers", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(StreamableHTTPServerTransport.prototype, "handleRequest")
      .mockImplementationOnce(async (_req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.write('{"partial":');
        await new Promise((resolve) => setTimeout(resolve, 20));
        throw new Error("synthetic-late-transport-failure");
      });

    const response = await request();
    expect(response.status).toBe(200);
    await expect(response.text()).rejects.toThrow();
    await new Promise((resolve) => setImmediate(resolve));
    expect(unhandled).toEqual([]);
  });

  it("still serves real tools/list after the failed requests", async () => {
    const response = await request();
    expect(response.status).toBe(200);
    const body = await response.json() as { result: { tools: { name: string }[] } };
    expect(body.result.tools.some((tool) => tool.name === "datto_run_quickjob")).toBe(true);
    expect(unhandled).toEqual([]);
  });
});
