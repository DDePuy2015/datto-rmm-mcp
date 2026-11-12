import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { request as httpRequest, type Server as HttpServer } from "node:http";
import worker from "../worker.js";
import { MAX_MCP_REQUEST_BODY_BYTES } from "../transport-limits.js";

const state = vi.hoisted(() => ({
  server: undefined as HttpServer | undefined,
  readDevice: vi.fn(),
}));
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
vi.mock("@wyre-ai/node-datto-rmm", () => ({
  DattoRmmClient: vi.fn().mockImplementation(function () {
    return { devices: { get: state.readDevice } };
  }),
}));

const token = "synthetic-request-limit-token";
const env = {
  DATTO_BACKEND_TOKEN: token,
  DATTO_API_KEY: "synthetic-key",
  DATTO_API_SECRET: "synthetic-secret",
};
const oldSignals = {
  SIGINT: process.listeners("SIGINT"),
  SIGTERM: process.listeners("SIGTERM"),
};
let endpoint: string;

beforeAll(async () => {
  for (const [name, value] of Object.entries({
    ...env,
    MCP_TRANSPORT: "http",
    AUTH_MODE: "env",
    MCP_HTTP_HOST: "127.0.0.1",
    MCP_HTTP_PORT: "0",
    CONDUIT_S2S_SECRET: "",
  })) vi.stubEnv(name, value);
  state.readDevice.mockResolvedValue({ uid: "fixture-device" });
  await import("../index.js");
  if (!state.server!.listening) {
    await new Promise<void>((resolve) => state.server!.once("listening", resolve));
  }
  const address = state.server!.address();
  if (!address || typeof address === "string") throw new Error("Missing listener");
  endpoint = `http://127.0.0.1:${address.port}/mcp`;
});
afterEach(() => state.readDevice.mockClear());
afterAll(async () => {
  state.server!.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    state.server!.close((error) => error ? reject(error) : resolve());
  });
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    for (const listener of process.listeners(signal)) {
      if (!oldSignals[signal].includes(listener)) process.off(signal, listener);
    }
  }
  vi.unstubAllEnvs();
});

function body(padding = "") {
  return JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "datto_get_device", arguments: { deviceUid: "fixture-device", padding } },
  });
}
function sizedBody(bytes: number) {
  return body("x".repeat(bytes - Buffer.byteLength(body())));
}

async function send(kind: "Node" | "Worker", payload: string, streamed = false, suppliedToken = token) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "x-summit-datto-backend-token": suppliedToken,
  };
  if (!streamed) headers["content-length"] = String(Buffer.byteLength(payload));
  if (kind === "Node") {
    if (!streamed) return fetch(endpoint, { method: "POST", headers, body: payload, signal: AbortSignal.timeout(3000) });
    return new Promise<Response>((resolve, reject) => {
      const req = httpRequest(endpoint, { method: "POST", headers, signal: AbortSignal.timeout(3000) }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", chunk => chunks.push(Buffer.from(chunk)));
        res.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: res.statusCode })));
        res.on("error", reject);
      });
      req.on("error", reject);
      // No Content-Length: Node emits chunked transfer encoding. Separate writes
      // make the transport count received bytes, not just trust a header.
      req.write(payload.slice(0, 1024));
      req.end(payload.slice(1024));
    });
  }
  const bytes = new TextEncoder().encode(payload);
  const requestBody = streamed ? new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes.slice(0, 1024));
      controller.enqueue(bytes.slice(1024));
      controller.close();
    },
  }) : payload;
  const init = { method: "POST", headers, body: requestBody, duplex: "half" as const };
  return worker.fetch(new Request("http://fixture.invalid/mcp", init), env);
}

describe.each(["Node", "Worker"] as const)("%s HTTP request byte limit", (kind) => {
  it("accepts exactly the limit with the provider mocked", async () => {
    const response = await send(kind, sizedBody(MAX_MCP_REQUEST_BODY_BYTES));
    expect(response.status).toBe(200);
    expect((await response.json() as { result: { isError?: boolean } }).result.isError).not.toBe(true);
    expect(state.readDevice).toHaveBeenCalledExactlyOnceWith("fixture-device");
  });
  it("rejects limit plus one before provider dispatch", async () => {
    const response = await send(kind, sizedBody(MAX_MCP_REQUEST_BODY_BYTES + 1));
    expect(response.status).toBe(413);
    expect(state.readDevice).not.toHaveBeenCalled();
  });
  it("rejects streamed oversized bodies without Content-Length", async () => {
    const response = await send(kind, sizedBody(MAX_MCP_REQUEST_BODY_BYTES + 1), true);
    expect(response.status).toBe(413);
    expect(state.readDevice).not.toHaveBeenCalled();
  });
  it("counts UTF-8 bytes rather than JavaScript string length", async () => {
    const payload = body("é".repeat(MAX_MCP_REQUEST_BODY_BYTES / 2));
    expect(payload.length).toBeLessThan(MAX_MCP_REQUEST_BODY_BYTES);
    expect(Buffer.byteLength(payload)).toBeGreaterThan(MAX_MCP_REQUEST_BODY_BYTES);
    expect((await send(kind, payload, true)).status).toBe(413);
    expect(state.readDevice).not.toHaveBeenCalled();
  });
  it("keeps backend authentication ahead of body parsing", async () => {
    expect((await send(kind, sizedBody(MAX_MCP_REQUEST_BODY_BYTES + 1), false, "wrong-token")).status).toBe(401);
    expect(state.readDevice).not.toHaveBeenCalled();
  });
  it("still handles an ordinary request after oversized rejections", async () => {
    expect((await send(kind, body())).status).toBe(200);
    expect(state.readDevice).toHaveBeenCalledExactlyOnceWith("fixture-device");
  });
});
