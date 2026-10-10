import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Server as HttpServer } from "node:http";
import { createHmac } from "node:crypto";

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

// Actual index.ts listener, MCP factory, SDK transport and Datto client.
// Only outbound Datto fetch is stubbed; unexpected destinations fail closed.
const DATTO_HOST = "https://concord-api.centrastage.net";
const TOKEN = "test-node-job-backend";
const S2S_SECRET = "test-node-job-s2s";
const realFetch = globalThis.fetch;
const oldSignals = {
  SIGINT: process.listeners("SIGINT"), SIGTERM: process.listeners("SIGTERM"),
};
let endpoint: string;
let requests: { path: string; method: string; authorization: string | null }[];
let oauth: { username: string | null; password: string | null }[];
let respond: (path: string, init?: RequestInit) => Response | Promise<Response>;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeAll(async () => {
  vi.stubEnv("MCP_TRANSPORT", "http");
  vi.stubEnv("AUTH_MODE", "gateway");
  vi.stubEnv("MCP_HTTP_HOST", "127.0.0.1");
  vi.stubEnv("MCP_HTTP_PORT", "0");
  vi.stubEnv("CONDUIT_S2S_SECRET", S2S_SECRET);
  vi.stubEnv("DATTO_BACKEND_TOKEN", TOKEN);
  vi.stubEnv("DATTO_API_KEY", "environment-key-must-not-be-used");
  vi.stubEnv("DATTO_API_SECRET", "environment-secret-must-not-be-used");
  await import("../index.js");
  if (!state.server!.listening) {
    await new Promise<void>((resolve) => state.server!.once("listening", resolve));
  }
  const address = state.server!.address();
  if (!address || typeof address === "string") throw new Error("Missing test listener");
  endpoint = `http://127.0.0.1:${address.port}/mcp`;
});

beforeEach(() => {
  requests = [];
  oauth = [];
  respond = () => json({ job: { uid: "job-123", status: "completed" } });
  globalThis.fetch = vi.fn(async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === `${DATTO_HOST}/auth/oauth/token`) {
      const body = new URLSearchParams(String(init?.body));
      const username = body.get("username");
      oauth.push({ username, password: body.get("password") });
      // Deliberately interleave credential-specific token acquisition.
      await new Promise((resolve) => setTimeout(resolve, username === "key-a" ? 20 : 1));
      return json({ access_token: `token-${username}`, token_type: "bearer", expires_in: 3600 });
    }
    if (!url.startsWith(`${DATTO_HOST}/api/v2/`)) throw new Error("Unexpected test destination");
    const path = url.slice(`${DATTO_HOST}/api/v2`.length);
    requests.push({ path, method: init?.method ?? "GET", authorization: new Headers(init?.headers).get("authorization") });
    return respond(path, init);
  }) as typeof fetch;
});

afterEach(() => { globalThis.fetch = realFetch; });
afterAll(async () => {
  state.server?.closeAllConnections();
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

function send(method: string, params?: unknown, overrides: Record<string, string> = {}) {
  const message = `t=${Math.floor(Date.now() / 1000)}`;
  const signature = createHmac("sha256", S2S_SECRET).update(message).digest("hex");
  return realFetch(endpoint, {
    method: "POST", signal: AbortSignal.timeout(3000),
    headers: {
      "Content-Type": "application/json", Accept: "application/json, text/event-stream",
      "x-summit-datto-backend-token": TOKEN, "x-gateway-s2s": `${message},v1=${signature}`,
      "x-datto-api-key": "key-default", "x-datto-api-secret": "secret-default", ...overrides,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params === undefined ? {} : { params }) }),
  });
}

async function call(args: unknown, headers: Record<string, string> = {}) {
  const response = await send("tools/call", { name: "datto_get_job", arguments: args }, headers);
  expect(response.status).toBe(200);
  const body = await response.json() as {
    result: { content: { type: string; text: string }[]; isError?: boolean; structuredContent?: unknown };
  };
  expect(body.result.content).toHaveLength(1);
  expect(body.result.content[0].type).toBe("text");
  expect(body.result).not.toHaveProperty("structuredContent");
  return { result: body.result, data: JSON.parse(body.result.content[0].text) };
}

describe("Node HTTP compact job status", () => {
  it("lists the new tool and classifies every read and mutation without OAuth", async () => {
    const response = await send("tools/list");
    expect(response.status).toBe(200);
    const body = await response.json() as { result: { tools: { name: string; annotations: { readOnlyHint: boolean }; inputSchema: { required: string[] } }[] } };
    const tools = body.result.tools;
    const mutations = ["datto_resolve_alert", "datto_run_quickjob", "datto_submit_connectivity_check"];
    const reads = ["datto_list_devices", "datto_list_device_summaries", "datto_find_device", "datto_get_device", "datto_get_device_patches", "datto_list_alerts", "datto_get_alert", "datto_list_sites", "datto_get_site", "datto_get_site_patches", "datto_get_device_audit", "datto_get_job"];
    expect(tools.map((tool) => tool.name).sort()).toEqual([...reads, ...mutations].sort());
    for (const tool of tools) expect(tool.annotations.readOnlyHint).toBe(reads.includes(tool.name));
    expect(tools.find((tool) => tool.name === "datto_get_job")!.inputSchema.required).toEqual(["jobUid"]);
    expect(oauth).toEqual([]);
    expect(requests).toEqual([]);
  });

  it.each([true, false])("returns compact JSON text from wrapped=%s API data", async (wrapped) => {
    const job = { uid: "job-123", status: "completed", deviceCount: 1, completedDeviceCount: 1, failedDeviceCount: 0, createdAt: 1706745000000, startedAt: 1706745060000, completedAt: 1706745120000, name: "private-job-name", createdBy: "private-actor", variables: { password: "private-variable" }, stdout: "private-output", extra: "x".repeat(100000) };
    respond = () => json(wrapped ? { job } : job);
    const { result, data } = await call({ jobUid: "job-123" });
    expect(result.isError).toBeFalsy();
    expect(data).toEqual({ uid: "job-123", status: "completed", deviceCount: 1, completedDeviceCount: 1, failedDeviceCount: 0, createdAt: 1706745000000, startedAt: 1706745060000, completedAt: 1706745120000 });
    expect(result.content[0].text.length).toBeLessThan(1024);
    expect(result.content[0].text).not.toContain("private-");
    expect(requests).toEqual([{ path: "/job/job-123", method: "GET", authorization: "Bearer token-key-default" }]);
  });

  it("omits malformed counts/timestamps and reports an unfamiliar status as unknown", async () => {
    respond = () => json({ job: { uid: "job-123", status: "secret".repeat(1000), deviceCount: -1, completedDeviceCount: { secret: "x" }, failedDeviceCount: 0.5, createdAt: "secret", startedAt: 9e15, completedAt: -1 } });
    expect((await call({ jobUid: "job-123" })).data).toEqual({ uid: "job-123", status: "unknown" });
  });

  it("checks job/device and device/site relationships using only GET endpoints", async () => {
    respond = (path) => {
      if (path === "/device/device-456") return json({ device: { uid: "device-456", siteUid: "site-789" } });
      if (path === "/job/job-123/results/device-456") return json({ result: { jobUid: "job-123", deviceUid: "device-456", status: "running", errorMessage: "private-error", stdout: "private-output" } });
      return json({ job: { uid: "job-123", status: "active" } });
    };
    const { result, data } = await call({ jobUid: "job-123", deviceUid: "device-456", siteUid: "site-789" });
    expect(result.isError).toBeFalsy();
    expect(data).toEqual({ uid: "job-123", status: "active", device: { uid: "device-456", siteUid: "site-789", status: "running" } });
    expect(requests.map(({ path, method }) => ({ path, method }))).toEqual([
      { path: "/device/device-456", method: "GET" }, { path: "/job/job-123", method: "GET" }, { path: "/job/job-123/results/device-456", method: "GET" },
    ]);
  });

  it.each([
    ["wrong-job", { jobUid: "other-job", deviceUid: "device-456" }],
    ["wrong-device", { jobUid: "job-123", deviceUid: "other-device" }],
    ["missing-relationship", {}],
  ])("rejects %s job/device results", async (_label, relationship) => {
    respond = (path) => path.includes("/results/") ? json({ result: relationship }) : json({ job: { uid: "job-123", status: "completed", name: "private-name" } });
    const { result, data } = await call({ jobUid: "job-123", deviceUid: "device-456" });
    expect(result.isError).toBe(true);
    expect(data.error.code).toBe("device_mismatch");
    expect(data).not.toHaveProperty("uid");
  });

  it.each([
    [{ uid: "device-456", siteUid: "other-site" }, "site_mismatch"],
    [{ uid: "device-456" }, "site_mismatch"],
    [{ uid: "other-device", siteUid: "site-789" }, "device_mismatch"],
  ])("rejects unconfirmed device/site data %j before reading the job", async (device, code) => {
    respond = () => json({ device });
    const { result, data } = await call({ jobUid: "job-123", deviceUid: "device-456", siteUid: "site-789" });
    expect(result.isError).toBe(true);
    expect(data.error.code).toBe(code);
    expect(requests.map((req) => req.path)).toEqual(["/device/device-456"]);
  });

  it("rejects a mismatched job UID", async () => {
    respond = () => json({ job: { uid: "other-job", status: "completed" } });
    expect((await call({ jobUid: "job-123" })).data.error.code).toBe("job_mismatch");
  });

  it.each([{}, { jobUid: "" }, { jobUid: "../other" }, { jobUid: "x?secret=y" }, { jobUid: 123 }, { jobUid: "x".repeat(129) }, { jobUid: "job-123", deviceUid: null }, { jobUid: "job-123", siteUid: "site-789" }, { jobUid: "job-123", tenantId: "spoofed" }])("rejects invalid selectors %j before OAuth", async (args) => {
    const { result, data } = await call(args);
    expect(result.isError).toBe(true);
    expect(data.error.code).toBe("invalid_arguments");
    expect(oauth).toEqual([]);
    expect(requests).toEqual([]);
  });

  it.each([403, 404])("sanitizes vendor errors with status %s", async (status) => {
    respond = () => json({ message: "private-provider-password", token: "private-provider-token" }, status);
    const { result, data } = await call({ jobUid: "job-123" });
    expect(result.isError).toBe(true);
    expect(data.error.code).toBe("job_status_unavailable");
    expect(result.content[0].text).not.toContain("private-provider");
  });

  it("isolates credentials and job results across overlapping gateway requests", async () => {
    respond = (path, init) => {
      const owner = new Headers(init?.headers).get("authorization") === "Bearer token-key-a" ? "a" : "b";
      expect(path).toBe(`/job/job-${owner}`);
      return json({ job: { uid: `job-${owner}`, status: owner === "a" ? "active" : "completed" } });
    };
    const [a, b] = await Promise.all([
      call({ jobUid: "job-a" }, { "x-datto-api-key": "key-a", "x-datto-api-secret": "secret-a" }),
      call({ jobUid: "job-b" }, { "x-datto-api-key": "key-b", "x-datto-api-secret": "secret-b" }),
    ]);
    expect(a.data).toEqual({ uid: "job-a", status: "active" });
    expect(b.data).toEqual({ uid: "job-b", status: "completed" });
    expect(oauth).toEqual([{ username: "key-a", password: "secret-a" }, { username: "key-b", password: "secret-b" }]);
  });

  it.each([
    [{ "x-summit-datto-backend-token": "wrong" }, 401],
    [{ "x-gateway-s2s": "wrong" }, 401],
    [{ "x-datto-api-key": "" }, 401],
  ])("preserves gateway guards before OAuth for %j", async (headers, status) => {
    const response = await send("tools/call", { name: "datto_get_job", arguments: { jobUid: "job-123" } }, headers);
    expect(response.status).toBe(status);
    expect(oauth).toEqual([]);
    expect(requests).toEqual([]);
  });
});
