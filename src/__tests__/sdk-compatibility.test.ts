import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../worker.js";

const { readDevice } = vi.hoisted(() => ({ readDevice: vi.fn() }));
vi.mock("@wyre-ai/node-datto-rmm", () => ({
  DattoRmmClient: vi.fn().mockImplementation(function () {
    return { devices: { get: readDevice } };
  }),
}));

const token = "synthetic-sdk-backend-token";
const env: Env = {
  DATTO_BACKEND_TOKEN: token,
  DATTO_API_KEY: "synthetic-key",
  DATTO_API_SECRET: "synthetic-secret",
};

function request(method: string, params: unknown, version: string, suppliedToken: string | undefined = token) {
  return worker.fetch(new Request("http://fixture.invalid/mcp", {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-protocol-version": version,
      ...(suppliedToken ? { "x-summit-datto-backend-token": suppliedToken } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  }), env);
}

async function body(response: Response) {
  return await response.json() as { result: {
    protocolVersion: string;
    tools: { name: string }[];
    isError?: boolean;
    content: { text: string }[];
  } };
}

describe("SDK transport compatibility with Summit authentication", () => {
  beforeEach(() => { readDevice.mockReset().mockResolvedValue({ uid: "fixture-device", hostname: "fixture" }); });
  afterEach(() => vi.unstubAllGlobals());

  it.each(["2025-06-18", "2025-11-25"])("preserves initialize, tool discovery and a mocked read on %s", async (version) => {
    const init = await request("initialize", { protocolVersion: version, capabilities: {}, clientInfo: { name: "fixture", version: "0" } }, version);
    expect(init.status).toBe(200);
    expect((await body(init)).result.protocolVersion).toBe(version);
    const list = await request("tools/list", {}, version);
    expect(list.status).toBe(200);
    expect((await body(list)).result.tools.map((tool) => tool.name)).toContain("datto_get_device");
    const read = await request("tools/call", { name: "datto_get_device", arguments: { deviceUid: "fixture-device" } }, version);
    expect(read.status).toBe(200);
    const result = (await body(read)).result;
    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text).uid).toBe("fixture-device");
    expect(readDevice).toHaveBeenCalledExactlyOnceWith("fixture-device");
  });

  it.each([undefined, "wrong-synthetic-token"])("rejects unauthenticated reads before the mocked provider (%s)", async (suppliedToken) => {
    // Pass an empty value to distinguish a missing header from the default token.
    const response = await request("tools/call", { name: "datto_get_device", arguments: { deviceUid: "fixture-device" } }, "2025-06-18", suppliedToken ?? "");
    expect(response.status).toBe(401);
    expect(readDevice).not.toHaveBeenCalled();
  });
});
