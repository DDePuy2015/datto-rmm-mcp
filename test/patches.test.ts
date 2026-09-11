import { afterEach, describe, expect, it, vi } from "vitest";
import { getDevicePatches, getSitePatches } from "../src/patches.js";
import type { DattoCredentials } from "../src/mcp-server.js";

function tokenResponse(accessToken: string) {
  return new Response(
    JSON.stringify({ access_token: accessToken, expires_in: 3600 }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

function patchesResponse() {
  return new Response(
    JSON.stringify({
      pageDetails: {
        count: 1,
        totalCount: 1,
        prevPageUrl: null,
        nextPageUrl: null,
      },
      patches: [
        {
          patchId: "patch-1",
          category: ["Security Updates"],
          type: "Windows",
          title: "Example update",
          description: "Example patch",
          releaseDate: "2026-09-01",
          severity: "Critical",
          maxSize: 123,
          rebootRequired: true,
          requireUserInput: false,
          kbArticleId: "KB0000001",
          installStatus: "Missing",
          manualOverride: false,
        },
      ],
    }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Datto patch reports", () => {
  it("uses the selected regional host and encodes device and site UIDs", async () => {
    const creds: DattoCredentials = {
      platform: "syrah",
      apiKey: "patch-endpoint-key",
      apiSecretKey: "patch-endpoint-secret",
    };
    const urls: string[] = [];

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const href = url.toString();
        urls.push(href);
        if (href.endsWith("/auth/oauth/token")) {
          expect(init?.method).toBe("POST");
          expect((init?.headers as Record<string, string>).Authorization).toBe(
            `Basic ${btoa("public-client:public")}`
          );
          const body = new URLSearchParams(init?.body as string);
          expect(body.get("username")).toBe(creds.apiKey);
          expect(body.get("password")).toBe(creds.apiSecretKey);
          return tokenResponse("endpoint-token");
        }
        return patchesResponse();
      })
    );

    await getDevicePatches(creds, "device/with spaces");
    await getSitePatches(creds, "site/with spaces");

    expect(urls).toEqual([
      "https://syrah-api.centrastage.net/auth/oauth/token",
      "https://syrah-api.centrastage.net/api/v2/device/device%2Fwith%20spaces/patches",
      "https://syrah-api.centrastage.net/api/v2/sites/site%2Fwith%20spaces/patches",
    ]);
  });

  it("returns the typed patch report", async () => {
    const creds: DattoCredentials = {
      platform: "merlot",
      apiKey: "patch-shape-key",
      apiSecretKey: "patch-shape-secret",
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) =>
        url.toString().endsWith("/auth/oauth/token")
          ? tokenResponse("shape-token")
          : patchesResponse()
      )
    );

    const result = await getDevicePatches(creds, "device-shape");
    expect(result.pageDetails.totalCount).toBe(1);
    expect(result.patches[0]?.installStatus).toBe("Missing");
  });

  it("isolates cached tokens between customers on the same platform", async () => {
    const customerA: DattoCredentials = {
      platform: "concord",
      apiKey: "cache-isolation-a",
      apiSecretKey: "a-secret",
    };
    const customerB: DattoCredentials = {
      platform: "concord",
      apiKey: "cache-isolation-b",
      apiSecretKey: "b-secret",
    };
    const apiAuthHeaders: string[] = [];

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (url.toString().endsWith("/auth/oauth/token")) {
          const params = new URLSearchParams(init?.body as string);
          return tokenResponse(`token-for-${params.get("username")}`);
        }
        apiAuthHeaders.push(
          (init?.headers as Record<string, string>).Authorization
        );
        return patchesResponse();
      })
    );

    await getDevicePatches(customerA, "device-a");
    await getDevicePatches(customerB, "device-b");

    expect(apiAuthHeaders).toEqual([
      "Bearer token-for-cache-isolation-a",
      "Bearer token-for-cache-isolation-b",
    ]);
  });

  it("reuses a cached token for repeated calls with the same credentials", async () => {
    const creds: DattoCredentials = {
      platform: "vidal",
      apiKey: "cache-reuse-key",
      apiSecretKey: "cache-reuse-secret",
    };
    let tokenCalls = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) => {
        if (url.toString().endsWith("/auth/oauth/token")) {
          tokenCalls += 1;
          return tokenResponse("reused-token");
        }
        return patchesResponse();
      })
    );

    await getDevicePatches(creds, "device-one");
    await getDevicePatches(creds, "device-two");

    expect(tokenCalls).toBe(1);
  });

  it("retries one 401 and invalidates only the failing credential cache", async () => {
    const customerA: DattoCredentials = {
      platform: "pinotage",
      apiKey: "cache-401-a",
      apiSecretKey: "a-secret",
    };
    const customerB: DattoCredentials = {
      platform: "pinotage",
      apiKey: "cache-401-b",
      apiSecretKey: "b-secret",
    };
    let firstARequest = true;
    let customerBTokenCalls = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const href = url.toString();
        if (href.endsWith("/auth/oauth/token")) {
          const params = new URLSearchParams(init?.body as string);
          if (params.get("username") === customerB.apiKey) customerBTokenCalls += 1;
          return tokenResponse(`token-for-${params.get("username")}`);
        }

        const authorization = (init?.headers as Record<string, string>).Authorization;
        if (authorization === "Bearer token-for-cache-401-a" && firstARequest) {
          firstARequest = false;
          return new Response("unauthorized", { status: 401 });
        }
        return patchesResponse();
      })
    );

    await getDevicePatches(customerB, "device-b");
    await getDevicePatches(customerA, "device-a");
    await getDevicePatches(customerB, "device-b-again");

    expect(customerBTokenCalls).toBe(1);
  });

  it("does not expose provider error bodies", async () => {
    const creds: DattoCredentials = {
      platform: "zinfandel",
      apiKey: "error-body-key",
      apiSecretKey: "error-body-secret",
    };
    const sensitiveBody = "internal-account-id-12345 provider secret details";

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) =>
        url.toString().endsWith("/auth/oauth/token")
          ? tokenResponse("error-token")
          : new Response(sensitiveBody, { status: 500 })
      )
    );

    await expect(getDevicePatches(creds, "device-error")).rejects.toThrow(
      "Datto RMM API request failed with status 500"
    );
    await expect(getDevicePatches(creds, "device-error")).rejects.not.toThrow(
      new RegExp("internal-account-id-12345")
    );
  });

  it("rejects an oversized successful provider response", async () => {
    const creds: DattoCredentials = {
      platform: "zinfandel",
      apiKey: "oversized-response-key",
      apiSecretKey: "oversized-response-secret",
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) =>
        url.toString().endsWith("/auth/oauth/token")
          ? tokenResponse("oversized-token")
          : new Response("x".repeat(8 * 1024 * 1024 + 1), { status: 200 })
      )
    );

    await expect(getDevicePatches(creds, "device-oversized")).rejects.toThrow(
      "exceeded the 8388608-byte limit"
    );
  });
});
