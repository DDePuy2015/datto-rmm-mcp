/**
 * Datto RMM 15.1 patch-compliance reports.
 *
 * The @wyre-ai/node-datto-rmm SDK exposes the stable inventory APIs, but the
 * 15.1 patch endpoints are not part of its public client surface. This module
 * uses the same platform hosts and OAuth password grant as the SDK while
 * keeping the two read-only report calls isolated from the SDK internals.
 */

import type { Platform } from "@wyre-ai/node-datto-rmm";
import type { DattoCredentials } from "./mcp-server.js";

const PLATFORM_URLS: Record<Platform, string> = {
  pinotage: "https://pinotage-api.centrastage.net",
  merlot: "https://merlot-api.centrastage.net",
  concord: "https://concord-api.centrastage.net",
  vidal: "https://vidal-api.centrastage.net",
  zinfandel: "https://zinfandel-api.centrastage.net",
  syrah: "https://syrah-api.centrastage.net",
};

// These limits match the provider-response boundary in summit-mcp-ops.
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES = 64 * 1024;
const TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000;

type CachedToken = { accessToken: string; expiresAt: number };
const tokenCache = new Map<string, CachedToken>();

function tokenCacheKey(creds: DattoCredentials): string {
  // apiKey identifies the Datto credential set without retaining the secret in
  // a cache key. Platform is included because the same key can exist in more
  // than one regional Datto account.
  return `${creds.platform}:${creds.apiKey}`;
}

function platformUrl(platform: Platform): string {
  const apiUrl = PLATFORM_URLS[platform];
  if (!apiUrl) throw new Error("Unsupported Datto RMM platform");
  return apiUrl;
}

async function drainResponse(response: Response, maxBytes: number): Promise<void> {
  if (!response.body) return;

  const reader = response.body.getReader();
  let bytesRead = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return;
      bytesRead += value.byteLength;
      if (bytesRead >= maxBytes) {
        await reader.cancel();
        return;
      }
    }
  } finally {
    reader.releaseLock();
  }
}

async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytesRead = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      bytesRead += value.byteLength;
      if (bytesRead > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error(
          `Datto RMM response exceeded the ${MAX_RESPONSE_BYTES}-byte limit`
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(bytesRead);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function readJson<T>(response: Response): Promise<T> {
  const text = await readBoundedText(response);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error("Datto RMM returned an invalid JSON response");
  }
}

async function getAccessToken(creds: DattoCredentials): Promise<string> {
  const apiUrl = platformUrl(creds.platform);
  const cacheKey = tokenCacheKey(creds);
  const cached = tokenCache.get(cacheKey);

  if (cached && Date.now() < cached.expiresAt - TOKEN_REFRESH_SKEW_MS) {
    return cached.accessToken;
  }

  // btoa is available in both Node's fetch runtime and Cloudflare Workers;
  // using it keeps this shared module free of a Node-only Buffer dependency.
  const basicAuth = btoa("public-client:public");
  const response = await fetch(`${apiUrl}/auth/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: "password",
      username: creds.apiKey,
      password: creds.apiSecretKey,
    }).toString(),
  });

  if (!response.ok) {
    await drainResponse(response, MAX_ERROR_BODY_BYTES);
    throw new Error(`Failed to acquire Datto RMM token: ${response.status}`);
  }

  const data = await readJson<{ access_token?: unknown; expires_in?: unknown }>(
    response
  );
  if (
    typeof data.access_token !== "string" ||
    !data.access_token ||
    typeof data.expires_in !== "number" ||
    !Number.isFinite(data.expires_in) ||
    data.expires_in <= 0
  ) {
    throw new Error("Datto RMM returned an invalid OAuth token response");
  }

  tokenCache.set(cacheKey, {
    accessToken: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
  return data.access_token;
}

export interface Patch {
  patchId: string;
  category: string[];
  type: string;
  title: string;
  description: string;
  releaseDate: string;
  severity: string;
  maxSize: number;
  rebootRequired: boolean;
  requireUserInput: boolean;
  kbArticleId: string;
  installStatus: string;
  manualOverride: boolean;
}

export interface PatchesResponse {
  pageDetails: {
    count: number;
    totalCount: number;
    prevPageUrl: string | null;
    nextPageUrl: string | null;
  };
  patches: Patch[];
}

async function fetchPatches(
  creds: DattoCredentials,
  path: string
): Promise<PatchesResponse> {
  const apiUrl = platformUrl(creds.platform);
  const token = await getAccessToken(creds);
  const response = await fetch(`${apiUrl}/api${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401) {
    // A provider-side token invalidation only invalidates this credential set.
    tokenCache.delete(tokenCacheKey(creds));
    const retryToken = await getAccessToken(creds);
    const retryResponse = await fetch(`${apiUrl}/api${path}`, {
      headers: { Authorization: `Bearer ${retryToken}` },
    });
    if (!retryResponse.ok) {
      await drainResponse(retryResponse, MAX_ERROR_BODY_BYTES);
      throw new Error(`Datto RMM API request failed with status ${retryResponse.status}`);
    }
    return readJson<PatchesResponse>(retryResponse);
  }

  if (!response.ok) {
    await drainResponse(response, MAX_ERROR_BODY_BYTES);
    throw new Error(`Datto RMM API request failed with status ${response.status}`);
  }

  return readJson<PatchesResponse>(response);
}

export function getDevicePatches(
  creds: DattoCredentials,
  deviceUid: string
): Promise<PatchesResponse> {
  return fetchPatches(creds, `/v2/device/${encodeURIComponent(deviceUid)}/patches`);
}

export function getSitePatches(
  creds: DattoCredentials,
  siteUid: string
): Promise<PatchesResponse> {
  return fetchPatches(creds, `/v2/site/${encodeURIComponent(siteUid)}/patches`);
}
