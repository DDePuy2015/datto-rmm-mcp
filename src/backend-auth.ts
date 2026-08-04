import { createHash, timingSafeEqual } from "node:crypto";

export const DATTO_BACKEND_TOKEN_HEADER = "x-summit-datto-backend-token";

export type BackendAuthFailure = "not_configured" | "missing_or_invalid";

function tokensMatch(configured: string, supplied: string): boolean {
  const expected = createHash("sha256").update(configured, "utf8").digest();
  const actual = createHash("sha256").update(supplied, "utf8").digest();
  return timingSafeEqual(expected, actual);
}

/**
 * Validate the proxy-to-provider token without logging or returning its value.
 * The provider fails closed when the token is not configured.
 */
export function validateBackendToken(
  configuredToken: string | undefined,
  suppliedToken: string | undefined
): BackendAuthFailure | undefined {
  if (!configuredToken) return "not_configured";
  if (!suppliedToken || !tokensMatch(configuredToken, suppliedToken)) {
    return "missing_or_invalid";
  }
  return undefined;
}
