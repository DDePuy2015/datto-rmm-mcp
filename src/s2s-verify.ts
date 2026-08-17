/**
 * Verifies the gateway's service-to-service authentication header.
 *
 * The check is intentionally dark-by-default: callers only enforce it when
 * CONDUIT_S2S_SECRET is provisioned. The secret is treated as an opaque,
 * per-service value; the gateway is responsible for deriving recipient-bound
 * subkeys before provisioning them to services.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/** Node lowercases incoming header names. */
export const S2S_HEADER = "x-gateway-s2s";

const HEADER_VALUE_RE = /^t=(\d{1,15}),v1=([0-9a-f]{64})$/;

export function verifyS2sHeader(
  headerValue: string | undefined,
  secret: string,
  maxSkewSeconds = 300
): boolean {
  if (!secret || !headerValue) return false;

  const match = HEADER_VALUE_RE.exec(headerValue);
  if (!match) return false;

  const timestamp = Number(match[1]);
  if (!Number.isSafeInteger(timestamp)) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > maxSkewSeconds) {
    return false;
  }

  const expected = createHmac("sha256", secret)
    .update(`t=${timestamp}`)
    .digest();
  const provided = Buffer.from(match[2], "hex");

  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
