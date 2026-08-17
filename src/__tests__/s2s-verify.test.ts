import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { verifyS2sHeader } from "../s2s-verify.js";

function mintHeader(secret: string, unixSeconds: number): string {
  const message = `t=${unixSeconds}`;
  const signature = createHmac("sha256", secret)
    .update(message)
    .digest("hex");
  return `${message},v1=${signature}`;
}

function deriveRecipientSubkey(masterSecret: string, slug: string): string {
  return createHmac("sha256", masterSecret)
    .update(`s2s-recipient:${slug}`)
    .digest("hex");
}

describe("verifyS2sHeader", () => {
  const masterSecret = "test-master-secret-do-not-use-in-prod";
  const secret = deriveRecipientSubkey(masterSecret, "datto-rmm");

  it("accepts a valid current header", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(verifyS2sHeader(mintHeader(secret, now), secret)).toBe(true);
  });

  it("rejects a header signed with a different secret", () => {
    const now = Math.floor(Date.now() / 1000);
    const siblingSecret = deriveRecipientSubkey(masterSecret, "itglue");
    expect(verifyS2sHeader(mintHeader(siblingSecret, now), secret)).toBe(false);
  });

  it("rejects timestamps outside the skew window", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(verifyS2sHeader(mintHeader(secret, now - 301), secret)).toBe(false);
    expect(verifyS2sHeader(mintHeader(secret, now + 301), secret)).toBe(false);
  });

  it("accepts a timestamp at the edge of the skew window", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(verifyS2sHeader(mintHeader(secret, now - 300), secret)).toBe(true);
  });

  it("rejects missing, malformed, tampered, and empty-secret values", () => {
    const now = Math.floor(Date.now() / 1000);
    const header = mintHeader(secret, now);
    const tampered = `${header.slice(0, -1)}${header.endsWith("0") ? "1" : "0"}`;

    expect(verifyS2sHeader(undefined, secret)).toBe(false);
    expect(verifyS2sHeader("not-a-valid-header", secret)).toBe(false);
    expect(verifyS2sHeader(tampered, secret)).toBe(false);
    expect(verifyS2sHeader(header, "")).toBe(false);
  });
});
