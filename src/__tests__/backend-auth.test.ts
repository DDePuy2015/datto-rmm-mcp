import { describe, expect, it } from "vitest";
import {
  validateBackendToken,
} from "../backend-auth.js";

describe("Datto proxy backend authentication", () => {
  it("fails closed when the provider token is not configured", () => {
    expect(validateBackendToken(undefined, "token")).toBe("not_configured");
  });

  it("rejects missing and incorrect tokens", () => {
    expect(validateBackendToken("expected", undefined)).toBe("missing_or_invalid");
    expect(validateBackendToken("expected", "wrong")).toBe("missing_or_invalid");
  });

  it("accepts the configured token", () => {
    expect(validateBackendToken("expected", "expected")).toBeUndefined();
  });
});
