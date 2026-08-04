import { describe, expect, it } from "vitest";
import { applyBrandInjection } from "../alert-card.js";

const HTML = "<html><!-- BRAND_INJECT: placeholder --></html>";

describe("applyBrandInjection", () => {
  it("passes branding through an encoded metadata element", () => {
    const brand = { name: "Summit", primaryColor: "#123456" };
    const output = applyBrandInjection(HTML, brand);
    const match = output.match(/<meta name="mcp-brand" content="([^"]+)">/);

    expect(match).not.toBeNull();
    expect(JSON.parse(decodeURIComponent(match?.[1] ?? ""))).toEqual(brand);
    expect(output).not.toContain("<script>window.__BRAND__");
  });

  it("keeps hostile script text outside executable HTML and JavaScript", () => {
    const output = applyBrandInjection(HTML, {
      name: "</script><script>alert(1)</script>",
    });

    expect(output).not.toContain("</script><script>alert(1)");
    expect(output).not.toContain("<script>window.__BRAND__");
    expect(output).toContain("mcp-brand");
  });

  it("does not alter neutral cards when no brand is configured", () => {
    expect(applyBrandInjection(HTML, {})).toBe(HTML);
  });
});
