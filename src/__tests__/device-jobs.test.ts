import { afterEach, describe, expect, it, vi } from "vitest";
import { listDeviceJobs } from "../device-jobs.js";
import { dattoApiGet } from "../patches.js";

const creds = { platform: "concord" as const, apiKey: "history-test", apiSecretKey: "history-secret" };
const host = "https://concord-api.centrastage.net";
const now = new Date("2026-11-14T12:00:00Z");
const time = now.getTime() - 60000;
const row = (job = "job-1", at = time, name = "Backup") => ({ date: at / 1000, details: JSON.stringify({ "job.uid": job, "device.uid": "device-1", "job.name": name }) });
function pages(values: unknown[]) {
  let index = 0;
  const calls: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    const url = String(input);
    if (url === `${host}/auth/oauth/token`) return Response.json({ access_token: "test-token", expires_in: 3600 });
    expect(url.startsWith(`${host}/api/v2/activity-logs?`)).toBe(true);
    expect(init?.redirect).toBe("error");
    calls.push(url);
    if (index >= values.length) throw new Error("Unexpected page");
    return Response.json(values[index++]);
  }));
  return calls;
}
const page = (activities: unknown[], next: string | null = null) => ({ activities, pageDetails: { nextPageUrl: next } });
const next = `${host}/api/v2/activity-logs?page=2`;
const result = (ranOn: number | null = time) => ({ jobUid: "job-1", deviceUid: "device-1", ranOn, jobDeploymentStatus: "completed", componentResults: [] });
afterEach(() => vi.unstubAllGlobals());

describe("device history correlation", () => {
  it("reads an adjacent page after max and withholds ambiguous recurring status", async () => {
    const calls = pages([page([row()], next), page([row("job-1", time - 10000)])]);
    const lookup = vi.fn(async () => result());
    const output = await listDeviceJobs(creds, "device-1", lookup, { now, max: 1 });
    expect(calls).toHaveLength(2);
    expect(output.activityScanComplete).toBe(true);
    expect(output.jobs).toHaveLength(1);
    expect(output.jobs[0].status).toBeUndefined();
    expect(output.jobs[0].statusNote).toContain("more than once");
    expect(lookup).toHaveBeenCalledTimes(1);
  });
  it("uses filtered-out adjacent deployments as correlation boundaries", async () => {
    pages([page([row()], next), page([row("job-1", time - 10000, "Renamed")])]);
    const output = await listDeviceJobs(creds, "device-1", async () => result(), { now, max: 1, name: "Backup" });
    expect(output.jobs[0].status).toBeUndefined();
  });
  it.each([time, null])("withholds timed and untimed status at the ten-page cap (%s)", async (ran) => {
    const calls = pages(Array.from({ length: 10 }, (_, i) => page(i === 0 ? [row()] : [], next)));
    const output = await listDeviceJobs(creds, "device-1", async () => result(ran), { now, max: 1 });
    expect(calls).toHaveLength(10);
    expect(output.activityScanComplete).toBe(false);
    expect(output.jobs[0].status).toBeUndefined();
    expect(output.jobs[0].statusNote).toContain("incomplete");
    expect(output.notes?.join()).toContain("10 activity-log pages");
  });
  it("does not claim no matches when the page cap hides older rows", async () => {
    pages(Array.from({ length: 10 }, () => page([], next)));
    const output = await listDeviceJobs(creds, "device-1", vi.fn(), { now });
    expect(output.activityScanComplete).toBe(false);
    expect(output.notes?.join()).not.toContain("No job runs");
  });
  it("assigns delayed latest results only to the owning deployment", async () => {
    pages([page([row(), row("job-1", time - 3600000)])]);
    const output = await listDeviceJobs(creds, "device-1", async () => result(time + 45000), { now });
    expect(output.jobs[0].status).toBe("completed");
    expect(output.jobs[1].status).toBeUndefined();
  });
  it("does not borrow a latest result outside a historical window", async () => {
    pages([page([row()])]);
    const output = await listDeviceJobs(creds, "device-1", async () => result(now.getTime()), { now: new Date(now.getTime() + 86400000), until: new Date(time + 1000).toISOString() });
    expect(output.jobs[0].status).toBeUndefined();
  });
  it("caps results lookups at fifty and reports component-filter incompleteness", async () => {
    pages([page(Array.from({ length: 100 }, (_, i) => row(`job-${i}`)))]);
    const lookup = vi.fn(async () => ({ componentResults: [] }));
    const output = await listDeviceJobs(creds, "device-1", lookup, { now, name: "missing", max: 100 });
    expect(lookup).toHaveBeenCalledTimes(50);
    expect(output.notes?.join()).toContain("Incomplete search");
  });
  it("rejects path-shaped job identifiers before results lookup", async () => {
    pages([page([row("../secret")])]);
    const lookup = vi.fn();
    expect((await listDeviceJobs(creds, "device-1", lookup, { now })).jobs).toEqual([]);
    expect(lookup).not.toHaveBeenCalled();
  });
  it("rejects mismatched returned job/device identities", async () => {
    pages([page([row()])]);
    const output = await listDeviceJobs(creds, "device-1", async () => ({ ...result(), deviceUid: "other-device" }), { now });
    expect(output.jobs[0].status).toBeUndefined();
    expect(output.jobs[0].statusNote).toContain("mismatched");
  });
  it("sanitizes lookup errors and distinguishes them from missing results", async () => {
    pages([page([row()])]);
    const output = await listDeviceJobs(creds, "device-1", async () => { throw new Error("secret-provider-body"); }, { now });
    expect(JSON.stringify(output)).not.toContain("secret-provider-body");
    expect(output.jobs[0].statusNote).toContain("failed");
  });
  it("sanitizes activity error bodies", async () => {
    pages([{ error: "secret-provider-body" }]);
    await expect(listDeviceJobs(creds, "device-1", vi.fn(), { now })).rejects.toThrow("activity log request failed");
  });
  it.each(["https://evil.invalid/api/v2/activity-logs", `${host}/api/v2/../../auth/oauth/token`, `https://user@concord-api.centrastage.net/api/v2/activity-logs`])("refuses unsafe page URLs before fetch: %s", async (url) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(dattoApiGet(creds, url)).rejects.toThrow("Refusing");
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([0, 101, 1.5, NaN])("rejects invalid max before fetch: %s", async (max) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(listDeviceJobs(creds, "device-1", vi.fn(), { max, now })).rejects.toThrow("Invalid");
    expect(fetch).not.toHaveBeenCalled();
  });
});
