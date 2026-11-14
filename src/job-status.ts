import type { DattoRmmClient } from "@wyre-ai/node-datto-rmm";

// UIDs enter SDK URL paths verbatim. Keep this read tool's selectors bounded
// and reject path/query syntax before OAuth or any Datto request.
export const JOB_UID_PATTERN = "^[A-Za-z0-9_-]{1,128}$";
const uidPattern = new RegExp(JOB_UID_PATTERN);
const statuses = new Set([
  "pending", "queued", "active", "running", "completed", "failed", "cancelled",
]);

function error(code: string, message: string) {
  return { error: { code, message } };
}

function status(value: unknown): string {
  return typeof value === "string" && statuses.has(value) ? value : "unknown";
}

function count(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value : undefined;
}

function timestamp(value: unknown): number | undefined {
  const number = count(value);
  return number !== undefined && number <= 8.64e15 ? number : undefined;
}

/**
 * Optional device/site selectors assert relationships reported by Datto.
 * They are caller-supplied consistency checks, never authorization scope.
 * The provider has no verified Entra actor or actor-to-site entitlement.
 */
export async function readJobStatus(client: DattoRmmClient, args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return error("invalid_arguments", "Provide jobUid and optional deviceUid/siteUid.");
  }
  const params = args as Record<string, unknown>;
  if (Object.keys(params).some((key) => !["jobUid", "deviceUid", "siteUid"].includes(key))) {
    return error("invalid_arguments", "Only jobUid, deviceUid, and siteUid are supported.");
  }
  for (const key of ["jobUid", "deviceUid", "siteUid"] as const) {
    const value = params[key];
    if (value === undefined && key !== "jobUid") continue;
    if (typeof value !== "string" || !uidPattern.test(value)) {
      return error("invalid_arguments", `${key} must contain 1-128 letters, digits, underscores, or hyphens.`);
    }
  }
  const { jobUid, deviceUid, siteUid } = params as {
    jobUid: string; deviceUid?: string; siteUid?: string;
  };
  if (siteUid !== undefined && deviceUid === undefined) {
    return error("invalid_arguments", "siteUid requires deviceUid to verify the device's site.");
  }

  try {
    // A job record has no device/site ownership fields in SDK 1.1.0. Use
    // the existing device and job-result endpoints when a check is requested.
    if (siteUid !== undefined) {
      const device = await client.devices.get(deviceUid!);
      if (!device || device.uid !== deviceUid) {
        return error("device_mismatch", "Datto did not confirm the requested device.");
      }
      if (device.siteUid !== siteUid) {
        return error("site_mismatch", "Datto did not confirm the requested device/site relationship.");
      }
    }

    const job = await client.jobs.get(jobUid);
    if (!job || job.uid !== jobUid) {
      return error("job_mismatch", "Datto did not confirm the requested job.");
    }
    let deviceStatus;
    if (deviceUid !== undefined) {
      const result = await client.jobs.results(jobUid, deviceUid);
      if (!result || result.jobUid !== jobUid || result.deviceUid !== deviceUid) {
        return error("device_mismatch", "Datto did not confirm the requested job/device relationship.");
      }
      deviceStatus = {
        uid: deviceUid,
        siteUid,
        status: status(result.status),
      };
    }

    // Fixed scalar allowlist: no names, actors, variables, components, output,
    // arbitrary nested fields, or unbounded strings from vendor responses.
    return {
      uid: jobUid,
      status: status(job.status),
      deviceCount: count(job.deviceCount),
      completedDeviceCount: count(job.completedDeviceCount),
      failedDeviceCount: count(job.failedDeviceCount),
      createdAt: timestamp(job.createdAt),
      startedAt: timestamp(job.startedAt),
      completedAt: timestamp(job.completedAt),
      device: deviceStatus,
    };
  } catch {
    // SDK errors can include provider bodies or OAuth details. Keep the new
    // tool's error contract independent of those untrusted details.
    return error("job_status_unavailable", "Datto job status or the requested relationship could not be verified.");
  }
}
