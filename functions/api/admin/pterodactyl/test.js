import { json, pteroRaw, requireAdmin } from "../../../_shared/ptero-utils.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "POST") {
    return json({ success: false, error: "Method not allowed", status: 405, details: "Use POST" }, 405);
  }
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return json({ success: false, error: "Unauthorized", status: 401, details: "Admin token missing or invalid" }, 401);

    const result = await pteroRaw(env, "/api/application/nodes");
    if (!result.success) {
      return json({
        success: false,
        error: result.error,
        status: result.status,
        details: result.details,
        endpoint: result.endpoint,
        apiKeyMissing: result.apiKeyMissing,
        panelUrlMissing: result.panelUrlMissing,
        checkedThroughBackendFunction: true,
      }, 200);
    }
    return json({
      success: true,
      message: "Pterodactyl API connected successfully",
      status: result.status || 200,
      details: result.details,
      endpoint: result.endpoint,
      nodes: result.data?.meta?.pagination?.total || result.data?.data?.length || 0,
    });
  } catch (error) {
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Backend route failed",
      status: 500,
      details: error instanceof Error ? error.stack || error.message : String(error),
    }, 200);
  }
}
