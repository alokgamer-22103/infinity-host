import { getDoc, json, requireAdmin } from "../../../_shared/ptero-utils.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET") {
    return json({ success: false, error: "Method not allowed", status: 405, details: "Use GET" }, 405);
  }
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return json({ success: false, error: "Unauthorized", status: 401, details: "Admin token missing or invalid" }, 401);
    const catalog = (await getDoc(env, "pterodactyl/catalog")) || {
      locations: [],
      nodes: [],
      allocations: [],
      nests: [],
      eggs: [],
      dockerImages: [],
    };
    return json({ success: true, status: 200, ...catalog });
  } catch (error) {
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Catalog route failed",
      status: 500,
      details: error instanceof Error ? error.stack || error.message : String(error),
      locations: [],
      nodes: [],
      allocations: [],
      nests: [],
      eggs: [],
      dockerImages: [],
    }, 200);
  }
}
