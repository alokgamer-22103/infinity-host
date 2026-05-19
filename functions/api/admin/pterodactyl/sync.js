import { json, requireAdmin, syncPterodactylCatalog } from "../../../_shared/ptero-utils.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "POST") {
    return json({ success: false, error: "Method not allowed", status: 405, details: "Use POST" }, 405);
  }
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return json({ success: false, error: "Unauthorized", status: 401, details: "Admin token missing or invalid" }, 401);

    const catalog = await syncPterodactylCatalog(env);
    return json({
      success: true,
      message: "Pterodactyl data synced successfully",
      status: 200,
      syncedAt: catalog.syncedAt,
      counts: {
        locations: catalog.locations.length,
        nodes: catalog.nodes.length,
        allocations: catalog.allocations.length,
        nests: catalog.nests.length,
        eggs: catalog.eggs.length,
        dockerImages: catalog.dockerImages.length,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Sync failed";
    const match = message.match(/\((\d+)\s+([^)]+)\)\s*([\s\S]*)$/);
    return json({
      success: false,
      error: "Pterodactyl sync failed",
      status: match ? Number(match[1]) : 500,
      endpoint: match ? match[2] : "",
      details: match ? match[3].slice(0, 500) : message.slice(0, 500),
    }, 200);
  }
}
