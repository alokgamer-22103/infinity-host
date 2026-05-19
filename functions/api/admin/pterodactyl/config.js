import { getDoc, json, normalizePanelUrl, patchOrCreateDoc, pteroConfig, requireAdmin } from "../../../_shared/ptero-utils.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (!["GET", "PUT"].includes(request.method)) {
    return json({ success: false, error: "Method not allowed", status: 405, details: "Use GET or PUT" }, 405);
  }
  try {
    const admin = await requireAdmin(env, request);
    if (!admin) return json({ success: false, error: "Unauthorized", status: 401, details: "Admin token missing or invalid" }, 401);

    if (request.method === "GET") {
      const cfg = await pteroConfig(env);
      return json({ success: true, panelUrl: cfg.panelUrl, hasApiKey: !!cfg.apiKey, status: 200 });
    }

    const body = await request.json().catch(() => ({}));
    const panelUrl = normalizePanelUrl(body.panelUrl || "");
    const apiKey = String(body.apiKey || "").trim();
    if (!panelUrl) return json({ success: false, error: "Panel URL is required", status: 400, details: "" }, 400);

    const existing = (await getDoc(env, "private_config/pterodactyl")) || {};
    const next = {
      panelUrl,
      apiKey: apiKey || existing.apiKey || "",
      updatedAt: new Date().toISOString(),
      updatedBy: admin.email || admin.username || admin.id || "",
    };
    await patchOrCreateDoc(env, "private_config/pterodactyl", next);
    return json({ success: true, panelUrl, hasApiKey: !!next.apiKey, status: 200 });
  } catch (error) {
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Config route failed",
      status: 500,
      details: error instanceof Error ? error.stack || error.message : String(error),
    }, 200);
  }
}
