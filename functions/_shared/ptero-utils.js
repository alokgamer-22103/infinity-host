const DB = "(default)";
let cachedToken = null;
let cachedTokenExp = 0;

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export async function safeJsonResponse(res) {
  const text = await res.text();
  if (!text) return { data: {}, text: "" };
  try {
    return { data: JSON.parse(text), text };
  } catch {
    return { data: null, text };
  }
}

export function normalizePanelUrl(raw) {
  return String(raw || "")
    .trim()
    .replace(/[}\s]+$/g, "")
    .replace(/\/+$/g, "");
}

function base64url(input) {
  const bytes = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemToArrayBuffer(pem) {
  const clean = String(pem || "").replace(/\\n/g, "\n").replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function firebaseToken(env) {
  if (cachedToken && Date.now() < cachedTokenExp - 60_000) return cachedToken;
  const missing = ["FIREBASE_PROJECT_ID", "FIREBASE_CLIENT_EMAIL", "FIREBASE_PRIVATE_KEY"].filter((key) => !env[key]);
  if (missing.length) throw new Error(`Missing env vars: ${missing.join(", ")}`);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(env.FIREBASE_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const assertion = `${unsigned}.${base64url(new Uint8Array(signature))}`;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const { data, text } = await safeJsonResponse(res);
  if (!res.ok) throw new Error(data?.error_description || text.slice(0, 300) || "Firebase service account auth failed");
  cachedToken = data.access_token;
  cachedTokenExp = Date.now() + Number(data.expires_in || 3600) * 1000;
  return cachedToken;
}

function docUrl(env, path) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/${DB}/documents/${path}`;
}

function toFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") return Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(toFirestoreValue) } };
  if (typeof value === "object") return { mapValue: { fields: toFirestoreFields(value) } };
  return { stringValue: String(value) };
}

function toFirestoreFields(obj) {
  return Object.fromEntries(Object.entries(obj).map(([key, value]) => [key, toFirestoreValue(value)]));
}

function fromFirestoreValue(value) {
  if (!value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return value.booleanValue;
  if ("timestampValue" in value) return value.timestampValue;
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(fromFirestoreValue);
  if ("mapValue" in value) return fromFirestoreFields(value.mapValue.fields || {});
  return null;
}

function fromFirestoreFields(fields = {}) {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, fromFirestoreValue(value)]));
}

function fromDoc(doc) {
  if (!doc) return null;
  const id = String(doc.name || "").split("/").pop();
  return { ...fromFirestoreFields(doc.fields || {}), id };
}

async function firestoreFetch(env, url, init = {}) {
  const token = await firebaseToken(env);
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });
  const { data, text } = await safeJsonResponse(res);
  if (!res.ok || !data) throw new Error(data?.error?.message || text.slice(0, 300) || `Firestore request failed: ${res.status}`);
  return data;
}

export async function getDoc(env, path) {
  try {
    return fromDoc(await firestoreFetch(env, docUrl(env, path)));
  } catch (error) {
    if (String(error.message).includes("NOT_FOUND")) return null;
    throw error;
  }
}

async function createDoc(env, collection, data, id = "") {
  const suffix = id ? `?documentId=${encodeURIComponent(id)}` : "";
  const result = await firestoreFetch(env, `${docUrl(env, collection)}${suffix}`, {
    method: "POST",
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
  return fromDoc(result);
}

async function patchDoc(env, path, data) {
  const params = new URLSearchParams();
  Object.keys(data).forEach((key) => params.append("updateMask.fieldPaths", key));
  return firestoreFetch(env, `${docUrl(env, path)}?${params}`, {
    method: "PATCH",
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
}

export async function patchOrCreateDoc(env, path, data) {
  const existing = await getDoc(env, path);
  if (existing) return patchDoc(env, path, data);
  const [collection, id] = path.split("/");
  return createDoc(env, collection, data, id);
}

export async function queryDocs(env, collectionName, field, op, value, limit = 10) {
  const query = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: { fieldFilter: { field: { fieldPath: field }, op, value: toFirestoreValue(value) } },
      limit,
    },
  };
  const res = await firestoreFetch(env, `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/${DB}/documents:runQuery`, {
    method: "POST",
    body: JSON.stringify(query),
  });
  return res.filter((row) => row.document).map((row) => fromDoc(row.document));
}

export async function requireAdmin(env, request) {
  const token = (request.headers.get("Authorization") || "").replace("Bearer ", "");
  if (!token) return null;
  const admins = await queryDocs(env, "admin_users", "token", "EQUAL", token, 1);
  const admin = admins[0];
  return admin?.isActive === false ? null : admin;
}

export async function pteroConfig(env) {
  const saved = (await getDoc(env, "private_config/pterodactyl")) || {};
  return {
    panelUrl: normalizePanelUrl(saved.panelUrl || env.PTERO_PANEL_URL || ""),
    apiKey: String(saved.apiKey || env.PTERO_API_KEY || ""),
  };
}

export function diagnosticHint(detail) {
  const body = String(detail.details || "").toLowerCase();
  if (detail.apiKeyMissing) return "Application API key missing hai. Admin settings me ptla_ key save karo.";
  if (detail.panelUrlMissing) return "Pterodactyl Panel URL missing hai.";
  if (detail.status === 401 || detail.status === 403) return "Application API key wrong hai ya required permissions missing hain.";
  if (detail.status === 404) return "Endpoint not found. Panel URL me extra path/typo check karo.";
  if (body.includes("<html") || body.includes("<!doctype")) return "HTML response mila. Route/panel URL wrong ho sakta hai.";
  if (detail.status === 0) return "Backend function request fail hui. Cloudflare env vars/DNS/SSL check karo.";
  return "";
}

export async function pteroRaw(env, path) {
  const cfg = await pteroConfig(env);
  const endpoint = `${normalizePanelUrl(cfg.panelUrl)}${path}`;
  const baseDetail = {
    endpoint,
    status: 0,
    apiKeyMissing: !cfg.apiKey,
    panelUrlMissing: !cfg.panelUrl,
    checkedThroughBackendFunction: true,
  };
  if (!cfg.panelUrl || !cfg.apiKey) {
    const details = "Panel URL or Application API key is missing";
    return { success: false, status: 400, error: diagnosticHint({ ...baseDetail, details }) || details, details, ...baseDetail };
  }
  try {
    const res = await fetch(endpoint, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${cfg.apiKey}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });
    const { data, text } = await safeJsonResponse(res);
    const details = text.slice(0, 500);
    if (!res.ok || !data) {
      const detail = { ...baseDetail, status: res.status, details };
      return {
        success: false,
        error: data?.errors?.[0]?.detail || data?.message || diagnosticHint(detail) || "Pterodactyl API request failed",
        status: res.status,
        details,
        ...baseDetail,
      };
    }
    return { success: true, status: res.status, message: "Pterodactyl API connected", data, details, ...baseDetail };
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    return { success: false, error: diagnosticHint({ ...baseDetail, details }) || "Backend function failed to reach Pterodactyl", status: 0, details, ...baseDetail };
  }
}

export async function pteroList(env, path) {
  let page = 1;
  const out = [];
  while (page <= 20) {
    const sep = path.includes("?") ? "&" : "?";
    const result = await pteroRaw(env, `${path}${sep}per_page=100&page=${page}`);
    if (!result.success) throw new Error(`${result.error} (${result.status} ${result.endpoint}) ${result.details}`);
    const data = result.data || {};
    out.push(...(data.data || []).map((item) => item.attributes || item));
    const pagination = data.meta?.pagination;
    if (!pagination || page >= Number(pagination.total_pages || 1)) break;
    page += 1;
  }
  return out;
}

function dockerImagesFromEgg(egg) {
  const images = egg.docker_images || egg.dockerImages || {};
  if (Array.isArray(images)) return images;
  return Object.values(images).filter(Boolean);
}

function variablesFromEgg(egg) {
  const variables = egg.relationships?.variables?.data || egg.variables || [];
  const entries = variables.map((item) => item.attributes || item).filter(Boolean);
  return Object.fromEntries(entries.map((v) => [v.env_variable || v.name, v.default_value || ""]));
}

export async function syncPterodactylCatalog(env) {
  const [locations, nodes, nests] = await Promise.all([
    pteroList(env, "/api/application/locations"),
    pteroList(env, "/api/application/nodes"),
    pteroList(env, "/api/application/nests"),
  ]);
  const allocations = [];
  for (const node of nodes) {
    const nodeId = node.id;
    const list = await pteroList(env, `/api/application/nodes/${nodeId}/allocations`).catch(() => []);
    allocations.push(...list.map((item) => ({ ...item, node: nodeId, nodeId })));
  }
  const eggs = [];
  for (const nest of nests) {
    const nestId = nest.id;
    const list = await pteroList(env, `/api/application/nests/${nestId}/eggs?include=variables`).catch(() => []);
    eggs.push(...list.map((egg) => ({
      ...egg,
      nest: nestId,
      nestId,
      dockerImages: dockerImagesFromEgg(egg),
      startup: egg.startup || "",
      environment: variablesFromEgg(egg),
    })));
  }
  const catalog = {
    locations,
    nodes,
    allocations,
    nests,
    eggs,
    dockerImages: Array.from(new Set(eggs.flatMap((egg) => egg.dockerImages || []))).sort(),
    syncedAt: new Date().toISOString(),
  };
  await patchOrCreateDoc(env, "pterodactyl/catalog", catalog);
  return catalog;
}
