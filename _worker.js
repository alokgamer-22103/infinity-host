const DB = "(default)";
let cachedToken = null;
let cachedTokenExp = 0;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function safeJsonResponse(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Non JSON response (${res.status} ${res.url || "unknown URL"}): ${text.slice(0, 300)}`);
  }
}

function normalizePanelUrl(raw) {
  return String(raw || "")
    .trim()
    .replace(/[}\s]+$/g, "")
    .replace(/\/+$/g, "");
}

function diagnosticHint(detail) {
  const body = String(detail.body || "");
  const lower = body.toLowerCase();
  if (detail.missingApiKey) return "Application API Key missing hai. Admin settings me ptla_ key save karo.";
  if (detail.missingPanelUrl) return "Panel URL missing hai. Example: https://panel.infinityhost.online";
  if (detail.networkError) return "Backend Worker Pterodactyl panel tak network request nahi kar pa raha. Panel URL/DNS/SSL check karo.";
  if (detail.status === 401 || detail.status === 403) return "API key missing/wrong hai ya Application API key me required permissions nahi hain.";
  if (detail.status === 404) return "API endpoint nahi mila. Panel URL me extra path/typo check karo. URL sirf domain hona chahiye, jaise https://panel.infinityhost.online";
  if (lower.includes("<html") || lower.includes("<!doctype")) return "Non-JSON/HTML response mila. Ya to panel URL galat hai, ya backend route Cloudflare Worker se serve nahi ho raha.";
  if (detail.status === 0) return "Backend route failed before HTTP response. Worker deployment/env vars check karo.";
  if (detail.status >= 500) return "Pterodactyl panel server-side error return kar raha hai. Panel logs check karo.";
  return "Pterodactyl API ne expected JSON success response nahi diya. Status, endpoint aur body dekho.";
}

async function pteroRawRequest(env, path, init = {}, config = null) {
  const cfg = config || await pteroConfig(env);
  const detail = {
    endpoint: "",
    status: 0,
    ok: false,
    body: "",
    contentType: "",
    missingApiKey: !cfg.apiKey,
    missingPanelUrl: !cfg.panelUrl,
    networkError: "",
  };
  if (!cfg.panelUrl || !cfg.apiKey) {
    detail.hint = diagnosticHint(detail);
    return { detail, data: null };
  }
  const base = normalizePanelUrl(cfg.panelUrl);
  detail.endpoint = `${base}${path}`;
  try {
    const res = await fetch(detail.endpoint, {
      ...init,
      headers: {
        Authorization: `Bearer ${cfg.apiKey}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
    });
    detail.status = res.status;
    detail.ok = res.ok;
    detail.contentType = res.headers.get("content-type") || "";
    const text = await res.text();
    detail.body = text.slice(0, 500);
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        detail.hint = diagnosticHint(detail);
        return { detail, data: null };
      }
    }
    if (!res.ok) {
      detail.hint = diagnosticHint(detail);
    }
    return { detail, data };
  } catch (error) {
    detail.networkError = error instanceof Error ? error.message : String(error);
    detail.body = detail.networkError.slice(0, 500);
    detail.hint = diagnosticHint(detail);
    return { detail, data: null };
  }
}

function base64url(input) {
  const bytes = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemToArrayBuffer(pem) {
  const clean = pem.replace(/\\n/g, "\n").replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function firebaseToken(env) {
  if (cachedToken && Date.now() < cachedTokenExp - 60_000) return cachedToken;
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
  const data = await safeJsonResponse(res);
  if (!res.ok) throw new Error(data.error_description || "Firebase service account auth failed");
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
  const data = await safeJsonResponse(res).catch((error) => ({ parseError: error.message }));
  if (!res.ok || data?.parseError) {
    const body = data?.parseError || JSON.stringify(data).slice(0, 300);
    const message = data?.error?.message || data?.parseError || "Firestore request failed";
    throw new Error(`${message} (${res.status} ${res.url}) ${body}`);
  }
  return data;
}

async function getDoc(env, path) {
  try {
    return fromDoc(await firestoreFetch(env, docUrl(env, path)));
  } catch (error) {
    if (String(error.message).includes("NOT_FOUND")) return null;
    throw error;
  }
}

async function patchDoc(env, path, data) {
  const params = new URLSearchParams();
  Object.keys(data).forEach((key) => params.append("updateMask.fieldPaths", key));
  return firestoreFetch(env, `${docUrl(env, path)}?${params}`, {
    method: "PATCH",
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
}

async function createDoc(env, collection, data, id = "") {
  const suffix = id ? `?documentId=${encodeURIComponent(id)}` : "";
  const result = await firestoreFetch(env, `${docUrl(env, collection)}${suffix}`, {
    method: "POST",
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
  return fromDoc(result);
}

async function queryDocs(env, collectionName, field, op, value, limit = 10) {
  const query = {
    structuredQuery: {
      from: [{ collectionId: collectionName }],
      where: {
        fieldFilter: {
          field: { fieldPath: field },
          op,
          value: toFirestoreValue(value),
        },
      },
      limit,
    },
  };
  const res = await firestoreFetch(env, `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/${DB}/documents:runQuery`, {
    method: "POST",
    body: JSON.stringify(query),
  });
  return res.filter((row) => row.document).map((row) => fromDoc(row.document));
}

async function settings(env) {
  return (await getDoc(env, "settings/site")) || {};
}

async function verifyRazorpaySignature(body, signature, secret) {
  if (!signature || !secret) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  const expected = [...new Uint8Array(signed)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return timingSafeEqual(expected, signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function now() {
  return new Date().toISOString();
}

function parseAmount(text, fallback = 0) {
  const match = String(text || "").match(/(\d+(?:\.\d+)?)/);
  return match ? Number(match[1]) : fallback;
}

function planLimits(plan) {
  const memory = Number(plan.pteroMemoryMb || 0) || Math.round(parseAmount(plan.ram, 1) * 1024);
  const disk = Number(plan.pteroDiskMb || 0) || Math.round(parseAmount(plan.ssd, 5) * 1024);
  const cpu = Number(plan.pteroCpuPercent || 0) || Math.round(parseAmount(plan.players, 100));
  return {
    memory: Math.max(128, memory),
    swap: Number(plan.pteroSwapMb || 0),
    disk: Math.max(512, disk),
    io: Math.max(10, Number(plan.pteroIoWeight || 500)),
    cpu: Math.max(10, cpu),
    threads: String(plan.pteroCpuPinning || "").trim(),
    oomDisabled: !!plan.pteroOomDisabled,
    databases: Math.max(0, Number(plan.pteroDatabases || 1)),
    allocations: Math.max(0, Number(plan.pteroAllocations || 1)),
    backups: Math.max(0, Number(plan.pteroBackups || 1)),
  };
}

function parseJsonObject(raw, fallback = {}) {
  if (!raw) return fallback;
  if (typeof raw === "object") return raw;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function randomId(length = 10) {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

function randomPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => chars[byte % chars.length]).join("");
}

async function pteroConfig(env) {
  const saved = (await getDoc(env, "private_config/pterodactyl")) || {};
  return {
    panelUrl: normalizePanelUrl(saved.panelUrl || env.PTERO_PANEL_URL || ""),
    apiKey: String(saved.apiKey || env.PTERO_API_KEY || ""),
  };
}

async function pteroFetch(env, path, init = {}, config = null) {
  const cfg = config || await pteroConfig(env);
  if (!cfg.panelUrl || !cfg.apiKey) throw new Error("Pterodactyl Panel URL or Application API Key is not configured");
  const { detail, data } = await pteroRawRequest(env, path, init, cfg);
  if (!detail.ok || !data) {
    const message = pteroApiErrorText(data) || detail.hint || "Pterodactyl API failed";
    throw new Error(`${message} (${detail.status} ${detail.endpoint}) ${String(detail.body || "").slice(0, 300)}`);
  }
  return data;
}

function pteroApiErrorText(data) {
  const errors = Array.isArray(data?.errors) ? data.errors : [];
  if (!errors.length) return data?.message || "";
  return errors.map((item) => {
    const field = item?.source?.field || item?.source?.pointer || item?.field || "";
    const detail = item?.detail || item?.message || item?.code || "Validation error";
    return field ? `${field}: ${detail}` : detail;
  }).join("; ");
}

async function pteroList(env, path, config = null) {
  let page = 1;
  const out = [];
  while (page <= 20) {
    const sep = path.includes("?") ? "&" : "?";
    const data = await pteroFetch(env, `${path}${sep}per_page=100&page=${page}`, {}, config);
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

async function syncPterodactylCatalog(env) {
  const cfg = await pteroConfig(env);
  const [locations, nodes, nests] = await Promise.all([
    pteroList(env, "/api/application/locations", cfg),
    pteroList(env, "/api/application/nodes", cfg),
    pteroList(env, "/api/application/nests", cfg),
  ]);
  const allocations = [];
  for (const node of nodes) {
    const nodeId = node.id;
    const list = await pteroList(env, `/api/application/nodes/${nodeId}/allocations`, cfg).catch(() => []);
    allocations.push(...list.map((item) => ({ ...item, node: nodeId, nodeId })));
  }
  const eggs = [];
  for (const nest of nests) {
    const nestId = nest.id;
    const list = await pteroList(env, `/api/application/nests/${nestId}/eggs?include=variables`, cfg).catch(() => []);
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
    syncedAt: now(),
  };
  await patchOrCreateDoc(env, "pterodactyl/catalog", catalog);
  return catalog;
}

async function patchOrCreateDoc(env, path, data) {
  const existing = await getDoc(env, path);
  if (existing) return patchDoc(env, path, data);
  const [collection, id] = path.split("/");
  return createDoc(env, collection, data, id);
}

async function createRandomPteroUser(env, order) {
  if (order.pteroUserId) {
    const existing = await pteroFetch(env, `/api/application/users/${order.pteroUserId}`).catch(() => null);
    const attrs = existing?.attributes || existing?.data?.attributes;
    if (attrs?.id) {
      return {
        user: attrs,
        credentials: {
          email: order.serverEmail || attrs.email || "",
          password: order.serverPassword || "",
          username: order.pteroUsername || attrs.username || "",
        },
      };
    }
  }
  const suffix = randomId(12);
  const credentials = {
    email: `server-${suffix}@infinityhost.online`,
    password: randomPassword(),
    username: `ih_${suffix}`.slice(0, 24),
    firstName: `Infinity${suffix.slice(0, 4)}`,
    lastName: `Host${suffix.slice(4, 8)}`,
  };
  const created = await pteroFetch(env, "/api/application/users", {
    method: "POST",
    body: JSON.stringify({
      email: credentials.email,
      username: credentials.username,
      first_name: credentials.firstName,
      last_name: credentials.lastName,
      password: credentials.password,
      external_id: `order-${order.id || suffix}`,
    }),
  });
  return { user: created.attributes || created.data?.attributes, credentials };
}

async function createPteroServer(env, order, plan, pteroUser) {
  const limits = planLimits(plan);
  const egg = Number(plan.pteroEggId || env.PTERO_DEFAULT_EGG_ID || 0);
  const node = Number(plan.pteroNodeId || env.PTERO_DEFAULT_NODE_ID || 0);
  const allocation = Number(plan.pteroAllocationId || env.PTERO_DEFAULT_ALLOCATION_ID || 0);
  if (!egg || !node || !allocation) throw new Error("Plan missing Pterodactyl Egg, Node, or Allocation mapping");
  const environment = {
    SERVER_JARFILE: "server.jar",
    ...parseJsonObject(env.PTERO_DEFAULT_ENVIRONMENT, {}),
    ...parseJsonObject(plan.pteroEnvironment, {}),
  };
  const additionalAllocations = Array.isArray(plan.pteroAdditionalAllocationIds)
    ? plan.pteroAdditionalAllocationIds.map(Number).filter(Boolean)
    : String(plan.pteroAdditionalAllocationIds || "").split(",").map((item) => Number(item.trim())).filter(Boolean);
  const serverLimits = {
    memory: limits.memory,
    swap: limits.swap,
    disk: limits.disk,
    io: limits.io,
    cpu: limits.cpu,
    oom_disabled: limits.oomDisabled,
  };
  if (limits.threads) serverLimits.threads = limits.threads;
  const result = await pteroFetch(env, "/api/application/servers", {
    method: "POST",
    body: JSON.stringify({
      name: `${order.planName || "Server"} - ${order.customerName || order.customerEmail || order.id}`,
      user: pteroUser.id,
      egg,
      docker_image: plan.pteroDockerImage || env.PTERO_DEFAULT_DOCKER_IMAGE || "ghcr.io/pterodactyl/yolks:java_21",
      startup: plan.pteroStartup || env.PTERO_DEFAULT_STARTUP || "java -Xms128M -XX:MaxRAMPercentage=95.0 -jar server.jar",
      environment,
      limits: serverLimits,
      feature_limits: {
        databases: limits.databases,
        allocations: limits.allocations,
        backups: limits.backups,
      },
      allocation: additionalAllocations.length ? { default: allocation, additional: additionalAllocations } : { default: allocation },
      skip_scripts: !!plan.pteroSkipScripts,
      start_on_completion: true,
    }),
  });
  return result.attributes || result.data?.attributes;
}

function validateProvisioningPlan(plan) {
  const missing = [];
  if (!plan?.id) missing.push("Plan ID");
  if (!String(plan?.pteroNodeId || "").trim()) missing.push("Node");
  if (!String(plan?.pteroEggId || "").trim()) missing.push("Egg");
  if (!String(plan?.pteroAllocationId || "").trim()) missing.push("Allocation / Port");
  if (!String(plan?.pteroDockerImage || "").trim()) missing.push("Docker Image");
  if (!String(plan?.pteroStartup || "").trim()) missing.push("Startup Command");
  if (!String(plan?.ram || "").trim()) missing.push("RAM");
  if (!String(plan?.ssd || "").trim()) missing.push("SSD Storage");
  if (!String(plan?.players || "").trim()) missing.push("CPU / vCPU Specs");
  if (missing.length) {
    throw new Error(`Plan mapping incomplete. Missing: ${missing.join(", ")}. Edit this plan in Admin > Pricing, fill Auto Provisioning Mapping, then Save Changes.`);
  }
}

async function writeProvisionLog(env, order, status, message, extra = {}) {
  await createDoc(env, "provisioning_logs", {
    orderId: order.id || "",
    paymentId: order.razorpayPaymentId || order.cashfreeOrderId || "",
    customerEmail: order.customerEmail || "",
    status,
    message,
    createdAt: now(),
    ...extra,
  }).catch(() => {});
}

async function provisionOrder(env, order, source = "webhook") {
  if (!order?.id) throw new Error("Order not found");
  if (order.status !== "PAID" && order.status !== "SUCCESS") throw new Error("Order is not paid");
  if (order.provisioningStatus === "Active" || order.serverProvisioned) {
    return { skipped: true, reason: "already_active" };
  }
  const attempts = Number(order.provisioningAttempts || 0) + 1;
  await patchDoc(env, `orders/${order.id}`, {
    provisioningStatus: "Creating",
    provisioningAttempts: attempts,
    provisioningLog: "",
    provisioningSource: source,
    provisioningStartedAt: now(),
  });
  try {
    const plan = (await getDoc(env, `plans/${order.planId}`)) || order;
    validateProvisioningPlan(plan);
    const { user: pteroUser, credentials } = await createRandomPteroUser(env, order);
    await patchDoc(env, `orders/${order.id}`, {
      serverEmail: credentials.email,
      serverPassword: credentials.password,
      pteroUsername: credentials.username,
      pteroUserId: String(pteroUser.id || ""),
      provisioningLog: "Panel user created, creating server...",
    });
    const server = await createPteroServer(env, order, plan, pteroUser);
    const cfg = await pteroConfig(env);
    const panelUrl = cfg.panelUrl || "";
    const serverConfiguration = [
      `Panel URL: ${panelUrl}`,
      `Panel Email: ${credentials.email}`,
      `Panel Username: ${credentials.username}`,
      `Panel Password: ${credentials.password}`,
      `Pterodactyl Server ID: ${server.id || server.identifier || ""}`,
      `Plan: ${order.planName || ""}`,
      `Website RAM: ${plan.ram || ""}`,
      `Website Disk: ${plan.ssd || ""}`,
      `Website CPU: ${plan.players || ""}`,
      `Server Memory: ${plan.pteroMemoryMb || ""} MB`,
      `Server Disk: ${plan.pteroDiskMb || ""} MB`,
      `Server CPU: ${plan.pteroCpuPercent || ""}%`,
      `Databases: ${plan.pteroDatabases ?? ""}`,
      `Backups: ${plan.pteroBackups ?? ""}`,
      `Allocations: ${plan.pteroAllocations ?? ""}`,
    ].filter(Boolean).join("\n");
    await patchDoc(env, `orders/${order.id}`, {
      provisioningStatus: "Active",
      serverProvisioned: true,
      provisioningLog: "Server created successfully",
      provisioningCompletedAt: now(),
      serverEmail: credentials.email,
      serverPassword: credentials.password,
      pteroUsername: credentials.username,
      panelUrl,
      pteroUserId: String(pteroUser.id || ""),
      pteroServerId: String(server.id || server.identifier || ""),
      serverConfiguration,
    });
    await notifyBillingPanel(env, order, server).catch((error) => writeProvisionLog(env, order, "billing_notify_failed", error.message));
    await writeProvisionLog(env, order, "active", "Server created successfully", { pteroServerId: String(server.id || server.identifier || "") });
    return { success: true, serverId: server.id || server.identifier };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Provisioning failed";
    await patchDoc(env, `orders/${order.id}`, {
      provisioningStatus: "Failed",
      provisioningLog: message,
      provisioningFailedAt: now(),
    });
    await writeProvisionLog(env, order, "failed", message);
    throw error;
  }
}

async function notifyBillingPanel(env, order, server) {
  if (!env.BILLING_PANEL_URL || !env.BILLING_API_TOKEN) return;
  const base = env.BILLING_PANEL_URL.replace(/\/$/, "");
  const res = await fetch(`${base}/api/provisioning/order-completed`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.BILLING_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ orderId: order.id, customerEmail: order.customerEmail, pteroServerId: server.id || server.identifier }),
  });
  if (!res.ok) throw new Error(`Billing panel notify failed: ${res.status}`);
}

async function orderFromPayment(env, payment) {
  const paymentId = payment.id || "";
  const byPayment = await queryDocs(env, "orders", "razorpayPaymentId", "EQUAL", paymentId, 1);
  if (byPayment[0]) return byPayment[0];
  const byCashfreeId = await queryDocs(env, "orders", "cashfreeOrderId", "EQUAL", paymentId, 1);
  if (byCashfreeId[0]) return byCashfreeId[0];
  return null;
}

async function createOrderFromPayment(env, payment) {
  const notes = payment.notes || {};
  const planId = String(notes.planId || notes.plan_id || "");
  if (!planId) return null;
  const plan = await getDoc(env, `plans/${planId}`).catch(() => null);
  const amount = Number(payment.amount || 0) / 100;
  return createDoc(env, "orders", {
    planId,
    planName: String(notes.planName || notes.plan_name || plan?.name || "Server Plan"),
    category: String(notes.category || plan?.category || ""),
    billingCycle: String(notes.billingCycle || notes.billing_cycle || "monthly"),
    customerName: String(notes.customerName || notes.customer_name || "Customer"),
    customerEmail: String(notes.customerEmail || notes.customer_email || payment.email || ""),
    amountPaid: amount,
    currency: String(payment.currency || "INR"),
    status: "PAID",
    paymentMethod: "razorpay",
    cashfreeOrderId: payment.id,
    razorpayPaymentId: payment.id,
    razorpayOrderId: payment.order_id || payment.id,
    provisioningStatus: "Pending",
    createdAt: now(),
    paymentVerifiedAt: now(),
  }, `rzp-${payment.id}`);
}

async function handleRazorpayWebhook(request, env) {
  const body = await request.text();
  const sig = request.headers.get("x-razorpay-signature") || "";
  const siteSettings = await settings(env);
  const secret = env.RAZORPAY_WEBHOOK_SECRET || siteSettings.razorpay_webhook_secret || "";
  if (!(await verifyRazorpaySignature(body, sig, secret))) return json({ error: "Invalid Razorpay signature" }, 401);
  const event = JSON.parse(body);
  const payment = event?.payload?.payment?.entity || {};
  const eventType = String(event.event || "");
  const paid = eventType === "payment.captured" && payment.status === "captured";
  if (!paid) return json({ ignored: true, reason: "not_paid_event", event: eventType });
  const eventId = `razorpay-${payment.id}`;
  if (await getDoc(env, `webhook_events/${eventId}`)) return json({ duplicate: true });
  await createDoc(env, "webhook_events", { id: eventId, event: eventType, paymentId: payment.id, createdAt: now() }, eventId);
  let order = await orderFromPayment(env, payment);
  if (!order) order = await createOrderFromPayment(env, payment);
  if (!order) {
    await writeProvisionLog(env, { razorpayPaymentId: payment.id }, "failed", "Paid webhook received but matching order was not found");
    return json({ error: "Matching order not found" }, 404);
  }
  await patchDoc(env, `orders/${order.id}`, {
    status: "PAID",
    cashfreeOrderId: order.cashfreeOrderId || payment.id,
    razorpayPaymentId: payment.id,
    paymentVerifiedAt: now(),
  });
  const updatedOrder = { ...order, status: "PAID", razorpayPaymentId: payment.id, cashfreeOrderId: order.cashfreeOrderId || payment.id };
  const result = await provisionOrder(env, updatedOrder, "razorpay_webhook");
  return json({ ok: true, result });
}

async function requireAdmin(env, request) {
  const token = (request.headers.get("Authorization") || "").replace("Bearer ", "");
  if (!token) return null;
  const admins = await queryDocs(env, "admin_users", "token", "EQUAL", token, 1);
  const admin = admins[0];
  return admin?.isActive === false ? null : admin;
}

async function handlePteroConfig(request, env) {
  const admin = await requireAdmin(env, request);
  if (!admin) return json({ error: "Unauthorized" }, 401);
  if (request.method === "GET") {
    const cfg = await pteroConfig(env);
    return json({ panelUrl: cfg.panelUrl, hasApiKey: !!cfg.apiKey });
  }
  const body = await request.json().catch(() => ({}));
  const panelUrl = normalizePanelUrl(body.panelUrl || "");
  const apiKey = String(body.apiKey || "").trim();
  if (!panelUrl) return json({ error: "Panel URL is required" }, 400);
  const existing = await pteroConfig(env);
  const next = {
    panelUrl,
    apiKey: apiKey || existing.apiKey || "",
    updatedAt: now(),
    updatedBy: admin.email || admin.username || admin.id || "",
  };
  await patchOrCreateDoc(env, "private_config/pterodactyl", next);
  return json({ panelUrl, hasApiKey: !!next.apiKey });
}

async function handlePteroTest(request, env) {
  const admin = await requireAdmin(env, request);
  if (!admin) return json({ error: "Unauthorized" }, 401);
  const cfg = await pteroConfig(env);
  const endpointPath = "/api/application/nodes";
  const { detail, data } = await pteroRawRequest(env, endpointPath, { method: "GET" }, cfg);
  const result = {
    success: detail.ok && !!data,
    ok: detail.ok && !!data,
    message: detail.ok && data ? "Pterodactyl connection successful" : "Connection test failed",
    status: detail.status,
    nodes: data?.meta?.pagination?.total || data?.data?.length || 0,
    diagnostic: {
      status: detail.status,
      endpoint: detail.endpoint || `${normalizePanelUrl(cfg.panelUrl)}${endpointPath}`,
      responseBody: detail.body || "",
      contentType: detail.contentType || "",
      hint: detail.hint || "",
      apiKeyMissing: detail.missingApiKey,
      panelUrlMissing: detail.missingPanelUrl,
      backendRouteFailed: !!detail.networkError || detail.status === 0,
      corsFrontendBlocked: false,
      checkedThroughBackendWorker: true,
    },
  };
  if (!result.ok) {
    await createDoc(env, "pterodactyl_logs", {
      action: "test_connection",
      status: result.diagnostic.status,
      endpoint: result.diagnostic.endpoint,
      responseBody: result.diagnostic.responseBody,
      hint: result.diagnostic.hint,
      createdAt: now(),
      createdBy: admin.email || admin.username || admin.id || "",
    }).catch(() => {});
    return json({ ...result, error: result.diagnostic.hint || result.message }, 502);
  }
  return json(result);
}

async function handlePteroSync(request, env) {
  const admin = await requireAdmin(env, request);
  if (!admin) return json({ error: "Unauthorized" }, 401);
  try {
    const catalog = await syncPterodactylCatalog(env);
    return json({
      success: true,
      ok: true,
      status: 200,
      message: "Pterodactyl data synced successfully",
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
    const diagnostic = {
      status: match ? Number(match[1]) : 0,
      endpoint: match ? match[2] : "",
      responseBody: match ? match[3].slice(0, 500) : message.slice(0, 500),
      hint: message,
      apiKeyMissing: message.toLowerCase().includes("api key") && message.toLowerCase().includes("missing"),
      backendRouteFailed: message.toLowerCase().includes("network") || message.toLowerCase().includes("fetch"),
      checkedThroughBackendWorker: true,
    };
    await createDoc(env, "pterodactyl_logs", {
      action: "sync",
      status: diagnostic.status,
      endpoint: diagnostic.endpoint,
      responseBody: diagnostic.responseBody,
      hint: diagnostic.hint,
      createdAt: now(),
      createdBy: admin.email || admin.username || admin.id || "",
    }).catch(() => {});
    return json({ success: false, ok: false, error: "Sync failed", status: diagnostic.status || 500, diagnostic }, 502);
  }
}

async function handlePteroCatalog(request, env) {
  const admin = await requireAdmin(env, request);
  if (!admin) return json({ error: "Unauthorized" }, 401);
  const catalog = (await getDoc(env, "pterodactyl/catalog")) || { locations: [], nodes: [], allocations: [], nests: [], eggs: [], dockerImages: [] };
  return json(catalog);
}

async function handleRetry(request, env) {
  const admin = await requireAdmin(env, request);
  if (!admin) return json({ error: "Unauthorized" }, 401);
  const body = await request.json().catch(() => ({}));
  const orderId = String(body.orderId || "");
  if (!orderId) return json({ error: "orderId is required" }, 400);
  const order = await getDoc(env, `orders/${orderId}`);
  if (!order) return json({ error: "Order not found" }, 404);
  if (order.status !== "PAID" && order.status !== "SUCCESS") return json({ error: "Only paid orders can be provisioned" }, 400);
  const result = await provisionOrder(env, order, "admin_retry");
  return json({ ok: true, result });
}

function missingEnv(env) {
  return ["FIREBASE_PROJECT_ID", "FIREBASE_CLIENT_EMAIL", "FIREBASE_PRIVATE_KEY"].filter((key) => !env[key]);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/razorpay/webhook" && request.method === "POST") {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handleRazorpayWebhook(request, env);
      }
      if (url.pathname === "/api/admin/provisioning/retry" && request.method === "POST") {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handleRetry(request, env);
      }
      if (url.pathname === "/api/admin/pterodactyl/config" && ["GET", "PUT"].includes(request.method)) {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handlePteroConfig(request, env);
      }
      if (url.pathname === "/api/admin/pterodactyl/test" && request.method === "POST") {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handlePteroTest(request, env);
      }
      if (url.pathname === "/api/admin/pterodactyl/sync" && request.method === "POST") {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handlePteroSync(request, env);
      }
      if (url.pathname === "/api/admin/pterodactyl/catalog" && request.method === "GET") {
        const missing = missingEnv(env);
        if (missing.length) return json({ error: `Missing env vars: ${missing.join(", ")}` }, 500);
        return handlePteroCatalog(request, env);
      }
      return env.ASSETS.fetch(request);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "Server error" }, 500);
    }
  },
};
