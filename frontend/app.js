
const API_BASE = window.location.protocol === "file:"
    ? "http://127.0.0.1:8000"
    : window.location.origin;

let endpoints = [];
let selected = null;

const $ = (selector) => document.querySelector(selector);

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;",
        '"': "&quot;", "'": "&#39;"
    }[ch]));
}

function methodHTML(method) {
    const known = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    const cls = known.includes(method) ? method : "OTHER";
    return `<span class="method ${cls}">${escapeHTML(method)}</span>`;
}

function rowHTML(endpoint, buttonText = "Open") {
    return `
      <div class="route-row">
        ${methodHTML(endpoint.method)}
        <code>${escapeHTML(endpoint.path)}</code>
        <button class="secondary" data-endpoint="${escapeHTML(endpoint.id)}">${buttonText}</button>
      </div>`;
}

function routeMatches(endpoint, words) {
    const text = `${endpoint.path} ${endpoint.summary} ${endpoint.tags.join(" ")}`.toLowerCase();
    return words.some(word => text.includes(word));
}

function renderGroup(id, words) {
    const matches = endpoints.filter(ep => routeMatches(ep, words));
    $(id).innerHTML = matches.length
        ? matches.map(ep => rowHTML(ep)).join("")
        : '<p class="muted">No matching routes were found in the API schema.</p>';
}

async function loadAPI() {
    $("#connection").textContent = "Connecting...";
    try {
        const response = await fetch(`${API_BASE}/openapi.json`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const schema = await response.json();

        endpoints = Object.entries(schema.paths || {}).flatMap(([path, pathItem]) =>
            Object.entries(pathItem).filter(([method, operation]) =>
                ["get", "post", "put", "patch", "delete", "options", "head"].includes(method.toLowerCase())
                && operation && typeof operation === "object"
            ).map(([method, operation]) => ({
                id: `${method.toUpperCase()} ${path}`,
                method: method.toUpperCase(),
                path,
                summary: operation.summary || operation.operationId || "API operation",
                description: operation.description || "",
                tags: operation.tags || [],
                parameters: [...(pathItem.parameters || []), ...(operation.parameters || [])],
                bodySchema: operation.requestBody?.content?.["application/json"]?.schema || null,
                requiredBody: Boolean(operation.requestBody?.required)
            }))
        ).sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));

        $("#connection").textContent = "● API connected";
        $("#apiStatus").textContent = "Online";
        $("#routeCount").textContent = endpoints.length;

        $("#preview").innerHTML = endpoints.slice(0, 6).map(ep => rowHTML(ep, "Explore")).join("");
        renderGroup("#studentRoutes", ["student", "pii", "user"]);
        renderGroup("#gradeRoutes", ["grade", "mark", "score"]);
        renderGroup("#certificateRoutes", ["certificate", "sign", "verify"]);
        renderAllRoutes();
    } catch (error) {
        $("#connection").textContent = "API unavailable";
        $("#apiStatus").textContent = "Offline";
        $("#routeCount").textContent = "—";
        $("#preview").textContent =
            `Could not load ${API_BASE}/openapi.json. Check that FastAPI is running and CORS permits this page.`;
        $("#allRoutes").textContent = "API connection failed. Check Connection settings or API_BASE.";
        console.error(error);
    }
}

function renderAllRoutes() {
    const query = $("#search").value.toLowerCase();
    const filtered = endpoints.filter(ep =>
        `${ep.path} ${ep.method} ${ep.summary} ${ep.tags.join(" ")}`
            .toLowerCase().includes(query)
    );

    $("#allRoutes").innerHTML = filtered.length
        ? filtered.map(ep => `
            <button class="route-choice ${selected?.id === ep.id ? "selected" : ""}"
                    data-endpoint="${escapeHTML(ep.id)}">
                ${methodHTML(ep.method)}
                <code>${escapeHTML(ep.path)}</code>
            </button>`).join("")
        : '<p class="muted">No routes match your search.</p>';
}

function resolveExample(schema, openapiSchema, depth = 0) {
    if (!schema || depth > 4) return {};
    if (schema.example !== undefined) return schema.example;
    if (schema.default !== undefined) return schema.default;
    if (schema.enum?.length) return schema.enum[0];

    if (schema.$ref) {
        const name = schema.$ref.split("/").pop();
        return resolveExample(openapiSchema.components?.schemas?.[name], openapiSchema, depth + 1);
    }
    if (schema.type === "object" || schema.properties) {
        const result = {};
        for (const [key, property] of Object.entries(schema.properties || {})) {
            if (property.readOnly) continue;
            if ((schema.required || []).includes(key) ||
                property.example !== undefined || property.default !== undefined) {
                result[key] = resolveExample(property, openapiSchema, depth + 1);
            }
        }
        return result;
    }
    if (schema.type === "array") return [resolveExample(schema.items, openapiSchema, depth + 1)];
    if (schema.type === "string") {
        if (schema.format === "email") return "student@example.com";
        if (schema.format === "date") return "2026-01-01";
        return "";
    }
    if (schema.type === "integer" || schema.type === "number") return 0;
    if (schema.type === "boolean") return false;
    return {};
}

async function selectEndpoint(id) {
    selected = endpoints.find(ep => ep.id === id);
    if (!selected) return;

    $("#selectedRoute").innerHTML = `${methodHTML(selected.method)} ${escapeHTML(selected.path)}`;
    $("#selectedDescription").textContent = selected.description || selected.summary;

    $("#parameters").innerHTML = selected.parameters.map((p, i) => `
      <label for="param-${i}">
        ${escapeHTML(p.name)}${p.required ? " *" : ""}
        <small>(${escapeHTML(p.in || "query")})</small>
      </label>
      <input id="param-${i}" data-index="${i}"
        data-name="${escapeHTML(p.name)}" data-in="${escapeHTML(p.in)}"
        placeholder="${escapeHTML(p.description || p.name)}"
        value="${escapeHTML(p.example ?? p.schema?.example ?? p.schema?.default ?? "")}">
    `).join("");

    const schemaResponse = await fetch(`${API_BASE}/openapi.json`);
    const openapi = await schemaResponse.json();
    const content = selected.bodySchema
        ? resolveExample(selected.bodySchema, openapi)
        : null;

    $("#body").value = content === null ? "" : JSON.stringify(content, null, 2);
    $("#body").disabled = content === null;
    $("#responseStatus").textContent = "Waiting";
    $("#response").textContent = "Your API response will appear here.";
    renderAllRoutes();
}

function makeURL(endpoint) {
    let path = endpoint.path;
    const query = new URLSearchParams();

    $$("#parameters input[data-index]").forEach(input => {
        const name = input.dataset.name;
        const location = input.dataset.in;
        const value = input.value.trim();

        if (location === "path") {
            path = path.replace(`{${name}}`, encodeURIComponent(value));
        } else if (location === "query" && value) {
            query.set(name, value);
        }
    });

    if (/\{[^}]+\}/.test(path)) {
        throw new Error("Fill in the path parameters before sending the request.");
    }
    return `${API_BASE}${path}${query.toString() ? "?" + query : ""}`;
}

async function sendRequest() {
    if (!selected) return;

    try {
        const url = makeURL(selected);
        const headers = { Accept: "application/json" };
        const token = $("#token").value.trim();
        if (token) headers.Authorization = `Bearer ${token}`;

        const rawBody = $("#body").value.trim();
        let body;
        if (rawBody && !$("#body").disabled) {
            try {
                body = JSON.parse(rawBody);
            } catch {
                throw new Error("Request body must be valid JSON.");
            }
            headers["Content-Type"] = "application/json";
        }

        $("#send").disabled = true;
        $("#send").textContent = "Sending...";
        $("#responseStatus").textContent = "Sending...";

        const start = performance.now();
        const response = await fetch(url, {
            method: selected.method,
            headers,
            ...(body !== undefined ? { body: JSON.stringify(body) } : {})
        });
        const elapsed = Math.round(performance.now() - start);

        let result;
        if (response.status === 204) {
            result = "No Content (204)";
        } else if ((response.headers.get("content-type") || "").includes("json")) {
            result = JSON.stringify(await response.json(), null, 2);
        } else {
            result = await response.text();
        }

        $("#responseStatus").textContent = `${response.status} · ${elapsed} ms`;
        $("#response").textContent = result || "(Empty response)";

        if (response.ok) {
            try {
                const parsed = JSON.parse(result);
                if (parsed.access_token) {
                    $("#token").value = parsed.access_token;
                    $("#authStatus").textContent = "Ready";
                }
            } catch {}
        }
    } catch (error) {
        $("#responseStatus").textContent = "Request failed";
        $("#response").textContent =
            `${error.message}\n\nIf the browser reports a CORS error, serve this UI from FastAPI or configure CORS for its origin.`;
    } finally {
        $("#send").disabled = false;
        $("#send").textContent = "▶ Send request";
    }
}

function showPage(name) {
    document.querySelectorAll(".page").forEach(page =>
        page.classList.toggle("hidden", page.id !== name)
    );
    document.querySelectorAll(".nav-item").forEach(button =>
        button.classList.toggle("active", button.dataset.page === name)
    );
    $("#pageTitle").textContent = ({
        overview: "Overview", students: "Students", grades: "Grades",
        certificates: "Certificates", api: "API Explorer"
    })[name] || name;
}

document.addEventListener("click", event => {
    const endpointButton = event.target.closest("[data-endpoint]");
    if (endpointButton) {
        showPage("api");
        selectEndpoint(endpointButton.dataset.endpoint);
        return;
    }

    const nav = event.target.closest("[data-page]");
    if (nav) showPage(nav.dataset.page);

    const go = event.target.closest("[data-open]");
    if (go) showPage(go.dataset.open);
});

$("#search").addEventListener("input", renderAllRoutes);
$("#send").addEventListener("click", sendRequest);
$("#refresh").addEventListener("click", loadAPI);
$("#clear").addEventListener("click", () => {
    $("#token").value = "";
    $("#body").value = "";
    $("#response").textContent = "Cleared.";
    $("#responseStatus").textContent = "Waiting";
});

loadAPI();
