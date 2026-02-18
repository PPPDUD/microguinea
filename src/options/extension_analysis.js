import JSZip from "jszip";
import { GoogleGenAI } from "@google/genai";

import { els } from "./dom";

/* =========================
   Public entry
========================= */

export function initExtensionAnalysis() {
  if (els.extAnalyzeBtn) {
    els.extAnalyzeBtn.addEventListener("click", analyzeCallback);
  }
  // if (els.codeCopyBtn) {
  //   els.codeCopyBtn.addEventListener("click", copyCodeCallback);
  // }
}

/* =========================
   State
========================= */

let extractedZip = null;
let currentExtensionId = null,
  formattedCode = null,
  currentFile = null;

/* =========================
   CRX handling
========================= */

function stripCrxHeader(buffer) {
  if (buffer.byteLength < 4) {
    throw new Error("File too small to be a CRX");
  }

  const view = new DataView(buffer);

  const magic =
    String.fromCharCode(view.getUint8(0)) +
    String.fromCharCode(view.getUint8(1)) +
    String.fromCharCode(view.getUint8(2)) +
    String.fromCharCode(view.getUint8(3));

  if (magic !== "Cr24") {
    throw new Error("Invalid CRX magic header");
  }

  if (buffer.byteLength < 8) {
    throw new Error("CRX header truncated");
  }

  const version = view.getUint32(4, true);

  if (version === 2) {
    if (buffer.byteLength < 16) {
      throw new Error("CRX2 header truncated");
    }

    const keyLen = view.getUint32(8, true);
    const sigLen = view.getUint32(12, true);
    const offset = 16 + keyLen + sigLen;

    if (buffer.byteLength < offset) {
      throw new Error("CRX2 payload truncated");
    }

    return buffer.slice(offset);
  }

  if (version === 3) {
    if (buffer.byteLength < 12) {
      throw new Error("CRX3 header truncated");
    }

    const headerSize = view.getUint32(8, true);
    const offset = 12 + headerSize;

    if (buffer.byteLength < offset) {
      throw new Error("CRX3 payload truncated");
    }

    return buffer.slice(offset);
  }

  throw new Error(`Unsupported CRX version ${version}`);
}

/* =========================
   Download
========================= */

async function downloadZip() {
  if (!extractedZip || !currentExtensionId) return;

  const outZip = new JSZip();

  for (const [path, file] of Object.entries(extractedZip.files)) {
    if (file.dir) {
      outZip.folder(path);
    } else {
      const content = await file.async("uint8array");
      outZip.file(path, content);
    }
  }

  const blob = await outZip.generateAsync({ type: "blob" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `${currentExtensionId}.zip`;
  a.click();

  URL.revokeObjectURL(url);
}

// /* =========================
//    Directory tree
// ========================= */

// function renderFileTree(zip) {
//   const tree = {};

//   Object.keys(zip.files).forEach((path) => {
//     const parts = path.split("/").filter(Boolean);
//     let node = tree;

//     parts.forEach((part, i) => {
//       if (!node[part]) {
//         node[part] = {
//           __path: parts.slice(0, i + 1).join("/"),
//           __isFile: i === parts.length - 1 && !zip.files[path].dir,
//           __children: {},
//         };
//       }
//       node = node[part].__children;
//     });
//   });

//   els.directoryTree.appendChild(buildTreeDom(tree));
// }

// function buildTreeDom(tree) {
//   const ul = document.createElement("ul");

//   for (const key in tree) {
//     const item = tree[key];
//     const li = document.createElement("li");

//     const span = document.createElement("span");
//     span.textContent = key;

//     if (item.__isFile) {
//       span.dataset.type = "file";
//       span.onclick = () => openFile(item.__path);
//     } else {
//       span.dataset.type = "folder";
//       span.onclick = () => {
//         li.classList.toggle("open");
//       };
//     }

//     li.appendChild(span);

//     const children = buildTreeDom(item.__children);
//     if (children.children.length) {
//       li.appendChild(children);
//     }

//     ul.appendChild(li);
//   }

//   return ul;
// }

// /* =========================
//    File viewer
// ========================= */

// async function openFile(path) {
//   const file = extractedZip.files[path];
//   if (!file) return;

//   const raw = await file.async("text");
//   formattedCode = raw;
//   currentFile = path;

//   els.directoryFileViewer.querySelector("pre").textContent = formattedCode;
// }

// async function copyCodeCallback() {
//   if (!formattedCode) {
//     alert("please select a file");
//     return;
//   }
//   await navigator.clipboard.writeText(formattedCode);
//   alert("copied code of " + currentFile);
// }

/* =========================
   Manifest analysis UI + AI integration
========================= */

/* =========================
   Gemini helper (client-side)
========================= */

async function generateGeminiResponse({ apiKey, prompt, enableSearch = true }) {
  try {
    const ai = new GoogleGenAI({ apiKey });

    // build model params
    const params = {
      model: "gemini-2.5-flash", // or whichever model you prefer
      contents: prompt,
    };

    // if search grounding is desired add tools
    if (enableSearch) {
      params.tools = [{ google_search: {} }];
    }

    const response = await ai.models.generateContent(params);

    // SDK returns .text on the response object
    return response.text || "";
  } catch (error) {
    console.log(error);
    alert(error.toString());
    return "";
  }
}

function buildAIManifestPrompt(manifest, permsText, localeMessagesText) {
  return `
You are acting as a joint review panel consisting of senior Chrome extension developers, red team security analysts, privacy engineers, and incident response specialists. Evaluate permissions conservatively and from a defense perspective.

Extension details:
name: ${manifest.name || "N/A"}
version: ${manifest.version || "N/A"}
description: ${manifest.description || "N/A"}

Locale messages (key: message):
${localeMessagesText || "(none provided)"}

Declared permissions:
${permsText}

Important evaluation rules:
1) Treat the manifest and locale messages together as the stated extension intent.
2) Judge permissions strictly by least privilege principles.
3) For host permissions, interpret patterns literally:
   - exact hosts like https://api.example.com/* are lower risk if aligned with purpose.
   - wildcard hosts like *://*/* or https://*/ are high risk.
   - broad scopes like "://*.com/*" are overbroad unless strongly justified.
4) For content_scripts matches, verify site scope matches the described intent.
5) Optional permissions are lower severity but still require justification.
6) If a permission enables reading, modifying, or exfiltrating user data without clear need, mark danger.
7) Keep each reason concrete and brief, 15–80 characters.
8) Be conservative: when unsure, prefer suspicious over ok.

Task:
For every declared permission and host pattern, produce exactly one verdict entry. Include optional permissions with "(optional)" appended so they are evaluated separately.

Output format:
Return ONLY valid JSON. No explanation or text outside the JSON object.

{
  "verdicts": [
    {
      "permission": "<permission string, append ' (optional)' if optional>",
      "verdict": "ok" | "suspicious" | "danger",
      "reason": "<short explanation, 15-80 chars>"
    }
  ],
  "summary": "<one-line overall risk summary>"
}
`.trim();
}

function buildAIServiceWorkerPrompt(
  manifest,
  permsText,
  localeMessagesText,
  bgSource,
) {
  return `
You are a collaborative team: red team security analysts, national incident responders, and experienced extension developers. Your mission is to analyze each service worker network call and produce a short, conservative verdict and reason grounded in the manifest, declared permissions, and locale messages.

Extension context:
name: ${manifest.name || "N/A"}
version: ${manifest.version || "N/A"}
description: ${manifest.description || "N/A"}

Locale messages:
${localeMessagesText || "(none provided)"}

Declared permissions and hosts:
${permsText || "none"}

Service worker source code:
${bgSource || "none"}

Analysis instructions:
1) Use manifest, host_permissions, and permissions to judge whether the call is expected for the extension purpose.
2) If host is not covered by host_permissions mark higher risk.
3) POST requests carrying profile, credentials, or user data with auth are high risk.
4) GET requests to analytics or telemetry endpoints may be ok but still note privacy risk.
5) Ternary or concatenated URL expressions should be evaluated conservatively: if any branch sends data to an external API and no justification exists then raise suspicion.
6) Keep each reason brief and concrete, 15 to 80 characters.
7) Be conservative: when unsure, prefer suspicious over ok.
8) Return ONLY valid JSON that exactly matches the schema below. Do not include any extra text, commentary, or markup.

Output schema:
Return only this JSON object.

{
  "analysis": ["...", "...", "..."],
  "summary": "<one-line summary of overall risk>",
  "recommendation": "<one-line remediation or investigation step>"
}

Examples of guidance to use:
- If host matches manifest host_permissions and purpose matches description, lean ok.
- If request is POST with Authorization header and profile or personally identifying fields, mark danger.
- If request uses wide host patterns like *://*/* or large scopes, mark suspicious or danger.
- If headers or body are obfuscated but show profile or token patterns, mark suspicious.
- If multiple distinct calls target same external domain, mention that in summary.

Strict formatting rules:
- Reasons must be 15 to 80 characters.
- All values must be strings.
- Do not use the word "danger". Use "[suspicious]" prefix for concerns.
- Return pure JSON only. No surrounding text, no markdown, no commentary.
- "analysis" is of type string[].
`.trim();
}

// not used, need to be worked on to reduce input tokens
// function extractFetchCallsFromBundle(code) {
//   // const results = [];
//   // let i = 0;
//   // function tryResolveInlineUrl(expr) {
//   //   // match: <something>.concat(a, b, c)
//   //   const concatMatch = expr.match(/\.concat\((.*)\)$/);
//   //   if (!concatMatch) return null;
//   //   const argsRaw = concatMatch[1];
//   //   const args = argsRaw
//   //     .split(/,(?![^()]*\))/)
//   //     .map((s) => s.trim())
//   //     .map((s) => {
//   //       // strip quotes if literal
//   //       if (
//   //         (s.startsWith('"') && s.endsWith('"')) ||
//   //         (s.startsWith("'") && s.endsWith("'"))
//   //       ) {
//   //         return s.slice(1, -1);
//   //       }
//   //       return null;
//   //     });
//   //   if (args.some((a) => a === null)) return null;
//   //   const result = args.join("");
//   //   if (result.includes("http")) return result;
//   //   return null;
//   // }
//   // while ((i = code.indexOf("fetch(", i)) !== -1) {
//   //   let start = i + 6;
//   //   let depth = 1;
//   //   let j = start;
//   //   // find end of fetch(...)
//   //   while (j < code.length && depth > 0) {
//   //     if (code[j] === "(") depth++;
//   //     else if (code[j] === ")") depth--;
//   //     j++;
//   //   }
//   //   const fetchCall = code.slice(i, j);
//   //   // URL expression (variable or literal)
//   //   const urlExpression =
//   //     fetchCall.match(/fetch\s*\(\s*([^,]+),/)?.[1]?.trim() || null;
//   //   // resolve variable URL if possible
//   //   let resolvedUrlExpression = null;
//   //   // 1. Inline concat resolution
//   //   if (urlExpression) {
//   //     resolvedUrlExpression = tryResolveInlineUrl(urlExpression);
//   //   }
//   //   // 2. Variable resolution fallback
//   //   if (
//   //     !resolvedUrlExpression &&
//   //     urlExpression &&
//   //     /^[a-zA-Z_$][\w$]*$/.test(urlExpression)
//   //   ) {
//   //     const name = urlExpression.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
//   //     // match ANY assignment expression: u = <expr>
//   //     const assignRe = new RegExp(
//   //       `${name}\\s*=\\s*([^;\\n\\r,)]+(?:\\([^)]*\\)[^;\\n\\r,)]*)?)`,
//   //       "g",
//   //     );
//   //     const before = code.slice(0, i);
//   //     let match;
//   //     while ((match = assignRe.exec(before))) {
//   //       const candidate = match[1].trim();
//   //       // must look URL-like
//   //       if (candidate.includes("http") || candidate.includes("://")) {
//   //         resolvedUrlExpression = candidate;
//   //       }
//   //     }
//   //   }
//   //   const method = fetchCall.match(/method\s*:\s*["'](\w+)["']/)?.[1] || "GET";
//   //   const headers =
//   //     fetchCall.match(/headers\s*:\s*\{([\s\S]*?)\}/)?.[1]?.trim() || null;
//   //   // body extraction (fixed)
//   //   let bodyExpression = null;
//   //   const bodyIdx = fetchCall.indexOf("body:");
//   //   if (bodyIdx !== -1) {
//   //     let k = bodyIdx + 5;
//   //     while (fetchCall[k] === " ") k++;
//   //     let parenDepth = 0;
//   //     let braceDepth = 0;
//   //     let seenOpen = false;
//   //     const startBody = k;
//   //     let endBody = k;
//   //     while (endBody < fetchCall.length) {
//   //       const ch = fetchCall[endBody];
//   //       if (ch === "(") {
//   //         parenDepth++;
//   //         seenOpen = true;
//   //       } else if (ch === ")") {
//   //         parenDepth--;
//   //       } else if (ch === "{") {
//   //         braceDepth++;
//   //         seenOpen = true;
//   //       } else if (ch === "}") {
//   //         braceDepth--;
//   //       }
//   //       if (seenOpen && parenDepth === 0 && braceDepth === 0) {
//   //         endBody++;
//   //         break;
//   //       }
//   //       endBody++;
//   //     }
//   //     bodyExpression = fetchCall.slice(startBody, endBody).trim();
//   //   }
//   //   results.push({
//   //     // urlExpression,
//   //     id: Math.floor(new Date().getTime() * Math.random()).toString(16),
//   //     resolvedUrlExpression,
//   //     method,
//   //     headers,
//   //     bodyExpression,
//   //   });
//   //   i = j;
//   // }
//   // return results;
// }

async function findManifestJson() {
  if (!extractedZip) return null;
  // const manifestPaths = [
  //   "manifest.json",
  //   "src/manifest.json",
  //   "dist/manifest.json",
  //   "app/manifest.json",
  // ];
  for (const p of Object.keys(extractedZip.files)) {
    if (p.toLowerCase().endsWith("manifest.json")) {
      try {
        const txt = await extractedZip.files[p].async("text");
        return JSON.parse(txt);
      } catch (err) {
        console.warn("failed to parse manifest", p, err);
        return null;
      }
    }
  }
  return null;
}
async function findOneLocaleMessages() {
  if (!extractedZip) return { messages: null };

  // Helper to try loading a messages.json for a given locale code
  const loadLocaleJson = async (locale) => {
    const path = `_locales/${locale}/messages.json`;
    const file = extractedZip.files[path];
    if (file) {
      try {
        return JSON.parse(await file.async("text"));
      } catch (err) {
        console.warn("Failed to parse locale messages", path, err);
      }
    }
    return { messages: null };
  };

  // First try the default locale from manifest.json
  const manifestEntry = await findManifestJson();
  let defaultLocale = null;
  try {
    defaultLocale = manifestEntry?.default_locale || null;
  } catch (error) {
    console.log("error", error);
  }

  if (defaultLocale) {
    const localeData = await loadLocaleJson(defaultLocale);
    if (localeData) {
      return { locale: defaultLocale, messages: localeData };
    }
  } else {
    return { messages: null }; // no default means no messages. CHROME enforces default
  }

  // If no default found or no file there, find any locale folder
  const localeFolders = Object.keys(extractedZip.files)
    // Match folder segments under _locales
    .map((p) => {
      const parts = p.split("/");
      if (parts[0] === "_locales" && parts[1]) {
        return parts[1];
      }
      return null;
    })
    .filter((loc, idx, arr) => loc && arr.indexOf(loc) === idx);

  for (const loc of localeFolders) {
    const localeData = await loadLocaleJson(loc);
    if (localeData) {
      return { locale: loc, messages: localeData };
    }
  }

  return { messages: null };
}
async function findServiceWorkerFiles(manifest) {
  if (!extractedZip) return [];
  if (!manifest) return [];

  const workerPaths = new Set();

  // MV3
  if (
    manifest.background &&
    typeof manifest.background.service_worker === "string"
  ) {
    workerPaths.add(manifest.background.service_worker);
  }

  // MV2
  if (manifest.background && Array.isArray(manifest.background.scripts)) {
    for (const script of manifest.background.scripts) {
      if (typeof script === "string" && script.endsWith(".js")) {
        workerPaths.add(script);
      }
    }
  }

  const results = [];

  for (const workerPath of workerPaths) {
    let file = extractedZip.files[workerPath];

    // fallback: search by filename only
    if (!file) {
      const name = workerPath.split("/").pop();
      for (const p of Object.keys(extractedZip.files)) {
        if (p === name || p.endsWith("/" + name)) {
          file = extractedZip.files[p];
          break;
        }
      }
    }

    if (!file) continue;

    try {
      const source = await file.async("text");
      results.push({
        path: workerPath,
        source,
      });
    } catch (err) {
      console.warn("failed to read service worker", workerPath, err);
    }
  }

  return results;
}

function populateManifestUI(manifest) {
  const summary = [];
  if (manifest.version) summary.push(`v${escapeHtml(manifest.version)}`);
  const summaryHTML = `<div style="margin-top:8px;color:#333;font-size:13px">${summary.join(" ")} </div>`;
  els.analysisContainer.querySelector(".ai-summary").innerHTML = summaryHTML;

  // permissions
  const permListElem = els.analysisContainer.querySelector(
    "#ai-permissions-list",
  );
  permListElem.innerHTML = "";

  let perms = [];
  if (Array.isArray(manifest.permissions)) perms = manifest.permissions.slice();
  if (manifest.host_permissions && Array.isArray(manifest.host_permissions)) {
    // manifest v3 host_permissions combine hosts
    perms = perms.concat(manifest.host_permissions);
  }
  if (
    manifest.optional_permissions &&
    Array.isArray(manifest.optional_permissions)
  ) {
    perms = perms.concat(
      manifest.optional_permissions.map((p) => `${p} (optional)`),
    );
  }

  if (perms.length === 0) {
    permListElem.innerHTML = `<div style="grid-column:1/-1;color:#666">No permissions declared</div>`;
    return;
  }

  // render rows; default status unknown
  perms.forEach((p) => {
    const permName = escapeHtml(p);
    const row = document.createElement("div");
    row.className = "permission-row";
    row.innerHTML = `
      <div class="permission-name" data-perm="${permName.split(" (optional)")[0]}">
        <span style="opacity:0.7">▹</span>
        <span>${permName}</span>
      </div>
      <div class="perm-status unknown" data-perm="${permName.split(" (optional)")[0]}">pending</div>

      <div class="permission-reason" data-perm-reason="${permName.split(" (optional)")[0]}" style="display:none"></div>
    `;
    permListElem.appendChild(row);
  });
}
function populateServiceWorkerUI() {
  const listElem = els.analysisContainer.querySelector(
    "#ai-serviceworker-list",
  );

  if (!listElem) return;

  listElem.innerHTML = "";

  const ul = document.createElement("ul");
  ul.className = "analysis-bullet-list";
  ul.id = "ai-serviceworker-bullets";

  listElem.appendChild(ul);
}

async function geminiAnalyze({ apiKey, manifest, messages, bgSource }) {
  //combine this and below function
  const permissions = [
    ...(manifest.permissions || []),
    ...(manifest.host_permissions || []),
    ...(manifest.optional_permissions || []),
  ];

  const permsText = permissions.length
    ? permissions.map((p) => `- ${p}`).join("\n")
    : "none";

  const localeMessagesText = messages
    ? Object.entries(messages)
        .map(([k, v]) => `${k}: "${(v.message || "").replace(/\n/g, "\\n")}"`)
        .join("\n")
    : "";

  const prompt1 = buildAIManifestPrompt(
    manifest,
    permsText,
    localeMessagesText,
  );
  const manifestAnalysis = await generateGeminiResponse({
    apiKey,
    prompt: prompt1,
    enableSearch: true,
  });

  if (!bgSource) {
    return { manifestAnalysis, bgAnalysis: "" };
  }

  const prompt2 = buildAIServiceWorkerPrompt(
    manifest,
    permsText,
    localeMessagesText,
    bgSource,
  );
  const bgAnalysis = await generateGeminiResponse({
    apiKey,
    prompt: prompt2,
    enableSearch: true,
  });

  return { manifestAnalysis, bgAnalysis };
}

function applyAIVerdicts(data) {
  if (!data) return;

  // manifest permissions
  const manifestData = data["permissionAnalysis"];
  if (!manifestData || !manifestData.verdicts) return;
  for (const v of manifestData.verdicts) {
    const perm = String(v.permission);
    const verdict = (v.verdict || "unknown").toLowerCase();
    const reason = v.reason || "";

    const statusElem = document.querySelector(
      `.perm-status[data-perm="${escapeSelector(perm)}"]`,
    );
    const permReasonElem = document.querySelector(
      `.permission-reason[data-perm-reason="${escapeSelector(perm)}"]`,
    );
    const permNameElem = document.querySelector(
      `.permission-name[data-perm="${escapeSelector(perm)}"]`,
    );

    if (!statusElem) {
      // try to match normalized permission text
      // skip if not found
      continue;
    }

    statusElem.classList.remove("unknown", "ok", "suspicious"); //danger
    if (verdict === "ok") {
      statusElem.classList.add("ok");
      statusElem.textContent = "ok";
    } else if (verdict === "suspicious") {
      statusElem.classList.add("suspicious");
      statusElem.textContent = "suspicious";
      if (permNameElem) permNameElem.style.borderLeft = "3px solid #ff9900";
    } else if (verdict === "danger" || verdict === "dangerous") {
      statusElem.classList.add("suspicious"); //danger
      statusElem.textContent = "suspicious";
      if (permNameElem) permNameElem.style.borderLeft = "3px solid #ff9900"; //#c53030";
    } else {
      statusElem.textContent = verdict;
    }

    if (permReasonElem) {
      if (reason) {
        permReasonElem.style.display = "block";
        permReasonElem.textContent = reason;
      } else {
        permReasonElem.style.display = "none";
      }
    }
  }

  // service worker
  const serviceWorkerData = data["serviceWorkerAnalysis"];
  if (!serviceWorkerData) return;

  const ul = els.analysisContainer.querySelector("#ai-serviceworker-bullets");
  if (!ul || !Array.isArray(serviceWorkerData.analysis)) return;
  for (const item of serviceWorkerData.analysis) {
    const li = document.createElement("li");
    li.textContent = item;
    ul.appendChild(li);
  }
}
async function triggerAICheck(manifest, messages, bgSource) {
  const apiKey = els.apiKeyInput?.value?.trim();

  // silently skip if no key
  if (!apiKey) return;

  try {
    const { manifestAnalysis, bgAnalysis } = await geminiAnalyze({
      apiKey,
      manifest,
      messages,
      bgSource,
    });

    const txt = manifestAnalysis.trim(); //raw
    const start = txt.indexOf("{");
    const end = txt.lastIndexOf("}");
    const parsed =
      start !== -1 && end !== -1
        ? JSON.parse(txt.slice(start, end + 1))
        : JSON.parse(txt);

    // service worker analysis
    const txt2 = bgAnalysis.trim(); //raw
    const start2 = txt2.indexOf("{");
    const end2 = txt2.lastIndexOf("}");
    const parsed2 =
      txt2.length == 0
        ? ""
        : start !== -1 && end !== -1
          ? JSON.parse(txt2.slice(start2, end2 + 1))
          : JSON.parse(txt2);

    applyAIVerdicts({
      permissionAnalysis: parsed,
      serviceWorkerAnalysis: parsed2,
    });
  } catch (error) {
    console.log("error", error);
    els.analysisContainer.querySelector(".ai-summary").textContent =
      "AI analysis failed";
  }
}

// Attach analyzer whenever extractedZip is available.
export async function attachAnalyzer() {
  // clear previous UI
  const container = els.analysisContainer;
  if (!container) return;

  // try to find manifest.json
  const manifest = await findManifestJson();
  if (!manifest) {
    container
      .querySelector(".ai-header")
      .insertAdjacentHTML(
        "beforeend",
        `<div style="color:#666;font-size:13px">No manifest.json found</div>`,
      );
    return;
  }

  // combine all background script sources into one text blob
  let combinedBackgroundSource = "";

  // reuse existing resolver logic
  const backgroundFiles = await findServiceWorkerFiles(manifest);

  for (const bg of backgroundFiles) {
    if (!bg?.source) continue;

    combinedBackgroundSource += `\n\n/* ===== BACKGROUND FILE: ${bg.path} ===== */\n\n`;
    combinedBackgroundSource += bg.source;
  }

  // Render manifest basic info
  populateManifestUI(manifest);
  populateServiceWorkerUI();

  const { messages } = await findOneLocaleMessages();

  // trigger an automatic AI scan in background
  triggerAICheck(manifest, messages, combinedBackgroundSource);
}

/* =========================
   Analyze
========================= */

async function analyzeCallback() {
  // const apiKey = els.apiKeyInput?.value?.trim();
  const id = els.extensionIdInput.value.trim();
  if (!id) return;

  els.extAnalysisOutput.textContent = "Processing CRX...";
  // els.directoryTree.innerHTML = "";
  // els.directoryFileViewer.querySelector("pre").textContent = "";

  try {
    const url = "https://clients2.google.com/service/update2/crx";

    const body =
      `response=redirect` +
      `&prodversion=121.0.0.0` +
      `&acceptformat=crx3` +
      `&x=id%3D${id}%26installsource%3Dondemand%26uc`;

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!res.ok) {
      throw new Error("CRX download failed");
    }

    const buffer = await res.arrayBuffer();

    if (buffer.byteLength < 16) {
      throw new Error("Downloaded file is not a valid CRX");
    }

    const zipData = stripCrxHeader(buffer);

    extractedZip = await JSZip.loadAsync(zipData);
    currentExtensionId = id;

    els.extAnalysisOutput.textContent = "";
    els.downloadExtSourceCode.disabled = false;
    els.downloadExtSourceCode.onclick = downloadZip;

    // renderFileTree(extractedZip);
    attachAnalyzer();
  } catch (err) {
    els.extAnalysisOutput.textContent = String(err);
  }
}

/* small helpers */
function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// CSS selector safe escape for dataset matching
function escapeSelector(s) {
  // we are using the dataset attributes containing permission text which can include slashes and colons
  const res = s.split(" (optional)")[0];
  return CSS.escape(res);
}
