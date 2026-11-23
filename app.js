"use strict";

const $ = (selector) => document.querySelector(selector);
const input = $("#config-input");
const sample = [
  { type: "s3_bucket", name: "customer-uploads", public_access: true, encryption_enabled: false, logging_enabled: false },
  { type: "security_group", name: "web-tier-sg", ingress: [{ protocol: "tcp", port: 22, cidr: "0.0.0.0/0" }, { protocol: "tcp", port: 443, cidr: "0.0.0.0/0" }] },
  { type: "rds_instance", name: "orders-db-prod", publicly_accessible: true, encryption_enabled: false, backup_enabled: false },
  { type: "iam_user", name: "legacy-deploy-user", mfa_enabled: false, access_key_age_days: 124 },
  { type: "cloudtrail", name: "organization-trail", logging_enabled: true, multi_region: true },
  { type: "ebs_volume", name: "analytics-volume-01", encryption_enabled: true }
];
const secureSample = [
  { type: "s3_bucket", name: "customer-uploads", public_access: false, encryption_enabled: true, logging_enabled: true },
  { type: "security_group", name: "web-tier-sg", ingress: [{ protocol: "tcp", port: 443, cidr: "0.0.0.0/0" }] },
  { type: "rds_instance", name: "orders-db-prod", publicly_accessible: false, encryption_enabled: true, backup_enabled: true },
  { type: "iam_user", name: "legacy-deploy-user", mfa_enabled: true, access_key_age_days: 30 },
  { type: "cloudtrail", name: "organization-trail", logging_enabled: true, multi_region: true },
  { type: "ebs_volume", name: "analytics-volume-01", encryption_enabled: true }
];

const rules = [
  { id: "S3_PUBLIC", severity: "Critical", title: "Storage bucket allows public access", fix: "Block public access and review the bucket policy.", check: (r) => r.type === "s3_bucket" && (r.public_access === true || r.acl === "public-read" || r.acl === "public-read-write") },
  { id: "SG_SSH_OPEN", severity: "Critical", title: "SSH exposed to the public internet", fix: "Restrict SSH to a trusted IP range or use a managed access service.", check: (r) => r.type === "security_group" && Array.isArray(r.ingress) && r.ingress.some((x) => x && typeof x === "object" && [22, "22"].includes(x.port) && ["0.0.0.0/0", "::/0"].includes(x.cidr)) },
  { id: "RDS_PUBLIC", severity: "Critical", title: "Database is publicly accessible", fix: "Disable public access and place the database in a private network.", check: (r) => r.type === "rds_instance" && r.publicly_accessible === true },
  { id: "ENCRYPTION_OFF", severity: "High", title: "Data at rest is not encrypted", fix: "Enable encryption at rest with a managed or customer controlled key.", check: (r) => ["s3_bucket", "rds_instance", "ebs_volume"].includes(r.type) && r.encryption_enabled === false },
  { id: "MFA_OFF", severity: "High", title: "Identity has no MFA enabled", fix: "Require multi-factor authentication for this identity.", check: (r) => ["iam_user", "iam_identity"].includes(r.type) && r.mfa_enabled === false },
  { id: "LOGGING_OFF", severity: "Medium", title: "Audit or access logging is disabled", fix: "Enable logging and send records to a protected central location.", check: (r) => ["s3_bucket", "cloudtrail"].includes(r.type) && r.logging_enabled === false },
  { id: "BACKUP_OFF", severity: "Medium", title: "Database backups are disabled", fix: "Enable automated backups and define a retention period.", check: (r) => r.type === "rds_instance" && r.backup_enabled === false },
  { id: "KEY_OLD", severity: "Low", title: "Access key may be overdue for rotation", fix: "Rotate the key and move workloads to short lived credentials.", check: (r) => ["iam_user", "iam_identity"].includes(r.type) && Number(r.access_key_age_days) > 90 }
];

const weights = { Critical: 25, High: 15, Medium: 8, Low: 3 };
let lastFindings = [];
let lastReport = null;

function saveFixAssistantContext(findings, metadata) {
  try {
    sessionStorage.setItem("cloudguard_latest_scan_v1", JSON.stringify({
      ...metadata,
      scannedAt: new Date().toISOString(),
      findings
    }));
  } catch { /* The current dashboard still works if session storage is unavailable. */ }
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

function scanResources(resources) {
  const findings = [];
  resources.forEach((resource, index) => {
    if (!resource || typeof resource !== "object" || Array.isArray(resource)) return;
    for (const rule of rules) {
      if (rule.check(resource)) findings.push({ ...rule, resourceName: resource.name || `Resource ${index + 1}`, resourceType: resource.type || "unknown" });
    }
  });
  return findings;
}

function getScore(findings) {
  const penalty = findings.reduce((total, finding) => total + weights[finding.severity], 0);
  return Math.max(0, 100 - penalty);
}

function renderFindings(findings, showAll = false) {
  const viewAll = $("#view-all");
  $("#copy-all-findings").disabled = findings.length === 0;
  $("#copy-all-findings-status").textContent = "";
  viewAll.dataset.all = String(showAll && findings.length > 4);
  viewAll.hidden = findings.length <= 4;
  viewAll.innerHTML = showAll ? 'Show less <span>↑</span>' : 'View all <span>→</span>';
  const host = $("#findings-list");
  if (!findings.length) {
    host.innerHTML = '<div class="empty-state success-empty"><div class="empty-icon">✓</div><strong>No matched issues in this snapshot</strong><span>Keep reviewing your real environment and policies.</span></div>';
    return;
  }
  const visible = showAll ? findings : findings.slice(0, 4);
  host.innerHTML = visible.map((finding) => `<article class="finding-row"><span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span><div class="finding-copy"><strong>${escapeHTML(finding.title)}</strong><span>${escapeHTML(finding.resourceName)} <i>·</i> ${escapeHTML(finding.resourceType)}</span><small>${escapeHTML(finding.fix)}</small><button class="secondary-button copy-finding" type="button" aria-label="Copy ${escapeHTML(finding.title)} finding">Copy</button><span class="copy-finding-status" role="status" aria-live="polite"></span></div><span class="finding-id">${finding.id}</span></article>`).join("");
}

$("#findings-list").addEventListener("click", async (event) => {
  const button = event.target.closest(".copy-finding");
  if (!button) return;
  const row = button.closest(".finding-row");
  const status = row.querySelector(".copy-finding-status");
  const lines = [
    `${row.querySelector(".severity-badge").textContent}: ${row.querySelector(".finding-copy strong").textContent}`,
    row.querySelector(".finding-copy > span").textContent.replace(/\s*·\s*/g, " · "),
    row.querySelector(".finding-copy small").textContent,
    `Finding code: ${row.querySelector(".finding-id").textContent}`
  ];
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    status.textContent = "Finding copied.";
  } catch {
    status.textContent = "Clipboard unavailable. Select the finding text and copy it.";
  }
});

$("#copy-all-findings").addEventListener("click", async () => {
  const text = lastFindings.map((finding) => [
    `${finding.severity}: ${finding.title}`,
    `${finding.resourceName} · ${finding.resourceType}`,
    finding.fix,
    `Finding code: ${finding.id}`
  ].join("\n")).join("\n\n");
  try {
    await navigator.clipboard.writeText(text);
    $("#copy-all-findings-status").textContent = `Copied all ${lastFindings.length} findings.`;
  } catch {
    $("#copy-all-findings-status").textContent = "Clipboard unavailable. Copy findings one at a time.";
  }
});

function updateBreakdown(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(({ severity }) => counts[severity]++);
  Object.entries(counts).forEach(([severity, count]) => {
    const id = severity.toLowerCase();
    $(`#legend-${id}`).textContent = count;
    if (severity === "Critical" || severity === "High") $(`#${id}-count`).textContent = count;
  });
  const total = findings.length;
  $("#risk-lines").textContent = [
    ...Object.entries(counts).map(([severity, count]) => `${severity}: ${count} (${total ? (count / total * 100).toFixed(1) : "0.0"}%)`),
    `Total: ${total} finding${total === 1 ? "" : "s"}`
  ].join("\n");
  $("#copy-risk").disabled = false;
  $("#copy-risk-status").textContent = "";
  $("#donut-total").textContent = total;
  $("#finding-total").textContent = `${total} total`;
  $("#nav-count").textContent = total;
  const colors = { Critical: "#ff5268", High: "#ff9857", Medium: "#ffcc68", Low: "#48d8a0" };
  const sum = total || 1;
  let cursor = 0;
  const segments = Object.entries(counts).map(([severity, count]) => {
    const start = cursor; cursor += count / sum * 100;
    return `${colors[severity]} ${start}% ${cursor}%`;
  });
  $("#donut").style.background = total ? `conic-gradient(${segments.join(", ")})` : "conic-gradient(#29334a 0 100%)";
  $("#risk-note").textContent = total ? `${counts.Critical + counts.High} of ${total} findings are critical or high priority.` : "No matched issues were found in this snapshot.";
}

function renderDashboard(resources, findings, mode = "Cloud config JSON") {
  const score = getScore(findings);
  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(({ severity }) => { if (severityCounts[severity] !== undefined) severityCounts[severity]++; });
  const deductions = Object.fromEntries(Object.entries(weights).map(([severity, points]) => [severity, severityCounts[severity] * points]));
  const totalDeduction = Object.values(deductions).reduce((sum, points) => sum + points, 0);
  const breakdown = Object.entries(weights).map(([severity, points]) => `${severity} ${severityCounts[severity]} × ${points} = ${deductions[severity]}`).join(" · ");
  $("#score-breakdown").textContent = `${breakdown}. Total deduction ${totalDeduction}; score is max(0, 100 − ${totalDeduction}) = ${score}.`;
  const critical = findings.filter((item) => item.severity === "Critical").length;
  const high = findings.filter((item) => item.severity === "High").length;
  $("#score").textContent = score;
  $("#score-ring-text").textContent = score;
  const scoreColor = score >= 80 ? "#48d8a0" : score >= 50 ? "#ffcc68" : "#ff5268";
  $(".score-ring").style.background = `conic-gradient(${scoreColor} ${score}%, #29334a ${score}% 100%)`;
  $("#score-caption").textContent = score >= 80 ? "Good security posture" : score >= 50 ? "Room to improve" : "Action recommended";
  $("#score-bar").style.width = `${score}%`;
  $("#score-bar").style.background = score >= 80 ? "#48d8a0" : score >= 50 ? "#ffcc68" : "#ff5268";
  $("#critical-count").textContent = critical;
  $("#high-count").textContent = high;
  $("#critical-caption").textContent = critical ? "Review immediately" : "No critical findings";
  $("#resource-count").textContent = resources.length;
  $("#resource-caption").textContent = `${new Set(resources.map((item) => item.type).filter(Boolean)).size} resource types`;
  $("#scan-summary").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"} across ${resources.length} resource${resources.length === 1 ? "" : "s"}`;
  $("#last-scan").textContent = `SCANNED ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  updateBreakdown(findings);
  renderFindings(findings);
  lastFindings = findings;
  lastReport = {
    project: "CloudGuard learning project",
    mode,
    scannedAt: new Date().toISOString(),
    demoScore: score,
    scoreCalculation: "max(0, 100 minus the severity-weighted finding deductions)",
    severityCounts,
    deductions,
    totalDeduction,
    resourcesScanned: resources.length,
    findings: findings.map(({ id, severity, title, resourceName, resourceType, fix }) => ({ id, severity, title, resourceName, resourceType, fix }))
  };
  $("#export-report").disabled = false;
  $("#export-readable-report").disabled = false;
}

function runScan(resources) {
  const validationError = validateResources(resources);
  if (validationError) throw new Error(validationError);
  $("#scan-feedback").classList.remove("error");
  const findings = scanResources(resources);
  saveFixAssistantContext(findings, { mode: "Cloud config JSON", resourceCount: resources.length });
  renderDashboard(resources, findings);
  $("#scan-feedback").textContent = `Scan complete · ${resources.length} resources checked`;
  $("#scan-feedback").classList.add("visible");
  $("#toast").textContent = `Scan complete: ${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  $("#toast").classList.add("show");
  window.setTimeout(() => $("#toast").classList.remove("show"), 2800);
}

$("#run-scan").addEventListener("click", () => {
  try { runScan(JSON.parse(input.value)); }
  catch (error) { $("#scan-feedback").textContent = error instanceof SyntaxError ? "That JSON could not be read. Check commas, quotes, and brackets." : error.message; $("#scan-feedback").classList.add("visible", "error"); }
});

$("#sample-button").addEventListener("click", () => { input.value = JSON.stringify(sample, null, 2); $("#scan-feedback").textContent = "Sample configuration loaded. Run the scan to see results."; $("#scan-feedback").classList.add("visible"); $("#scan-feedback").classList.remove("error"); });
$("#secure-sample-button").addEventListener("click", () => { input.value = JSON.stringify(secureSample, null, 2); $("#scan-feedback").textContent = "Secure example loaded. Run the scan to see the sample findings clear."; $("#scan-feedback").classList.add("visible"); $("#scan-feedback").classList.remove("error"); });
$("#run-demo").addEventListener("click", () => {
  runScan(sample);
  $("#findings").scrollIntoView({ behavior: "smooth", block: "start" });
});
$("#export-report").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `cloudguard-report-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
$("#export-readable-report").addEventListener("click", () => {
  if (!lastReport) return;
  const findings = lastReport.findings.length ? lastReport.findings.map((finding) => `
    <article class="finding">
      <div class="finding-head"><span class="severity ${escapeHTML(finding.severity.toLowerCase())}">${escapeHTML(finding.severity)}</span><span class="rule">${escapeHTML(finding.id)}</span></div>
      <h2>${escapeHTML(finding.title)}</h2>
      <p class="resource">${escapeHTML(finding.resourceName)} · ${escapeHTML(finding.resourceType)}</p>
      <p>${escapeHTML(finding.fix)}</p>
    </article>`).join("") : '<p class="clear">No matched issues were found in this scan snapshot.</p>';
  const severitySummary = Object.entries(lastReport.severityCounts).map(([severity, count]) => `${escapeHTML(severity)}: ${count}`).join(" · ");
  const breakdown = Object.entries(lastReport.deductions).map(([severity, points]) => `${escapeHTML(severity)} −${points}`).join(" · ");
  const markup = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CloudGuard scan report</title><style>
    *{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172235;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}.sheet{max-width:900px;margin:36px auto;background:white;padding:40px;border:1px solid #dce3ec;border-radius:14px}.brand{color:#127f82;font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}h1{font-size:30px;margin:8px 0 4px}.meta{color:#64748b;margin:0 0 24px}.score{display:flex;gap:24px;align-items:center;background:#f0f8f7;border:1px solid #c9e8e3;padding:18px;border-radius:10px}.score strong{font-size:36px;line-height:1}.score small{display:block;color:#526477}.score p{margin:0;color:#34475b}.counts{font-size:13px;color:#526477;margin:8px 0 0}.finding{border-top:1px solid #e2e8f0;padding:18px 0}.finding-head{display:flex;justify-content:space-between;align-items:center}.severity{font-size:11px;font-weight:800;border-radius:30px;padding:3px 9px;background:#e7edf5}.critical{color:#a91e35;background:#fde8ec}.high{color:#a34413;background:#fff0e4}.medium{color:#8b6200;background:#fff6d8}.low{color:#176b4b;background:#e3f6ed}.rule{font:12px ui-monospace,monospace;color:#66758a}.finding h2{font-size:18px;margin:8px 0 0}.resource{color:#64748b;font-size:13px;margin:2px 0 8px}.clear{padding:18px;background:#e8f8ef;color:#16633e;border-radius:8px}.scope{border-top:1px solid #e2e8f0;margin-top:24px;padding-top:14px;font-size:12px;color:#64748b}.scope strong{color:#334155}@media(max-width:640px){.sheet{margin:0;padding:22px;border:0;border-radius:0}.score{align-items:flex-start;flex-direction:column}h1{font-size:25px}}
  </style></head><body><main class="sheet"><div class="brand">CloudGuard · Scan report</div><h1>Security scan summary</h1><p class="meta">${escapeHTML(lastReport.mode)} · ${escapeHTML(new Date(lastReport.scannedAt).toLocaleString())} · ${lastReport.resourcesScanned} resource(s)</p><section class="score"><div><strong>${lastReport.demoScore}<small>/ 100</small></strong></div><div><b>Educational posture score</b><p>Starts at 100, minus severity-weighted finding deductions, with a floor of 0.</p><p class="counts">${severitySummary}</p><p class="counts">Deductions: ${breakdown}. Total: ${lastReport.totalDeduction} points.</p></div></section><h2>Findings (${lastReport.findings.length})</h2>${findings}<footer class="scope"><strong>Scope and limits:</strong> CloudGuard is an internship learning project using heuristic checks. Results may be incomplete or false positives. Manually verify each finding in the target environment; this report is not a production security assessment.</footer></main></body></html>`;
  const blob = new Blob([markup], { type: "text/html;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `cloudguard-readable-report-${new Date().toISOString().slice(0, 10)}.html`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});
$("#copy-risk").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#risk-lines").textContent);
    $("#copy-risk-status").textContent = "Copied risk breakdown.";
  } catch {
    $("#copy-risk-status").textContent = "Clipboard unavailable. Select the lines and copy them.";
  }
});
$("#top-scan").addEventListener("click", () => { $("#scanner").scrollIntoView({ behavior: "smooth" }); input.focus({ preventScroll: true }); });
$("#view-all").addEventListener("click", (event) => { const showingAll = event.currentTarget.dataset.all === "true"; renderFindings(lastFindings, !showingAll); event.currentTarget.dataset.all = String(!showingAll); event.currentTarget.innerHTML = showingAll ? 'View all <span>→</span>' : 'Show less <span>↑</span>'; });
$("#dismiss-notice").addEventListener("click", () => $("#notice").remove());
$("#file-input").addEventListener("change", async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try { input.value = await file.text(); $("#scan-feedback").textContent = `${file.name} loaded. Run the scan to analyze it.`; $("#scan-feedback").classList.add("visible"); $("#scan-feedback").classList.remove("error"); }
  catch { $("#scan-feedback").textContent = "Could not read that file."; $("#scan-feedback").classList.add("visible", "error"); }
  event.target.value = "";
});

input.value = JSON.stringify(sample, null, 2);

// The same-origin server handles local runs; GitHub Pages sends scans to the
// companion hosted Python service. That service makes read-only GET requests.
const scannerApiBase = window.CLOUDGUARD_API_URL ||
  (location.hostname.endsWith(".github.io") ? "https://cloud-risk-scanner-api.onrender.com" : location.origin);
const webStatus = $("#webscan-status");
$(".scan-tabs").addEventListener("click", (event) => {
  const button = event.target.closest(".scan-tab");
  if (!button) return;
  document.querySelectorAll(".scan-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
  document.querySelectorAll("#config-pane, #webscan-pane, .format-details").forEach((pane) => {
    pane.hidden = pane.id === "config-pane" ? button.dataset.pane !== "config-pane" :
      pane.id === "webscan-pane" ? button.dataset.pane !== "webscan-pane" : button.dataset.pane !== "config-pane";
  });
});

$("#web-scan-button").addEventListener("click", async () => {
  const target = $("#target-url").value.trim();
  webStatus.classList.remove("error");
  if (!target) { webStatus.textContent = "Enter your application's full URL first."; webStatus.classList.add("error"); return; }
  webStatus.textContent = "Scanning pages with read-only requests…";
  $("#web-scan-button").disabled = true;
  try {
    const response = await fetch(`${scannerApiBase}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: target }) });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "Scan request failed.");
    saveFixAssistantContext(result.findings, { mode: "Website", target, pagesScanned: result.pagesScanned });
    renderDashboard(result.pages.map((page) => ({ type: "web page", name: new URL(page.url).pathname || "/" })), result.findings, "Website");
    webStatus.textContent = `Completed: ${result.pagesScanned} page${result.pagesScanned === 1 ? "" : "s"} inspected. ${result.mode}.`;
    $("#page-list").replaceChildren(...result.pages.map((page) => {
      const row = document.createElement("div"); row.className = "page-item";
      const status = document.createElement("b"); status.textContent = String(page.status);
      const label = document.createElement("span"); label.textContent = `${new URL(page.url).pathname || "/"} · ${page.contentType.split(";")[0]}`;
      row.append(status, label); return row;
    }));
    $("#findings").scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (error) {
    webStatus.textContent = `${error.message} The hosted scanner service may still be starting. Try again in a moment.`;
    webStatus.classList.add("error");
  } finally { $("#web-scan-button").disabled = false; }
});
