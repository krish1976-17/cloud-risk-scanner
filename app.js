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
  viewAll.dataset.all = String(showAll && findings.length > 4);
  viewAll.hidden = findings.length <= 4;
  viewAll.innerHTML = showAll ? 'Show less <span>↑</span>' : 'View all <span>→</span>';
  const host = $("#findings-list");
  if (!findings.length) {
    host.innerHTML = '<div class="empty-state success-empty"><div class="empty-icon">✓</div><strong>No matched issues in this snapshot</strong><span>Keep reviewing your real environment and policies.</span></div>';
    return;
  }
  const visible = showAll ? findings : findings.slice(0, 4);
  host.innerHTML = visible.map((finding) => `<article class="finding-row"><span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span><div class="finding-copy"><strong>${escapeHTML(finding.title)}</strong><span>${escapeHTML(finding.resourceName)} <i>·</i> ${escapeHTML(finding.resourceType)}</span><small>${escapeHTML(finding.fix)}</small></div><span class="finding-id">${finding.id}</span></article>`).join("");
}

function updateBreakdown(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(({ severity }) => counts[severity]++);
  Object.entries(counts).forEach(([severity, count]) => {
    const id = severity.toLowerCase();
    $(`#legend-${id}`).textContent = count;
    if (severity === "Critical" || severity === "High") $(`#${id}-count`).textContent = count;
  });
  const total = findings.length;
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

function renderDashboard(resources, findings) {
  const score = getScore(findings);
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
}

function runScan(resources) {
  if (!Array.isArray(resources)) throw new Error("Your JSON must contain an array of resource objects.");
  if (resources.length > 10000) throw new Error("This demo accepts up to 10,000 resources at a time.");
  if (resources.some((item) => !item || typeof item !== "object" || Array.isArray(item))) throw new Error("Each array item must be a resource object.");
  if (resources.some((item) => !item.type || typeof item.type !== "string")) throw new Error("Every resource needs a string 'type' property. See the example format below.");
  $("#scan-feedback").classList.remove("error");
  const findings = scanResources(resources);
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

// Web application scan mode talks to the local Python service. The service sends
// only ordinary GET requests and returns passive observations to this page.
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
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: target }) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Scan request failed.");
    renderDashboard(result.pages.map((page) => ({ type: "web page", name: new URL(page.url).pathname || "/" })), result.findings);
    webStatus.textContent = `Completed: ${result.pagesScanned} page${result.pagesScanned === 1 ? "" : "s"} inspected. ${result.mode}.`;
    $("#page-list").replaceChildren(...result.pages.map((page) => {
      const row = document.createElement("div"); row.className = "page-item";
      const status = document.createElement("b"); status.textContent = String(page.status);
      const label = document.createElement("span"); label.textContent = `${new URL(page.url).pathname || "/"} · ${page.contentType.split(";")[0]}`;
      row.append(status, label); return row;
    }));
    $("#findings").scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (error) {
    webStatus.textContent = `${error.message} Make sure you started CloudGuard with python server.py.`;
    webStatus.classList.add("error");
  } finally { $("#web-scan-button").disabled = false; }
});
