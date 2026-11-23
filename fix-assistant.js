"use strict";

const advice = {
  S3_PUBLIC: { title: "Storage bucket allows public access", why: "If anonymous access is not intentional, public objects may expose private or customer data.", steps: ["Check the bucket policy, access control list, and public access block in your cloud account.", "Remove public read or write access unless the bucket is deliberately public.", "Check access logs and rotate any credentials that may have been exposed."], verify: "Re-scan a fresh configuration export and confirm public access is disabled." },
  SG_SSH_OPEN: { title: "SSH is open to the internet", why: "Public SSH access increases exposure to password guessing and attacks against the host.", steps: ["Find the security group or firewall rule allowing port 22 from 0.0.0.0/0 or ::/0.", "Restrict SSH to a trusted admin IP range, VPN, or managed access service.", "Remove unused SSH rules and confirm the host has a supported patch level."], verify: "Export the updated rule and confirm port 22 is limited to the intended trusted range." },
  RDS_PUBLIC: { title: "Database is publicly reachable", why: "A public database endpoint can be reached from the internet if network rules also allow it.", steps: ["Confirm whether public database access is needed for this workload.", "Disable public accessibility and place the database in private subnets when possible.", "Restrict database security group rules to the application tier and approved admin paths."], verify: "Re-scan the database configuration and confirm public accessibility is false." },
  ENCRYPTION_OFF: { title: "Encryption at rest is disabled", why: "Stored data may lack an important protection if storage media, snapshots, or backups are exposed.", steps: ["Identify the affected storage resource and whether it contains sensitive data.", "Enable encryption using an approved managed or customer-controlled key.", "Plan any migration or snapshot replacement needed to encrypt existing data."], verify: "Export the updated resource configuration and confirm encryption is enabled." },
  MFA_OFF: { title: "Multi-factor authentication is disabled", why: "A stolen password or access key is easier to use when the identity has no second factor.", steps: ["Identify the human or service identity and its owner.", "Require MFA for human sign-in and move automation to short-lived role credentials where possible.", "Review recent sign-in activity and rotate credentials if misuse is suspected."], verify: "Confirm the account policy or identity setting requires MFA; do not add MFA to unattended service identities without checking the supported method." },
  LOGGING_OFF: { title: "Audit or access logging is disabled", why: "Without logs, suspicious access and changes may be difficult to investigate.", steps: ["Identify which service or resource is missing logs.", "Enable audit or access logging and send records to a protected central destination.", "Set retention and alerting appropriate to the data and incident response process."], verify: "Confirm new log events arrive in the approved destination and are retained." },
  BACKUP_OFF: { title: "Database backups are disabled", why: "A failure, accidental deletion, or ransomware event may be harder to recover from.", steps: ["Enable automated backups and choose a retention period based on recovery needs.", "Protect backups from deletion or modification by ordinary application credentials.", "Run a restore exercise in a safe environment."], verify: "Confirm a recent backup exists and a restore test succeeds." },
  KEY_OLD: { title: "Access key may need rotation", why: "Long-lived keys increase the time window for misuse if they are copied or exposed.", steps: ["Identify what uses the key and check whether it is still needed.", "Create a replacement using a managed secret store or short-lived credentials.", "Update the workload, verify it works, then disable and remove the old key."], verify: "Confirm the workload uses the replacement and the old key is inactive." },
  PAGE_FETCH: { title: "Page could not be inspected", why: "The scanner did not receive a usable response, so this page has no security findings either way.", steps: ["Open the exact page URL in a browser and check whether it requires a login or blocks automated requests.", "Check DNS, TLS certificate validity, redirects, and availability.", "If the site intentionally blocks scanners, use an approved internal review method."], verify: "Retry the scan after confirming the page is publicly reachable; do not interpret a fetch failure as a clean result." },
  DIR_LISTING: { title: "Directory listing may be enabled", why: "A directory index can reveal filenames or files that were not intended to be browsed publicly.", steps: ["Open the reported path and confirm whether it lists directory contents.", "Disable directory indexes in the web server or hosting configuration.", "Move private files outside the public web root and review listed files for exposure."], verify: "Request the path again and confirm it no longer displays a file listing." },
  MIXED_CONTENT: { title: "HTTPS page references HTTP content", why: "Insecure resources can be modified in transit and may weaken an otherwise secure page.", steps: ["Review the reported HTTP resource references.", "Change them to trusted HTTPS URLs or remove resources that are no longer needed.", "Check third-party scripts and styles before allowing them on sensitive pages."], verify: "Re-scan and confirm the HTTPS page no longer references HTTP resources." },
  FORM_HTTP: { title: "Form submits over HTTP", why: "Form data sent without transport encryption may be readable or changed in transit.", steps: ["Confirm the form destination and whether it is still in use.", "Change the destination to HTTPS and ensure the receiving service supports it.", "Avoid sending sensitive values in query strings."], verify: "Inspect the rendered form action and confirm it uses HTTPS." },
  PASSWORD_FORM_HTTP: { title: "Password form does not submit over HTTPS", why: "Credentials must be protected in transit from the browser to the sign-in service.", steps: ["Serve the sign-in page and its form destination over HTTPS.", "Remove redirects or embedded form actions that downgrade to HTTP.", "If credentials may have been sent over HTTP, rotate them and review access logs."], verify: "Confirm the page and form destination both use HTTPS, then re-scan." },
  BLANK_NOOPENER: { title: "New-tab link may lack opener protection", why: "A page opened in a new tab can sometimes access or change the page that opened it.", steps: ["Find links using target=\"_blank\".", "Add rel=\"noopener noreferrer\" unless the opener relationship is required.", "Review any links generated by templates or content systems."], verify: "Inspect the link markup and confirm opener protection is present." },
  HTTPS_NOT_USED: { title: "Website uses HTTP", why: "HTTP does not encrypt traffic or authenticate the destination server.", steps: ["Enable HTTPS with a valid certificate.", "Update internal links and resources to HTTPS.", "Redirect HTTP requests to HTTPS after confirming the full site works securely."], verify: "Open the site over HTTPS and confirm it stays on HTTPS across the pages you use." },
  HSTS_MISSING: { title: "Strict Transport Security header is missing", why: "HSTS tells browsers to use HTTPS for later visits to the site.", steps: ["Confirm every intended hostname and subdomain supports HTTPS.", "Add a suitable Strict-Transport-Security header with an initial short max-age.", "Increase the policy gradually after checking deployment and rollback plans."], verify: "Re-scan and confirm the response includes the expected HSTS header." },
  CSP_MISSING: { title: "Content Security Policy is missing", why: "A well-designed policy can limit the sources of scripts and other content, reducing the impact of some injection bugs.", steps: ["Inventory the scripts, styles, images, and APIs the application needs.", "Start with Content-Security-Policy-Report-Only and review violations.", "Build a restrictive policy, test key workflows, then enforce it."], verify: "Confirm the final policy appears on the intended pages and does not break legitimate workflows." },
  NOSNIFF_MISSING: { title: "MIME sniffing protection is missing", why: "Browsers may interpret some responses differently from their declared content type.", steps: ["Add X-Content-Type-Options: nosniff to web responses.", "Ensure each response has a correct Content-Type.", "Check downloads and script/style resources after the change."], verify: "Confirm the response header is exactly X-Content-Type-Options: nosniff." },
  FRAME_GUARD_MISSING: { title: "Framing protection may be missing", why: "Unwanted framing can let another site overlay or disguise parts of your application.", steps: ["Decide whether the application must be embedded by other sites.", "If not, set CSP frame-ancestors 'none' or an appropriate X-Frame-Options header.", "If embedding is required, list only trusted parent origins."], verify: "Check the response policy and test any legitimate embedding workflow." },
  REFERRER_MISSING: { title: "Referrer Policy is missing", why: "A deliberate policy helps control how much URL information is shared when users follow links.", steps: ["Choose a policy that fits the application, such as strict-origin-when-cross-origin.", "Set the Referrer-Policy response header.", "Check analytics and navigation behavior after the change."], verify: "Confirm the expected Referrer-Policy is present on the relevant pages." },
  PERMISSIONS_MISSING: { title: "Permissions Policy is missing", why: "A Permissions Policy can disable browser features the application does not use.", steps: ["List browser features the app needs, such as camera or microphone access.", "Set a Permissions-Policy that allows only required features and origins.", "Test workflows that use those features."], verify: "Confirm the policy is returned and the required browser features still work." },
  COOKIE_FLAGS: { title: "Cookie security attributes may be missing", why: "Cookie flags help reduce exposure through insecure transport, script access, or cross-site requests.", steps: ["Identify the affected cookie and whether it contains a session or sensitive value.", "Use Secure on HTTPS cookies and HttpOnly for cookies not needed by JavaScript.", "Choose a SameSite setting that fits sign-in, embedded, and cross-site flows."], verify: "Inspect Set-Cookie responses and confirm appropriate Secure, HttpOnly, and SameSite attributes." }
};

const storageKey = "cloudguard_latest_scan_v1";
const input = document.querySelector("#findings-input");
const output = document.querySelector("#fix-output");
const status = document.querySelector("#fix-status");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function loadLatest() {
  try {
    const value = sessionStorage.getItem(storageKey);
    if (!value) return null;
    const parsed = JSON.parse(value);
    return parsed && Array.isArray(parsed.findings) ? parsed : null;
  } catch { return null; }
}

function normalizeFindings(value) {
  if (Array.isArray(value)) return value.filter((item) => item && typeof item === "object");
  if (value && Array.isArray(value.findings)) return value.findings.filter((item) => item && typeof item === "object");
  return [];
}

function parseUserInput(raw) {
  const text = raw.trim();
  if (!text) return null;
  try { return normalizeFindings(JSON.parse(text)); }
  catch {
    const upper = text.toUpperCase();
    const matches = Object.entries(advice).filter(([id, item]) => upper.includes(id) || text.toLowerCase().includes(item.title.toLowerCase()));
    return matches.map(([id, item]) => ({ id, title: item.title, severity: "Review", detail: text }));
  }
}

function renderPlan(findings, context = {}) {
  output.replaceChildren();
  status.classList.remove("error");
  if (!findings.length) {
    const empty = element("section", "panel fix-empty");
    empty.append(element("h2", "", "No findings to work on yet"));
    empty.append(element("p", "", "Run a CloudGuard scan in this browser tab, or paste a finding ID or report above. The latest scan is saved only for this browser tab session."));
    const link = element("a", "primary-button", "Open scanner"); link.href = "index.html#scanner";
    empty.append(link); output.append(empty);
    status.textContent = "";
    return;
  }

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach((finding) => { if (counts[finding.severity] !== undefined) counts[finding.severity]++; });
  const summary = element("div", "fix-summary");
  const label = element("strong", "", `${findings.length} finding${findings.length === 1 ? "" : "s"} · ${context.mode || "Pasted report"}`);
  const total = element("span", "", `Critical ${counts.Critical} · High ${counts.High} · Medium ${counts.Medium} · Low ${counts.Low}`);
  summary.append(label, total);
  if (context.target) summary.append(element("span", "", context.target));
  output.append(summary);

  const list = element("div", "fix-list");
  findings.forEach((finding) => {
    const id = String(finding.id || "").toUpperCase();
    const guidance = advice[id] || {
      title: finding.title || "Review this finding",
      why: "CloudGuard flagged a condition that needs a manual check in the target environment.",
      steps: [finding.fix || "Review the finding evidence and identify the exact setting or response involved.", "Make the smallest safe change that addresses the confirmed cause.", "Re-run the scan to check whether the finding is resolved."],
      verify: "Confirm the underlying setting or response has changed; a lower score alone does not prove the issue is fixed."
    };
    const card = element("article", "panel fix-card");
    const top = element("div", "fix-card-top");
    const severity = element("span", `severity-badge ${(finding.severity || "low").toLowerCase()}`, finding.severity || "Review");
    const heading = element("div");
    heading.append(element("h2", "", finding.title || guidance.title));
    heading.append(element("div", "fix-resource", finding.resourceName || finding.resourceType || context.target || "CloudGuard finding"));
    top.append(severity, heading, element("div", "fix-rule", id || "GENERAL"));
    card.append(top);

    const evidenceText = finding.detail || finding.fix || "No evidence text was included. Open the original scan and inspect the affected resource or page.";
    card.append(element("div", "fix-evidence", `Evidence from the scan: ${evidenceText}`));
    const columns = element("div", "fix-columns");
    const stepsBlock = element("div");
    stepsBlock.append(element("h3", "", "Steps to address it"));
    const steps = element("ol");
    const completion = element("div", "fix-card-done");
    guidance.steps.forEach((step) => {
      const item = element("li");
      const checkbox = document.createElement("input"); checkbox.type = "checkbox";
      checkbox.setAttribute("aria-label", step);
      const text = element("span", "", step);
      item.style.display = "flex"; item.style.gap = "7px"; item.style.alignItems = "flex-start";
      item.append(checkbox, text); steps.append(item);
      checkbox.addEventListener("change", () => {
        const boxes = [...steps.querySelectorAll("input[type=checkbox]")];
        completion.textContent = boxes.every((box) => box.checked) ? "Checklist done. Re-scan and verify the original evidence before calling this resolved." : "";
      });
    });
    stepsBlock.append(steps);
    const whyBlock = element("div");
    whyBlock.append(element("h3", "", "Why it matters"), element("p", "", guidance.why));
    columns.append(stepsBlock, whyBlock);
    card.append(columns);
    const verify = element("div", "fix-verify");
    verify.append(element("strong", "", "How to confirm the fix"), element("p", "", guidance.verify));
    card.append(verify, completion);
    list.append(card);
  });
  output.append(list);
  const scanned = context.scannedAt ? new Date(context.scannedAt).toLocaleString() : "";
  status.textContent = scanned ? `Loaded from the latest scan in this tab · ${scanned}` : "Built-in fix guidance loaded from the finding text.";
}

document.querySelector("#load-latest").addEventListener("click", () => {
  const latest = loadLatest();
  if (!latest) {
    status.textContent = "No recent scan is saved in this tab. Run a scan here or paste a finding above.";
    status.classList.add("error");
    return;
  }
  input.value = "";
  renderPlan(latest.findings, latest);
});

document.querySelector("#make-plan").addEventListener("click", () => {
  const latest = loadLatest();
  const text = input.value.trim();
  if (!text && latest) { renderPlan(latest.findings, latest); return; }
  if (!text) { renderPlan([]); return; }
  const findings = parseUserInput(text);
  if (!findings || !findings.length) {
    status.textContent = "I couldn't match that text to a finding. Paste a CloudGuard report JSON or a finding code such as CSP_MISSING.";
    status.classList.add("error");
    return;
  }
  renderPlan(findings);
});

const latest = loadLatest();
if (latest) renderPlan(latest.findings, latest);
else renderPlan([]);
