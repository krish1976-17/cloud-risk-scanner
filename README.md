# CloudGuard — Cloud Misconfiguration & Web Application Risk Scanner

CloudGuard is an internship learning project with two scan modes:

- **Cloud config JSON:** browser-based analysis for common cloud configuration patterns.
- **Web application:** a passive URL scan that inspects up to 12 same-site pages for HTTPS use, browser security headers, cookie attributes, mixed content, insecure forms, directory listings, and opener protection.

## Hosted website scanner

The GitHub Pages dashboard sends web scan requests to the companion Python service. To run both parts as one hosted application, create a Render Blueprint from this repository; Render reads the included `render.yaml` file and deploys the Python service. The service also serves the dashboard at [cloud-risk-scanner-api.onrender.com](https://cloud-risk-scanner-api.onrender.com). GitHub Pages uses that address as its API; if Render assigns a different service URL, update `scannerApiBase` in `app.js` to that address and publish the change. See [Render's Blueprint deployment guide](https://render.com/docs/infrastructure-as-code) for the setup flow.

The web scanner accepts public HTTP and HTTPS sites on standard ports only. It makes ordinary GET requests, follows same-origin redirects, and does not log in, submit forms, send attack payloads, or change the target. It limits each scan to 12 pages, 1 MB per response, and a six second timeout; it allows up to five scans per client in a minute. Private, reserved, and link-local network addresses are blocked, and DNS is pinned to validated public IPs. Scan only sites you own or are authorized to assess. This learning project is not a penetration test or a production security service.

## Run locally

Python 3 is required. The project uses only Python's standard library.

1. Open PowerShell in this project folder.
2. Start the app with `python server.py`.
3. Open **http://127.0.0.1:8000** in your browser.
4. Select **Web application**, enter a full public site URL (or a localhost target while running locally), and choose **Scan application**.
5. Stop the server with **Ctrl+C**.

## GitHub Pages

GitHub Pages hosts the dashboard and **Cloud config JSON** mode. Web application scans use the companion hosted Python service above. To publish the static dashboard, push the files to your repository, then go to **Settings → Pages → Deploy from a branch**, select `main` and `/ (root)`, and save.

The public site includes `robots.txt` and `sitemap.xml` to help search engines discover it. For Google, add the site as a URL-prefix property in [Google Search Console](https://search.google.com/search-console), verify ownership, and submit `https://krish1976-17.github.io/cloud-risk-scanner/sitemap.xml`. Search listings can take time and are not guaranteed.

## Cloud configuration scan

Use the **Cloud config JSON** tab and paste or upload an array of resources. Each object needs a string `type`. Supported types: `s3_bucket`, `security_group`, `rds_instance`, `iam_user`, `iam_identity`, `cloudtrail`, and `ebs_volume`.

```json
[
  {
    "type": "s3_bucket",
    "name": "customer-uploads",
    "public_access": false,
    "encryption_enabled": true,
    "logging_enabled": true
  }
]
```

The cloud rules check public bucket access, public SSH, publicly accessible databases, encryption, MFA, logging, backups, and old access keys. The posture score is an educational demonstration: 100 minus 25 per Critical, 15 per High, 8 per Medium, and 3 per Low finding, with a floor of 0. Each matched rule is counted independently, so repeated findings can lower the score quickly. It is not an industry-standard rating or a measure of overall cloud security.

For a guided demonstration, choose **Try sample scan** on the dashboard, open **Fix assistant** for the findings, then return to the scanner, choose **Load secure example**, and run the scan again. The sample issues should clear. The score formula and each scan's point deductions are shown beside the dashboard score and included in the downloadable JSON report.

## Web scan checks

The web scan checks for HTTP instead of HTTPS, missing HSTS/CSP and related response headers, missing cookie attributes, HTTP references from HTTPS pages, insecure form destinations, password forms without HTTPS, directory index pages, and `target="_blank"` links without opener protections. These are heuristic observations from HTTP responses; JavaScript-rendered content, authenticated areas, API behavior, business logic, and many classes of vulnerability are outside its scope. Findings can be incomplete or false positives. Verify them manually.

## Run the tests

The backend tests use Python's standard library. The cloud JSON validation tests use Node.js's built-in test runner; the app itself still runs without Node.js.

```powershell
python -m unittest discover -s tests -p "test_*.py"
node --test tests/test_config_validation.js
```

## Files

- `index.html`, `guide.html`, `fixes.html`, `styles.css`, `app.js`, `fix-assistant.js`, `config-validation.js` — the dashboard, guide, session-based fix assistant, browser interaction, and cloud JSON validation.
- `server.py` — dashboard server and passive web scan endpoint.
- `render.yaml` — hosted backend deployment settings.
- `tests/` — backend URL/network-safety tests and cloud JSON validation tests.
- `README.md` — setup and usage guide.
- `LICENSE` — MIT License.
