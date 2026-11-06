# CloudGuard — Cloud Misconfiguration & Web Application Risk Scanner

CloudGuard is an internship learning project with two scan modes:

- **Cloud config JSON:** browser-based analysis for common cloud configuration patterns.
- **Web application:** a passive URL scan that inspects up to 12 same-site pages for HTTPS use, browser security headers, cookie attributes, mixed content, insecure forms, directory listings, and opener protection.

## Start CloudGuard

Python 3 is required. The project uses only Python's standard library; there are no packages to install.

1. Open PowerShell in this project folder.
2. If an older web server is already running in that window, stop it with **Ctrl+C**.
3. Start the app with:

   ```powershell
   python server.py
   ```

4. Open **http://127.0.0.1:8000** in your browser.
5. Select **Web application**, enter the full URL of an application you own or are authorized to assess, and choose **Scan application**.
6. Stop the server with **Ctrl+C**.

The server listens only on your computer's loopback interface. The web scan makes ordinary GET requests, follows same-origin redirects, and does not log in, submit forms, send attack payloads, or change the target. It limits the scan to 12 pages, a 1 MB response per page, and a six second request timeout. Remote targets must resolve to public IP addresses; private, reserved, and link-local ranges are blocked. The explicit `localhost`, `127.0.0.1`, and `::1` names are allowed for development. DNS is checked again before each fetched page and changes to the resolved address set stop the scan. This is a useful defense for a local demo, not a substitute for running scanners in a dedicated, restricted environment.

## GitHub Pages

GitHub Pages can host the static dashboard and **Cloud config JSON** mode. The **Web application** mode needs the Python service in `server.py`, so it will not work from a Pages-only deployment. The web scanner is intended for local use and should not be exposed as a public service. It has no user authentication or job controls. A team deployment needs authentication, authorization, rate limits, network egress controls, and an approved target policy.

To publish the static dashboard, push the files to your repository, then go to **Settings → Pages → Deploy from a branch**, select `main` and `/ (root)`, and save.

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

## Web scan checks

The web scan checks for HTTP instead of HTTPS, missing HSTS/CSP and related response headers, missing cookie attributes, HTTP references from HTTPS pages, insecure form destinations, password forms without HTTPS, directory index pages, and `target="_blank"` links without opener protections. These are heuristic observations from HTTP responses; JavaScript-rendered content, authenticated areas, API behavior, business logic, and many classes of vulnerability are outside its scope. Findings can be incomplete or false positives. Verify them manually; this is not a penetration test or a substitute for a professional assessment.

## Files

- `index.html`, `styles.css`, `app.js` — the responsive dashboard and browser interaction.
- `server.py` — local static file server and passive web scan endpoint.
- `README.md` — setup and usage guide.
- `LICENSE` — MIT License.
