"""Local, read-only web application posture scanner for the CloudGuard demo."""
from __future__ import annotations

import html.parser
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
ALLOWED_ORIGINS = {item.strip() for item in os.environ.get(
    "ALLOWED_ORIGINS",
    "https://krish1976-17.github.io,https://cloud-risk-scanner-api.onrender.com",
).split(",") if item.strip()}
MAX_PAGES = 12
MAX_BYTES = 1_000_000
TIMEOUT = 6
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_SCANS = 5
_scan_times = {}
_scan_times_lock = threading.Lock()

class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.title = ""
        self.in_title = False
        self.mixed = []
        self.external_blank = 0
        self.password_forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title": self.in_title = True
        for key in ("src", "href", "action"):
            value = attrs.get(key, "")
            if value.startswith("http://"):
                self.mixed.append(value)
        if tag in ("a", "link") and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "form":
            form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower()}
            self.forms.append(form)
        if tag == "input" and attrs.get("type", "").lower() == "password" and self.forms:
            self.password_forms.append(len(self.forms) - 1)
        if tag == "a" and attrs.get("target", "").lower() == "_blank":
            rel = set(attrs.get("rel", "").lower().split())
            if not {"noopener", "noreferrer"}.intersection(rel): self.external_blank += 1

    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False

    def handle_data(self, data):
        if self.in_title: self.title += data

def validate_url(value):
    if not isinstance(value, str):
        raise ValueError("Enter a full http:// or https:// URL.")
    parsed = urllib.parse.urlparse(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing a username or password are not accepted.")
    try: port = parsed.port
    except ValueError: raise ValueError("The URL has an invalid port.")
    origin = (parsed.scheme, parsed.hostname.lower(), port or (443 if parsed.scheme == "https" else 80))
    if origin[2] not in (80, 443) and origin[1] not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Remote scans are limited to standard HTTP and HTTPS ports (80 and 443).")
    # Permit loopback only by its explicit local names for development. Remote scans
    # must resolve exclusively to globally routable addresses.
    local_names = {"localhost", "127.0.0.1", "::1"}
    is_local_target = origin[1] in local_names
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(origin[1], origin[2], type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve that host: {error}")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if is_local_target and ip.is_loopback:
            continue
        if not ip.is_global:
            raise ValueError("Private, reserved, and link-local network addresses are blocked. Only public sites and explicit localhost targets can be scanned.")
    if is_local_target and not all(ipaddress.ip_address(address.split("%", 1)[0]).is_loopback for address in addresses):
        raise ValueError("Localhost must resolve only to loopback addresses.")
    return parsed, origin, frozenset(addresses)

def fetch(url, origin, allowed_addresses):
    class PinnedHTTPConnection(http.client.HTTPConnection):
        def __init__(self, host, port, address):
            super().__init__(host, port, timeout=TIMEOUT)
            self.pinned_address = address
        def _create_connection(self, address, timeout, source_address):
            return socket.create_connection((self.pinned_address, address[1]), timeout, source_address)

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, host, port, address):
            super().__init__(host, port, timeout=TIMEOUT, context=ssl.create_default_context())
            self.pinned_address = address
        def _create_connection(self, address, timeout, source_address):
            return socket.create_connection((self.pinned_address, address[1]), timeout, source_address)

    current_url = url
    for redirect_count in range(6):
        current = urllib.parse.urlparse(current_url)
        current_origin = (current.scheme, (current.hostname or "").lower(), current.port or (443 if current.scheme == "https" else 80))
        if current_origin != origin:
            raise ValueError("Cross-origin redirects are blocked.")
        try:
            current_addresses = {item[4][0] for item in socket.getaddrinfo(origin[1], origin[2], type=socket.SOCK_STREAM)}
        except socket.gaierror as error:
            raise ValueError(f"Could not resolve the target host: {error}")
        if not current_addresses or not current_addresses.issubset(allowed_addresses):
            raise ValueError("The target host changed its DNS addresses during the scan.")
        local_names = {"localhost", "127.0.0.1", "::1"}
        for address in current_addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            if not ip.is_global and not (origin[1] in local_names and ip.is_loopback):
                raise ValueError("The target resolved to a blocked network address.")

        address = sorted(current_addresses)[0]
        connection_type = PinnedHTTPSConnection if current.scheme == "https" else PinnedHTTPConnection
        connection = connection_type(origin[1], origin[2], address)
        path = urllib.parse.urlunparse(("", "", current.path or "/", current.params, current.query, ""))
        host_header = f"[{origin[1]}]" if ":" in origin[1] else origin[1]
        default_port = 443 if origin[0] == "https" else 80
        if origin[2] != default_port:
            host_header += f":{origin[2]}"
        try:
            connection.request("GET", path, headers={
                "Host": host_header,
                "User-Agent": "CloudGuard-InternshipScanner/1.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.2",
                "Connection": "close",
            })
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308) and response.getheader("Location"):
                next_url = urllib.parse.urljoin(current_url, response.getheader("Location"))
                next_parsed = urllib.parse.urlparse(next_url)
                next_origin = (next_parsed.scheme, (next_parsed.hostname or "").lower(), next_parsed.port or (443 if next_parsed.scheme == "https" else 80))
                response.read(1024)
                if next_origin != origin:
                    raise ValueError("Cross-origin redirects are blocked.")
                if redirect_count == 5:
                    raise ValueError("The target redirected too many times.")
                current_url = next_url
                continue
            body = response.read(MAX_BYTES + 1)[:MAX_BYTES]
            return current_url, response.status, response.headers, body
        finally:
            connection.close()
    raise ValueError("The target redirected too many times.")

HEADER_RULES = [
    ("CSP_MISSING", "Medium", "Content Security Policy is missing", "Add a Content-Security-Policy suited to the application's scripts, styles, and APIs.", "content-security-policy"),
    ("NOSNIFF_MISSING", "Low", "MIME sniffing protection is missing", "Set X-Content-Type-Options: nosniff.", "x-content-type-options"),
    ("FRAME_GUARD_MISSING", "Medium", "Clickjacking protection is missing", "Set CSP frame-ancestors or X-Frame-Options if framing is not required.", "x-frame-options"),
    ("REFERRER_MISSING", "Low", "Referrer Policy is missing", "Set a deliberate Referrer-Policy such as strict-origin-when-cross-origin.", "referrer-policy"),
    ("PERMISSIONS_MISSING", "Low", "Permissions Policy is missing", "Set a Permissions-Policy that disables browser features the app does not need.", "permissions-policy"),
]

def scan(target):
    parsed, origin, allowed_addresses = validate_url(target)
    queue = [urllib.parse.urlunparse(parsed._replace(fragment=""))]
    seen, findings, pages, all_headers, tech = set(), [], [], [], set()
    def add(severity, rule, title, detail, fix, page):
        findings.append({"severity": severity, "id": rule, "title": title, "detail": detail, "fix": fix, "resourceName": page, "resourceType": "web page"})
    while queue and len(seen) < MAX_PAGES:
        url = queue.pop(0)
        if url in seen: continue
        seen.add(url)
        try:
            final_url, status, headers, body = fetch(url, origin, allowed_addresses)
        except Exception as error:
            add("Medium", "PAGE_FETCH", "Page could not be inspected", f"{url}: {str(error)[:180]}", "Confirm the URL is reachable and try again.", url)
            continue
        page = urllib.parse.urlparse(final_url).path or "/"
        content_type = headers.get("Content-Type", "")
        pages.append({"url": final_url, "status": status, "contentType": content_type})
        all_headers.append(headers)
        server = headers.get("Server")
        if server: tech.add("Server header present")
        if "text/html" not in content_type.lower(): continue
        text = body.decode("utf-8", errors="replace")
        parser = LinkParser()
        try: parser.feed(text)
        except Exception: pass
        if parser.title.strip().lower().startswith("index of "):
            add("Medium", "DIR_LISTING", "Directory listing may be enabled", "This page title resembles a server directory index.", "Disable directory indexes unless the content is intentionally public.", page)
        if parsed.scheme == "https" and parser.mixed:
            add("Medium", "MIXED_CONTENT", "Page references insecure HTTP resources", f"Found {len(parser.mixed)} HTTP resource reference(s).", "Serve scripts, styles, images, and form destinations over HTTPS.", page)
        for form in parser.forms:
            action = urllib.parse.urljoin(final_url, form["action"] or final_url)
            if urllib.parse.urlparse(final_url).scheme == "https" and urllib.parse.urlparse(action).scheme == "http":
                add("High", "FORM_HTTP", "Form submits over insecure HTTP", f"Form destination: {action}", "Submit form data only over HTTPS.", page)
        for idx in parser.password_forms:
            form = parser.forms[idx]
            action = urllib.parse.urljoin(final_url, form["action"] or final_url)
            if urllib.parse.urlparse(action).scheme != "https":
                add("Critical", "PASSWORD_FORM_HTTP", "Password form does not submit over HTTPS", f"Form destination: {action}", "Serve the page and submit credentials only over HTTPS.", page)
        if parser.external_blank:
            add("Low", "BLANK_NOOPENER", "New-tab links may lack opener protection", f"Found {parser.external_blank} link(s) with target=_blank and no noopener/noreferrer.", "Add rel=noopener to links opened in a new tab.", page)
        for href in parser.links:
            absolute = urllib.parse.urljoin(final_url, href)
            dest = urllib.parse.urlparse(absolute)
            candidate_origin = (dest.scheme, (dest.hostname or "").lower(), dest.port or (443 if dest.scheme == "https" else 80))
            if candidate_origin == origin and dest.scheme in ("http", "https") and absolute not in seen and absolute not in queue and not dest.path.lower().endswith(tuple((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".pdf", ".zip"))):
                queue.append(urllib.parse.urlunparse(dest._replace(fragment="")))
    if not pages: raise ValueError("No pages could be read. Check the URL and make sure the app is running.")
    first = all_headers[0]
    if origin[0] == "http":
        add("High", "HTTPS_NOT_USED", "Application is using HTTP", "The scanned URL does not use HTTPS.", "Use HTTPS for the application and redirect HTTP traffic to HTTPS.", origin[1])
    else:
        if not any("strict-transport-security" in h for h in all_headers):
            add("Medium", "HSTS_MISSING", "Strict Transport Security is missing", "No scanned page returned a Strict-Transport-Security header.", "Add HSTS after confirming all subdomains support HTTPS.", origin[1])
    for rule, severity, title, fix, header in HEADER_RULES:
        if not any(h.get(header) for h in all_headers):
            if rule == "FRAME_GUARD_MISSING" and any(h.get("Content-Security-Policy", "").lower().find("frame-ancestors") >= 0 for h in all_headers): continue
            add(severity, rule, title, f"No scanned page returned the {header} header.", fix, origin[1])
    cookies = [value for headers in all_headers for value in headers.get_all("Set-Cookie", [])]
    for cookie in cookies:
        low = cookie.lower()
        missing = [name for name in ("secure", "httponly", "samesite") if not re.search(r"(?:^|;\s*)" + name + r"(?:=|;|$)", low)]
        if missing:
            add("Medium", "COOKIE_FLAGS", "Cookie may be missing security attributes", "A response cookie lacks: " + ", ".join(missing), "Set Secure, HttpOnly, and an appropriate SameSite attribute where applicable.", origin[1])
    return {"target": target, "pagesScanned": len(pages), "pages": pages, "findings": findings, "mode": "read-only GET requests; no login or payload tests"}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(ROOT), **kwargs)
    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        request_origin = self.headers.get("Origin", "")
        allowed_origins = ALLOWED_ORIGINS | {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
        if request_origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", request_origin)
            self.send_header("Vary", "Origin")
        super().end_headers()
    def do_OPTIONS(self):
        request_origin = self.headers.get("Origin", "")
        allowed_origins = ALLOWED_ORIGINS | {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
        if self.path != "/api/scan" or request_origin not in allowed_origins:
            self.send_error(403, "This page is not allowed to use the scanner."); return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", request_origin)
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()
    def do_POST(self):
        if self.path != "/api/scan": self.send_error(404); return
        origin = self.headers.get("Origin", "")
        allowed_origins = ALLOWED_ORIGINS | {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
        if origin not in allowed_origins:
            self.send_error(403, "This page is not allowed to use the scanner."); return
        try:
            client_ip = self.headers.get("CF-Connecting-IP", self.headers.get("X-Forwarded-For", self.client_address[0]).split(",", 1)[0]).strip()
            now = time.monotonic()
            with _scan_times_lock:
                if len(_scan_times) > 1000:
                    _scan_times.clear()
                recent = [stamp for stamp in _scan_times.get(client_ip, []) if now - stamp < RATE_LIMIT_WINDOW]
                if len(recent) >= RATE_LIMIT_SCANS:
                    self._send_json(429, {"error": "Scan limit reached. Wait a minute and try again."})
                    return
                recent.append(now)
                _scan_times[client_ip] = recent
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096: raise ValueError("Request size is invalid.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict): raise ValueError("Request body must be a JSON object.")
            result = scan(str(data.get("url", "")))
            self._send_json(200, result)
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
        except Exception as error:
            self._send_json(502, {"error": f"Scan failed: {str(error)[:200]}"})
    def do_GET(self):
        if self.path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "CloudGuard passive scanner"})
            return
        super().do_GET()
    def _send_json(self, status, value):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, fmt, *args): print("[CloudGuard] " + fmt % args)

if __name__ == "__main__":
    print(f"CloudGuard is ready at http://{HOST}:{PORT}")
    print("Use this scanner only with applications you own or are authorized to assess.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


