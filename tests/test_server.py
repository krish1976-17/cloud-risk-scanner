import http.client
import socket
import unittest
from unittest import mock

import server


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"<html><title>Safe</title></html>"):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, _size=-1):
        return self._body


class FakeHTTPConnection:
    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.request_path = None

    def request(self, _method, path, headers=None):
        self.request_path = path
        self._create_connection((self.host, self.port), None, None)

    def _create_connection(self, address, timeout, source_address):
        return socket.create_connection(address, timeout, source_address)

    def getresponse(self):
        if self.request_path == "/redirect":
            return FakeResponse(302, {"Location": "/final"}, b"")
        if self.request_path == "/cross-origin":
            return FakeResponse(302, {"Location": "http://example.com/"}, b"")
        return FakeResponse()

    def close(self):
        pass


class ScannerNetworkTests(unittest.TestCase):
    def setUp(self):
        self.url = "http://127.0.0.1:8123/"
        _parsed, self.origin, self.addresses = server.validate_url(self.url)

    def fetch_with_fakes(self, url):
        observed = []
        def record(address, *_args, **_kwargs):
            observed.append(address)
            return object()
        with mock.patch.object(server.http.client, "HTTPConnection", FakeHTTPConnection), \
             mock.patch.object(server.socket, "create_connection", side_effect=record):
            result = server.fetch(url, self.origin, self.addresses)
        return result, observed

    def test_connection_uses_the_validated_ip_address(self):
        (final_url, status, _headers, body), observed = self.fetch_with_fakes(self.url)
        self.assertEqual(status, 200)
        self.assertIn(b"<title>Safe</title>", body)
        self.assertEqual(final_url, self.url)
        self.assertEqual(observed[0][0], "127.0.0.1")

    def test_same_origin_redirect_is_followed(self):
        target = self.url.rstrip("/") + "/redirect"
        (final_url, status, _headers, _body), _observed = self.fetch_with_fakes(target)
        self.assertEqual(status, 200)
        self.assertTrue(final_url.endswith("/final"))

    def test_cross_origin_redirect_is_rejected(self):
        target = self.url.rstrip("/") + "/cross-origin"
        with self.assertRaisesRegex(ValueError, "Cross-origin redirects are blocked"):
            self.fetch_with_fakes(target)

    def test_non_global_dns_address_is_rejected(self):
        private_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80))]
        with mock.patch.object(server.socket, "getaddrinfo", return_value=private_result):
            with self.assertRaisesRegex(ValueError, "Private, reserved, and link-local"):
                server.validate_url("http://scanner.example/")

    def test_dns_change_after_validation_stops_the_connection(self):
        changed_result = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8123))]
        with mock.patch.object(server.socket, "getaddrinfo", return_value=changed_result):
            with self.assertRaisesRegex(ValueError, "changed its DNS addresses"):
                self.fetch_with_fakes(self.url)

    def test_non_string_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "full http"):
            server.validate_url(None)


if __name__ == "__main__":
    unittest.main()
