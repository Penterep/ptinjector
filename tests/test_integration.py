import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class ReflectedParameterHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = f"<html><body>{value}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class CliIntegrationTest(unittest.TestCase):
    def test_cli_finds_reflected_xss_against_local_target(self):
        server = HTTPServer(("127.0.0.1", 0), ReflectedParameterHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{server.server_port}/?q=value"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ptinjector.ptinjector",
                    "-u",
                    url,
                    "-P",
                    "q",
                    "-ts",
                    "xss",
                    "-j",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "finished")
        self.assertTrue(output["results"]["vulnerabilities"])
        self.assertEqual(
            output["results"]["vulnerabilities"][0]["vulnCode"],
            "PTV-WEB-SANIT-OUTPUTENC",
        )


if __name__ == "__main__":
    unittest.main()
