import json
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class VulnerableTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlsplit(self.path)
        parameters = parse_qs(parsed_url.query)

        if parsed_url.path == "/boolean":
            body = self.boolean_sqli_response(parameters.get("id", [""])[0])
        elif parsed_url.path == "/time":
            value = parameters.get("id", [""])[0]
            if "sleep(7)" in value.casefold():
                time.sleep(5.8)
            body = f"<html><body>{value}</body></html>"
        else:
            value = parameters.get("q", [""])[0]
            body = f"<html><body>{value}</body></html>"

        body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def boolean_sqli_response(value):
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(
                "CREATE TABLE items (id INTEGER, name TEXT);"
                "INSERT INTO items VALUES (1, 'one'), (2, 'two'), (3, 'three'), (4, 'four');"
            )
            try:
                rows = connection.execute(
                    f"SELECT id, name FROM items WHERE id = '{value}'"
                ).fetchall()
            except sqlite3.Error:
                rows = []
        finally:
            connection.close()

        contents = "\n".join(f"{item_id}:{name}" for item_id, name in rows)
        return f"<html><body>\n{contents}\n</body></html>"

    def log_message(self, format, *args):
        pass


class CliIntegrationTest(unittest.TestCase):
    def run_cli(self, path, parameter, test_name, timeout=30):
        server = HTTPServer(("127.0.0.1", 0), VulnerableTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{server.server_port}{path}"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ptinjector.ptinjector",
                    "-u",
                    url,
                    "-P",
                    parameter,
                    "-ts",
                    test_name,
                    "-j",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "finished")
        return output

    def assert_sqli_found(self, output):
        self.assertTrue(output["results"]["vulnerabilities"])
        self.assertEqual(
            output["results"]["vulnerabilities"][0]["vulnCode"],
            "PTV-WEB-SANIT-SQLINJ",
        )

    def test_cli_finds_reflected_xss_against_local_target(self):
        output = self.run_cli("/?q=value", "q", "xss")

        self.assertTrue(output["results"]["vulnerabilities"])
        self.assertEqual(
            output["results"]["vulnerabilities"][0]["vulnCode"],
            "PTV-WEB-SANIT-OUTPUTENC",
        )

    def test_cli_finds_boolean_sqli_against_sqlite_target(self):
        output = self.run_cli("/boolean?id=1", "id", "sqli_boolean")
        self.assert_sqli_found(output)

    def test_cli_confirms_time_sqli_twice(self):
        output = self.run_cli("/time?id=1", "id", "sqli_time", timeout=30)
        self.assert_sqli_found(output)


if __name__ == "__main__":
    unittest.main()
