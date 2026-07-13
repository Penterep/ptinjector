import json
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen


class VulnerableTargetHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        request_data = self.rfile.read(content_length).decode()
        value = parse_qs(request_data).get("q", [""])[0]
        expected_context = (
            self.headers.get("Cookie") == "session=integration"
            and self.headers.get("X-Integration") == "enabled"
            and self.headers.get("User-Agent") == "ptinjector-integration"
        )
        body = (
            f"<html><body>{value}</body></html>"
            if expected_context else "<html><body>missing request context</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed_url = urlsplit(self.path)
        parameters = parse_qs(parsed_url.query)
        response_status = 200
        response_headers = {}

        if parsed_url.path == "/boolean":
            body = self.boolean_sqli_response(parameters.get("id", [""])[0])
        elif parsed_url.path == "/time":
            value = parameters.get("id", [""])[0]
            if "sleep(7)" in value.casefold():
                time.sleep(5.8)
            body = f"<html><body>{value}</body></html>"
        elif parsed_url.path == "/ssrf":
            value = parameters.get("url", [""])[0]
            if value.startswith(("http://", "https://")):
                with urlopen(value, timeout=2) as callback_response:
                    callback_response.read()
            body = "<html><body>request processed</body></html>"
        elif parsed_url.path == "/disconnect":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        elif parsed_url.path == "/error-sqli":
            value = parameters.get("q", [""])[0]
            body = (
                "You have an error in your SQL syntax;"
                if any(character in value for character in ("'", '"', "\\"))
                else "normal database response"
            )
        elif parsed_url.path == "/redirect":
            value = parameters.get("next", [""])[0]
            body = "redirect"
            if value.startswith(("http://", "https://", "//")):
                response_status = 302
                response_headers["Location"] = value
        elif parsed_url.path == "/crlf":
            value = parameters.get("q", [""])[0]
            body = "header response"
            for line in value.replace("\r", "").split("\n")[1:]:
                header_name, separator, header_value = line.partition(":")
                if separator and header_name:
                    response_headers[header_name] = header_value
        elif parsed_url.path == "/host":
            body = f"<html><body>{self.headers.get('Host', '')}</body></html>"
        elif parsed_url.path == "/command":
            value = parameters.get("q", [""])[0]
            expression = re.search(r"(\d{4})\s*\*\s*10", value)
            body = str(int(expression.group(1)) * 10) if expression else "normal command response"
        else:
            value = parameters.get("q", [""])[0]
            body = f"<html><body>{value}</body></html>"

        body = body.encode()
        self.send_response(response_status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for header_name, header_value in response_headers.items():
            self.send_header(header_name, header_value)
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
    def run_cli(self, path, parameter, test_name, timeout=30, extra_args=None, expected_returncode=0):
        server = HTTPServer(("127.0.0.1", 0), VulnerableTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{server.server_port}{path}"
            command = [
                sys.executable,
                "-m",
                "ptinjector.ptinjector",
                "-u",
                url,
                "-P",
                parameter,
                "-ts",
                test_name,
            ]
            command.extend(extra_args or [])
            command.append("-j")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.assertEqual(result.returncode, expected_returncode, result.stderr)
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

    def test_cli_preserves_post_cookies_headers_and_user_agent(self):
        output = self.run_cli(
            "/form",
            "q",
            "xss",
            extra_args=[
                "--data", "q=value",
                "--cookie", "session=integration",
                "--headers", "X-Integration: enabled",
                "--user-agent", "ptinjector-integration",
            ],
        )

        self.assertEqual(
            output["results"]["vulnerabilities"][0]["vulnCode"],
            "PTV-WEB-SANIT-OUTPUTENC",
        )

    def test_cli_scans_parameter_from_request_file(self):
        server = HTTPServer(("127.0.0.1", 0), VulnerableTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as directory:
                request_path = f"{directory}/request.txt"
                with open(request_path, "w") as request_file:
                    request_file.write(
                        "GET /?q=value HTTP/1.1\n"
                        f"Host: 127.0.0.1:{server.server_port}\n\n"
                    )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ptinjector.ptinjector",
                        "--request-file",
                        request_path,
                        "--parameter",
                        "q",
                        "--tests",
                        "xss",
                        "--json",
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

    def test_cli_finds_error_based_sqli(self):
        output = self.run_cli("/error-sqli?q=value", "q", "sqli_error")
        self.assert_sqli_found(output)

    def test_cli_finds_open_redirect(self):
        output = self.run_cli("/redirect?next=value", "next", "openredirect")
        self.assertEqual(output["results"]["vulnerabilities"][0]["vulnCode"], "REDIR")

    def test_cli_finds_crlf_header_injection(self):
        output = self.run_cli("/crlf?q=value", "q", "crlf")
        self.assertEqual(output["results"]["vulnerabilities"][0]["vulnCode"], "CRLF")

    def test_cli_finds_host_header_injection(self):
        output = self.run_cli("/host?q=value", "q", "hhi")
        self.assertEqual(output["results"]["vulnerabilities"][0]["vulnCode"], "HHI")

    def test_cli_finds_command_injection_marker(self):
        output = self.run_cli("/command?q=value", "q", "oscommand", timeout=60)
        self.assertEqual(
            output["results"]["vulnerabilities"][0]["vulnCode"],
            "Command injection",
        )

    def test_cli_does_not_reuse_stale_ssrf_callback(self):
        from ptinjector.server.app import MyAPI
        from werkzeug.serving import make_server

        with tempfile.TemporaryDirectory() as config_path:
            callback_api = MyAPI(None, 0, config_path=config_path, start_scheduler=False)
            callback_server = make_server("127.0.0.1", 0, callback_api.app)
            callback_thread = threading.Thread(target=callback_server.serve_forever, daemon=True)
            callback_thread.start()
            try:
                callback_base_url = f"http://127.0.0.1:{callback_server.server_port}"
                output = self.run_cli(
                    "/ssrf?url=value",
                    "url",
                    "ssrf",
                    timeout=30,
                    extra_args=["--verify-url", callback_base_url, "--keep-testing"],
                )
            finally:
                callback_server.shutdown()
                callback_thread.join(timeout=5)
                callback_server.server_close()

        vulnerabilities = output["results"]["vulnerabilities"]
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["vulnCode"], "SSRF")

    def test_cli_marks_network_failure_as_incomplete(self):
        output = self.run_cli(
            "/disconnect?q=value",
            "q",
            "xss",
            expected_returncode=2,
        )

        self.assertEqual(output["status"], "finished")
        self.assertIn("results are incomplete", output["message"])
        self.assertTrue(output["results"]["properties"]["incomplete"])
        self.assertTrue(output["results"]["properties"]["requestErrors"])


if __name__ == "__main__":
    unittest.main()
