import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ptinjector.ptinjector import PtInjector
from ptinjector.request_parser import InjectionRequestParser


def request_cases():
    cases = [
        ("GET", "GET", "/?id=1", None, "", "id"),
        ("form", "POST", "/", "application/x-www-form-urlencoded", "id=1", "id"),
        ("JSON", "POST", "/", "application/json", '{"user":{"id":1}}', "user.id"),
        ("XML", "POST", "/", "application/xml", "<root><id>1</id></root>", "root.id"),
        ("multipart", "POST", "/", "multipart/form-data; boundary=boundary",
         '--boundary\nContent-Disposition: form-data; name="id"\n\n1\n--boundary--\n', "id"),
    ]
    for name, method, path, content_type, body, parameter in cases:
        request = f"{method} {path} HTTP/1.1\nHost: 127.0.0.1:9\n"
        if content_type:
            request += f"Content-Type: {content_type}\nContent-Length: {len(body.encode())}\n"
        yield name, request + "\n" + body, parameter


class RequestParameterValidationTest(unittest.TestCase):
    def make_injector(self):
        injector = object.__new__(PtInjector)
        injector.PLACEHOLDER_EXISTS = False
        injector.use_json = False
        injector.ptjsonlib = SimpleNamespace(end_error=Mock(side_effect=SystemExit(1)))
        injector.request_parser = InjectionRequestParser(injector.ptjsonlib, False)
        injector.send_initial_request = Mock()
        return injector

    def test_existing_names_and_indexes_remain_valid(self):
        for name, request, parameter in request_cases():
            for selector in (parameter, "0"):
                with self.subTest(format=name, selector=selector):
                    injector = self.make_injector()
                    args = SimpleNamespace(request_file="request.txt", request_text=request, parameter=selector)
                    self.assertTrue(injector.is_valid_request(args))
                    injector.ptjsonlib.end_error.assert_not_called()

    def test_missing_parameter_is_rejected_before_network_request(self):
        for name, request, _ in request_cases():
            for selector in ("missing", "99"):
                with self.subTest(format=name, selector=selector):
                    injector = self.make_injector()
                    args = SimpleNamespace(request_file="request.txt", request_text=request, parameter=selector)
                    with self.assertRaises(SystemExit):
                        injector.run(args)
                    injector.send_initial_request.assert_not_called()
                    message, use_json = injector.ptjsonlib.end_error.call_args.args
                    self.assertIn(f"Parameter {selector!r} was not found", message)
                    self.assertIn("Available parameters:", message)

    def test_cli_missing_parameter_has_no_traceback_in_text_or_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.txt"
            for name, request, _ in request_cases():
                path.write_text(request)
                for use_json in (False, True):
                    with self.subTest(format=name, json=use_json):
                        command = [sys.executable, "-m", "ptinjector.ptinjector",
                                   "--request-file", str(path), "-P", "missing", "-ts", "sqli_boolean"]
                        if use_json:
                            command.append("--json")
                        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("Traceback", result.stdout + result.stderr)
                        self.assertNotIn("Request failed", result.stdout + result.stderr)
                        self.assertIn("Parameter 'missing' was not found", result.stdout)
                        if use_json:
                            output = json.loads(result.stdout)
                            self.assertEqual(output["status"], "error")
