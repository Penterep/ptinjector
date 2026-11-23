import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ptinjector.ptinjector import PtInjector, INJECTION_MARKER, split_parameters
from ptinjector.request_parser import InjectionRequestParser


def cases():
    yield "GET", "/?login=alice&password=secret", None, "", ["login", "password"]
    yield "form", "/", "application/x-www-form-urlencoded", "login=alice&password=secret", ["login", "password"]
    yield "JSON", "/", "application/json", '{"user":{"login":"alice","password":"secret"}}', ["user.login", "user.password"]
    yield "XML", "/", "application/xml", "<root><login>alice</login><password>secret</password></root>", ["root.login", "root.password"]
    yield "multipart", "/", "multipart/form-data; boundary=boundary", (
        '--boundary\nContent-Disposition: form-data; name="login"\n\nalice\n'
        '--boundary\nContent-Disposition: form-data; name="password"\n\nsecret\n--boundary--\n'
    ), ["login", "password"]


def make_injector(path, content_type, body, parameters, request_file=True):
    headers = {} if content_type is None else {"Content-Type": content_type}
    request = f"{'POST' if body else 'GET'} {path} HTTP/1.1\nHost: 127.0.0.1:9\n"
    for name, value in headers.items():
        request += f"{name}: {value}\n"
    request += "\n" + body
    args = SimpleNamespace(
        request_file="request.txt" if request_file else None,
        request_text=request if request_file else None,
        url=None if request_file else "http://127.0.0.1:9" + path,
        data=None if request_file else (body or None), parameter=parameters,
    )
    injector = object.__new__(PtInjector)
    injector.args = args
    injector.PLACEHOLDER_EXISTS = False
    injector.PLACEHOLDER_SYMBOL = INJECTION_MARKER
    injector.use_json = False
    injector.http_headers = headers
    injector.ptjsonlib = SimpleNamespace(end_error=Mock(side_effect=SystemExit(1)))
    injector.request_parser = InjectionRequestParser(injector.ptjsonlib, False, INJECTION_MARKER)
    injector.apply_initial_redirect = lambda url, headers: (url, headers)
    injector.send_initial_request = Mock()
    return injector, args


class MultipleParametersTest(unittest.TestCase):
    def test_split_preserves_order_and_removes_whitespace_and_duplicates(self):
        self.assertEqual(split_parameters("login, password,login"), ["login", "password"])
        self.assertEqual(split_parameters("0,1"), ["0", "1"])
        self.assertEqual(split_parameters(None), [])
        for value in ("", " ", ",login", "login,", "login,,password"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                split_parameters(value)

    def test_selected_parameters_are_generated_independently(self):
        for name, path, content_type, body, names in cases():
            for request_file in (True, False):
                with self.subTest(format=name, request_file=request_file):
                    injector, args = make_injector(path, content_type, body, ", ".join(names + names[:1]), request_file)
                    self.assertTrue(injector.is_valid_request(args))
                    results = list(injector.generate_request_data(args))
                    self.assertEqual([r["parameter"] for r in results], names)
                    self.assertEqual([r["original_value"] for r in results], ["alice", "secret"])
                    first = results[0]["url"] + (results[0]["data"] or "")
                    second = results[1]["url"] + (results[1]["data"] or "")
                    self.assertEqual(first.count(INJECTION_MARKER), 1)
                    self.assertEqual(second.count(INJECTION_MARKER), 1)
                    self.assertIn("secret", first)
                    self.assertNotIn("alice", first)
                    self.assertIn("alice", second)
                    self.assertNotIn("secret", second)
                    self.assertEqual(results[0]["original_http_request"], results[1]["original_http_request"])

    def test_unknown_second_parameter_is_rejected_before_sending(self):
        for name, path, content_type, body, names in cases():
            for request_file in (True, False):
                with self.subTest(format=name, request_file=request_file):
                    injector, args = make_injector(path, content_type, body, names[0] + ",missing", request_file)
                    with self.assertRaises(SystemExit):
                        injector.run(args)
                    injector.send_initial_request.assert_not_called()
                    self.assertIn("Parameter 'missing' was not found", injector.ptjsonlib.end_error.call_args.args[0])

    def test_query_and_form_numeric_indexes_still_work(self):
        for name, path, content_type, body, _ in list(cases())[:2]:
            with self.subTest(format=name):
                injector, args = make_injector(path, content_type, body, "0,1")
                self.assertTrue(injector.is_valid_request(args))
                self.assertEqual(
                    [r["original_value"] for r in injector.generate_request_data(args)],
                    ["alice", "secret"],
                )

    def test_cli_rejects_empty_items_before_network_access(self):
        for value in ("login,,password", "login,", ",login", " "):
            with self.subTest(value=value):
                result = subprocess.run(
                    [sys.executable, "-m", "ptinjector.ptinjector", "-u",
                     "http://127.0.0.1:9/?login=alice&password=secret", "-P", value,
                     "-ts", "sqli_boolean"], capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("Parameter list must not contain empty names", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn("Request failed", result.stdout + result.stderr)
