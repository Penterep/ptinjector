import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from ptinjector.ptinjector import INJECTION_MARKER, PtInjector
from ptinjector.request_parser import InjectionRequestParser


class RequestTrailingNewlinesTest(unittest.TestCase):
    def make_injector(self, body, parameter="login"):
        injector = object.__new__(PtInjector)
        injector.PLACEHOLDER_SYMBOL = INJECTION_MARKER
        injector.PLACEHOLDER_EXISTS = INJECTION_MARKER in body
        injector.request_parser = InjectionRequestParser(
            SimpleNamespace(end_error=Mock(side_effect=AssertionError)),
            False, INJECTION_MARKER,
        )
        injector.apply_initial_redirect = lambda url, headers: (url, headers)
        injector.args = SimpleNamespace(
            request_file="request.txt", url=None, parameter=parameter,
            request_text=(
                "POST /login HTTP/1.1\nHost: example.test\n"
                "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n\n"
                + body
            ),
        )
        return injector

    def test_initial_and_payload_requests_ignore_file_ending_newlines(self):
        body = "login=test&password=test&action=login"
        for ending in ("", "\n", "\r\n", "\r\n\r\n"):
            for parameter in ("login", "action", None):
                with self.subTest(ending=ending, parameter=parameter):
                    injector = self.make_injector(body + ending, parameter)
                    self.assertEqual(injector.build_initial_request(injector.args)[3], body)
                    for request in injector.generate_request_data(injector.args):
                        self.assertEqual(
                            request["data"].replace(INJECTION_MARKER, request["original_value"]),
                            body,
                        )

    def test_explicit_placeholder_uses_same_normalization(self):
        body = f"login={INJECTION_MARKER}&password=test&action=login"
        injector = self.make_injector(body + "\r\n", None)
        self.assertEqual(injector.build_initial_request(injector.args)[3], body.replace(INJECTION_MARKER, ""))
        request, = injector.generate_request_data(injector.args)
        self.assertEqual(request["data"], body)

    def test_encoded_crlf_is_preserved(self):
        body = "login=test&password=test&action=login%0D%0A"
        injector = self.make_injector(body + "\r\n")
        self.assertEqual(injector.build_initial_request(injector.args)[3], body)
        request, = injector.generate_request_data(injector.args)
        self.assertTrue(request["data"].endswith("action=login%0D%0A"))

    def test_other_content_types_and_form_spaces_are_preserved(self):
        parser = self.make_injector("").request_parser
        for content_type, body in (
            ("multipart/form-data; boundary=test", "--test--\r\n"),
            ("application/json", '{"login":"test"}\r\n'),
            ("application/xml", "<login>test</login>\r\n"),
            ("text/plain", "test\r\n"),
            ("application/x-www-form-urlencoded", "login=test "),
        ):
            with self.subTest(content_type=content_type):
                raw = f"POST / HTTP/1.1\nHost: example.test\nContent-Type: {content_type}\n\n{body}"
                self.assertEqual(parser.parse_http_request(raw)[3], body)


if __name__ == "__main__":
    unittest.main()
