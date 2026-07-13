import datetime
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from ptinjector import payloadgenerator
from ptinjector.modules import BOOLEAN, HEADER, HOST_HEADER, HTML_ATTR, HTML_TAG, REDIRECT, REGEX, REQUEST, TIME


def make_response(*, seconds=0, text="", content=None, headers=None, status_code=200):
    return SimpleNamespace(
        elapsed=datetime.timedelta(seconds=seconds),
        text=text,
        content=text.encode() if content is None else content,
        headers=headers or {},
        status_code=status_code,
    )


class RecordingInjector:
    RANDOM_STRING = "1234567890"

    def __init__(self, responses):
        self.responses = iter(responses)
        self.payloads = []

    def run_payload_str(self, request_data, payload):
        self.payloads.append(payload)
        return next(self.responses), {"request": payload, "response": ""}


class TimeVerifierTest(unittest.TestCase):
    def test_run_uses_a_fresh_control_before_each_negative_payload(self):
        injector = RecordingInjector([
            make_response(seconds=0.1),
            make_response(seconds=0.2),
            make_response(seconds=0.1),
            make_response(seconds=0.2),
        ])

        results = list(TIME.run(
            {"payload": ["sleep-a", "sleep-b"]},
            {},
            {"parameter": "id"},
            injector,
        ))

        self.assertEqual(injector.payloads, [
            f"{injector.RANDOM_STRING}-control-0-1",
            "sleep-a",
            f"{injector.RANDOM_STRING}-control-1-1",
            "sleep-b",
        ])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(len(responses) == 2 for _, responses, _ in results))

    def test_run_confirms_a_suspected_delay_with_a_second_pair(self):
        injector = RecordingInjector([
            make_response(seconds=0.1),
            make_response(seconds=5.8),
            make_response(seconds=0.2),
            make_response(seconds=5.9),
        ])

        results = list(TIME.run(
            {"payload": ["sleep-a"], "verify": [7]},
            {},
            {"parameter": "id"},
            injector,
        ))

        self.assertEqual(len(results[0][1]), 4)
        self.assertEqual(injector.payloads[-1], "sleep-a")

    def test_repeated_expected_delay_is_vulnerable(self):
        responses = [
            make_response(seconds=3.0),
            make_response(seconds=8.7),
            make_response(seconds=4.0),
            make_response(seconds=9.8),
        ]
        self.assertTrue(TIME.check_if_vulnerable(responses, [7], None))

    def test_slow_baseline_does_not_cause_false_positive(self):
        responses = [
            make_response(seconds=5.0),
            make_response(seconds=7.1),
            make_response(seconds=4.0),
            make_response(seconds=9.8),
        ]
        self.assertFalse(TIME.check_if_vulnerable(responses, [7], None))

    def test_one_off_latency_spike_is_rejected(self):
        responses = [
            make_response(seconds=0.1),
            make_response(seconds=6.0),
            make_response(seconds=0.1),
            make_response(seconds=0.2),
        ]
        self.assertFalse(TIME.check_if_vulnerable(responses, [7], None))

    def test_changed_status_code_is_rejected(self):
        responses = [
            make_response(seconds=0.1),
            make_response(seconds=6.0, status_code=500),
            make_response(seconds=0.1),
            make_response(seconds=6.0, status_code=500),
        ]
        self.assertFalse(TIME.check_if_vulnerable(responses, [7], None))

    def test_repeated_slow_server_errors_are_rejected(self):
        responses = [
            make_response(seconds=0.1, status_code=500),
            make_response(seconds=6.0, status_code=500),
            make_response(seconds=0.1, status_code=500),
            make_response(seconds=6.0, status_code=500),
        ]
        self.assertFalse(TIME.check_if_vulnerable(responses, [7], None))

    def test_invalid_verification_value_is_rejected(self):
        responses = [make_response(seconds=0.1) for _ in range(4)]
        with redirect_stdout(io.StringIO()):
            self.assertFalse(TIME.check_if_vulnerable(responses, [0], None))
            self.assertFalse(TIME.check_if_vulnerable(responses, ["invalid"], None))


class RegexVerifierTest(unittest.TestCase):
    def test_new_pattern_after_payload_is_vulnerable(self):
        responses = [make_response(text="normal"), make_response(text="SQL syntax error")]
        self.assertTrue(REGEX.check_if_vulnerable(responses, ["SQL syntax"], None))

    def test_pattern_present_in_baseline_is_rejected(self):
        responses = [make_response(text="SQL syntax error"), make_response(text="SQL syntax error")]
        self.assertFalse(REGEX.check_if_vulnerable(responses, ["SQL syntax"], None))

    def test_invalid_pattern_is_rejected(self):
        responses = [make_response(text="normal"), make_response(text="anything")]
        self.assertFalse(REGEX.check_if_vulnerable(responses, ["[invalid"], None))


class HeaderVerifierTest(unittest.TestCase):
    def test_new_expected_header_is_vulnerable(self):
        responses = [
            make_response(headers={"Server": "test"}),
            make_response(headers={"Server": "test", "TH1234": "injected"}),
        ]
        self.assertTrue(HEADER.check_if_vulnerable(responses, ["TH1234"], None))

    def test_header_present_in_baseline_is_rejected(self):
        responses = [
            make_response(headers={"Foo": "old"}),
            make_response(headers={"Foo": "new"}),
        ]
        self.assertFalse(HEADER.check_if_vulnerable(responses, ["foo"], None))

    def test_partial_header_name_match_is_rejected(self):
        responses = [make_response(headers={}), make_response(headers={"X-Foo-Bar": "value"})]
        self.assertFalse(HEADER.check_if_vulnerable(responses, ["foo"], None))


class HostHeaderVerifierTest(unittest.TestCase):
    def test_new_host_reflection_is_vulnerable(self):
        responses = [
            make_response(text="normal"),
            make_response(
                text="generated link: example.com",
                headers={"Content-Type": "text/html; charset=utf-8"},
            ),
            "example.com",
        ]
        self.assertTrue(HOST_HEADER.check_if_vulnerable(responses, [], None))

    def test_host_present_in_baseline_is_rejected(self):
        responses = [
            make_response(text="default example.com"),
            make_response(text="default example.com", headers={"Content-Type": "text/html"}),
            "example.com",
        ]
        self.assertFalse(HOST_HEADER.check_if_vulnerable(responses, [], None))

    def test_run_does_not_mutate_original_headers(self):
        calls = []
        request_data = {"parameter": "id", "headers": {"Original": "value"}}

        class Injector:
            RANDOM_STRING = "1234567890"

            def run_payload_str(self, current_request_data, payload):
                calls.append((payload, dict(current_request_data["headers"])))
                return make_response(text=payload, headers={"Content-Type": "text/html"}), {
                    "request": payload,
                    "response": "",
                }

        list(HOST_HEADER.run({"payload": ["example.com"]}, {}, request_data, Injector()))

        self.assertEqual(request_data["headers"], {"Original": "value"})
        self.assertEqual(calls[0], ("1234567890", {"Original": "value"}))
        self.assertEqual(calls[1][1]["Host"], "example.com")


class HtmlTagVerifierTest(unittest.TestCase):
    def test_new_expected_tag_is_vulnerable(self):
        responses = [
            make_response(text="<html><body>normal</body></html>"),
            make_response(text="<html><body><foo>injected</foo></body></html>"),
        ]
        self.assertTrue(HTML_TAG.check_if_vulnerable(responses, ["foo"], None))

    def test_tag_present_in_baseline_without_new_instance_is_rejected(self):
        responses = [
            make_response(text="<foo>existing</foo>"),
            make_response(text="<foo>existing</foo>"),
        ]
        self.assertFalse(HTML_TAG.check_if_vulnerable(responses, ["foo"], None))

    def test_additional_expected_tag_is_vulnerable(self):
        responses = [
            make_response(text="<foo>existing</foo>"),
            make_response(text="<foo>existing</foo><foo>injected</foo>"),
        ]
        self.assertTrue(HTML_TAG.check_if_vulnerable(responses, ["foo"], None))


class HtmlAttributeVerifierTest(unittest.TestCase):
    def test_new_expected_attribute_is_vulnerable(self):
        responses = [
            make_response(text="<div>normal</div>"),
            make_response(text="<div foo='injected'>payload</div>"),
        ]
        self.assertTrue(HTML_ATTR.check_if_vulnerable(responses, ["foo"], None))

    def test_attribute_present_in_baseline_without_new_instance_is_rejected(self):
        responses = [
            make_response(text="<div foo='existing'></div>"),
            make_response(text="<div foo='changed'></div>"),
        ]
        self.assertFalse(HTML_ATTR.check_if_vulnerable(responses, ["foo"], None))


class RedirectVerifierTest(unittest.TestCase):
    def test_new_exact_redirect_is_vulnerable(self):
        payload = "https://www.example.com"
        responses = [
            make_response(status_code=200),
            make_response(status_code=302, headers={"Location": payload}),
            payload,
        ]
        self.assertTrue(REDIRECT.check_if_vulnerable(responses, ["REDIRECT"], None))

    def test_non_redirect_response_is_rejected(self):
        payload = "https://www.example.com"
        responses = [
            make_response(status_code=200),
            make_response(status_code=200, headers={"Location": payload}),
            payload,
        ]
        self.assertFalse(REDIRECT.check_if_vulnerable(responses, ["REDIRECT"], None))

    def test_different_redirect_target_is_rejected(self):
        responses = [
            make_response(status_code=200),
            make_response(status_code=302, headers={"Location": "https://safe.example"}),
            "https://www.example.com",
        ]
        self.assertFalse(REDIRECT.check_if_vulnerable(responses, ["REDIRECT"], None))


class BooleanVerifierTest(unittest.TestCase):
    def test_json_content_type_with_charset_is_parsed(self):
        response = make_response(
            text='{"result": "five"}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        self.assertEqual(BOOLEAN.tagset(response), {"result: five"})

    def test_missing_or_malformed_content_type_falls_back_to_raw_content(self):
        missing_header = make_response(content=b"raw response")
        malformed_json = make_response(
            text="not-json",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(BOOLEAN.tagset(missing_header), {b"raw response"})
        self.assertEqual(BOOLEAN.tagset(malformed_json), {b"not-json"})

    def test_equivalent_expression_responses_are_detected(self):
        responses = [
            make_response(content=b"false"),
            make_response(content=b"one"),
            make_response(content=b"unique"),
            make_response(content=b"same"),
            make_response(content=b"same"),
        ]
        self.assertTrue(BOOLEAN.equivalence_check(responses, []))

    def test_distinct_expression_responses_are_rejected(self):
        responses = [
            make_response(content=b"false"),
            make_response(content=b"one"),
            make_response(content=b"three"),
            make_response(content=b"four"),
            make_response(content=b"five"),
        ]
        self.assertFalse(BOOLEAN.equivalence_check(responses, []))

    def test_increasing_limit_requires_successful_responses(self):
        responses = [
            make_response(text="one", status_code=200),
            make_response(text="one\ntwo", status_code=500),
        ]
        self.assertFalse(BOOLEAN.increasing_limit_check(responses, []))


class RequestVerifierTest(unittest.TestCase):
    def test_confirmed_callback_is_vulnerable(self):
        response = SimpleNamespace(status_code=200, json=lambda: {"msg": "true"})
        self.assertTrue(REQUEST.check_if_vulnerable([response], [], None))

    def test_missing_or_invalid_callback_is_rejected(self):
        missing = SimpleNamespace(status_code=200, json=lambda: {"msg": "false"})
        invalid = SimpleNamespace(status_code=200, json=lambda: {"invalid": True})
        error = SimpleNamespace(status_code=503, json=lambda: {"msg": "true"})
        self.assertFalse(REQUEST.check_if_vulnerable([missing], [], None))
        self.assertFalse(REQUEST.check_if_vulnerable([invalid], [], None))
        self.assertFalse(REQUEST.check_if_vulnerable([error], [], None))

    @patch("ptinjector.modules.REQUEST.requests.get")
    def test_run_queries_verification_url_after_target_payload(self, get):
        verification_response = SimpleNamespace(status_code=200, json=lambda: {"msg": "true"})
        get.return_value = verification_response

        injector = SimpleNamespace(
            VERIFICATION_URL="https://callback.example/verify/code",
            proxy={"http": "http://proxy", "https": "http://proxy"},
            timeout=30,
            run_payload_str=lambda request_data, payload: (
                make_response(text="target response"),
                {"request": payload, "response": "target response"},
            ),
        )

        results = list(REQUEST.run(
            {
                "payload": ["callback-payload"],
                "verification_urls": ["https://callback.example/verify/unique-code"],
            },
            {},
            {"parameter": "url"},
            injector,
        ))

        get.assert_called_once_with(
            "https://callback.example/verify/unique-code",
            proxies=injector.proxy,
            verify=False,
            timeout=5,
        )
        self.assertIs(results[0][1][0], verification_response)

    @patch("ptinjector.modules.REQUEST.time.sleep")
    @patch("ptinjector.modules.REQUEST.requests.get")
    def test_run_polls_until_delayed_callback_arrives(self, get, sleep):
        missing = SimpleNamespace(status_code=200, json=lambda: {"msg": "false"})
        confirmed = SimpleNamespace(status_code=200, json=lambda: {"msg": "true"})
        get.side_effect = [missing, missing, confirmed]
        injector = SimpleNamespace(
            VERIFICATION_URL="https://callback.example/verify/fallback",
            proxy={"http": None, "https": None},
            timeout=90,
            run_payload_str=lambda request_data, payload: (
                make_response(),
                {"request": payload, "response": ""},
            ),
        )

        results = list(REQUEST.run(
            {
                "payload": ["callback-payload"],
                "verification_urls": ["https://callback.example/verify/unique-code"],
            },
            {},
            {"parameter": "url"},
            injector,
        ))

        self.assertEqual(get.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue(REQUEST.check_if_vulnerable(results[0][1], [], injector))

    @patch("ptinjector.modules.REQUEST.requests.get")
    def test_unreachable_verifier_does_not_crash_scan(self, get):
        get.side_effect = REQUEST.requests.exceptions.ConnectionError("offline")
        record_request_error = MagicMock()
        injector = SimpleNamespace(
            VERIFICATION_URL="https://callback.example/verify/code",
            proxy={"http": None, "https": None},
            timeout=90,
            run_payload_str=lambda request_data, payload: (
                make_response(),
                {"request": payload, "response": ""},
            ),
            record_request_error=record_request_error,
        )

        results = list(REQUEST.run(
            {"payload": ["callback-payload"]},
            {},
            {"parameter": "url"},
            injector,
        ))

        self.assertEqual(results[0][1], [])
        self.assertFalse(REQUEST.check_if_vulnerable(results[0][1], [], injector))
        record_request_error.assert_called_once()

    def test_ssrf_payloads_receive_unique_verification_urls(self):
        from ptinjector.definitions._loader import DefinitionsLoader

        args = SimpleNamespace(
            json=True,
            verification_url="https://callback.example",
            technology=set(),
            tests=["ssrf"],
            request_file=None,
            url="https://target.example/?url=value",
        )
        payload_objects = DefinitionsLoader(args, "1234567890").load_definitions()["ssrf"]["payloads"]
        callback_pairs = [
            (payload, verification_url)
            for payload_object in payload_objects
            for payload, verification_url in zip(
                payload_object["payload"], payload_object["verification_urls"]
            )
        ]

        self.assertEqual(len(callback_pairs), 2)
        self.assertEqual(len({url for _, url in callback_pairs}), 2)
        for payload, verification_url in callback_pairs:
            callback_code = verification_url.rsplit("/", 1)[1]
            self.assertIn(f"/save/{callback_code}", payload)

    def test_local_server_base_url_is_exposed_to_definition_loader(self):
        from ptinjector.ptinjector import PtInjector

        injector = object.__new__(PtInjector)
        injector.RANDOM_STRING = "1234567890"
        injector.get_local_ip = lambda: "127.0.0.1"
        injector.start_local_server = lambda host, port: None
        args = SimpleNamespace(start_local_server="5000", verification_url=None)

        verification_url, _ = injector.setup_verification_url(args)

        self.assertEqual(args.verification_url, "http://127.0.0.1:5000")
        self.assertEqual(verification_url, "http://127.0.0.1:5000/verify/1234567890")


class CallbackServerTest(unittest.TestCase):
    def test_callback_code_can_only_be_verified_once(self):
        from ptinjector.server.app import MyAPI

        with tempfile.TemporaryDirectory() as config_path:
            api = MyAPI(None, 0, config_path=config_path, start_scheduler=False)
            client = api.app.test_client()

            self.assertEqual(client.get("/save/unique-code").status_code, 200)
            self.assertEqual(client.get("/verify/unique-code").get_json(), {"msg": "true"})
            self.assertEqual(client.get("/verify/unique-code").get_json(), {"msg": "false"})

    @patch("ptinjector.ptinjector.atexit.register")
    @patch("ptinjector.ptinjector.socket.create_connection")
    @patch("ptinjector.ptinjector.subprocess.Popen")
    def test_local_server_is_stopped_after_successful_start(self, popen, create_connection, register):
        from ptinjector.ptinjector import PtInjector

        process = popen.return_value
        process.poll.return_value = None
        create_connection.return_value = MagicMock()
        injector = object.__new__(PtInjector)
        injector.local_server_process = None

        self.assertIs(injector.start_local_server("127.0.0.1", "5000"), process)
        injector.stop_local_server()

        register.assert_called_once()
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)
        self.assertIsNone(injector.local_server_process)

    @patch("ptinjector.ptinjector.time.monotonic", side_effect=[0, 6])
    @patch("ptinjector.ptinjector.subprocess.Popen")
    def test_local_server_startup_has_a_deadline(self, popen, monotonic):
        from ptinjector.ptinjector import PtInjector

        process = popen.return_value
        injector = object.__new__(PtInjector)
        injector.local_server_process = None

        with self.assertRaisesRegex(RuntimeError, "did not start"):
            injector.start_local_server("127.0.0.1", "5000")

        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)


class RequestPreparationTest(unittest.TestCase):
    def test_cookie_user_agent_and_header_values_are_prepared(self):
        from ptinjector.ptinjector import headers_cookies_prepare

        args = SimpleNamespace(
            cookie=[["PHPSESSID=abc", "language=en"]],
            user_agent="Custom Agent",
            data=None,
            headers=[["Authorization: Bearer abc:def"]],
        )

        headers = headers_cookies_prepare(args)

        self.assertEqual(headers["Cookie"], "PHPSESSID=abc;language=en")
        self.assertEqual(headers["User-Agent"], "Custom Agent")
        self.assertEqual(headers["Authorization"], "Bearer abc:def")

    def test_parse_args_resolves_request_file_from_working_directory(self):
        from ptinjector import ptinjector as core

        core.SCRIPTNAME = "ptinjector"
        argv = [
            "ptinjector",
            "--request-file", "fixtures/request.txt",
            "--user-agent", "Custom Agent",
            "--verify-url", "https://callback.example",
            "--timeout", "15",
            "--headers", "Authorization: Bearer abc:def",
        ]
        with patch.object(sys, "argv", argv), patch.object(core.ptprinthelper, "print_banner"):
            args = core.parse_args()

        self.assertEqual(args.request_file, os.path.abspath("fixtures/request.txt"))
        self.assertEqual(args.user_agent, "Custom Agent")
        self.assertEqual(args.verification_url, "https://callback.example")
        self.assertEqual(args.timeout, 15)
        self.assertEqual(args.headers, [["Authorization: Bearer abc:def"]])


class ErrorHandlingTest(unittest.TestCase):
    def make_injector(self):
        from ptinjector.ptinjector import PtInjector
        from ptlibs import ptjsonlib

        injector = object.__new__(PtInjector)
        injector.use_json = True
        injector.ptjsonlib = ptjsonlib.PtJsonLib()
        injector.scan_errors = []
        injector.consecutive_request_errors = 0
        injector.abort_scan = False
        return injector

    def test_three_consecutive_request_errors_trigger_circuit_breaker(self):
        injector = self.make_injector()

        for attempt in range(3):
            injector.record_request_error(
                REQUEST.requests.exceptions.ConnectionError(f"offline-{attempt}"),
                context="test target",
            )

        self.assertTrue(injector.abort_scan)
        self.assertEqual(len(injector.scan_errors), 3)

    def test_scan_continues_after_recoverable_payload_error_and_marks_result_incomplete(self):
        injector = self.make_injector()
        injector.LOADED_DEFINITIONS = {
            "test": {
                "description": "Test vulnerability",
                "payloads": [{"type": "REGEX"}, {"type": "REGEX"}],
            }
        }
        injector.is_valid_request = MagicMock()
        injector.generate_request_data = MagicMock(return_value=[{"parameter": "id"}])
        injector.run_payload_object = MagicMock(side_effect=[
            REQUEST.requests.exceptions.ConnectionError("temporary failure"),
            ([], []),
        ])
        injector.print_results = MagicMock()
        args = SimpleNamespace(technology=set())

        with redirect_stdout(io.StringIO()):
            completed = injector.run(args)

        self.assertFalse(completed)
        self.assertEqual(injector.run_payload_object.call_count, 2)
        injector.print_results.assert_called_once_with(
            parameter="id",
            confirmed_payloads=[],
            sent_payloads=[],
            vulnerability_name="test",
            vulnerability_description="Test vulnerability",
            incomplete=True,
        )
        properties = injector.ptjsonlib.json_object["results"]["properties"]
        self.assertTrue(properties["incomplete"])
        self.assertEqual(len(properties["requestErrors"]), 1)


class PayloadGeneratorTest(unittest.TestCase):
    def test_generated_payload_objects_are_distinct_and_reusable(self):
        template = {
            "payload": ["value"],
            "verify": ["marker"],
            "type": "REGEX",
            "tags": ["payload_template"],
            "vars": {"value": ["first", "second"]},
        }

        payloads = list(payloadgenerator.prepare_templates([template]))
        first_pass = [payload["payload"] for payload in payloads]
        second_pass = [payload["payload"] for payload in payloads]

        self.assertEqual(first_pass, [["first"], ["second"]])
        self.assertEqual(second_pass, first_pass)
        self.assertEqual(len({id(payload) for payload in payloads}), len(payloads))

    def test_template_expansion_preserves_callback_metadata(self):
        template = {
            "payload": ["value"],
            "verify": ["marker"],
            "verification_urls": ["https://callback.example/verify/code"],
            "type": "REQUEST",
            "tags": ["payload_template"],
            "vars": {"value": ["first"]},
        }

        payload = next(payloadgenerator.prepare_templates([template]))

        self.assertEqual(payload["verification_urls"], template["verification_urls"])


if __name__ == "__main__":
    unittest.main()
