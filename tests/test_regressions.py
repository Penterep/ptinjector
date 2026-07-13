import datetime
import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

from ptinjector import payloadgenerator
from ptinjector.modules import HEADER, REGEX, TIME


def make_response(*, seconds=0, text="", headers=None):
    return SimpleNamespace(
        elapsed=datetime.timedelta(seconds=seconds),
        text=text,
        headers=headers or {},
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
    def test_run_sends_baseline_before_payloads(self):
        injector = RecordingInjector([
            make_response(seconds=0.1),
            make_response(seconds=7.1),
            make_response(seconds=7.2),
        ])

        results = list(TIME.run(
            {"payload": ["sleep-a", "sleep-b"]},
            {},
            {"parameter": "id"},
            injector,
        ))

        self.assertEqual(injector.payloads, [injector.RANDOM_STRING, "sleep-a", "sleep-b"])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(len(responses) == 2 for _, responses, _ in results))

    def test_expected_delay_over_baseline_is_vulnerable(self):
        responses = [make_response(seconds=3.0), make_response(seconds=8.7)]
        self.assertTrue(TIME.check_if_vulnerable(responses, [7], None))

    def test_slow_baseline_does_not_cause_false_positive(self):
        responses = [make_response(seconds=5.0), make_response(seconds=7.1)]
        self.assertFalse(TIME.check_if_vulnerable(responses, [7], None))

    def test_invalid_verification_value_is_rejected(self):
        responses = [make_response(seconds=0.1), make_response(seconds=7.1)]
        self.assertFalse(TIME.check_if_vulnerable(responses, [0], None))
        with redirect_stdout(io.StringIO()):
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


if __name__ == "__main__":
    unittest.main()
