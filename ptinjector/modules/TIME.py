
from decimal import Decimal, ROUND_CEILING
from time import monotonic
from requests.exceptions import RequestException
from datetime import timedelta


CONTROL_MAX_AGE_SECONDS = 30
CONTROL_MAX_USES = 10

def get_control(request_data, injector, control_id, force=False):
    cached = request_data.get("time_control")

    if (
        not force
        and cached is not None
        and cached["uses"] < CONTROL_MAX_USES
        and monotonic() - cached["measured_at"] < CONTROL_MAX_AGE_SECONDS
    ):
        return cached["response"]

    request_data.pop("time_control", None)

    errors_before = len(getattr(injector, "scan_errors", []))
    measured_at = monotonic()

    response, _ = injector.run_payload_str(request_data, control_id)

    if (
        200 <= response.status_code < 400
        and len(getattr(injector, "scan_errors", [])) == errors_before
    ):
        request_data["time_control"] = {
            "response": response,
            "measured_at": measured_at,
            "uses": 0,
        }

    return response

def send_timing_payload(request_data, injector, payload):
    errors_before = len(getattr(injector, "scan_errors", []))
    try:
        response, dump = injector.run_payload_str(request_data, payload)
    except RequestException:
        request_data.pop("time_control", None)
        raise

    cached = request_data.get("time_control")
    if cached is not None:
        cached["uses"] += 1
        if (
            response.status_code != cached["response"].status_code
            or len(getattr(injector, "scan_errors", [])) != errors_before
        ):
            request_data.pop("time_control", None)

    return response, dump


class TimingResponses(list):
    def __init__(self, responses, progressive):
        super().__init__(responses)
        self.progressive = progressive

from ptinjector.response_utils import get_response_chain
def response_time(response):
    total = 0.0

    for part in get_response_chain(response):
        total += part.elapsed.total_seconds()

    return total


def expected_delay(verification_list):
    if len(verification_list) != 1:
        return None

    try:
        delay = float(verification_list[0])
    except (TypeError, ValueError):
        return None

    return delay if delay > 0 else None

def delay_steps(final_delay ):
    steps=[]

    for delay in (0.0001, 0.001, 0.01, 0.1, 1):
        if delay < final_delay:
            steps.append(delay)
 
    steps.append(final_delay)
    return steps 

def format_waitfor_delay(delay):
    value = Decimal(str(delay))

    if not value.is_finite() or value <= 0:
        raise ValueError("WAITFOR delay must be a positive finite number.")

    total_ms = int(
        (value * 1000).to_integral_value(rounding=ROUND_CEILING)
    )

    if total_ms >= 86_400_000:
        raise ValueError("WAITFOR delay must be less than 24 hours.")

    total_seconds, milliseconds = divmod(total_ms, 1000)
    total_minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(total_minutes, 60)

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{milliseconds:03d}"

def render_payload(payload_template, delay):
    if "PTINJECTORDELAYHOURS" in payload_template:
        hours, minutes, seconds = format_waitfor_delay(delay).split(":")
        seconds, milliseconds = seconds.split(".")

        replacements = {
            "PTINJECTORDELAYHOURS": hours,
            "PTINJECTORDELAYMINUTES": minutes,
            "PTINJECTORDELAYSECONDS": seconds,
            "PTINJECTORDELAYMILLISECONDS": milliseconds,
        }

        for marker, value in replacements.items():
            payload_template = payload_template.replace(marker, value)

    return payload_template.replace("PTINJECTORDELAY", str(delay))
    


def pair_has_expected_delay(
    baseline_response, payload_response, delay, progressive=False
):
    if (
        baseline_response.status_code != payload_response.status_code
        or not 200 <= payload_response.status_code < 400
    ):
        return False

    baseline_time = sum(
        (part.elapsed for part in get_response_chain(baseline_response)),
        timedelta(),
    )
    payload_time = sum(
        (part.elapsed for part in get_response_chain(payload_response)),
        timedelta(),
    )

    increase = payload_time - baseline_time
    required_delay = delay if progressive else delay * 0.8

    return increase >= timedelta(seconds=required_delay)

def run(payload_object, definition_contents, request_data, injector):
    threshold = expected_delay(payload_object.get("verify", []))

    for payload_index, payload_template in enumerate(payload_object["payload"]):
        progressive = "PTINJECTORDELAY" in payload_template
        if progressive:
            if threshold is None:
                raise ValueError("TIME requires one positive number in verify.")
            steps = delay_steps(threshold)
        else:
            steps = [None]

        for step_index, requested_delay in enumerate(steps):
            payload_str = (
                render_payload(payload_template, requested_delay)
                if requested_delay is not None else payload_template
            )

            control_id = f"{injector.RANDOM_STRING}-control-{payload_index}"
            if requested_delay is not None:
                control_id += f"-{step_index}"

            errors_before = len(getattr(injector, "scan_errors", []))
            baseline = get_control(
                request_data, injector, f"{control_id}-1"
            )
            response, dump = send_timing_payload(
                request_data, injector, payload_str
            )

            responses = TimingResponses([baseline, response], progressive)
            confirmed = False

            if (
                threshold is not None
                and len(getattr(injector, "scan_errors", [])) == errors_before
                and 200 <= response.status_code < 400
                and (
                    baseline.status_code != response.status_code
                    or pair_has_expected_delay(
                        baseline, response, threshold, progressive=progressive
                    )
                )
            ):
                # Screening with a cached control is not evidence.
                responses = TimingResponses([], progressive)
                for confirmation in (1, 2):
                    errors_before = len(getattr(injector, "scan_errors", []))
                    fresh_baseline = get_control(
                        request_data, injector,
                        f"{control_id}-confirm-{confirmation}", force=True,
                    )
                    fresh_response, dump = send_timing_payload(
                        request_data, injector, payload_str
                    )
                    if len(getattr(injector, "scan_errors", [])) != errors_before:
                        responses.clear()
                        break

                    responses.extend([fresh_baseline, fresh_response])
                    if not pair_has_expected_delay(
                        fresh_baseline, fresh_response, threshold,
                        progressive=progressive,
                    ):
                        break

                confirmed = check_if_vulnerable(responses, [threshold], injector)

            yield [payload_str], responses, dump

            if confirmed:
                break



def check_if_vulnerable(responses, verification_list, injector):
    """Return True when both pairs exceed the verification threshold over baseline."""
    delay = expected_delay(verification_list)
    if delay is None:
        print(verification_list, "Invalid definition: 'verify' field must contain one positive number.")
        return False

    if len(responses) != 4:
        return False

    progressive = getattr(responses, "progressive", False)

    return all(
        pair_has_expected_delay(
            responses[index],
            responses[index + 1],
            delay,
            progressive=progressive,
        )
        for index in (0, 2)
    )



def find_evidence(responses, verification_list, injector):
    if not check_if_vulnerable(responses, verification_list, injector):
        return None

    delay = expected_delay(verification_list)
    progressive = getattr(responses, "progressive", False)
    required_increase = delay if progressive else delay * 0.8
    comparison = ">=" if progressive else ">="

    lines = [
        "Time-based evidence (times include redirects).",
        f"Required increase over control: {comparison} {required_increase:.6f} s.",
    ]

    for pair_number, index in enumerate((0, 2), start=1):
        control_time = response_time(responses[index])
        payload_time = response_time(responses[index + 1])
        increase = payload_time - control_time

        lines.append(
            f"Pair {pair_number}: control={control_time:.6f} s, "
            f"payload={payload_time:.6f} s, "
            f"increase=**{increase:.6f} s**."
        )

    return {
        "response": responses[-1],
        "spans": [],
        "poc": "\n".join(lines),
    }