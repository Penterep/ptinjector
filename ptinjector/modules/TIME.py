

MIN_DELAY_RATIO = 0.8


def expected_delay(verification_list):
    if len(verification_list) != 1:
        return None

    try:
        delay = float(verification_list[0])
    except (TypeError, ValueError):
        return None

    return delay if delay > 0 else None


def pair_has_expected_delay(baseline_response, payload_response, delay):
    if (
        baseline_response.status_code != payload_response.status_code
        or not 200 <= payload_response.status_code < 400
    ):
        return False

    baseline_time = baseline_response.elapsed.total_seconds()
    payload_time = payload_response.elapsed.total_seconds()
    return payload_time - baseline_time >= delay * MIN_DELAY_RATIO


def run(payload_object, definition_contents, request_data, injector):
    delay = expected_delay(payload_object.get("verify", []))

    for payload_index, payload_str in enumerate(payload_object["payload"]):
        control = f"{injector.RANDOM_STRING}-control-{payload_index}-1"
        baseline_response, _ = injector.run_payload_str(request_data, control)
        payload_response, dump = injector.run_payload_str(request_data, payload_str)
        responses = [baseline_response, payload_response]

        if delay is not None and pair_has_expected_delay(baseline_response, payload_response, delay):
            confirmation_control = f"{injector.RANDOM_STRING}-control-{payload_index}-2"
            confirmation_baseline, _ = injector.run_payload_str(request_data, confirmation_control)
            confirmation_payload, dump = injector.run_payload_str(request_data, payload_str)
            responses.extend([confirmation_baseline, confirmation_payload])

        yield [payload_str], responses, dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when the payload adds most of the expected delay over baseline."""
    delay = expected_delay(verification_list)
    if delay is None:
        print(verification_list, "Invalid definition: 'verify' field must contain one positive number.")
        return False

    if len(responses) != 4:
        return False

    return all(
        pair_has_expected_delay(responses[index], responses[index + 1], delay)
        for index in (0, 2)
    )
