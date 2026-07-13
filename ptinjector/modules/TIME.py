

MIN_DELAY_RATIO = 0.8


def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when the payload adds most of the expected delay over baseline."""
    if len(verification_list) != 1:
        print(verification_list, "Invalid definition: 'verify' field in vuln. definition must contain a single number.")
        return False

    try:
        expected_delay = float(verification_list[0])
    except (TypeError, ValueError):
        print(verification_list, "Invalid definition: 'verify' field in vuln. definition must contain a valid number.")
        return False

    if expected_delay <= 0 or len(responses) != 2:
        return False

    baseline_time = responses[0].elapsed.total_seconds()
    payload_time = responses[1].elapsed.total_seconds()
    observed_delay = payload_time - baseline_time

    return observed_delay >= expected_delay * MIN_DELAY_RATIO
