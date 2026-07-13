

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when injection adds an expected response header."""
    if len(responses) != 2 or not verification_list:
        return False

    expected_headers = {header.casefold() for header in verification_list}
    baseline_headers = {header.casefold() for header in responses[0].headers}
    payload_headers = {header.casefold() for header in responses[1].headers}

    return bool((payload_headers - baseline_headers) & expected_headers)
