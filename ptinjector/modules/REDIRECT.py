def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response, payload_str], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when a payload introduces a redirect to its exact value."""
    if len(responses) != 3:
        return False

    baseline_response, payload_response, payload = responses
    baseline_location = baseline_response.headers.get("Location", "")
    payload_location = payload_response.headers.get("Location", "")

    return 300 <= payload_response.status_code < 400 and payload_location == payload and baseline_location != payload
