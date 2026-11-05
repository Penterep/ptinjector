from ptlibs import ptmisclib
from ptinjector.response_utils import get_response_chain
def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(
        request_data, injector.RANDOM_STRING
    )

    for payload_str in payload_object["payload"]:
        response, _ = injector.run_payload_str(request_data, payload_str)

        for current_response in get_response_chain(response):
            dump = ptmisclib.get_response_data_dump(current_response)

            yield [payload_str], [
                baseline_response,
                current_response,
                payload_str,
            ], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when a payload introduces a redirect to its exact value."""
    if len(responses) != 3:
        return False

    baseline_response, payload_response, payload = responses
    payload_location = payload_response.headers.get("Location", "")

    if not 300 <= payload_response.status_code < 400:
        return False

    if payload_location != payload:
        return False

    for baseline_part in get_response_chain(baseline_response):
        if baseline_part.headers.get("Location", "") == payload:
            return False

    return True
