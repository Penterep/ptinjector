
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

            yield [payload_str], [baseline_response, current_response], dump

def check_if_vulnerable(responses, verification_list, injector):
    """Return True when injection adds an expected response header."""
    if len(responses) != 2 or not verification_list:
        return False

    expected_headers = {header.casefold() for header in verification_list}
    
    baseline_headers = set()

    for baseline_part in get_response_chain(responses[0]):
        for header in baseline_part.headers:
            baseline_headers.add(header.casefold())

    payload_headers = {header.casefold() for header in responses[1].headers}

    return bool((payload_headers - baseline_headers) & expected_headers)
