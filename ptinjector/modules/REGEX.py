import re

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when a verification pattern appears only after injection."""
    if len(responses) != 2 or not verification_list:
        return False

    try:
        verification_re = re.compile('(' + ')|('.join(verification_list) + ')')
    except (TypeError, re.error):
        return False

    baseline_response, payload_response = responses
    baseline_matches = re.search(verification_re, baseline_response.text)
    payload_matches = re.search(verification_re, payload_response.text)

    return payload_matches is not None and baseline_matches is None
