import re
from ptlibs import ptmisclib
from ptinjector.response_utils import get_response_chain

def run(payload_object, definition_contents, request_data, injector):
    baseline_response = injector.initial_response

    if injector.redirect_target_url is not None:
        baseline_response = None

    for payload_str in payload_object["payload"]:
        response, _ = injector.run_payload_str(request_data, payload_str)

        for current_response in get_response_chain(response):
            dump = ptmisclib.get_response_data_dump(current_response)
            yield [payload_str], [baseline_response, current_response], dump


def check_if_vulnerable(responses, verification_list, injector):
    if len(responses) != 2 or not verification_list:
        return False

    try:
        verification_re = re.compile(
            '(' + ')|('.join(verification_list) + ')'
        )
    except (TypeError, re.error):
        return False

    baseline_response, payload_response = responses

    if re.search(verification_re, payload_response.text) is None:
        return False

    if baseline_response is None:
        return True

    return re.search(verification_re, baseline_response.text) is None