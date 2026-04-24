import re

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Check if <verification_re> in <response.text>"""
    response = responses.pop()
    """Check if <verification_re> in <response.text>"""
    verification_re = '(' + ')|('.join(verification_list) + ')'
    verification_re = re.compile(verification_re)
    return bool(re.search(verification_re, response.text))
