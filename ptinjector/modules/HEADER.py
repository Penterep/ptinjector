

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    response = responses[0]
    return True if any([any(verification_string in header_name for verification_string in verification_list) for header_name in response.headers.keys()]) else False

