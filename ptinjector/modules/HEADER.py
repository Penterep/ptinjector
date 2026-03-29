import ptinjector


def run(payload_object, definition_contents, request_data, injector: ptinjector.PtInjector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector: ptinjector.PtInjector):
    response = responses[0]
    return True if any([any(verification_string in header_name for verification_string in verification_list) for header_name in response.headers.keys()]) else False

