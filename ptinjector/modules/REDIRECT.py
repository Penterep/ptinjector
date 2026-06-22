
last_payload_str = None

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    global last_payload_str
    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        last_payload_str = payload_str
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    global last_payload_str
    response = responses[0]
    return response.headers.get("Location", "") == last_payload_str

