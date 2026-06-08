

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        request_data['headers']['Host'] = payload_str
        request_data['headers']["X-Forwarded-Host"] = payload_str
        request_data['headers']["X-Client-IP"] = payload_str
        request_data['headers']["X-Real-IP"] = payload_str
        request_data['headers']["X-Remote-IP"] = payload_str
        request_data['headers']["X-Remote-Addr"] = payload_str
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    response = responses[0]
    result =  False

    if response.headers['Content-Type'] == 'text/html':
        for verification_string in verification_list:
            result |= verification_string in response.text

    return result

