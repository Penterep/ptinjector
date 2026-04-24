

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Pokud response odpovedi trva dele nez cas uvedeny v definici, je to zranitelne."""
    response = responses[0]
    if len(verification_list) != 1:
        print(verification_list, "Invalid definition: 'verify' field in vuln. definition must contain a single number.")
        return False
    try:
        vulnerable_time = float(verification_list[0])
    except ValueError:
        print(verification_list, "Invalid definition: 'verify' field in vuln. definition must contain a valid number.")
        return False
    return vulnerable_time <= response.elapsed.total_seconds()
