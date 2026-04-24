

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Verify request type payloads"""
    # Send requests to /verify endpoint of verification-url.
    try:
        res, dump = injector._send_payload(injector.VERIFICATION_URL, "")
        if res.json().get("msg") == "true":
            return True
    except requests.exceptions.RequestException as e:
        injector.ptjsonlib.end_error(f"Error connecting to {injector.VERIFICATION_URL}", details=e, condition=injector.use_json)
        return False
