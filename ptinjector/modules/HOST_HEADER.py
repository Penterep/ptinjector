

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        payload_request_data = {**request_data, "headers": dict(request_data.get("headers", {}))}
        for header in ("Host", "X-Forwarded-Host", "X-Client-IP", "X-Real-IP", "X-Remote-IP", "X-Remote-Addr"):
            payload_request_data["headers"][header] = payload_str

        response, dump = injector.run_payload_str(payload_request_data, payload_str)
        yield [payload_str], [baseline_response, response, payload_str], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when the injected host is newly reflected in an HTML response."""
    if len(responses) != 3:
        return False

    baseline_response, payload_response, payload = responses
    content_type = payload_response.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()

    return content_type == "text/html" and payload in payload_response.text and payload not in baseline_response.text
