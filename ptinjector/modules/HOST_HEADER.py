from ptlibs import ptmisclib
from ptinjector.response_utils import get_response_chain

HOST_HEADERS = (
    "Host",
    "X-Forwarded-Host",
    "X-Client-IP",
    "X-Real-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
)

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        payload_request_data = {**request_data, "headers": dict(request_data.get("headers", {}))}
        for header in HOST_HEADERS:
            payload_request_data["headers"][header] = payload_str

        response, _ = injector.run_payload_str(
            payload_request_data, payload_str
        )

        for current_response in get_response_chain(response):
            dump = ptmisclib.get_response_data_dump(current_response)

            yield [payload_str], [
                baseline_response,
                current_response,
                payload_str,
            ], dump


def find_evidence(responses, verification_list, injector):
    if len(responses) != 3:
        return None

    baseline_response, payload_response, payload = responses
    content_type = (
        payload_response.headers.get("Content-Type", "")
        .split(";", 1)[0].strip().casefold()
    )

    if content_type != "text/html" or payload not in payload_response.text:
        return None

    for baseline_part in get_response_chain(baseline_response):
        if payload in baseline_part.text:
            return None

    start = payload_response.text.find(payload)
    return {
        "response": payload_response,
        "spans": [(start, start + len(payload))],
        "request_header_names": HOST_HEADERS,
    }


def check_if_vulnerable(responses, verification_list, injector):
    return find_evidence(responses, verification_list, injector) is not None
