
import requests


def run(payload_object, definition_contents, request_data, injector):
    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        verification_response = requests.get(
            injector.VERIFICATION_URL,
            proxies=injector.proxy,
            verify=False,
            timeout=injector.timeout,
        )
        yield [payload_str], [verification_response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when the verification service confirms the callback."""
    if len(responses) != 1:
        return False

    response = responses[0]
    if response.status_code != 200:
        return False

    try:
        return str(response.json().get("msg", "")).casefold() == "true"
    except (AttributeError, TypeError, ValueError):
        return False
