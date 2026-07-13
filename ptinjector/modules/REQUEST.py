
import requests
import time


VERIFICATION_ATTEMPTS = 5
VERIFICATION_INTERVAL = 0.5


def callback_confirmed(response):
    if response.status_code != 200:
        return False

    try:
        return str(response.json().get("msg", "")).casefold() == "true"
    except (AttributeError, TypeError, ValueError):
        return False


def run(payload_object, definition_contents, request_data, injector):
    verification_urls = payload_object.get("verification_urls", [])

    for payload_index, payload_str in enumerate(payload_object["payload"]):
        response, dump = injector.run_payload_str(request_data, payload_str)
        verification_url = (
            verification_urls[payload_index]
            if payload_index < len(verification_urls)
            else injector.VERIFICATION_URL
        )
        verification_responses = []

        for attempt in range(VERIFICATION_ATTEMPTS):
            try:
                verification_response = requests.get(
                    verification_url,
                    proxies=injector.proxy,
                    verify=False,
                    timeout=min(injector.timeout, 5),
                )
            except requests.exceptions.RequestException:
                break

            verification_responses.append(verification_response)
            if callback_confirmed(verification_response):
                break
            if attempt < VERIFICATION_ATTEMPTS - 1:
                time.sleep(VERIFICATION_INTERVAL)

        yield [payload_str], verification_responses, dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when the verification service confirms the callback."""
    return any(callback_confirmed(response) for response in responses)
