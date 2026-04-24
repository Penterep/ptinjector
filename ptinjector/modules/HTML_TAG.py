from bs4 import BeautifulSoup

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Returns True if definition['verify'] in <response> text"""
    # TODO: Call fnc is_safe_to_parse()
    response = responses[0]
    soup = BeautifulSoup(response.text, "html5lib")
    if soup.find_all(verification_list):
        return True

    return False
