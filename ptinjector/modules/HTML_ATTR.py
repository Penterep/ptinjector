from bs4 import BeautifulSoup

def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        yield [payload_str], [response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """See if any HTML attribute reflects <definition["verify"]>"""
    # TODO: Call fnc is_safe_to_parse()
    response = responses[0]
    soup = BeautifulSoup(response.text, "html5lib")
    for tag in soup.find_all(True):  # True finds all tags
        for attr, value in tag.attrs.items():
            for verification_str in verification_list:
                if verification_str == attr:
                    return True

    return False
