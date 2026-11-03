from bs4 import BeautifulSoup
from ptlibs import ptmisclib
from ptinjector.response_utils import get_response_chain


def run(payload_object, definition_contents, request_data, injector):
    for payload_str in payload_object["payload"]:
        response, _ = injector.run_payload_str(request_data, payload_str)

        for current_response in get_response_chain(response):
            dump = ptmisclib.get_response_data_dump(current_response)

            yield [payload_str], [current_response], dump


def check_if_vulnerable(responses, verification_list, injector):
    if len(responses) != 1 or not verification_list:
        return False

    expected_tags = {name.casefold() for name in verification_list}
    soup = BeautifulSoup(responses[0].text, "html5lib")

    return any(
        tag.name.casefold() in expected_tags
        for tag in soup.find_all(True)
    )