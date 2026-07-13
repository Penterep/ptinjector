from bs4 import BeautifulSoup
from collections import Counter

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when injection adds an expected HTML attribute."""
    if len(responses) != 2 or not verification_list:
        return False

    expected_attributes = {attribute.casefold() for attribute in verification_list}

    def count_expected_attributes(response):
        soup = BeautifulSoup(response.text, "html5lib")
        return Counter(
            attribute.casefold()
            for tag in soup.find_all(True)
            for attribute in tag.attrs
            if attribute.casefold() in expected_attributes
        )

    baseline_attributes = count_expected_attributes(responses[0])
    payload_attributes = count_expected_attributes(responses[1])

    return any(payload_attributes[attribute] > baseline_attributes[attribute] for attribute in expected_attributes)
