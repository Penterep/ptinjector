from bs4 import BeautifulSoup
from collections import Counter

def run(payload_object, definition_contents, request_data, injector):
    baseline_response, _ = injector.run_payload_str(request_data, injector.RANDOM_STRING)

    for payload_str in payload_object["payload"]:
        response, dump = injector.run_payload_str(request_data, payload_str)
        yield [payload_str], [baseline_response, response], dump


def check_if_vulnerable(responses, verification_list, injector):
    """Return True when injection adds an expected HTML tag."""
    if len(responses) != 2 or not verification_list:
        return False

    expected_tags = {tag.casefold() for tag in verification_list}

    def count_expected_tags(response):
        soup = BeautifulSoup(response.text, "html5lib")
        return Counter(tag.name.casefold() for tag in soup.find_all(True) if tag.name.casefold() in expected_tags)

    baseline_tags = count_expected_tags(responses[0])
    payload_tags = count_expected_tags(responses[1])

    return any(payload_tags[tag] > baseline_tags[tag] for tag in expected_tags)
