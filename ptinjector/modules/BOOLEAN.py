from bs4 import BeautifulSoup as bsoup
import hashlib


def get_md5(s: str):
    h = hashlib.new('md5', s.encode())
    return h.digest()


def run(payload_object, definition_contents, request_data, injector):
    responses = []
    payloads = []
    for payload_str in payload_object["payload"]:
        response, dump = injector._send_payload(payload_str, request_data)
        responses.append(response)
        payloads.append(payload_str)
    yield payloads, responses, dump


def tagset(response) -> set:
    tmp_list = list(bsoup(response.text, 'html.parser').find_all('a'))
    return {x.decode_contents() for x in tmp_list}


def equivalence_check(responses, verification_list):
    """
    Used to evaluate payload objects of the form:
    "SQL always false"
    "some valid value" (like id 1)
    "second valid value" (like 5)
    "SQL expression which evaluetes to 5"
    "SQL other expression which evaluates to 5"
    "SQL yet different expression which evaluetes to 5"
    ...

    If we can retrieve the same unique content with different SQL expressions (here for example evaluating to 5) it means
    they were evaluated - hence there is an injection.
    """

    if any(r.status_code != 200 for r in responses):
        return False

    # to filter out contents returned for different payloads or for 'false' payloads (ei. and false--+ and similar)
    false_contents = tagset(responses[0])
    common_contents = tagset(responses[1])
    response_contents = list()

    for r in responses[2:]:
        contents = tagset(r)
        common_contents = common_contents.intersection(contents)
        response_contents.append(contents)

    response_contents_filtered = (map(lambda c: c.difference(common_contents).difference(false_contents), response_contents))
    total_elements = sum(len(s) for s in response_contents_filtered)
    contents_union = set()
    for s in response_contents_filtered:
        contents_union = contents_union.union(s)

    # if the contents_union has less than total_elements it means there were duplicates
    # in response_contents_filtered, so different SQL expressions returned the same contents
    # which also were not default-returned, (since we removed false_contents
    return len(contents_union) < total_elements


def increasing_limit_check(responses, verification_list):
    differencesum = 0
    prev = set(bsoup(responses[0].text, 'html.parser').text.splitlines())
    for i in range(1, len(responses)):
        current = set(bsoup(responses[i].text, 'html.parser').text.splitlines())
        differencesum += int(1 == len(current.difference(prev)))
        prev = current

    return differencesum == len(responses) - 1


def check_if_vulnerable(responses, verification_list, injector):
    checks = {
        "equivalence_check": equivalence_check,
        "increasing_limit_check": increasing_limit_check
    }
    for verify_type in verification_list:
        check = checks.get(verify_type, False)
        if not check:
            import os
            print(f"\nWARNING: verify field '{verify_type}' not defined in {os.path.basename(__file__)}, defined checks are:\n{'\n'.join(checks.keys())}\n")
            continue
        if check(responses, verification_list):
            return True

    return False

