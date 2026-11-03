from bs4 import BeautifulSoup as bsoup
import hashlib
import xml.etree.ElementTree as ET
import json
import re
from difflib import SequenceMatcher
import html
from urllib.parse import quote, quote_plus, unquote, unquote_plus


def get_md5(s: str):
    h = hashlib.new('md5', s.encode())
    return h.digest()

def split_content(text):
    return re.findall(r"\w+(?:[-:./+]\w+)*|[^\w]", text)

def find_dynamic_regions(first_text, second_text):
    first_parts = split_content(first_text)
    second_parts = split_content(second_text)

    matcher = SequenceMatcher(
        None, first_parts, second_parts, autojunk= False
    )

    regions = []

    for operation, start, end, other_start, other_end in matcher.get_opcodes():
        if operation != "equal":
            regions.append((start, end))
    return {
        "reference": first_parts,
        "regions": regions,
    }

def remove_dynamic_content(text, models):
    parts = split_content(text)
    ignored = set()

    for model in models:
        if not model["regions"]:
            continue

        matcher = SequenceMatcher(
            None, model["reference"], parts, autojunk=False
        )

        for operation, start, end, new_start, new_end in matcher.get_opcodes():
            for dynamic_start, dynamic_end in model["regions"]:
                if operation == "equal":
                    left = max(start, dynamic_start)
                    right = min(end, dynamic_end)
                    for index in range(left, right):
                        ignored.add(new_start + index - start)

                elif start == end:
                    if (
                        dynamic_start < start < dynamic_end
                        or dynamic_start == dynamic_end == start
                    ):
                        ignored.update(range(new_start, new_end))

                elif dynamic_start <= start and end <= dynamic_end:
                    ignored.update(range(new_start, new_end))

    clean_parts = []
    for index, part in enumerate(parts):
        if index not in ignored:
            clean_parts.append(part)

    return "".join(clean_parts)


def remove_reflected_payload(text, payload):
    if not payload:
        return text

    payload_values = {payload, unquote(payload), unquote_plus(payload)}

    try:
        payload_values.add(json.loads('"' + payload + '"'))
    except json.JSONDecodeError:
        pass

    variants = set()
    for value in payload_values:
        variants.update({
            value,
            html.escape(value),
            html.escape(value, quote=False),
            quote(value, safe=""),
            quote_plus(value, safe=""),
            json.dumps(value)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1],
        })

    for value in list(variants):
        variants.add(value.replace("&#x27;", "&#39;"))


    for value in sorted(variants, key=len, reverse=True):
        text = text.replace(value, "[PAYLOAD]")

    return text


def get_baseline(request_data, injector):
    if "boolean_baseline" in request_data:
        return request_data["boolean_baseline"]

    request_data["boolean_baseline"] = None
    errors_before = len(injector.scan_errors)
    invalid_value = f"ptinjector_invalid_{injector.RANDOM_STRING}"

    invalid_first, _ = injector.run_payload_str(request_data, invalid_value)
    invalid_second, _ = injector.run_payload_str(request_data, invalid_value)
    valid_first = injector.send_original_request(request_data)
    valid_second = injector.send_original_request(request_data)

    if len(injector.scan_errors) != errors_before:
        return None

    baseline = {
        "invalid": [invalid_first, invalid_second],
        "valid": [valid_first, valid_second],
        "dynamic_models": [
            find_dynamic_regions(invalid_first.text, invalid_second.text),
            find_dynamic_regions(valid_first.text, valid_second.text),

        ]
    }

    request_data["boolean_baseline"] = baseline
    return baseline

def run(payload_object, definition_contents, request_data, injector):
    baseline = get_baseline(request_data, injector)
    if baseline is None:
        return

    for true_payload, false_payload in payload_object["payload"]:
        true_payload = true_payload.replace("[VALUE]", request_data["original_value"])
        false_payload = false_payload.replace("[VALUE]", request_data["original_value"])
        errors_before = len(injector.scan_errors)

        true_response, true_dump = injector.run_payload_str(
            request_data, true_payload
        )
        false_response, _ = injector.run_payload_str(
            request_data, false_payload
        )

        if len(injector.scan_errors) != errors_before:
            continue

        comparison = {
            "baseline": baseline,
            "true_response": true_response,
            "false_response": false_response,
            "true_payload": true_payload,
            "false_payload": false_payload,
        }

        yield [true_payload, false_payload], comparison, true_dump


def json_to_pathtags(loaded_json):
    """"
    Creates tags for easier comparasion of json content.
    Ex:
    {
        "a": "Avalue",
        "b":{
            "c": "BCvalue"
        }
    }
    ->
    a: Avalue
    b:c: BCvalue
    """
    result = []
    keys = []

    def recurse(current):
        if type(current) in {str, int}:
            result.append(":" + ":".join(keys) + str(current))
            return
        for k in current:
            if type(current[k]) == str:
                result.append(":".join(keys) + k + ": " + current[k])
            elif type(current[k]) == list:
                keys.append(k)
                for e in current[k]:
                    recurse(e)
                keys.pop()
            elif type(current[k]) == dict:
                keys.append(k + ":")
                recurse(current[k])
                keys.pop()
    # ignoring 'pathologicaly nested' json
    try:
        recurse(loaded_json)
    except RecursionError:
        pass

    return set(result)

def tagset(response) -> set:
    content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().casefold()

    try:
        if content_type == 'text/html':
            links = bsoup(response.text, 'html.parser').find_all('a')
            return {link.decode_contents() for link in links}

        if content_type in {"application/json", "text/x-json", "text/json"}:
            return json_to_pathtags(json.loads(response.text))

        if content_type in {"application/xml", "text/xml"}:
            elements = set()
            tree = ET.fromstring(response.text)
            for elem in tree.iter():
                elements.add((elem.tag, elem.text))
            return elements
    except (ET.ParseError, json.JSONDecodeError, TypeError):
        pass

    return {response.content}


def error_code_check(responses, verification_list):

    if len(responses) < 5:
        return False

    status_codes = [r.status_code for r in responses]

    return status_codes[1] == 200 and status_codes[2] == 200 and any(500 == round(sc, -2) for sc in status_codes)

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

    response_contents_filtered = [c.difference(common_contents).difference(false_contents) for c in response_contents]
    total_elements = sum(len(s) for s in response_contents_filtered)
    contents_union = set()
    for s in response_contents_filtered:
        contents_union = contents_union.union(s)

    # if the contents_union has less than total_elements it means there were duplicates
    # in response_contents_filtered, so different SQL expressions returned the same contents
    # which also were not default-returned, (since we removed false_contents and there is a check for
    # nonempty contents_union in case the same content is returned.

    return (len(contents_union) < total_elements) and len(contents_union) != 0


def increasing_limit_check(responses, verification_list):
    if len(responses) < 2 or any(response.status_code != 200 for response in responses):
        return False

    differencesum = 0
    prev = set(bsoup(responses[0].text, 'html.parser').text.splitlines())
    for i in range(1, len(responses)):
        current = set(bsoup(responses[i].text, 'html.parser').text.splitlines())
        differencesum += int(1 == len(current.difference(prev)))
        prev = current

    return differencesum == len(responses) - 1


def check_if_vulnerable(comparison, verification_list, injector):
    models = comparison["baseline"]["dynamic_models"]

    true_text = remove_reflected_payload(
        comparison["true_response"].text,
        comparison["true_payload"],
    )
    false_text = remove_reflected_payload(
        comparison["false_response"].text,
        comparison["false_payload"],
    )

    if true_text == false_text:
        return False

    true_text = remove_dynamic_content(true_text, models)
    false_text = remove_dynamic_content(false_text, models)

    return true_text != false_text
