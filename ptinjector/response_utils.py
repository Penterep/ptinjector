from html.parser import HTMLParser
import re
from bs4 import BeautifulSoup
import requests
import json

def get_response_chain(response):
    if response is None:
        return []

    history = getattr(response, "history", [])


    return list(history) + [response]

def make_evidence_snippet(text, start, end):
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)

    if line_end == -1:
        line_end = len(text)


    return (
        text[line_start:start]
        + f"**{text[start:end]}**"
        + text[end:line_end]
    )


def make_evidence_response(response_dump, text, spans, header_names=()):
    headers = response_dump.split("\r\n\r\n", 1)[0]
    expected_headers = {name.casefold() for name in header_names}
    header_spans = []

    for match in re.finditer(r"(?m)^([^:\r\n]+):[^\r\n]*", headers):
        if match.group(1).casefold() in expected_headers:
            header_spans.append(match.span())

    headers = highlight_spans(headers, header_spans)
    regions = []

    for start, end in sorted(spans):
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end == -1:
            line_end = len(text)

        if regions and line_start <= regions[-1][1]:
            regions[-1] = (
                regions[-1][0],
                max(regions[-1][1], line_end),
            )
        else:
            regions.append((line_start, line_end))

    snippets = []
    for start, end in regions:
        local_spans = [
            (left - start, right - start)
            for left, right in spans
            if start <= left < right <= end
        ]
        snippets.append(highlight_spans(text[start:end], local_spans))

    return headers + "\r\n\r\n" + "\r\n...\r\n".join(snippets)

class HTMLTagSpanParser(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)

        self.line_starts = [0]
        for index, character in enumerate(text):
            if character == "\n":
                self.line_starts.append(index + 1)

        self.spans = {}

    def handle_starttag(self, tag, attrs):
        line, column = self.getpos()

        start = self.line_starts[line - 1] + column
        end = start + len(self.get_starttag_text())

        self.spans[(tag.casefold(), end)] = (start, end)

def find_html_tag_span(text, tag):
    if tag.sourceline is None or tag.sourcepos is None:
        return None

    line_starts = [0]
    for newline in re.finditer(r"\r\n|\r|\n", text):
        line_starts.append(newline.end())

    end = line_starts[tag.sourceline - 1] + tag.sourcepos + 1

    parser = HTMLTagSpanParser(text)
    parser.feed(text)
    parser.close()

    return parser.spans.get((tag.name.casefold(), end))


def find_html_evidence(responses, verification_list, search_attributes=False):
    if len(responses) != 1 or not verification_list:
        return None

    response = responses[0]
    expected_names = {name.casefold() for name in verification_list}
    soup = BeautifulSoup(response.text, "html5lib")

    for tag in soup.find_all(True):
        if search_attributes:
            names = tag.attrs
        else:
            names = [tag.name]

        if any(name.casefold() in expected_names for name in names):
            span = find_html_tag_span(response.text, tag)

            if span is not None:
                return {
                    "response": response,
                    "spans": [span],
                }

    return None



def highlight_spans(text, spans):
    for start, end in sorted(spans, reverse=True):
        text = (
            text[:start]
            + f"**{text[start:end]}**"
            + text [end:]
        )

    return text

def find_injected_span(text, template, placeholder):
    if not placeholder or template.count(placeholder) != 1:
        return None

    prefix, suffix = template.split(placeholder, 1)

    if not text.startswith(prefix) or not text.endswith(suffix):
        return None

    start = len(prefix)
    end = len(text) - len(suffix) 

    if start >= end:
        return None
    return start,end



def make_url_templates(url_template, placeholder):
    token = "ptinjectorplaceholder"

    while token in url_template:
        token += "_"

    temporary_url = url_template.replace(placeholder, token, 1)
    prepared = requests.Request("GET", temporary_url).prepare()

    return ( 
        prepared.path_url.replace(token, placeholder),
        prepared.url.replace(token, placeholder),
    )


def highlight_url_payload(request_dump, url_template, payloads, placeholder):
    if not placeholder or url_template.count(placeholder) != 1:
        return request_dump

    first_line = request_dump.split("\n", 1)[0]
    parts = first_line.split(" ", 2)

    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return request_dump

    target = parts[1]

    try:
        templates = make_url_templates(url_template, placeholder)
        expected_targets = []

        for payload in payloads:
            url = url_template.replace(placeholder, payload, 1)
            request = requests.Request("GET", url)
            prepared = request.prepare()
            expected_targets.extend((prepared.path_url, prepared.url))

    except requests.RequestException:
        return request_dump

    if target not in expected_targets:
        return request_dump

    for template in templates:
        span = find_injected_span(target, template, placeholder)

        if span is not None:
            offset = len(parts[0]) + 1
            start, end = span
            return highlight_spans(
                request_dump,
                [(offset + start, offset + end)],
            )

    return request_dump



def restore_request_body(request_dump, body):
    if body is None:
        return request_dump

    headers, separator, _ = request_dump.partition("\r\n\r\n")

    if not separator:
        return request_dump

    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="surrogateescape")
    elif not isinstance(body, str):
        return request_dump

    return headers + separator + body


def highlight_body_payload(
    request_dump, body_template, payloads, placeholder, content_type
):
    if not isinstance(body_template, str):
        return request_dump

    headers, separator, body = request_dump.partition("\r\n\r\n")
    if not separator:
        return request_dump

    span = find_injected_span(body, body_template, placeholder)
    if span is None:
        return request_dump

    start, end = span
    content_type = (content_type or "").split(";", 1)[0].strip().lower()

    for payload in payloads:
        expected = payload

        if content_type == "application/json":
            expected = json.dumps(payload)[1:-1]

        if body[start:end] == expected:
            offset = len(headers) + len(separator)
            return highlight_spans(
                request_dump,
                [(offset + start, offset + end)],
            )

    return request_dump

def highlight_header_payload(
    request_dump, header_templates, payloads, placeholder, injected_headers=()
):
    if not placeholder:
        return request_dump

    headers, separator, _ = request_dump.partition("\r\n\r\n")
    if not separator and not request_dump.endswith("\r\n\r"):
        return request_dump

    first_line, line_break, header_text = headers.partition("\r\n")
    if not line_break:
        return request_dump

    templates = requests.structures.CaseInsensitiveDict(header_templates)
    for name in injected_headers:
        templates[name] = placeholder

    header_offset = len(first_line) + len(line_break)
    spans = set()

    for match in re.finditer(
        r"(?m)^([^:\r\n]+):[ \t]*([^\r\n]*)", header_text
    ):
        actual_name, actual_value = match.groups()

        for name, value in templates.items():
            if placeholder not in name and placeholder not in value:
                continue

            for payload in payloads:
                expected_name = name.replace(placeholder, payload)
                expected_value = value.replace(placeholder, payload)

                if (
                    actual_name.casefold() != expected_name.casefold()
                    or len(actual_name) != len(expected_name)
                    or actual_value != expected_value
                ):
                    continue

                for group, template, expected in (
                    (1, name, expected_name),
                    (2, value, expected_value),
                ):
                    span = find_injected_span(expected, template, placeholder)
                    if span is not None:
                        start, end = span
                        offset = header_offset + match.start(group)
                        spans.add((offset + start, offset + end))

    return highlight_spans(request_dump, spans)

def format_request_dump(
    request_dump, response, request_data, payloads, placeholder, content_type,
    injected_headers=(),
):
    prepared_request = getattr(response, "request", None)

    if prepared_request is not None:
        request_dump = restore_request_body(
            request_dump,
            prepared_request.body,
        )

    request_dump = highlight_url_payload(
        request_dump,
        request_data["url"],
        payloads,
        placeholder,
    )

    request_dump = highlight_body_payload(
        request_dump,
        request_data["data"],
        payloads,
        placeholder,
        content_type,
    )

    return highlight_header_payload(
        request_dump,
        request_data["headers"],
        payloads,
        placeholder,
        injected_headers,
    )