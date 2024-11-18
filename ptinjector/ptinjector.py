#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptinjector is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptinjector is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptinjector.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import base64
import random
import re
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import subprocess
import socket
import time
import tempfile
import urllib
from typing import Tuple

import requests
from bs4 import BeautifulSoup
from ptlibs import ptprinthelper, ptmisclib, ptjsonlib, ptnethelper, ptcharsethelper
from ptlibs.parsers.http_request_parser import HttpRequestParser

from _version import __version__
from definitions._loader import DefinitionsLoader

class PtInjector:
    def __init__(self, args):
        self.ptjsonlib: object                              = ptjsonlib.PtJsonLib()
        self.use_json: bool                                 = args.json
        self.http_headers                                   = ptnethelper.get_request_headers(args)
        self.proxy: dict                                    = {"http": args.proxy, "https": args.proxy}
        self.parameter: str                                 = args.parameter
        self.keep_testing                                   = args.keep_testing
        self.PLACEHOLDER_SYMBOL: str                        = args.placeholder
        self.RANDOM_STRING: str                             = ''.join([random.choice(ptcharsethelper.get_charset(["numbers"])) for i in range(10)])
        self.VERIFICATION_URL, self.BASE64_VERIFICATION_URL = self.setup_verification_url(args)
        self.PLACEHOLDER_EXISTS: bool                       = True if args.request_file else self.check_if_placeholder_exists()
        self.URL_PLACEHOLDER_INDEX: int                     = -1
        self.LOADED_DEFINITIONS: dict                       = self.load_definitions(args, random_string=self.RANDOM_STRING)
        self.request_parser: object                         = HttpRequestParser(ptjsonlib=self.ptjsonlib, use_json=self.use_json, placeholder=self.PLACEHOLDER_SYMBOL)

    def run(self, args):
        """Main method"""

        # Iterate specified tests
        for vulnerability_name in self.LOADED_DEFINITIONS.keys():
            is_vulnerable: bool = False
            is_vulnerable_during_keep_testing = False
            definition_contents: dict = self.LOADED_DEFINITIONS[vulnerability_name]
            vulnerability_description: str = definition_contents.get('description', vulnerability_name)
            confirmed_payloads = set()

            self.is_valid_request(args)
            # TODO: Test stability of server
            # TODO: ptprinthelper.ptprint(f"Testing connection to the target URL", "TITLE", colortext=True, condition=not self.use_json)

            # Current tested vulnerability
            ptprinthelper.ptprint(f"{vulnerability_name.upper() if not vulnerability_description else vulnerability_description}", "TITLE", colortext=True, condition=not self.use_json, newline_above=True)

            # Test parameter loop
            for request_data in self.generate_request_data(args):
                parameter_name = request_data["parameter"]
                is_vulnerable: bool = False
                ptprinthelper.ptprint(f"Testing parameter: <{ptprinthelper.get_colored_text(request_data['parameter'], 'TITLE')}>", "TITLE", not self.use_json, colortext=False, clear_to_eol=True, newline_above=True)

                # Iterate available payloads
                for payload_object in definition_contents.get("payloads", []):
                    for payload_str in payload_object["payload"]:
                        if is_vulnerable and not self.keep_testing:
                            break

                        #ptprinthelper.ptprint(f"Sending payload: {payload_str}", "", not self.use_json, end=f"\r", colortext=False, clear_to_eol=True)
                        ptprinthelper.ptprint(f"Sending payload: {payload_str}", "INFO", not self.use_json, end=f"\n", colortext=False, clear_to_eol=True)
                        response, dump = self._send_payload(request_data.get("url"), payload_str, request_data)
                        response.history.append(response) # Append final destination to the response history

                        #if response.status_code != 200:
                        #    ptprinthelper.ptprint(f"Status code: {response.status_code}", "TITLE", not self.use_json, colortext=False, clear_to_eol=True, newline_above=False)

                        for response_object in response.history:
                            is_vulnerable = self.check_if_vulnerable(response_object, payload_object)
                            if self.keep_testing and is_vulnerable and not is_vulnerable_during_keep_testing:
                                is_vulnerable_during_keep_testing = True
                            if is_vulnerable and not self.keep_testing:
                                break

                    if is_vulnerable:
                        ptprinthelper.ptprint(f"Payload executed: {payload_str}", "VULN", not self.use_json, end="\n", colortext=False, clear_to_eol=True)

                        ptprinthelper.ptprint(f"Parameter <{parameter_name}> seems to be vulnerable to {vulnerability_description}", "VULN", condition=not self.use_json and not self.keep_testing, colortext=True, clear_to_eol=True)
                        if self.keep_testing:
                            confirmed_payloads.add(payload_str)
                        self.ptjsonlib.add_vulnerability(definition_contents.get("vulnerability"), vuln_request=dump["request"], vuln_response=dump["response"])
                        if not self.keep_testing:
                            break

                if self.keep_testing:
                    if is_vulnerable_during_keep_testing:
                        ptprinthelper.ptprint(f"Vulnerable to {vulnerability_description}", "VULN", condition=not self.use_json, colortext=True, clear_to_eol=True)
                    else:
                        ptprinthelper.ptprint(f"Not vulnerable to {vulnerability_description}", "NOTVULN", condition=not self.use_json, colortext=True, clear_to_eol=True)

                    """
                    if confirmed_payloads:
                        ptprinthelper.ptprint(f"Executed payloads:", "TITLE", condition=not self.use_json, colortext=True, clear_to_eol=True)
                        ptprinthelper.ptprint("\n".join(confirmed_payloads), "TEXT", condition=not self.use_json, colortext=False)
                    """
                else:
                    if not is_vulnerable and definition_contents.get("payloads", []):
                        ptprinthelper.ptprint(f"Not vulnerable to {vulnerability_description}", "NOTVULN", condition=not self.use_json, colortext=True, clear_to_eol=True)

                if not definition_contents.get("payloads", []):
                    ptprinthelper.ptprint(f"No payloads available to test for {vulnerability_description} vulnerability", "NOTVULN", condition=not self.use_json, colortext=False, clear_to_eol=True)

        ptprinthelper.ptprint("Finished", "TITLE", condition=not self.use_json, clear_to_eol=True, newline_above=True)
        if self.use_json:
            self.ptjsonlib.set_status("finished")
            print(self.ptjsonlib.get_result_json())


    def check_if_vulnerable(self, response, payload_object: dict) -> bool:
        """Verify if payload was executed"""
        payload_type = payload_object.get("type").upper()
        verification_list = payload_object.get("verify")

        if payload_type == "HTML_TAG":
            is_vulnerable = self.verify_html_tags(response, verification_list)
        elif payload_type == "HTML_ATTR":
            is_vulnerable = self.verify_html_attrs(response, verification_list)
        elif payload_type == "REGEX":
            is_vulnerable = self.verify_regex(response, verification_list)
        elif payload_type == "TIME":
            is_vulnerable = self.verify_time(response, verification_list)
        elif payload_type == "BOOLEAN":
            is_vulnerable = self.verify_boolean(response, verification_list)
        elif payload_type == "HEADER":
            is_vulnerable = self.verify_headers(response, verification_list)
        elif payload_type == "REQUEST":
            is_vulnerable = self.verify_request()
        else:
            return
        return is_vulnerable

    def verify_request(self):
        """Verify request type payloads"""
        # Send requests to /verify endpoint of verification-url.
        res, dump = self._send_payload(self.VERIFICATION_URL, "")
        if res.json().get("msg") == "true":
            return True

    def verify_html_tags(self, response, verification_list: list):
        """Returns True if definition['verify'] in <response> text"""
        # TODO: Call fnc is_safe_to_parse()
        soup = BeautifulSoup(response.text, "html5lib")
        if soup.findAll(verification_list):
            return True

    def verify_html_attrs(self, response, verification_list: list):
        """See if any HTML attribute reflects <definition["verify"]>"""
        # TODO: Call fnc is_safe_to_parse()
        soup = BeautifulSoup(response.text, "html5lib")
        for tag in soup.findAll(True):  # True finds all tags
            for attr, value in tag.attrs.items():
                for verification_str in verification_list:
                    if verification_str == attr:
                        return True

    def verify_regex(self, response: requests.Response, verification_list: list):
        """Check if <verification_re> in <response.text>"""
        for verification_re in verification_list:
            if re.search(verification_re, response.text):
                return True

    def verify_time(self, response, verification_list):
        """Pokud response odpovedi trva dele nez cas uvedeny v definici, je to zranitelne."""

        def custom_sort_key(item):
        # Try to convert the item to an integer for sorting
            try:
                # Assuming the item is a string that can represent an integer
                return (0, -int(item))  # Negative for descending order
            except ValueError:
                # Item is not a number, so sort as a string
                return (1, item)

        verification_list.sort(key=custom_sort_key)

        if not verification_list[0].isdigit():
            print(verification_list, "Invalid definitions")
            return False

        if response.elapsed.total_seconds() > int(verification_list[0]):
            print(True)

            ptprinthelper.ptprint("Zranitelne na Time-based", "VULN", not self.use_json, colortext=True)
            return True

    def verify_boolean(self, response, definition):
        try:
            if response.elapsed.total_seconds() > definition["verify"][0]:
                return True
        except:
            return False

    def verify_headers(self, response, verification_list: list):
        return True if any([any(verification_string in header_name for verification_string in verification_list) for header_name in response.headers.keys()]) else False

    def _send_payload(self, url: str, payload: str, rdata=None) -> requests.models.Response:
        """Send <payload> to <url>"""

        param, url, http_method, headers, data = rdata["parameter"], rdata["url"], rdata["method"], rdata["headers"], rdata["data"]
        timeout=None

        URL_PLACEHOLDER_INDEX = self.get_placeholder_from_url(url)
        if URL_PLACEHOLDER_INDEX != -1:
            # Payload marker is in <url>
            url = url[:URL_PLACEHOLDER_INDEX] + payload + url[URL_PLACEHOLDER_INDEX + len(self.PLACEHOLDER_SYMBOL):]  # Substitute payload marker with actual payload
            response, dump = ptmisclib.load_url_from_web_or_temp(url, method=http_method, headers=headers, data=data, redirects=False, proxies=self.proxy, verify=False, timeout=timeout, dump_response=True)
            return response, dump
        else:
            # Payload  marker is in <request data>
            request_data = re.sub(self.PLACEHOLDER_SYMBOL, lambda _: payload, data) # Use a callable to substitute the payload directly
            return ptmisclib.load_url_from_web_or_temp(url, method=http_method, headers=headers, proxies=self.proxy, data=request_data, redirects=False, verify=False, timeout=timeout, dump_response=True)

        # TODO: Header injection: attack_data = self.payload2dict(self.str2dict(), payload)

    def is_valid_definition(self, definition: dict):
        """Return True if <definition> is in a valid format"""
        try:
            assert definition.get("payloads")
        except AssertionError:
            sys.exit("ASSERTION ERROR")

    def payload2dict(self, dictionary, payload):
        """Find and replace * in dict for payload"""
        for k, v in dictionary.items():
            if v.find(self.PLACEHOLDER_SYMBOL) != -1:
                v = v.replace(self.PLACEHOLDER_SYMBOL, payload)
                dictionary[k] = v
                break
        return dictionary

    def str2dict(self):
        result = {}
        try:
            for i in self.request_data.split("&"):
                pair = i.split("=")
                result.update({pair[0]: pair[1]})
        except IndexError:
            self.ptjsonlib.end_error("invalid data", self.use_json)
        return result

    def get_placeholder_from_url(self, url) -> Tuple[str, int]:
        """Extracts the placeholder from the URL."""
        placeholder_position: int = url.find(self.PLACEHOLDER_SYMBOL) # Returns -1 if not present
        parsed_url = urllib.parse.urlparse(url)
        pathless_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, "/", "", "", "")) # https://www.example.com/

        if placeholder_position != -1 and placeholder_position < len(pathless_url):
            self.ptjsonlib.end_error("Wrong placeholder usage (placeholder supported only in PATH)", self.use_json)
        if not re.match("https?", parsed_url.scheme):
            self.ptjsonlib.end_error(f"Missing or wrong scheme, did you mean https://{url}?", self.use_json)
        return placeholder_position

    def check_if_placeholder_exists(self):
        """Check for presence of placeholder in <sys.argv>"""
        placeholder_count = 0
        for arg in list(sys.argv[1:]):
            placeholder_count += arg.count(self.PLACEHOLDER_SYMBOL)

        if placeholder_count > 1:
            self.ptjsonlib.end_error(f"Only one occurrence of placeholder '*' character is allowed, found {str(placeholder_count)}", self.use_json)

        return True if placeholder_count else False

    def get_local_ip(self):
        try:
            # Create a UDP socket and connect to an arbitrary IP address
            # This does not require an actual network connection
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('192.168.0.1', 1)) # Dummy IP, doesn't have to exist and internet access is not required.
                local_ip = s.getsockname()[0]
                return local_ip
        except Exception as e:
            self.ptjsonlib.end_error(f"Unable to get IP address while starting local server. ({e})", self.use_json)

    def start_local_server(self, host, port):
        """Starts local server on specified <port>"""
        # Remove the signal file if it exists
        if os.path.exists(os.path.join(tempfile.gettempdir(), "flask_ready.txt")):
            os.remove(os.path.join(tempfile.gettempdir(), "flask_ready.txt"))

        # Start the Flask app using subprocess
        path_to_app = os.path.join(__file__.rsplit("/", 1)[0], "server", "app.py")
        flask_process = subprocess.Popen([sys.executable, path_to_app, '--host', host, '--port', port], stdout=subprocess.DEVNULL)#, stderr=subprocess.DEVNULL)#, stderr=subprocess)

        # TODO: Catch errors, such as port already in use. etc.

        # Wait for the signal file to be created
        while not os.path.exists(os.path.join(tempfile.gettempdir(), "flask_ready.txt")):
            time.sleep(0.1)
        return flask_process

    def setup_verification_url(self, args):
        if args.start_local_server:
            local_ip = self.get_local_ip()
            port = args.start_local_server
            self.start_local_server(host=local_ip, port=port)
            verification_url = f"http://{local_ip}:{port}/verify/{self.RANDOM_STRING}"
        elif args.verification_url:
            verification_url = f"{args.verification_url}/verify/{self.RANDOM_STRING}"
        else:
            verification_url = None

        base64_verification_url = (
            base64.b64encode(bytes(f'<img src="{verification_url}">', "ascii"))
            if verification_url else None
        )
        return verification_url, base64_verification_url

    def process_parameters(self):
        """Process GET and POST parameters to replace the specified parameter with a placeholder symbol."""

        if self.parameter:
            parsed_url = urllib.parse.urlparse(self.url)
            get_parameters = re.findall(r"([\w\d]+)=", urllib.parse.urlparse(self.url).query)
            post_parameters_dict = dict(urllib.parse.parse_qsl(self.request_data))

            # If <parameter> in GET params
            if self.parameter in get_parameters: # Rebuild the query string
                _get_parameters = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.url).query))
                _get_parameters[self.parameter] = self.PLACEHOLDER_SYMBOL # Replace value of specified <parameter> for <placeholder_symbol>.
                new_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, '&'.join([f'{key}={value}' for key, value in _get_parameters.items()]), parsed_url.fragment))
                self.url = new_url

            # If <parameter> in request data
            if self.request_data:
                # TODO: Properly parse <request_data> by <content_type>
                if self.parameter in post_parameters_dict: # Check if <parameter> in dict keys
                    post_parameters_dict[self.parameter] = self.PLACEHOLDER_SYMBOL
                    self.request_data = urllib.parse.urlencode(post_parameters_dict, safe=self.PLACEHOLDER_SYMBOL)

            if self.parameter not in get_parameters and self.parameter not in post_parameters_dict:
                error_message = (
                    f"Specified parameter '{self.parameter}' was not found.\n"
                    f"    Available GET parameters: {', '.join(get_parameters) if get_parameters else None}\n"
                    f"    Available POST parameters: {', '.join(post_parameters_dict.keys()) if post_parameters_dict else None}")
                self.ptjsonlib.end_error(error_message, self.use_json)

    def load_definitions(self, args, random_string: str):
        """Load Definitions. <random_string> is for replacing placeholders inside."""
        try:
            return DefinitionsLoader(use_json=args.json, random_string=random_string, verification_url=args.verification_url, technologies=args.technology).load_definitions(args.tests)
        except Exception as exc:
            self.ptjsonlib.end_error(f"{exc}, program will exit.", self.use_json)

    def _ensure_valid_param_or_placeholder_usage(self):
        if not self.parameter and not self.PLACEHOLDER_EXISTS:
            self.ptjsonlib.end_error(f"You must specify a parameter to test or use the '{self.PLACEHOLDER_SYMBOL}' placeholder to indicate where the script should perform the test.", self.use_json)
        if self.parameter and self.PLACEHOLDER_EXISTS:
            self.ptjsonlib.end_error(f"Cannot combine --parameter and placeholder '{self.PLACEHOLDER_SYMBOL}' together", self.use_json)

    def is_valid_request(self, args) -> bool:
        """
        Validates that the request has enough information to be generated.

        Ensures that either a URL with path or query parameters, or request data,
        or an valid external request file is provided.

        :return: True if the request data is valid, otherwise ends with error.
        """

        if args.request_file:
            http_request = self.request_parser.is_valid_http_request(args.request_file)
            _req_data = self.request_parser.get_request_data(http_request)
            if not _req_data and not self.request_parser.has_query_params(args.request_file):
                self.ptjsonlib.end_error(f"Provided request file contains no parameters to test.", self.use_json)
        else:
            parsed_url = urllib.parse.urlparse(args.url)
            if (not parsed_url.path or parsed_url.path == "/") and not parsed_url.query and not args.data:
                self.ptjsonlib.end_error(f"Provided URL contains no parameters to test.", self.use_json)
        return True

    def generate_request_data(self, args):
        """
        Generates the data needed to construct HTTP requests based on input parameters.

        Processes parameters to prepare the necessary data, including the URL, request body,
        HTTP method, and headers. Inserts placeholders for specified parameters as needed.

        :param args: Input arguments with data needed to build requests.
        :yield: A dictionary with request components (URL, data, method, headers, parameter).
        """

        def build_and_mark_request(parameter):
            """Builds a request template and marks a placeholder for the specified parameter."""
            if args.request_file:
                http_request = self.request_parser.mark_placeholder(http_request=args.request_file, parameter=parameter)
            else:
                http_request = self.request_parser.build_request(url=args.url, headers=self.http_headers, request_data=args.data)
                http_request = self.request_parser.mark_placeholder(http_request=http_request, parameter=parameter)
            return http_request

        def parse_and_yield_request(parameter_name, http_request):
            """Parses the HTTP request and yields a dictionary with request data components."""
            url, method, headers, request_data = self.request_parser.parse_http_request(http_request=http_request)
            yield {"parameter": parameter_name, "url": url, "method": method, "headers": headers, "data": request_data}

        # Generování požadavků na základě přítomných parametrů
        if args.parameter:
            # Single parameter case
            http_request = build_and_mark_request(args.parameter)
            yield from parse_and_yield_request(args.parameter, http_request)
        else:
            # Multiple parameters case
            parameter_index = 0
            while True:
                try:
                    http_request = build_and_mark_request(parameter_index)
                    parameter_name = self.request_parser.get_parameter_name_by_index(http_request, parameter_index)
                    yield from parse_and_yield_request(parameter_name, http_request)
                    parameter_index += 1
                except IndexError:
                    break  # Konec při dosažení posledního parametru


def get_help():
    return [
        {"description": ["ptinjector - Injection Vulnerabilities Testing Tool"]},
        {"usage": ["ptinjector <options>"]},
        {"usage_example": [
            ["ptinjector -u https://www.example.com/?parameter1=abc&parameter2=def --parameter search -t XSS, SQLI"],
            ["ptinjector -u https://www.example.com/?parameter1=abc&parameter2=def* -t XSS, SQLI"],
            ["ptinjector -u http://192.168.0.3/admin/ping.php -d 'host=127.0.0.1*' -c 'PHPSESSID=cf0a2784f5b34228a016ec5' -H 'X-Forwarded-For:127.0.0.1' -p http://127.0.0.1:8080",]
        ]},
        {"specials": [
            f"Use '*' character to set placeholder for injections",
        ]},
        {"options": [
            ["-u",  "--url",                   "<url>",           "Test URL"],
            ["-t",  "--test",      "<test>",                      "Specify one or more tests to perform:"],
            *DefinitionsLoader().get_definitions_help(),
            ["",    "",                       "",                 ""],
            ["-rf", "--request_file",         "<request-file>",   "Set request-file.txt"],
            ["-d",  "--data",                 "<data>",           "Set request-data"],
            ["-P",  "--parameter",            "<parameter>",      "Set parameter to test (e.g. GET, POST parameters)"],
            ["-H",  "--headers",              "<headers>",        "Set Header(s)"],
            ["-c",  "--cookie",               "<cookie>",         "Set Cookie(s)"],
            ["-a",  "--agent",                "<agent>",          "Set User-Agent"],
            ["-p",  "--proxy",                "<proxy>",          "Set Proxy"],
            ["-vu", "--verify-url",           "<verify-url>",     "Set Verification URL (used with e.g. SSRF)"],
            ["-g", "--technology",            "<technology>",     "Set Technology"],
            ["-k",  "--keep-testing",         "",                 "Keep sending payloads, even if vulnerability is already detected"],
            ["-l",  "--start-local-server",   "<port>",           "Start local server on <port> (default 5000)"],
            ["-v",  "--version",                "",               "Show script version and exit"],
            ["-h",  "--help",                   "",               "Show this help message and exit"],
            ["-j",  "--json",                   "",               "Output in JSON format"],
        ]
        }]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True, usage=f"{SCRIPTNAME} <options>")
    exclusive = parser.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("-u",  "--url",              type=str)
    exclusive.add_argument("-rf", "--request-file",     type=str)
    parser.add_argument("-t",  "--tests",               type=str,  nargs="+")
    parser.add_argument("-g",  "--technology",          type=str,  nargs="+", default=[])
    parser.add_argument("-a",  "--user_agent",          type=str)
    parser.add_argument("-vu", "--verification_url",    type=str)
    parser.add_argument("-p",  "--proxy",               type=str)
    parser.add_argument("-c",  "--cookie",              type=str)
    parser.add_argument("-P",  "--parameter",           type=str)
    parser.add_argument("-d",  "--data",                type=str)
    parser.add_argument("-l",  "--start-local-server",  type=str, nargs="?", const="5000")
    parser.add_argument("-H",  "--headers",             type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-k",  "--keep-testing",        action="store_true")
    parser.add_argument("-j",  "--json",                action="store_true")
    parser.add_argument("-v",  "--version",             action="version", version=f"{SCRIPTNAME} {__version__}")
    parser.add_argument("--placeholder",                type=str, default="<INJECT_HERE>")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        help = get_help()
        ptprinthelper.help_print(help, SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    args.request_file = os.path.abspath(os.path.join(os.path.dirname(__file__), args.request_file)) if args.request_file else None
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptinjector"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtInjector(args)
    script.run(args)


if __name__ == "__main__":
    main()




