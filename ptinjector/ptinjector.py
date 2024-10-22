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

from _version import __version__
from definitions._loader import DefinitionsLoader
from helpers.request_file_parser import RequestFileParser


class PtInjector:
    def __init__(self, args):
        self.ptjsonlib: object                              = ptjsonlib.PtJsonLib()
        self.use_json: bool                                 = args.json
        self.http_headers: dict                             = ptnethelper.get_request_headers(args)
        self.proxy: dict                                    = {"http": args.proxy, "https": args.proxy}
        self.parameter: str                                 = args.parameter
        self.keep_testing                                   = args.keep_testing
        self.PLACEHOLDER_SYMBOL: str                        = "*"
        self.RANDOM_STRING: str                             = ''.join([random.choice(ptcharsethelper.get_charset(["numbers"])) for i in range(10)])
        self.IS_PLACEHOLDER: bool                           = self.placeholder_exists(is_request_file=bool(args.request_file))
        self.VERIFICATION_URL, self.BASE64_VERIFICATION_URL = self.setup_verification_url(args)
        self.LOADED_DEFINITIONS: dict                       = self.get_definitions(args, random_string=self.RANDOM_STRING) # Load definitions
        self.URL_PLACEHOLDER_INDEX: int                     = -1
        self.url, self.request_data, self.http_method       = self.load_url_or_request_file(args)
        self._ensure_valid_param_or_placeholder_usage()
        if self.parameter:
            self.process_parameters()

    def run(self, args):
        """Main method"""
        # Iterate specified tests
        for vulnerability_name in self.LOADED_DEFINITIONS.keys():
            is_vulnerable: bool = False
            definition_contents: dict = self.LOADED_DEFINITIONS[vulnerability_name]
            vulnerability_description = definition_contents.get('description', vulnerability_name)
            confirmed_payloads = set()
            if self.keep_testing:
                is_vulnerable_during_keep_testing = False
            ptprinthelper.ptprint(f"Testing: {vulnerability_name.upper() if not vulnerability_description else vulnerability_description}", "TITLE", colortext=True, condition=not self.use_json)

            # Iterate available payloads
            for payload_object in definition_contents.get("payloads", []):
                for payload_str in payload_object["payload"]:
                    if is_vulnerable and not self.keep_testing:
                        break

                    # Send payload
                    ptprinthelper.ptprint(f"Sending payload: {payload_str}", "", not self.use_json, end=f"\r", colortext=False, clear_to_eol=True)
                    response, dump = self._send_payload(self.url, payload_str)
                    response.history.append(response) # Append final destination to the response history

                    for response_object in response.history:
                        is_vulnerable = self.check_if_vulnerable(response_object, payload_object)
                        if self.keep_testing and is_vulnerable and not is_vulnerable_during_keep_testing:
                            is_vulnerable_during_keep_testing = True
                        if is_vulnerable and not self.keep_testing:
                            break

                if is_vulnerable:
                    ptprinthelper.ptprint(f"Vulnerable to {vulnerability_description} ({payload_str})", "VULN", condition=not self.use_json and not self.keep_testing, colortext=False, clear_to_eol=True)
                    if self.keep_testing:
                        confirmed_payloads.add(payload_str)
                    self.ptjsonlib.add_vulnerability(definition_contents.get("vulnerability"), vuln_request=dump["request"], vuln_response=dump["response"]) # TODO: If <args.keep_testing>, do not add same vulnerability to json x times. Kolikrát se to má přidávat?
                    if not self.keep_testing:
                        break

            if self.keep_testing:
                if is_vulnerable_during_keep_testing:
                    ptprinthelper.ptprint(f"Vulnerable to {vulnerability_description}", "VULN", condition=not self.use_json, colortext=False, clear_to_eol=True)
                else:
                    ptprinthelper.ptprint(f"Not vulnerable to {vulnerability_description}", "NOTVULN", condition=not self.use_json, colortext=False, clear_to_eol=True)

                if confirmed_payloads:
                    ptprinthelper.ptprint(f"Confirmed payloads:", "TITLE", condition=not self.use_json, colortext=True, clear_to_eol=True)
                    ptprinthelper.ptprint("\n".join(confirmed_payloads), "TEXT", condition=not self.use_json, colortext=False)

            else:
                if not is_vulnerable and definition_contents.get("payloads", []):
                    ptprinthelper.ptprint(f"Not vulnerable to {vulnerability_description}", "NOTVULN", condition=not self.use_json, colortext=False, clear_to_eol=True)

            if not definition_contents.get("payloads", []):
                ptprinthelper.ptprint(f"No payloads available to test for {vulnerability_description} vulnerability", "NOTVULN", condition=not self.use_json, colortext=False, clear_to_eol=True)

            ptprinthelper.ptprint(f" ", "", condition=not self.use_json, colortext=False, clear_to_eol=True)

        ptprinthelper.ptprint("Finished", "TITLE", condition=not self.use_json, clear_to_eol=True)
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

    def _send_payload(self, url: str, payload: str) -> requests.models.Response:
        """Send <payload> to <url>"""
        attack_headers = self.payload2dict({**self.http_headers}, payload) if self.IS_PLACEHOLDER and not self.placeholder_in_url() else {**self.http_headers}
        timeout = None #payload_dict["verify"][0] if payload_dict["type"] == "time" else 10

        if self.placeholder_in_url():
            response, dump = ptmisclib.load_url_from_web_or_temp(url[:self.URL_PLACEHOLDER_INDEX] + payload + url[self.URL_PLACEHOLDER_INDEX:], method=self.http_method, headers=attack_headers, proxies=self.proxy, data=self.request_data, redirects=False, verify=False, timeout=timeout, dump_response=True)
            return response, dump

        else: # placeholder elsewhere (in headers or post data)
            if self.http_method == "GET":
                #url = re.sub(fr"{self.parameter}=([\d\w]+)", fr"{self.parameter}={payload}", url)
                #response = requests.request(self.http_method, url, headers=headers, proxies=self.proxy, data=self.request_data, allow_redirects=False, verify=False, timeout=timeout)
                response, dump = ptmisclib.load_url_from_web_or_temp(url, method=self.http_method, headers=attack_headers, proxies=self.proxy, data=self.request_data, redirects=False, verify=False, timeout=timeout, dump_response=True)
                return response, dump

            if self.http_method == "POST":
                attack_data = self.payload2dict(self.str2dict(), payload) # TODO: Make it work for different content-types: eg. JSON, XML, ...
                response, dump = ptmisclib.load_url_from_web_or_temp(url, method=self.http_method, headers=attack_headers, proxies=self.proxy, data=attack_data, redirects=False, verify=False, timeout=timeout, dump_response=True)
                return response, dump

    def placeholder_in_url(self) -> bool:
        """Returns True if placeholder is present in URL."""
        return True if self.URL_PLACEHOLDER_INDEX != -1 else False

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
        """
        Extracts the placeholder from the URL.
        Returns a tuple containing:
            1. The URL with the placeholder removed.
            2. The position of the placeholder in the original URL.
        """
        placeholder_position: str = url.find(self.PLACEHOLDER_SYMBOL) # Returns -1 if not present
        parsed_url = urllib.parse.urlparse(url)
        pathless_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, "/", "", "", "")) # https://www.example.com/

        if placeholder_position != -1 and placeholder_position < len(pathless_url):
            self.ptjsonlib.end_error("Wrong placeholder usage (placeholder supported only in PATH)", self.use_json)
        if not re.match("https?", parsed_url.scheme):
            self.ptjsonlib.end_error(f"Missing or wrong scheme, did you mean https://{url}?", self.use_json)

        new_url = url.replace(self.PLACEHOLDER_SYMBOL, "")
        return new_url, placeholder_position

    def placeholder_exists(self, is_request_file: bool):
        """Check for presence of placeholder in <sys.argv>"""
        if is_request_file:
            return True  # Placeholder presence is already checked inside request_file parser.
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

    def load_url_or_request_file(self, args):
        """
        Load the URL or request data from the provided arguments.

        This method checks if a URL or a request file is specified in the
        provided arguments. If a URL is given, it extracts the URL and any
        relevant parameters. If a request file is specified, it parses the
        file to retrieve the URL, request data, HTTP method, and headers.
        The headers are updated in the instance's HTTP headers.

        Args:
            args: An object containing command-line arguments, which may include:
                - url: A string representing the target URL.
                - request_file: A path to a file containing request data.

        Returns:
            tuple: A tuple containing:
                - url (str): The loaded or parsed URL.
                - request_data (str): The associated request data.
                - http_method (str): The HTTP method to be used for the request.

        Raises:
            ValueError: If neither a URL nor a request file is provided in args.
        """
        if args.url:
            url, placeholder_position = self.get_placeholder_from_url(args.url)
            request_data = args.data or None
            http_method = "POST" if args.data else "GET"  # Default to "POST" if data is provided
            self.URL_PLACEHOLDER_INDEX = placeholder_position
            return url, request_data, http_method

        elif args.request_file:
            url, request_data, http_method, headers = RequestFileParser(self.PLACEHOLDER_SYMBOL, self.ptjsonlib, self.use_json).parse_request_file(os.path.abspath(os.path.join(os.path.dirname(__file__), args.request_file)))
            url, placeholder_position = self.get_placeholder_from_url(url)
            self.URL_PLACEHOLDER_INDEX = placeholder_position
            self.http_headers.update(headers)
            return url, request_data, http_method
        else:
            self.ptjsonlib.end_error("<URL> or <request-file> is required", self.use_json)

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

    def get_definitions(self, args, random_string: str):
        """Load Definitions. <random_string> is for replacing placeholders inside."""
        try:
            return DefinitionsLoader(use_json=args.json, random_string=random_string, verification_url=args.verification_url, technologies=args.technology).load_definitions(args.tests)
        except Exception as exc:
            self.ptjsonlib.end_error(f"{exc}, program will exit.", self.use_json)

    def _ensure_valid_param_or_placeholder_usage(self):
        if not self.parameter and not self.IS_PLACEHOLDER:
            self.ptjsonlib.end_error(f"You must specify a parameter to test or use the '{self.PLACEHOLDER_SYMBOL}' placeholder to indicate where the script should perform the test.", self.use_json)
        if self.parameter and self.IS_PLACEHOLDER:
            self.ptjsonlib.end_error(f"Cannot combine --parameter and placeholder '{self.PLACEHOLDER_SYMBOL}' together", self.use_json)

def get_help():
    return [
        {"description": ["ptinjector - Injection Vulnerabilities Framework"]},
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
            ["-l",  "--start-local-server",   "<port>",           "Start local server on <port> (default 5000)"], # TODO: ip address of verificatino url is localhost?
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

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        help = get_help()
        ptprinthelper.help_print(help, SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
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
