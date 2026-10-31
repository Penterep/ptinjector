import urllib.parse
from ptlibs.parsers.http_request_parser import HttpRequestParser

class InjectionRequestParser(HttpRequestParser):
    def _update_parameter_value(self, http_request: str, parameter: str | int, new_value: str) -> str:
        """
        Updates the specified parameter in GET and POST data with a new value.
        Handles both parameter name (string) and index (int).

        Args:
            http_request (str): The original HTTP request.
            parameter (str | int): The name or index of the parameter to replace.
            new_value (str): The new value to insert for the parameter.

        Returns:
            str: The updated HTTP request string.

        Raises:
            ValueError: If the parameter is not found by name or index in both GET and POST data.
        """
        request_url, request_method, request_headers, request_data = self.parse_http_request(http_request=http_request)
        content_type = next((value for key, value in request_headers.items() if key.lower() == "content-type"), None)

        if isinstance(parameter, str) and parameter.isdigit():
            parameter = int(parameter)
        # Parse URL and parameters
        parsed_url = urllib.parse.urlparse(request_url)
        get_parameters_list: list = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)
        post_parameters_dict: dict = self._parse_post_data(request_data, content_type)
        # Update parameters
        if isinstance(parameter, int):
            if parameter < len(get_parameters_list):
                key, _ = get_parameters_list[parameter]
                get_parameters_list[parameter] = (key, new_value)
            elif parameter < len(post_parameters_dict) + len(get_parameters_list):
                key = list(post_parameters_dict.keys())[parameter - len(get_parameters_list)]
                post_parameters_dict[key] = new_value
            else:
                raise IndexError("Parameter index '{parameter}' out of bounds.")
                #self.ptjsonlib.end_error(f"Parameter index '{parameter}' out of bounds.", self.use_json)
        else:
            if parameter in dict(get_parameters_list):
                get_parameters_dict = dict(get_parameters_list)
                get_parameters_dict[parameter] = new_value
                get_parameters_list[:] = list(get_parameters_dict.items())
            elif parameter in post_parameters_dict:
                post_parameters_dict[parameter] = new_value
            else:
                self.ptjsonlib.end_error(
                    f"Parameter '{parameter}' not found in GET or POST data.\n"
                    f"           Available GET parameters: [{', '.join(dict(get_parameters_list).keys())}]\n"
                    f"           Available POST parameters: [{', '.join(post_parameters_dict.keys())}]",
                    self.use_json
                )

        # Reconstruct URL with updated GET parameters
        updated_query = urllib.parse.urlencode(get_parameters_list, safe=self.placeholder)
        updated_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, updated_query, parsed_url.fragment))

        # Update request_data with modified POST data
        request_data = self._reconstruct_post_data(post_parameters_dict, content_type)

        query_string = f"?{updated_query}" if updated_query else ""


        # Construct the updated HTTP request
        updated_http_request = f"{request_method} {parsed_url.path}{query_string} {self.HTTP_VERSION}" + "\n" + "\n".join(f"{key}: {value}" for key, value in request_headers.items()) + "\n\n" + request_data
        return updated_http_request


    def get_parameter_name_by_index(self, http_request, parameter_index: int):
        assert type(parameter_index) == int
        url, request_method, headers, request_data = self.parse_http_request(http_request)
        # Parse URL and parameters
        content_type = self.get_content_type(headers)
        parsed_url = urllib.parse.urlparse(url)
        get_parameters_list: list = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values = True)
        post_parameters_dict: dict = self._parse_post_data(request_data, content_type)


        if parameter_index < len(get_parameters_list):
            key, _ = get_parameters_list[parameter_index]
            return key
        elif parameter_index < len(post_parameters_dict) + len(get_parameters_list):
            key = list(post_parameters_dict.keys())[parameter_index - len(get_parameters_list)]
            return key
        else:
            raise IndexError("Parameter index '{parameter_index}' out of bounds.")


    def has_query_params(self, http_request: str):
        http_request = self._load_and_validate_http_request(http_request)
        url, method, headers, request_data = self.parse_http_request(http_request)
        parsed_query: dict = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values = True)
        return bool(parsed_query)