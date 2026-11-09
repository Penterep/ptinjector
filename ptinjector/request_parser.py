import urllib.parse
import json
from ptlibs.parsers.http_request_parser import HttpRequestParser
import xml.etree.ElementTree as ET

# for parsing boundary (multipart content-type)
from email import policy
from email.parser import BytesParser
import email

class InjectionRequestParser(HttpRequestParser):
    def _parse_post_data(self, request_data: str, content_type: str) :

        if not request_data:
            return {}
        if content_type is None:
            return None

        


        # safe boundary if content-type is multipart
        original_content_type = content_type



        # getting content-type without parameters 
        content_type = content_type.split(";", 1)[0].strip().lower()


        if content_type == "application/json":

            try:
                return json.loads(request_data)
            except json.JSONDecodeError:
                self.ptjsonlib.end_error("Invalid JSON format in request data.", self.use_json)

        
        elif (content_type == "application/xml") or (content_type == "text/xml"):

            try:
                return ET.fromstring(request_data)
                
            except ET.ParseError:
                self.ptjsonlib.end_error(
                    "Invalid XML format in request data.",
                    self.use_json
                )
            
        
        elif content_type == "multipart/form-data":

            raw_message = (
                f"Content-Type: {original_content_type}\r\n"
                "MIME-Version: 1.0\r\n"
                "\r\n"
                f"{request_data}"
            ).encode("utf-8") # if multipart contains binary files like pictures or smth, this may corrupt the file s



            message = BytesParser(policy=policy.default).parsebytes(raw_message)

            return message
         
        elif content_type in ["application/x-www-form-urlencoded", "", None]:

            parsed_qs = urllib.parse.parse_qs(request_data)
            all_keys = set(key.split('=')[0] for key in request_data.split('&') if key)

            # Add missing keys to parsed_qs with empty string value
            for key in all_keys:
                if key not in parsed_qs:
                    parsed_qs[key] = ['']

            # Convert to regular dictionary, extracting the first value if the list contains one item
            parsed_qs_dict = {key: values[0] if values else '' for key, values in parsed_qs.items()}
            return parsed_qs_dict
            


        




        return


    def _reconstruct_post_data(self, post_parameters, content_type):
        content_type = (content_type or "").split(";", 1)[0].strip().lower()
        if content_type in ("application/xml", "text/xml"):
            return ET.tostring(post_parameters, encoding="unicode")

        if content_type == "multipart/form-data":
            raw_message = post_parameters.as_bytes()
            separator = b"\r\n\r\n"

            if separator not in raw_message:
                separator = b"\n\n"

            return raw_message.split(separator, 1)[1].decode("utf-8")

        return super()._reconstruct_post_data(
            post_parameters,
            content_type,
        )

    @staticmethod
    def get_value_based_on_parameter_path(data, parameter):

        if not parameter:
            raise ValueError("Parameter path cannot be empty")

        parts = parameter.split(".")
        current = data

        

        for part in parts :
            while isinstance(current, list):
                if not current:
                    raise ValueError(f"Parametr path not found: {parameter}")

                current = current[0]
            
            if not isinstance(current, dict) or part not in current:
                raise ValueError(f"Parameter path not found: {parameter}")

            current = current[part]

        return current



    @staticmethod
    def get_parameter_paths(parameter, data) -> list:

        if not parameter:
            raise ValueError(f"Parameter path not found {parameter}")


        parts = parameter.split(".")
        paths = []


        for part in range(1, len(parts) + 1):
            
            path = ".".join(parts[:part])
            paths.append(path)

        return paths

    @staticmethod
    def get_all_json_paths(data: dict, prefix: str = "") -> list:
        paths = []

        for key, value in data.items():
            while isinstance(value, list):
                if not value:
                    raise ValueError(f"Parameter path not found {value}")
                value = value[0]

            path = f"{prefix}.{key}" if prefix else key
            paths.append(path)


            if isinstance(value, dict):
                paths.extend(
                    InjectionRequestParser.get_all_json_paths(value, path)
                )

        return paths


    @staticmethod
    def get_all_multipart_parameter_names(message):
        names = []

        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue

            name = part.get_param("name", header = "content-disposition")

            if name is not None and name not in names:
                names.append(name)

        return names

    @staticmethod
    def get_all_xml_paths(element, prefix=""):
        path = f"{prefix}.{element.tag}" if prefix else element.tag
        paths = [path]
        seen_tags = set()

        for child in element:

            if child.tag in seen_tags:
                continue

            seen_tags.add(child.tag)
            paths.extend(
                InjectionRequestParser.get_all_xml_paths(child, path)
            )
            
        return paths
    
    @staticmethod
    def find_xml_element_by_path(parameter, data):
        if not parameter: 
            raise ValueError("Parameter path cannot be empty")
        
        parts = parameter.split(".")
        current = data


        if current.tag != parts[0]:
            raise IndexError(
            f"Could not find parameter {parameter}"
        )

        for part in parts[1:]:

                child = next (
                    (child for child in current if child.tag == part), None
                )
                if child is None:
                    raise IndexError(f"Could not find parameter {parameter}")
                current = child

        return current

    @staticmethod
    def replace_xml_value(data, parameter, new_value):
        if not parameter:
            raise IndexError(f"Could not find parameter path: {parameter}")
        
        element = InjectionRequestParser.find_xml_element_by_path(
            parameter,
            data,
        )
        for child in list(element):
            element.remove(child)
        element.text = new_value
        return data

            

    @staticmethod
    def replace_multipart_value(message, parameter, new_value):

        if not parameter:
            raise IndexError(f"Could not find parameter path: {parameter}")

        for part in message.iter_parts():
            name = part.get_param(
                "name",
                header="content-disposition",
            )
            if name == parameter:
                part.set_payload(new_value)
                return message

        raise IndexError(
            f"Could not find multipart parameter: {parameter}"
        )



    @staticmethod 
    def replace_json_value( data, parameter, new_value):
        if not parameter:
            raise IndexError(f"Could not find parameter path: {parameter}")
        parts = parameter.split(".")
        current = data

        for part in parts[:-1]:
            while isinstance(current, list):
                if not current: 
                    raise ValueError(f"Parameter path not found {parameter}")

                current = current[0]
            
            if not isinstance(current, dict) or part not in current:
                raise IndexError(f"Could not find parameter path: {parameter}")
            current = current[part]
        while isinstance(current, list):
            if not current:
                raise ValueError(
                    f"Parameter path not found: {parameter}"
                )
            current = current[0]

        last_part = parts[-1]
         
        if not isinstance(current, dict) or last_part not in current:
            raise IndexError(
                f"Could not find parameter path: {parameter}"
            )

        current[last_part] = new_value

                

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
        post_parameters = self._parse_post_data(request_data, content_type)
        # Update parameters
        original_content_type = content_type
        content_type = (content_type or "").split(";" , 1)[0].strip().lower()

        if content_type == "application/json":
            if not isinstance(parameter, str):
                raise TypeError("JSON parameter must be a string")

            self.replace_json_value(post_parameters, parameter, new_value)

        elif content_type in ("application/xml", "text/xml"):
            self.replace_xml_value(
                post_parameters, parameter, new_value
            )

        elif content_type == "multipart/form-data":

            self.replace_multipart_value(
                post_parameters,
                parameter,
                new_value,
            )


        elif content_type in ("application/x-www-form-urlencoded", ""):
            if isinstance(parameter, int):
                if parameter < len(get_parameters_list):
                    key, _ = get_parameters_list[parameter]
                    get_parameters_list[parameter] = (key, new_value)
                elif parameter < len(post_parameters) + len(get_parameters_list):
                    key = list(post_parameters.keys())[parameter - len(get_parameters_list)]
                    post_parameters[key] = new_value
                else:
                    raise IndexError("Parameter index '{parameter}' out of bounds.")
                    #self.ptjsonlib.end_error(f"Parameter index '{parameter}' out of bounds.", self.use_json)
            else:
                if parameter in dict(get_parameters_list):
                    get_parameters_dict = dict(get_parameters_list)
                    get_parameters_dict[parameter] = new_value
                    get_parameters_list[:] = list(get_parameters_dict.items())
                elif parameter in post_parameters:
                    post_parameters[parameter] = new_value
                else:
                    self.ptjsonlib.end_error(
                        f"Parameter '{parameter}' not found in GET or POST data.\n"
                        f"           Available GET parameters: [{', '.join(dict(get_parameters_list).keys())}]\n"
                        f"           Available POST parameters: [{', '.join(post_parameters.keys())}]",
                        self.use_json
                    )

        # Reconstruct URL with updated GET parameters
        updated_query = urllib.parse.urlencode(get_parameters_list, safe=self.placeholder)
        updated_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, updated_query, parsed_url.fragment))
        # Update request_data with modified POST data

        request_data = self._reconstruct_post_data(post_parameters, content_type)
 
        query_string = f"?{updated_query}" if updated_query else ""


            # Construct the updated HTTP request
        updated_http_request = f"{request_method} {parsed_url.path}{query_string} {self.HTTP_VERSION}" + "\n" + "\n".join(f"{key}: {value}" for key, value in request_headers.items()) + "\n\n" + request_data
        return updated_http_request


    def get_parameter_name_by_index(self, http_request, parameter_index: int):
        assert type(parameter_index) == int
        url, request_method, headers, request_data = self.parse_http_request(http_request)
        # Parse URL and parameters
        content_type = self.get_content_type(headers)
        content_type_normalized = (content_type or "").split(";", 1)[0].strip().lower()


        parsed_url = urllib.parse.urlparse(url)
        get_parameters_list: list = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values = True)
        post_parameters_dict: dict = self._parse_post_data(request_data, content_type)

        if content_type_normalized == "application/json":
            json_paths = self.get_all_json_paths(post_parameters_dict)
            post_parameter_index = parameter_index - len(get_parameters_list)

            if 0 <= post_parameter_index < len(json_paths):
                return json_paths[post_parameter_index]

            raise IndexError("Parameter index out of bounds")

        if content_type_normalized in ("application/xml", "text/xml"):
            xml_paths = self.get_all_xml_paths(post_parameters_dict)
            post_parameter_index = parameter_index - len(get_parameters_list)
            if 0 <= post_parameter_index < len(xml_paths):
                return xml_paths[post_parameter_index]

            raise IndexError("Parameter index out of bounds")

        if content_type_normalized == "multipart/form-data":
            names = self.get_all_multipart_parameter_names(
                post_parameters_dict
            )

            post_parameter_index = parameter_index - len(get_parameters_list)

            if 0 <= post_parameter_index < len(names):
                return names[post_parameter_index]

            raise IndexError("Parameter index out of bounds")

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

    def get_parameter_value(self, http_request, parameter):
        url, method, headers, data = self.parse_http_request(http_request)
        query = urllib.parse.urlparse(url).query
        get_parameters = urllib.parse.parse_qsl(
            query, keep_blank_values=True
        )
        content_type = self.get_content_type(headers)
        content_type_normalized = (content_type or "").split(";", 1)[0].strip().lower()
        post_parameters = self._parse_post_data(data, content_type)

        if content_type_normalized in ("application/xml", "text/xml"):
            element = self.find_xml_element_by_path(
                parameter,
                post_parameters,
            )
            return element.text or ""

        if content_type_normalized == "multipart/form-data":
            for part in post_parameters.iter_parts():
                name = part.get_param(
                    "name",
                    header="content-disposition",
                )

                if name == parameter:
                    return part.get_content()

            raise ValueError(f"Parameter {parameter!r} not found ")

        if "." in parameter:

            if content_type_normalized == "application/json"  :
                
                return self.get_value_based_on_parameter_path(
                    post_parameters,
                    parameter,
                    )

        if isinstance(parameter, str) and parameter.isdigit():
            parameter = int(parameter)

        if isinstance(parameter, int):
            parameters = get_parameters + list(post_parameters.items())
            if parameter < 0 or parameter >= len(parameters):
                raise IndexError("Parameter index out of bounds")
            return parameters[parameter][1]

        get_parameters = dict(get_parameters)
        if parameter in get_parameters:
            return get_parameters[parameter]
        if parameter in post_parameters:
            return post_parameters[parameter]

        raise ValueError(f"Parameter {parameter!r} not found")