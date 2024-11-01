class RequestFileParser:
    def __init__(self, placeholder_char: str, ptjsonlib: object, use_json: bool):
        self.ptjsonlib = ptjsonlib
        self.use_json = use_json
        self.placeholder_char = placeholder_char
        self.host = None

    def parse_request_file(self, request_file):
        """Parse the provided request file.

        Args:
            request_file (str): The path to the request file.

        Returns:
            tuple: A tuple containing the URL, request data, HTTP method, and headers parsed from the request file.
        """
        try:
            headers, request_data = self._initialize_parsing_variables()
            method, path = self._parse_first_line(request_file)

            # Parse remaining lines for headers and body
            self._parse_lines(request_file, headers, request_data)

            # Construct URL based on host header
            url = self._construct_url(path)

            # Check for placeholder character in URL or request data
            self._check_placeholder(url, request_data, headers)
            request_data = ''.join(request_data)
            return url, request_data, method, headers

        except FileNotFoundError:
            self.ptjsonlib.end_error("Path to request file is not valid", self.use_json)
        except Exception as e:
            self.ptjsonlib.end_error(f"Error parsing request file ({e})", self.use_json)

    def _initialize_parsing_variables(self):
        """Initialize variables for parsing."""
        headers = {}
        request_data = []
        return headers, request_data

    def _parse_lines(self, request_file, headers, request_data):
        """Parse the lines of the request file.

        Args:
            request_file (str): The path to the request file.
            headers (dict): The headers to populate.
            request_data (list): The list to accumulate request data.
        """
        is_body = False
        with open(request_file, "r") as file:
            lines = file.readlines()[1:]  # Přeskočit první řádek

            for line in lines:
                line = line.strip()
                if is_body:
                    request_data.append(line)
                else:
                    is_body = self._parse_header(line, headers)


    def _parse_first_line(self, request_file):
        """Parse the first line of the request file.

        Args:
            request_file (str): The path to the request file.

        Returns:
            tuple: The HTTP method and path from the first line.

        Example:
            If the first line of the request file is:
                GET /search?query=foo HTTP/1.1
            The method would be 'GET' and the path would be '/search?query=foo'.
        """
        with open(request_file, "r") as file:
            first_line = file.readline().strip()
            line_parts = first_line.split()
            if len(line_parts) != 3:
                self.ptjsonlib.end_error("Provided file is not a valid request file", self.use_json)

            method, path = line_parts[0], line_parts[1]
            return method, path

    def _parse_header(self, line, headers):
        """Parse a header line.

        Args:
            line (str): The header line.
            headers (dict): The headers to populate.

        Returns:
            bool: True if the body starts; False otherwise.
        """
        line_parts = line.split(":", 1)
        if len(line_parts) == 2:
            headers[line_parts[0].strip()] = line_parts[1].strip()
            if line_parts[0].strip().lower() == "host":
                self.host = line_parts[1].strip()  # Store the host for URL construction
        elif len(line_parts) == 1 and not line_parts[0]:
            return True  # Empty line indicates the start of the body
        return False  # Still in headers

    def _construct_url(self, path):
        """Construct the URL from the path and host.

        Args:
            path (str): The path from the request file.

        Returns:
            str: The constructed URL.
        """
        if self.host:
            return f"https://{self.host}{path}"
        else:
            self.ptjsonlib.end_error("Host header is missing in the request file", self.use_json)


    def _check_placeholder(self, url, request_data, headers):
        """Check if the placeholder character is present in the URL, request data, or headers.

        Args:
            url (str): The URL to check.
            request_data (list): The request data to check.
            headers (dict): The headers to check.
        """
        # Check if placeholder in URL
        if self.placeholder_char in url:
            return

        # Check if placeholder in  request data
        if self.placeholder_char in ''.join(request_data):
            return

        # Check if placeholder in headers
        for header_key, header_value in headers.items():
            if self.placeholder_char in header_key or self.placeholder_char in header_value:
                return

        self.ptjsonlib.end_error("Placeholder character is required in URL, request data, or headers", self.use_json)