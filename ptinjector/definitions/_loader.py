import re
import os
import json

from ptlibs import ptprinthelper

from typing import Optional, List

class DefinitionsLoader:
    def __init__(self, use_json: bool = False, random_string: str = None, verification_url: str = None, technologies: list = []):
        self.use_json = use_json
        self.RANDOM_CODE: str = random_string
        self.verification_url: str = verification_url
        self.technologies: list = [technology.lower() for technology in technologies if technologies]
        self.folder_path: str = os.path.dirname(__file__)
        self.available_definition_files: list = [f for f in sorted(os.listdir(self.folder_path)) if (os.path.join(self.folder_path, f) and (not f.startswith("_") and f.endswith(".json")))]

    def load_definitions(self, specified_tests: Optional[List[str]]) -> dict:
        """
        Load and validate JSON definitions from available files.

        This method reads through the available definition files, validates their
        structure and values, replaces any placeholders within the contents, and
        loads the valid definitions into a dictionary. If no valid definitions are
        found, an exception is raised.

        Args:
            specified_tests (Optional[List[str]], optional): A list of specific tests to load.
                                                            If None, all available tests will be loaded.
                                                            Defaults to None.

        Returns:
            dict: A dictionary containing the loaded and validated definitions.

        Raises:
            Exception: If no valid definitions are available.
        """

        loaded_definitions: dict = {}
        skipped_tests: list = []
        for definition_filename in self.available_definition_files:
            definition_name: str = definition_filename .split(".json")[0]

            # Determine if the current definition should be processed
            if specified_tests is None or definition_name in specified_tests or self.matches_specified_test(definition_name, specified_tests):
                definition_contents = self._read_definition_file(definition_filename)
                if self.validate_json_structure_and_values(definition_contents, definition_filename):
                    # Replace placeholders and add to loaded definitions
                    definition_contents = self.process_payloads_and_replace_placeholders(definition_contents)
                    if definition_contents["payloads"]:
                        loaded_definitions.update({definition_name : definition_contents})
                    else:
                        skipped_tests.append(definition_filename.split(".json")[0].replace("_", " ").upper())

        #if skipped_tests:
        #    ptprinthelper.ptprint(f"Skipped tests: {', '.join(skipped_tests)} - definitions do not contain any valid payloads.", "WARNING", condition=not self.use_json)

        if loaded_definitions:
            ptprinthelper.ptprint(f" ", "TEXT", condition=not self.use_json)
            return loaded_definitions
        else:
            raise Exception("No definitions were loaded")

    def matches_specified_test(self, definition_filename: str, specified_tests: list):
        """Returns True if <definition_filename> matches any of the <specified_tests>"""
        return True if [test for test in specified_tests if definition_filename.startswith(f'{test}_')] else False

    def _read_definition_file(self, definition_filename: str, ) -> dict|None:
        try:
            file_path: str = os.path.join(self.folder_path, definition_filename )
            with open(file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            pass #print(f"Error decoding JSON in '{definition_file}'. Check the file structure.")
            return None

    def validate_json_structure_and_values(self, json_data: dict, definition_filename) -> bool:
        """
        Validates the structure of the provided JSON data.

        This function checks if the provided JSON data has the required keys
        ("description" and "payloads") and that these keys contain values of the
        correct type.

        Args:
            json_data (dict): The JSON data to validate.
            definition_filename (str): Filename of loaded json_data


        Returns:
            bool: True if the JSON data is valid, False otherwise.
        """
        required_top_level_keys = ["description", "payloads"]
        # Check top-level keys and their types
        if not json_data or not all(key in json_data for key in required_top_level_keys) or not isinstance(json_data["description"], str) or not isinstance(json_data["payloads"], list):
            #ptprinthelper.ptprint(f"Warning: File {definition_filename} is not of a valid structure. Please ensure that the file follows the correct structure and contains valid values.", "WARNING", condition=not self.use_json)
            return False
        else:
            return True


    def process_payloads_and_replace_placeholders (self, json_data: dict):
        """Replaces found placeholders inside definition files. Also converts any int to str."""
        def replace_with_slice(match):
            # Extract the number from the match
            if match.group().upper() == "[URL]":
                if self.verification_url:
                    return self.verification_url + f"/save/{self.RANDOM_CODE}"
                else:
                    return "[URL]"
            else:
                num = int(match.group(1))  # Convert captured group to integer
                # Return my_string sliced to the length of num
                return self.RANDOM_CODE[:num]

        # Matches [RANDOM_(digits)] or [URL|url]
        placeholders_re_pattern = re.compile(r"\[RANDOM_(\d+)\]|\[(URL|url)\]", re.VERBOSE)
        required_payload_keys = ["payload", "verify", "type"]
        invalid_payloads = []

        for payload_index, payload_object in reversed(list(enumerate(json_data["payloads"]))):
            # Check each item in "payloads" for required keys and non-empty values before processing.
            if not all(key in payload_object and payload_object.get(key) for key in required_payload_keys) and not all(payload_object.get(key) for key in required_payload_keys):
                invalid_payloads.append(payload_object)
                json_data["payloads"].pop(payload_index)
                continue

            # Convert payload and verify keys to lists if they are strings
            payload_object["payload"] = [payload_object["payload"]] if isinstance(payload_object["payload"], str) else payload_object["payload"]
            payload_object["verify"]  = [payload_object["verify"]] if isinstance(payload_object["verify"], (str, int)) else payload_object["verify"]

            # Convert verify values to strings
            payload_object["verify"] = [str(value) for value in payload_object["verify"]]

            # Check if payload should be skipped based on technology
            if self.technologies:
                if payload_object.get("technology") and payload_object["technology"].lower() not in self.technologies:
                    #print(f"Skipping payload due to unmatched technology: {payload_object}")
                    json_data["payloads"].pop(payload_index)
                    continue

            # Check if payload should be skipped based on verification URL
            if not self.verification_url and payload_object["type"].lower() == "request":
                #print(f"Skipping payload due to missing verification URL: {payload_object}")
                json_data["payloads"].pop(payload_index)
                continue

            # REPLACE PLACEHOLDERS
            payload_object["verify"] = [re.sub(placeholders_re_pattern, replace_with_slice, text) for text in payload_object["verify"]]
            payload_object["payload"] = [re.sub(placeholders_re_pattern, replace_with_slice, payload) for payload in payload_object["payload"]]


        if invalid_payloads and json_data["payloads"]:
            ptprinthelper.ptprint(f"Found invalid payloads, they will be skipped.", "WARNING", condition=not self.use_json)

        return json_data

    def get_definitions_help(self):
        """Builds and returns help rows"""
        help_rows = []
        for file_name in self.available_definition_files:
            try:
                row = ["", "", f' {file_name.rsplit(".json")[0].split()[0]}', f'  Test for {self._read_definition_file(file_name).get("description")}']
            except:
                row = ["", "", f' {file_name.rsplit(".json")[0].split()[0]}', f'  Test for {file_name.rsplit(".json")[0].split()[0]}']
            finally:
                help_rows.append(row)

        return sorted(help_rows, key=lambda x: x[2])