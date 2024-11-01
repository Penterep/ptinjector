import json
import os

import time, datetime

class CodeAlreadyExistsError(Exception):
    """Raised when an already existing code is encountered"""
    pass

class Config:
    def __init__(self, config_path: str) -> None:
        self.config_path: str = config_path
        self.json_file_path: str = os.path.join(self.config_path, "codes.json")

    def make_files(self) -> None:
        if not os.path.exists(self.config_path):
            os.makedirs(self.config_path)
        if not os.path.exists(self.json_file_path):
            with open(self.json_file_path, 'w') as file:
                json.dump([], file, indent=4)

    def add_to_json(self, data: dict):
        json_data_list = self._read_json()
        for json_obj in json_data_list:
            for value in json_obj.values():
                if data["code"] == value:
                    raise CodeAlreadyExistsError

        json_data_list.append(data)
        self._write_to_json(json_data_list)

    def _write_to_json(self, content: list):
        """Write <content> to json file"""
        with open(self.json_file_path, "w") as file:
            #file.write(json.dumps(content, indent=4))
            json.dump(content, file, indent=4)

    def _read_json(self):
        """Return contents of codes.json"""
        try:
            with open(self.json_file_path, 'r') as file:
                data = json.load(file)
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Soubor {file} nebyl nalezen, vytvářím nový.")


    def get_json_file_path(self):
        return self.json_file_path
