import argparse
import os
import time, datetime
import threading
import json
import tempfile

from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

from config import Config, CodeAlreadyExistsError


class MyAPI:
    def __init__(self, host, port):
        self.app = Flask(__name__)
        self.config = Config(os.path.join(os.path.expanduser('~'), ".ptinjector"))
        self.config.make_files()
        self.lock = threading.Lock()
        self.setup_routes()
        self.host = host if host else None
        self.port = port
        scheduler = BackgroundScheduler()
        scheduler.add_job(self._delete_expired_codes, 'interval', seconds=10)
        scheduler.start()

    def run(self):
        # Start flask server
        with open(os.path.join(tempfile.gettempdir(), "flask_ready.txt"), 'w') as f:
            f.write('ready')
        self.app.run(debug=False, host=self.host, port=self.port)

    def setup_routes(self):
        """Define API Endpoints"""

        @self.app.route('/save/<string:code>', methods=['GET'])
        def save_code(code):
            #if len(code) != 16:
            #    return jsonify({"error": "bad length of code"}), 400
            new_code = {"code": code, "created":  datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')}
            try:
                self.config.add_to_json(new_code)
            except CodeAlreadyExistsError:
                return jsonify({"msg": "Code already exists"}), 403

            return jsonify({"msg": "Code saved successfully"}), 200

        @self.app.route('/verify/<string:code>', methods=['GET'])
        def verify_code(code):
            with self.lock, open(self.config.json_file_path, "r+") as file:
                data = json.load(file)
                result = [json_obj for json_obj in data if json_obj["code"] == code]
            return jsonify({"msg": "true" if len(result) else "false"})

        @self.app.errorhandler(404)
        def page_not_found(e):
            return jsonify({"error": "Not implemented"})

    def _delete_expired_codes(self):
        """This method is processed by BackgroundScheduler"""
        ten_minutes_ago = datetime.datetime.now() - datetime.timedelta(minutes=10)
        with self.lock, open(self.config.json_file_path, "r+") as file:
            data = json.load(file)
            result = [json_obj for json_obj in data if datetime.datetime.strptime(json_obj.get("created"), '%Y-%m-%d %H:%M:%S') > ten_minutes_ago]
            file.seek(0)
            json.dump(result, file, indent=4)
            file.truncate()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str)
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    app = MyAPI(host=args.host, port=args.port)
    app.run()

