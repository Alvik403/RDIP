import json
import os
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DATA_FILE = Path(os.getenv("DATA_FILE", ROOT / "data" / "data.json"))
PORT = int(os.getenv("PORT", "8080"))


def read_data():
    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"contracts": [], "payments": [], "history": []}


def write_data(data):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=DATA_FILE.parent, delete=False
    ) as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        temp_name = file.name
    os.replace(temp_name, DATA_FILE)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/data":
            self.send_json(read_data())
            return
        if self.path in ("/", "/index.html"):
            self.path = "/index.html"
            return super().do_GET()
        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path != "/api/data":
            self.send_error(404, "Not found")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length > 5_000_000:
                self.send_json({"error": "Слишком большой запрос"}, 413)
                return
            payload = json.loads(self.rfile.read(content_length))
            if not isinstance(payload, dict):
                raise ValueError
            contracts = payload.get("contracts")
            payments = payload.get("payments")
            history = payload.get("history", [])
            if (
                not isinstance(contracts, list)
                or not isinstance(payments, list)
                or not isinstance(history, list)
            ):
                raise ValueError
            write_data(
                {
                    "contracts": contracts,
                    "payments": payments,
                    "history": history[-50:],
                }
            )
            self.send_json({"ok": True})
        except (json.JSONDecodeError, ValueError):
            self.send_json({"error": "Некорректный формат данных"}, 400)

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")


if __name__ == "__main__":
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Реестр договоров: http://localhost:{PORT}")
    server.serve_forever()
