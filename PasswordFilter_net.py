from base64 import b64decode
from functools import partial
from http.server import SimpleHTTPRequestHandler, test
from io import BytesIO
from tempfile import mkdtemp


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def list_directory(self, path):
        return BytesIO()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_POST(self):
        if not self.headers.get("Authorization", False):
            self.do_AUTHHEAD()
            self.wfile.write(b"401 Unauthorized")
        else:
            auth = self.headers.get("Authorization", "")

            try:
                print(b64decode(bytes(auth.replace("Basic ", ""), "utf8")).decode())
            except Exception:
                print(f"Auth decode error {auth}")

            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get("Authorization").encode())
            self.wfile.write(b"401 Unauthorized")

    def do_GET(self):
        self.do_AUTHHEAD()
        self.wfile.write(b"401 Unauthorized")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--cgi", action="store_true", help="Run as CGI Server")
    parser.add_argument(
        "--bind",
        "-b",
        metavar="ADDRESS",
        default="127.0.0.1",
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "port",
        action="store",
        default=80,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 80]",
    )

    temp_dir = mkdtemp(prefix="pre_", suffix="_suf")
    print(f"Using {temp_dir}")

    args = parser.parse_args()
    handler_class = partial(
        AuthHTTPRequestHandler,
        directory=temp_dir,
    )
    test(HandlerClass=handler_class, port=args.port, bind=args.bind)
