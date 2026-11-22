#!/usr/bin/env python3
"""fake-ntfy is a small ntfy server for contrib/ansible/test/ci.sh.

    fake-ntfy.py CERT KEY PORT ANSWER_TOPIC

It listens with TLS on 127.0.0.1:PORT. It takes each message that the
broker publishes (POST /), and answers as ntfy does. When a message has
the button "once", it presses it a second later: it sends the body of
that button to the subscribers of ANSWER_TOPIC (GET /TOPIC/json). So
each request of the broker is approved once, with no person. It is a
test program only: never use it with a real broker.
"""

import json
import secrets
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERT, KEY, PORT, ANSWER = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

lock = threading.Condition()
answers = []  # the events of the answer topic, in order


def new_id():
    return secrets.token_hex(6)


def press_later(body):
    time.sleep(1)
    with lock:
        answers.append({"id": new_id(), "time": int(time.time()), "event": "message", "topic": ANSWER, "message": body})
        lock.notify_all()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("fake-ntfy: " + (fmt % args) + "\n")

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        msg = json.loads(self.rfile.read(size))
        for action in msg.get("actions") or []:
            if json.loads(action.get("body", "{}")).get("action") == "once":
                threading.Thread(target=press_later, args=(action["body"],), daemon=True).start()
        out = json.dumps({"id": new_id(), "time": int(time.time()), "event": "message", "topic": msg["topic"]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out.encode())

    def do_GET(self):
        if self.path.split("?")[0] != "/" + ANSWER + "/json":
            self.send_error(404)
            return
        since = self.path.partition("since=")[2]
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        self.line({"id": new_id(), "time": int(time.time()), "event": "open", "topic": ANSWER})
        with lock:
            if since.isdigit():
                sent = len([a for a in answers if a["time"] < int(since)])
            else:
                ids = [a["id"] for a in answers]
                sent = ids.index(since) + 1 if since in ids else len(answers)
        while True:
            with lock:
                lock.wait_for(lambda: len(answers) > sent, timeout=20)
                new = answers[sent:]
                sent = len(answers)
            for ev in new:
                self.line(ev)
            if not new:
                self.line({"id": new_id(), "time": int(time.time()), "event": "keepalive", "topic": ANSWER})

    def line(self, ev):
        self.wfile.write((json.dumps(ev) + "\n").encode())
        self.wfile.flush()


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.daemon_threads = True
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
