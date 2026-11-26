#!/usr/bin/env python3
"""A tiny fake Telegram Bot API for contrib/pullgate/test/ci.sh.

A copy of test/units/faketg.py of pullgate v0.4.0
(https://github.com/code6x/pullgate, Apache License 2.0, as nodkey).

It listens on 127.0.0.1:PORT. It appends the name of each method it gets
to LOG, one per line. It never prints a request path, so the test token
never shows.

With --tap TEXTS it also:
- appends the text of each sendMessage to TEXTS, as one JSON string per
  line, so a test can wait for "Applied";
- taps the Apply button of each question it gets, two seconds later, as
  the owner (user 4242) in the chat 4242, through getUpdates;
- on POST /test/say with {"text": "..."}, sends that text as a message of
  the owner in the chat, through getUpdates (the pairing code).

Usage: python3 -I faketg.py PORT LOG [--tap TEXTS]
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
TEXTS = None
if len(sys.argv) == 5 and sys.argv[3] == "--tap":
    TEXTS = sys.argv[4]
elif len(sys.argv) != 3:
    sys.exit("usage: faketg.py PORT LOG [--tap TEXTS]")
CHAT = 4242
OWNER = 4242
# The listener saves a question after sendMessage returns. A tap that came
# before that would find no question, so the tap waits a little.
TAP_DELAY = 2.0

lock = threading.Lock()
state = {"next_msg": 1, "next_update": 1, "updates": []}


def apply_button(req):
    """The callback data of the Apply button of a question, or None."""
    rows = (req.get("reply_markup") or {}).get("inline_keyboard") or []
    for row in rows:
        for b in row:
            data = b.get("callback_data", "")
            if data.startswith("a:"):
                return data
    return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        if self.path == "/test/say":
            with lock:
                state["updates"].append({
                    "at": time.monotonic(),
                    "update": {
                        "update_id": state["next_update"],
                        "message": {
                            "message_id": 100000 + state["next_update"],
                            "from": {"id": OWNER},
                            "chat": {"id": CHAT, "type": "private"},
                            "text": str(req.get("text", "")),
                        },
                    },
                })
                state["next_update"] += 1
            self.send_response(204)
            self.end_headers()
            return
        method = self.path.rsplit("/", 1)[-1]
        with lock:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(method + "\n")
        if method == "getMe":
            result = {"id": 1, "is_bot": True, "username": "example_bot"}
        elif method == "getUpdates":
            result = self.updates(int(req.get("offset") or 0))
        elif method == "sendMessage":
            text = str(req.get("text", ""))
            with lock:
                mid = state["next_msg"]
                state["next_msg"] += 1
                if TEXTS is not None:
                    with open(TEXTS, "a", encoding="utf-8") as f:
                        f.write(json.dumps(text, ensure_ascii=False) + "\n")
                    data = apply_button(req)
                    if data is not None:
                        state["updates"].append({
                            "at": time.monotonic() + TAP_DELAY,
                            "update": {
                                "update_id": state["next_update"],
                                "callback_query": {
                                    "id": "tap-%d" % mid,
                                    "from": {"id": OWNER},
                                    # The text that this fake gives back, so
                                    # the listener's text hash matches.
                                    "message": {"message_id": mid, "chat": {"id": CHAT}, "text": text},
                                    "data": data,
                                },
                            },
                        })
                        state["next_update"] += 1
            result = {"message_id": mid, "chat": {"id": CHAT}, "text": text if TEXTS is not None else ""}
        else:
            result = True
        body = json.dumps({"ok": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def updates(self, offset):
        """The updates from offset on that are due. Waits up to a second."""
        end = time.monotonic() + 1
        while True:
            now = time.monotonic()
            with lock:
                state["updates"] = [u for u in state["updates"] if u["update"]["update_id"] >= offset]
                due = [u["update"] for u in state["updates"] if u["at"] <= now]
            if due or now >= end:
                return due
            time.sleep(0.1)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
