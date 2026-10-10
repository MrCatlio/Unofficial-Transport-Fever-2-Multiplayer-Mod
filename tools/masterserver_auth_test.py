"""Master-server ownership and source-rate-limit regression tests."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "netpunch"))
import masterserver


def request(server, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


masterserver._servers.clear()
masterserver._http_rates.clear()
server = ThreadingHTTPServer(("127.0.0.1", 0), masterserver.H)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    base = {"id": "owned", "name": "one", "code": "C", "players": 1, "max": 4}
    status, reply = request(server, "/announce", base)
    assert status == 200 and reply.get("token"), (status, reply)
    token = reply["token"]

    status, _ = request(server, "/announce", {**base, "name": "takeover"})
    assert status == 403, status
    status, _ = request(server, "/announce", {**base, "token": "wrong"})
    assert status == 403, status
    status, reply = request(server, "/announce", {**base, "name": "owner", "token": token})
    assert status == 200 and reply["token"] == token, (status, reply)

    status, _ = request(server, "/leave", {"id": "owned", "token": "wrong"})
    assert status == 403, status
    status, _ = request(server, "/leave", {"id": "owned", "token": token})
    assert status == 200, status

    masterserver._http_rates.clear()
    for i in range(masterserver.ANNOUNCE_PER_IP_MIN):
        status, _ = request(server, "/announce", {**base, "id": f"rate-{i}"})
        assert status == 200, (i, status)
    status, _ = request(server, "/announce", {**base, "id": "rate-over"})
    assert status == 429, status
finally:
    server.shutdown()
    server.server_close()
    thread.join(2)

print("PASS: announce ownership, leave ownership, and rate limits")
