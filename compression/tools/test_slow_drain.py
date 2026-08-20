#!/usr/bin/env python3
"""Slow-client backpressure test for the recycling pause path.

The Test::Nginx suites prove the buffer cap's SAME-invocation
pause/reclaim/resume (t/06-buffers.t) — on a local socket everything
drains instantly, so the genuine cross-invocation pause (ship drained
nothing back, filter returns NGX_AGAIN, r->buffered keeps the writer
re-poking, the entry nomem block resumes later) is unreachable there.
This tool forces it: a small listen sndbuf, ``compression_buffers 2``,
a ~1 MB incompressible body, and a client that reads deliberately
slowly. Under that geometry the write filter cannot drain the busy
chain within an invocation, so the genuine pause MUST occur, and its
dedicated witness line ("resuming after drain" — logged ONLY on the
writer-driven re-entry, never on a same-invocation resume) MUST
appear, alongside the cap-pause and buf-reuse lines.

Oracles per coding:

* byte-exact decode of the fully drained body (pause/resume seams
  preserved the stream);
* error.log contains, at debug level: "buffer cap 2 reached",
  "reused output buf", and "resuming after drain".

Requires an nginx binary built ``--with-debug`` (the witnesses are
ngx_log_debug lines) with the compression module compiled in, plus
the ``zstd`` and ``brotli`` CLIs.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time

SIZE = 1_000_000
READ_CHUNK = 16384
READ_DELAY = 0.02

CODINGS = {
    "zstd": {"decode": ["zstd", "-d", "-q", "-c"], "loc": "zs"},
    "br":   {"decode": ["brotli", "-d", "-c"],     "loc": "br"},
}

WITNESSES = [
    "buffer cap 2 reached",
    "reused output buf",
    "resuming after drain",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--port", type=int, default=18192)
    return p.parse_args()


def fixture_bytes(n: int) -> bytes:
    buf = bytearray(n)
    x = (n * 2654435761) & 0xFFFFFFFF
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return bytes(buf)


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def slow_get(port: int, path: str, coding: str,
             timeout: float = 120.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    # SO_RCVBUF small too: without it the kernel happily buffers the
    # whole compressed response client-side and nginx never feels the
    # backpressure this test exists to create.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    req = (f"GET {path} HTTP/1.0\r\n"
           f"Host: t\r\nAccept-Encoding: {coding}\r\n\r\n")
    s.sendall(req.encode("latin1"))
    raw = b""
    while True:
        piece = s.recv(READ_CHUNK)
        if not piece:
            break
        raw += piece
        time.sleep(READ_DELAY)
    s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = head.decode("latin1", "replace")
    m = re.search(r"(?im)^content-encoding:\s*(\S+)", headers)
    got = m.group(1) if m else None
    if got != coding:
        raise RuntimeError(f"{path}: Content-Encoding {got!r}, "
                           f"wanted {coding!r}")
    return body


def decode(coding: str, blob: bytes) -> bytes:
    r = subprocess.run(CODINGS[coding]["decode"], input=blob,
                       capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"{coding} decode failed (truncated/corrupt stream): "
            + r.stderr.decode("utf-8", "replace").strip())
    return r.stdout


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True)
    if "compression" not in v.stderr:
        raise RuntimeError("nginx -V shows no compression module")
    if "--with-debug" not in v.stderr:
        raise RuntimeError("the witnesses are ngx_log_debug lines: "
                           "this tool needs an nginx built --with-debug")

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="compression-drain-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        html = root / "html" / "d"
        html.mkdir(parents=True)
        (html / "big").write_bytes(fixture_bytes(SIZE))

        locs = "".join(
            f"""        location /{c['loc']}/ {{
            alias {html}/;
            compression on;
            compression_order {name};
            compression_http_version 1.0;
            compression_buffers 2;
            compression_min_length 1;
            compression_types application/octet-stream;
            gzip_vary on;
        }}
""" for name, c in CODINGS.items())

        conf = root / "nginx.conf"
        conf.write_text(f"""worker_processes 1;
error_log {root}/logs/error.log debug;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    server {{
        listen 127.0.0.1:{args.port} sndbuf=16384;
{locs}    }}
}}
""", encoding="utf-8")

        proc = subprocess.Popen(
            [str(nginx), "-p", str(root), "-c", str(conf),
             "-g", "daemon off; master_process off;"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            wait_port(args.port)
            failures: list[str] = []
            expected = fixture_bytes(SIZE)

            for name, c in CODINGS.items():
                label = f"{name} slow-drain"
                try:
                    t0 = time.time()
                    body = slow_get(args.port, f"/{c['loc']}/big", name)
                    took = time.time() - t0
                    plain = decode(name, body)
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{label}: {exc}")
                    continue
                if plain != expected:
                    failures.append(
                        f"{label}: decoded {len(plain)}B, expected "
                        f"{len(expected)}B — the pause/resume seams "
                        f"corrupted or truncated the stream")
                    continue
                print(f"  {label}: {len(body)}B compressed drained in "
                      f"{took:.1f}s, decoded byte-exact")

            elog = (root / "logs" / "error.log").read_text(
                "utf-8", "replace")
            for w in WITNESSES:
                n = elog.count(w)
                if n == 0:
                    failures.append(
                        f"witness missing: {w!r} never logged — the "
                        f"genuine pause path did not run (geometry "
                        f"drift, or the entry nomem block changed)")
                else:
                    print(f"  witness: {w!r} x{n}")

            if failures:
                sys.stderr.write(f"slow-drain FAILED ({len(failures)}):\n")
                for f in failures:
                    sys.stderr.write(f"  - {f}\n")
                return 1

            print("OK: both codings survived forced backpressure with "
                  "the genuine cross-invocation pause witnessed")
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
