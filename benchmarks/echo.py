# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Keep the benchmark peer outside the process sampler's Python interpreter."""

from contextlib import contextmanager
import multiprocessing
import socket
import socketserver
import threading


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while data := self.request.recv(128 * 1024):
            self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


def serve(control):
    with control, Server(("127.0.0.1", 0), Echo) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            control.send(server.server_address[1])
            try:
                control.recv()
            except EOFError:
                pass  # Parent completion or failure closes the lifetime pipe.
        finally:
            server.shutdown()
            thread.join()


@contextmanager
def echo_server():
    # Spawn on every platform, so no guest descriptors or sampler state are inherited.
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    with parent, child:
        process = context.Process(target=serve, args=(child,), daemon=True)
        process.start()
        child.close()
        try:
            if not parent.poll(10):
                raise TimeoutError("echo server did not become ready")
            yield parent.recv()
        finally:
            parent.close()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
            code = process.exitcode
            process.close()
            if code != 0:
                raise RuntimeError(f"echo server exited with {code}")
