#!/usr/bin/env python3

import os
import socketserver
from http.server import SimpleHTTPRequestHandler

import daemon

import socket

# find a free port
sock = socket.socket()
sock.bind(("", 0))
port = sock.getsockname()[1]
sock.close()

handler = SimpleHTTPRequestHandler
socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
daemon_context = daemon.DaemonContext()
daemon_context.files_preserve = [httpd.fileno()]

with daemon_context:
    os.chdir("/tmp/")
    httpd.handle_request()
