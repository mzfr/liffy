#!/usr/bin/env python3

import os
import socketserver
from http.server import SimpleHTTPRequestHandler

import daemon

handler = SimpleHTTPRequestHandler
socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("0.0.0.0", 8080), handler)
daemon_context = daemon.DaemonContext()
daemon_context.files_preserve = [httpd.fileno()]

with daemon_context:
    os.chdir("/tmp/")
    httpd.handle_request()
