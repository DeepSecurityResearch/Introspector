# Introspector.py 

import argparse
import json
import os
import random
import string
import socket
import threading
import time
import ipaddress
import atexit
import sys
from datetime import datetime

from flask import Flask, request, Response, send_file, jsonify
from werkzeug.serving import make_server, WSGIRequestHandler  # <-- MODIFICADO: agregado WSGIRequestHandler
from werkzeug.datastructures import Headers  

import core_state as st
from services import (
    init_geoip,
    init_persist,
    parse_request_data,
    log_to_console,
    store_log_in_memory,
    _build_response_raw,
    log_headers_to_file,
    get_local_ip,
    whois_cached,
    hosted_upload,
    hosted_unload,
    hosted_list,
    start_dns_listener,   
)

from admin_app import start_admin_server

app = Flask(__name__)

class RawResponse(Response):
    """
    Custom Response que da control TOTAL sobre los headers.
    No agrega Content-Length, Connection, ni ningún header automático.
    """
    default_mimetype = None  # Evita Content-Type automático
    automatically_set_content_length = False
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.automatically_set_content_length = False
    
    def get_wsgi_headers(self, environ):
        """
        Retorna SOLO los headers que el usuario definió explícitamente.
        No filtra nada, no agrega nada.
        """
        # NO llamamos a super() - eso agregaría headers automáticos
        # Retornamos solo lo que está en self.headers
        return Headers(list(self.headers))


# ============================================================
# FIX: Custom HTTP Handler para eliminar headers automáticos
# ============================================================
class RawWSGIRequestHandler(WSGIRequestHandler):
    """
    Handler HTTP personalizado que NO agrega headers automáticos (Server, Date).
    Esto permite control total sobre los headers en Response Designer.
    """
    
    # Elimina el header "Server: Werkzeug/x.x.x Python/x.x.x"
    def version_string(self):
        return ""
    
    # Sobrescribe send_response para NO enviar Server ni Date automáticamente
    def send_response(self, code, message=None):
        """Send response without automatic Server/Date headers."""
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ""
        
        if self.request_version != "HTTP/0.9":
            # Envía solo la línea de status, SIN headers automáticos
            self._headers_buffer = []
            self._headers_buffer.append(
                f"{self.protocol_version} {code} {message}\r\n".encode("latin-1")
            )
    
    # Silenciar logs de Werkzeug (opcional, ya se hace con logging)
    def log_request(self, code="-", size="-"):
        pass


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "loaded": len(st.LOGS)})


@app.route("/api/response-template/<template_name>", methods=["GET"])
def get_response_template(template_name):
    try:
        with open('response_templates.json', 'r') as f:
            templates = json.load(f)
        if template_name in templates:
            return jsonify(templates[template_name])
        else:
            return jsonify({"error": "Template not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def handle_response_designer_request(path, log):
    """Handle requests to /design/* paths"""
    # Remove 'design/' prefix
    request_path = path[7:] if path.startswith('design/') else path
    
    with st.RESPONSE_DESIGNER_LOCK:
        designed_response = st.RESPONSE_DESIGNER_PATHS.get(f"design/{request_path}")
    
    if designed_response:
        try:
            # Parse headers from the stored headers string
            headers_str = designed_response['headers']
            resp_headers = {}
            status_code = 200
            
            # Debug: Log what we received
            if st.VERBOSE_LEVEL >= 2:
                print(f"[DEBUG] Headers string: {repr(headers_str)}")
            
            # Parse HTTP headers (normalize line endings first)
            if headers_str:
                headers_str = headers_str.replace('\r\n', '\n').replace('\r', '\n')
                lines = headers_str.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Handle status line (HTTP/1.1 200 OK)
                    if line.startswith('HTTP/'):
                        parts = line.split(' ', 2)
                        if len(parts) >= 2:
                            try:
                                status_code = int(parts[1])
                            except ValueError:
                                status_code = 200
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        resp_headers[key.strip()] = value.strip()
                        
                        if st.VERBOSE_LEVEL >= 2:
                            print(f"[DEBUG] Parsed header: {key.strip()} = {value.strip()}")
            
            # Create response
            body = designed_response['body']
            
            # Set headers and content type
            content_type = None
            if 'content-type' in resp_headers:
                content_type = resp_headers['content-type']
                del resp_headers['content-type']
            
            # Build headers dict
            headers = resp_headers.copy()
            if content_type:
                headers['content-type'] = content_type
            
            # Create response and clear default headers (Server, Date, etc)
            resp = RawResponse(body, status=status_code)
            resp.headers.clear()
            
            # Set custom headers
            for key, value in headers.items():
                resp.headers[key] = value
            
            # Debug: Log final response
            if st.VERBOSE_LEVEL >= 2:
                print(f"[DEBUG] Response status: {status_code}")
                print(f"[DEBUG] Response content-type: {content_type}")
                print(f"[DEBUG] Response headers: {dict(resp.headers)}")
            
            # Log the request
            if log:
                log["event"] = "response_designer"
                log["designer_path"] = request_path
                log["response_name"] = designed_response.get('name', 'Unknown')
                log["response_raw"] = _build_response_raw(status_code, headers, body)
                log_to_console(log)
                store_log_in_memory(log)
            
            return resp
            
        except Exception as e:
            if st.VERBOSE_LEVEL >= 2:
                print(f"{st.C['RED']}[!] Error in response designer: {e}{st.C['RESET']}")
            return Response("Internal Server Error", status=500)
    
    return None


def handle_redirect_detection(path, log):
    # Check if follow-redirect scanner is enabled
    if not st.SCAN_MODULES.get("follow-redirect", {}).get("enabled", False):
        return None
    
    redirect_url = None
    if path == "absolute":
        redirect_url = "/roboted.txt"
    elif path == "favicon-followed":
        redirect_url = "/index.ico"

    if redirect_url and log:
        log["event"] = "open_redirect"
        log["redirect_to"] = redirect_url
        log["headers"]["Redirect-To"] = redirect_url

    status_code = None
    resp_headers = {}
    body = None

    if path == "robots.txt":
        log_headers_to_file(request, path)
        status_code = 302
        resp_headers["Location"] = "/absolute"
        body = "<!doctype html><title>Redirecting...</title>"

    if path == "favicon.ico":
        log_headers_to_file(request, path)
        status_code = 302
        resp_headers["Location"] = "/favicon-followed"
        body = "<!doctype html><title>Redirecting...</title>"

    if path == "absolute" and redirect_url:
        status_code = 302
        resp_headers["Location"] = redirect_url
        body = "<!doctype html><title>Redirecting...</title>"

    if path == "favicon-followed" and redirect_url:
        status_code = 302
        resp_headers["Location"] = redirect_url
        body = "<!doctype html><title>Redirecting...</title>"

    if status_code:
        return status_code, resp_headers, body
    return None


def handle_delayer_detection(path, log):
    # Check if delayer module is enabled
    if not st.SCAN_MODULES.get("delayer", {}).get("enabled", False):
        return None
    
    # Check if path starts with delayresponse
    if path.startswith("delayresponse"):
        return process_delay_request(path, log)
    
    return None


def process_delay_request(path, log):
    try:
        # Use Flask's built-in query parameter parsing
        delay_time = request.args.get('t', 20, type=int)
        
        # Validate time range
        if delay_time is None or delay_time < 1:
            delay_time = 1
        elif delay_time > 300:  # max 5 minutes
            delay_time = 300
        
        # Log delay request
        log["event"] = "delayer_request"
        log["delay_time"] = delay_time
        
        # Sleep for the specified time
        import time
        time.sleep(delay_time)
        
        # Always return 200 OK with delay message
        status_code = 200
        resp_headers = {}
        body = f"Delayed {delay_time} seconds"
        
        return status_code, resp_headers, body
        
    except Exception as e:
        if st.VERBOSE_LEVEL >= 2:
            print(f"{st.C['RED']}[!] Error in delayer: {e}{st.C['RESET']}")
        return None


@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE"])
def catch_all(path):
    # Skip logging for admin paths (web UI and APIs)
    admin_paths = [f"/{st.LOG_PATH}", "/api/"]
    is_admin = any(path.startswith(admin_path) for admin_path in admin_paths)
    
    log = None
    if not is_admin:
        log = parse_request_data(request)
        if not log:
            return "Error", 500

    status_code = 200
    resp_headers = {}
    body = "Logged" if not is_admin else "Admin response"

    # Check for response designer requests FIRST (before other modules)
    designer_result = handle_response_designer_request(path, log)
    if designer_result:
        return designer_result

    if path.startswith(f"{st.HOSTED_PREFIX}/"):
        tail = path[len(st.HOSTED_PREFIX) + 1:]
        base, ext = os.path.splitext(tail)
        hid = base.strip()
        if hid:
            with st.HOSTED_LOCK:
                meta = st.HOSTED_FILES.get(hid)
            if meta:
                fp = meta.get("path")
                try:
                    if fp and os.path.isfile(fp):
                        resp = send_file(fp)
                        if log:
                            log["response_raw"] = ""
                            log_to_console(log)
                            store_log_in_memory(log)
                        return resp
                except Exception:
                    pass
        status_code = 404
        body = "Not Found"

        
    if path.startswith("run/"):
        name = path[4:]
        if name in st.RUN_PATHS:
            entry = st.RUN_PATHS[name]
            return Response(entry["content"], mimetype=entry["content_type"])

    if path.startswith(f"{st.REDIRECT_PREFIX}/"):
        redirect_id = path[len(st.REDIRECT_PREFIX) + 1:]
        with st.REDIRECT_LOCK:
            redirect_data = st.REDIRECTS.get(redirect_id)
        if redirect_data:
            if log:
                log["event"] = "redirect"
                log["redirect_to"] = redirect_data["to"]
                log_headers_to_file(request, path)
                resp = Response("", status=302, headers={"Location": redirect_data["to"]})
                log["response_raw"] = _build_response_raw(resp.status_code, dict(resp.headers), "")
                log_to_console(log)
                store_log_in_memory(log)
                return resp
            else:
                # Admin redirect - just return without logging
                return Response("", status=302, headers={"Location": redirect_data["to"]})

    # Check for delayer module first
    delayer_result = handle_delayer_detection(path, log)
    if delayer_result:
        status_code, resp_headers, body = delayer_result
        resp = Response(body, status=status_code)
        for k, v in resp_headers.items():
            resp.headers[k] = v

        if log:
            log["response_raw"] = _build_response_raw(resp.status_code, dict(resp.headers), body)
            log_to_console(log)
            store_log_in_memory(log)
        return resp
    else:
        # Check for redirect detection
        redirect_result = handle_redirect_detection(path, log)
        if redirect_result:
            status_code, resp_headers, body = redirect_result

    resp = Response(body, status=status_code)
    for k, v in resp_headers.items():
        resp.headers[k] = v

    if log:
        log["response_raw"] = _build_response_raw(resp.status_code, dict(resp.headers), body)
        log_to_console(log)
        store_log_in_memory(log)
    return resp


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE"])
def index_alias():
    return catch_all("")


class ThreadedWSGIServer:
    def __init__(self, host, port, flask_app):
        # --- SSL FIX ---
        ssl_context = None
        if port == st.HTTPS_PORT:
            cert = st.HTTPS_CERT
            key = st.HTTPS_KEY
            
            import os
            if os.path.exists(cert) and os.path.exists(key):
                ssl_context = (cert, key)
                print(f"[+] SSL ON PORT {port}")
            else:
                print(f"[!] ERROR: no CERTS {cert}")
        # ------------------

        self.server = make_server(
            host, 
            port, 
            flask_app, 
            threaded=True,
            request_handler=RawWSGIRequestHandler,
            ssl_context=ssl_context  
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()


def start_http_listener(port: int):
    if port in st.ACTIVE_SERVERS:
        print(f"[=] Already listening on port {port}")
        return
    try:
        srv = ThreadedWSGIServer("0.0.0.0", port, app)
    except OSError as e:
        print(f"[!] Could not bind to port {port}: {e}")
        return
    srv.start()
    st.ACTIVE_SERVERS[port] = srv
    print(f"[+] HTTP listener started on port {port}")


# Readline setup
def setup_readline():
    try:
        import readline
        
        # Command definitions for completion
        ALL_COMMANDS = [
            'run', 'file', 'redirect', 'system', 'listen', 'help', 'exit', 'introspect'
        ]
        
        RUN_PAYLOADS = list(st.RUN_PAYLOADS.keys())
        SYSTEM_SUBCOMMANDS = ['status', 'verbose', 'persist', 'log-path']
        FILE_SUBCOMMANDS = ['upload', 'list', 'delete']
        REDIRECT_SUBCOMMANDS = ['create', 'list', 'delete']
        INTROSPECT_SUBCOMMANDS = ['enable', 'disable', 'status', 'list']
        SCAN_MODULE_NAMES = list(st.SCAN_MODULES.keys()) if hasattr(st, 'SCAN_MODULES') else []
        
        def complete_command(text, state):
            """Tab completion function"""
            buffer = readline.get_line_buffer()
            
            # Check if user wants subcommands (command + space)
            wants_subcommands = buffer.endswith(' ') and len(buffer.split()) == 1
            
            if wants_subcommands:
                # User typed "command " and wants subcommands
                cmd = buffer.strip()
                if cmd == 'run':
                    options = ['create', 'list']
                elif cmd == 'file':
                    options = FILE_SUBCOMMANDS
                elif cmd == 'redirect':
                    options = REDIRECT_SUBCOMMANDS
                elif cmd == 'system':
                    options = SYSTEM_SUBCOMMANDS
                elif cmd == 'introspect':
                    options = INTROSPECT_SUBCOMMANDS
                elif cmd in ('listen', 'help', 'exit'):
                    options = []
                else:
                    options = []
            elif len(buffer.strip()) == 0:
                # Empty buffer - show all commands
                options = ALL_COMMANDS
            else:
                # User is typing main command or arguments
                parts = buffer.split()
                if len(parts) == 1:
                    # Complete main commands
                    options = [cmd for cmd in ALL_COMMANDS if cmd.startswith(text)]
                elif len(parts) == 2 and parts[0] == 'run' and parts[1] == 'create':
                    # Complete payload names for "run create <TAB>"
                    options = [p for p in RUN_PAYLOADS if p.startswith(text)]
                elif len(parts) == 2 and parts[0] == 'run':
                    # Complete payloads for backward compatibility "run <TAB>"
                    options = [p for p in RUN_PAYLOADS if p.startswith(text)]
                elif len(parts) == 2 and parts[0] == 'introspect' and parts[1] in ['enable', 'disable', 'status']:
                    # Complete scan module names for "introspect enable/disable/status <TAB>"
                    options = [m for m in SCAN_MODULE_NAMES if m.startswith(text)]
                else:
                    options = []
            
            return options[state] if state < len(options) else None
        
        # Setup completion
        readline.set_completer(complete_command)
        readline.parse_and_bind("tab: complete")
        
        # Setup history
        history_file = os.path.expanduser("~/.introspector_history")
        try:
            readline.read_history_file(history_file)
        except FileNotFoundError:
            pass
        
        # Save history on exit
        atexit.register(readline.write_history_file, history_file)
        
    except ImportError:
        # readline not available on Windows
        pass

def start_repl():
    while True:
        try:
            cmd = input("[Introspector]> ").strip()
            if not cmd:
                continue
            parts = cmd.split()
            base = parts[0].lower()

            if base == "run":
                if len(parts) == 1:
                    cmd_run_list()
                elif len(parts) >= 2 and parts[1].lower() == "create" and len(parts) == 3:
                    cmd_run(parts[2].lower())
                elif len(parts) >= 2 and parts[1].lower() == "list":
                    cmd_run_list()
                elif len(parts) == 2:
                    # Backward compatibility - treat as create
                    cmd_run(parts[1].lower())
                else:
                    print("[!] Usage: run create <payload> | run list")

            elif base == "listen" and len(parts) == 2:
                try:
                    port = int(parts[1])
                    start_http_listener(port)
                except ValueError:
                    print("[!] Invalid port. Usage: listen 8080")



            elif base == "file" and len(parts) >= 2:
                sub = parts[1].lower()
                if sub == "upload" and len(parts) >= 3:
                    hosted_upload(" ".join(parts[2:]))
                elif sub == "delete" and len(parts) == 3:
                    hosted_unload(parts[2].strip())
                elif sub == "list" and len(parts) == 2:
                    hosted_list()
                elif sub == "unload" and len(parts) == 3:
                    # Backward compatibility for old unload command
                    hosted_unload(parts[2].strip())
                    print("[!] Note: 'unload' is deprecated, use 'delete'")
                else:
                    print("[!] Usage: file upload <path> | file delete <id> | file list")

            elif base == "redirect":
                if len(parts) >= 2 and parts[1].lower() == "create" and len(parts) == 3:
                    cmd_redirect_create(parts[2])
                elif len(parts) >= 2 and parts[1].lower() == "list":
                    cmd_redirect_list()
                elif len(parts) >= 3 and parts[1].lower() == "delete" and len(parts) == 3:
                    cmd_redirect_kill(parts[2].strip())
                elif len(parts) == 2:
                    # Backward compatibility - treat as create
                    cmd_redirect_create(parts[1])
                elif len(parts) >= 3 and parts[1].lower() == "kill":
                    # Backward compatibility for old kill command
                    cmd_redirect_kill(parts[2].strip())
                    print("[!] Note: 'kill' is deprecated, use 'delete'")
                else:
                    print("[!] Usage: redirect create <url> | redirect list | redirect delete <id>")

            elif base == "introspect":
                if len(parts) == 1:
                    cmd_introspect_list()
                elif len(parts) >= 2:
                    action = parts[1].lower()
                    if action == "list" and len(parts) == 2:
                        cmd_introspect_list()
                    elif len(parts) == 3 and action in ["enable", "disable", "status"]:
                        module_name = parts[2].lower()
                        if action == "enable":
                            cmd_introspect_enable(module_name)
                        elif action == "disable":
                            cmd_introspect_disable(module_name)
                        elif action == "status":
                            cmd_introspect_status(module_name)
                    else:
                        print("[!] Usage: introspect <enable|disable|status> <module> | introspect list")
                else:
                    print("[!] Usage: introspect <enable|disable|status> <module> | introspect list")

            elif base == "system":
                if len(parts) >= 2 and parts[1].lower() == "status":
                    cmd_system_status()
                elif len(parts) >= 2 and parts[1].lower() == "verbose" and len(parts) == 3:
                    set_verbose_level(parts[2])
                elif len(parts) >= 2 and parts[1].lower() == "verbose" and len(parts) == 2:
                    print(f"[=] Verbose: {st.VERBOSE_LEVEL} (0=off, 1=min, 2=full)")
                elif len(parts) >= 2 and parts[1].lower() == "persist":
                    if len(parts) == 2:
                        persist_status = st.PERSIST_PATH or "OFF"
                        print(f"[PERSIST] {persist_status}")
                    else:
                        print("[!] Usage: system persist")
                elif len(parts) >= 2 and parts[1].lower() == "log-path":
                    if len(parts) == 2:
                        print(f"[LOG PATH] /{st.LOG_PATH}")
                    else:
                        print("[!] Usage: system log-path")
                else:
                    print("[!] Usage: system status | system verbose <level> | system persist | system log-path")

            elif base == "help":
                cmd_help()

            elif base == "exit":
                print("[!] Exiting...")
                os._exit(0)

            elif base == "verbose":
                if len(parts) == 1:
                    print(f"[=] Verbose: {st.VERBOSE_LEVEL} (0=off, 1=min, 2=full)")
                elif len(parts) == 2:
                    set_verbose_level(parts[1])
                    print("[!] Note: 'verbose' is deprecated, use 'system verbose'")
                else:
                    print("[!] Usage: verbose <0|1|2>")

            elif base == "list":
                cmd_list()
                print("[!] Note: 'list' is deprecated, use 'run list'")

            else:
                print("[!] Unknown command or syntax. Try 'help'")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            os._exit(0)
        except (EOFError, OSError):
            while True:
                time.sleep(3600)


def set_verbose_level(val):
    try:
        v = int(val)
    except Exception:
        print("[!] Usage: verbose <0|1|2>")
        return
    if v < 0:
        v = 0
    if v > 2:
        v = 2
    st.VERBOSE_LEVEL = v
    print(f"[+] Verbose set to {st.VERBOSE_LEVEL}")


def cmd_run(payload):
    if payload not in st.RUN_PAYLOADS:
        print(f"[!] Unknown run payload: {payload}")
        return

    entry = st.RUN_PAYLOADS[payload]
    filename = entry["file"]
    content_type = entry["content_type"]

    template_path = os.path.join(st.TEMPLATE_DIR, filename)
    if not os.path.exists(template_path):
        print(f"[!] Template file tools/{filename} not found.")
        return

    with open(template_path, "rb") as f:
        content = f.read()

    # extraemos extensión real del archivo
    ext = filename.rsplit(".", 1)[-1]

    rid = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    name = f"{rid}.{ext}"

    st.RUN_PATHS[name] = {
        "payload": payload,
        "ext": ext,
        "content_type": content_type,
        "content": content,
    }

    if len(st.RUN_PATHS) > st.MAX_RUNS:
        st.RUN_PATHS.pop(next(iter(st.RUN_PATHS)))

    print(f"[+] Created /run/{name} ({payload}, Content-Type: {content_type})")


def cmd_list():
    if not st.RUN_PATHS:
        print("[=] No active run modules.")
        return
    print("[=] Registered paths:")
    for name, entry in st.RUN_PATHS.items():
        print(f" - /run/{name} ({entry['content_type']})")

def cmd_run_list():
    payloads = getattr(st, "RUN_PAYLOADS", None)
    if not payloads:
        print("[!] No RUN payloads registered (st.RUN_PAYLOADS is empty or missing).")
        return

    # Orden estable y fácil de leer
    keys = sorted(payloads.keys())

    print("[+] Available run payloads:")
    for k in keys:
        entry = payloads.get(k, {}) or {}
        filename = entry.get("file", "?")
        content_type = entry.get("content_type", "?")
        print(f"  - {k:<16} -> tools/{filename}  ({content_type})")

    print(f"[+] Total: {len(keys)}")


def cmd_system_status():
    try:
        import requests
        local_ip = get_local_ip()
    except Exception:
        local_ip = "?"
    
    admin_port = getattr(st, 'ADMIN_PORT', 8000)
    
    if st.LOG_PATH:
        print(f"[LOG UI] http://{local_ip}:{admin_port}/{st.LOG_PATH}")
    else:
        print("[!] No log path assigned yet")
    
    # Show current ports
    if st.ACTIVE_SERVERS:
        ports_str = ", ".join(str(p) for p in st.ACTIVE_SERVERS.keys())
        print(f"[PORTS] {ports_str}")
    else:
        print("[PORTS] No active listeners")
    
    # Show DNS status
    dns_ok = st.DNS_SERVER.get("running", False)
    dns_port = st.DNS_CONFIG.get("listen_port", 53)
    dns_mode = st.DNS_CONFIG.get("mode", "A")
    dns_status = "ON" if dns_ok else f"ERR ({st.DNS_SERVER.get('error', 'Unknown')})"
    print(f"[DNS] {dns_status} (udp/{dns_port}) - Mode: {dns_mode}")
    
    # Show persist status
    persist_status = st.PERSIST_PATH or "OFF"
    print(f"[PERSIST] {persist_status}")
    
    # Show other stats
    print(f"[PAYLOADS] {len(st.RUN_PAYLOADS)}")
    print(f"[EVENTS] {len(st.LOGS)} events")
    if st.REDIRECTS:
        print(f"[REDIRECTS] {len(st.REDIRECTS)} active")
    if st.HOSTED_FILES:
        print(f"[HOSTED FILES] {len(st.HOSTED_FILES)}")

def cmd_redirect_create(url):
    rid = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    with st.REDIRECT_LOCK:
        st.REDIRECTS[rid] = {
            "to": url
        }
    
    if len(st.REDIRECTS) > st.MAX_REDIRECTS:
        with st.REDIRECT_LOCK:
            st.REDIRECTS.pop(next(iter(st.REDIRECTS)))
    
    print(f"[+] Created redirect: /{st.REDIRECT_PREFIX}/{rid} -> {url}")

def cmd_redirect_list():
    with st.REDIRECT_LOCK:
        if not st.REDIRECTS:
            print("[=] No active redirects.")
            return
        
        print("[=] Active redirects:")
        for rid, data in st.REDIRECTS.items():
            print(f" - /{st.REDIRECT_PREFIX}/{rid} -> {data['to']}")

def cmd_redirect_kill(redirect_id):
    with st.REDIRECT_LOCK:
        if redirect_id in st.REDIRECTS:
            data = st.REDIRECTS[redirect_id]
            del st.REDIRECTS[redirect_id]
            print(f"[+] Deleted redirect: {redirect_id} -> {data['to']}")
        else:
            print(f"[!] Redirect not found: {redirect_id}")

def cmd_introspect_enable(module_name):
    if module_name not in st.SCAN_MODULES:
        print(f"[!] Unknown scan module: {module_name}")
        return
    
    st.SCAN_MODULES[module_name]["enabled"] = True
    print(f"[+] Scan module '{module_name}' enabled")

def cmd_introspect_disable(module_name):
    if module_name not in st.SCAN_MODULES:
        print(f"[!] Unknown scan module: {module_name}")
        return
    
    st.SCAN_MODULES[module_name]["enabled"] = False
    print(f"[-] Scan module '{module_name}' disabled")

def cmd_introspect_status(module_name):
    if module_name not in st.SCAN_MODULES:
        print(f"[!] Unknown scan module: {module_name}")
        return
    
    status = "ENABLED" if st.SCAN_MODULES[module_name]["enabled"] else "DISABLED"
    print(f"[MODULE] {module_name}: {status}")

def cmd_introspect_list():
    if not st.SCAN_MODULES:
        print("[!] No scan modules available")
        return
    
    print("[+] Available scan modules:")
    for module_name, module_data in st.SCAN_MODULES.items():
        status = "ENABLED" if module_data["enabled"] else "DISABLED"
        print(f"  - {module_name}: {status}")
    
    print(f"[+] Total: {len(st.SCAN_MODULES)}")

def cmd_help():
    # Framework Commands Section
    print(st.C['CYAN'] + "\n### INTROSPECTOR - FRAMEWORK COMMANDS")
    print(st.C['GREEN'] + "  run create <payload>    Create payload template")
    print(st.C['GREEN'] + "  run list            List available payloads") 
    print(st.C['GREEN'] + "  listen <port>         Start HTTP listener")
    
    # Platform Tools Section
    print(st.C['CYAN'] + "\n### INTROSPECTOR - PLATFORM TOOLS")
    print(st.C['GREEN'] + "  file upload <path>     Host a file")
    print(st.C['GREEN'] + "  file delete <id>       Delete hosted file by ID")
    print(st.C['GREEN'] + "  file list            List all hosted files")
    print(st.C['GREEN'] + "  redirect create <url>   Create redirect URL")
    print(st.C['GREEN'] + "  redirect delete <id>    Delete redirect by ID")
    print(st.C['GREEN'] + "  redirect list        List active redirects")
    
    # Scan Modules Section
    print(st.C['CYAN'] + "\n### INTROSPECTOR - SCAN MODULES")
    print(st.C['GREEN'] + "  introspect <module> <action>   Control scan modules")
    print(st.C['GREEN'] + "  introspect list                  List all scan modules")
    print(st.C['CYAN'] + "    Available actions: enable, disable, status")
    
    # System Management Section
    print(st.C['CYAN'] + "\n### INTROSPECTOR - SYSTEM MANAGEMENT")
    print(st.C['GREEN'] + "  system status       Show system info and URLs")
    print(st.C['GREEN'] + "  system verbose <level> Set verbosity level (0-2)")
    print(st.C['GREEN'] + "  system persist        Show persistence status")
    print(st.C['GREEN'] + "  system log-path       Show web UI path")
    
    # Meta Commands Section
    print(st.C['CYAN'] + "\n### META COMMANDS")
    print(st.C['GREEN'] + "  help                 Show this help")
    print(st.C['GREEN'] + "  exit                  Terminate Introspector")
    
    # Pro Tip
    print(st.C['CYAN'] + "\n💡 Pro tip: Use " + st.C['YELLOW'] + "TAB" + st.C['CYAN'] + " for autocomplete and " + st.C['YELLOW'] + "↑" + st.C['CYAN'] + " for history!" + st.C['RESET'])


def main():
    init_geoip()

    parser = argparse.ArgumentParser(description="Introspector - HTTP Trap Listener")
    parser.add_argument("--log-path", type=str, help="Custom web UI path (default: logs-xxxx)")
    parser.add_argument("--ports", type=str, help="Comma-separated list of HTTP ports to listen on (default: 80)")
    parser.add_argument("--admin-port", type=int, default=8000, help="Admin UI port (default: 8000)")
    parser.add_argument("--persist", type=str, help="Persist logs to file or session (session-name or /path/to/logs.jsonl)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose mode (-v: minimal, -vv: full)")
    args = parser.parse_args()

    st.VERBOSE_LEVEL = int(args.verbose or 0)
    if st.VERBOSE_LEVEL < 0:
        st.VERBOSE_LEVEL = 0
    if st.VERBOSE_LEVEL > 2:
        st.VERBOSE_LEVEL = 2

    init_persist(args.persist)

    st.LOG_PATH = args.log_path or ("logs-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)))
    
    admin_port = args.admin_port if hasattr(args, 'admin_port') and args.admin_port else 8000
    st.ADMIN_PORT = admin_port

    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print("[!] Invalid --ports value. Using default port 80.")
            ports = [80]
    else:
        ports = [80]

    ip = get_local_ip()
    ports_str = ", ".join(str(p) for p in ports)
    geoip_status = "OK" if st.GEOIP_READER is not None else f"ERR (missing {st.GEOIP_DB_PATH})"
    persist_status = "OFF" if not st.PERSIST_PATH else f"ON ({st.PERSIST_PATH})"

    # inicia DNS listener (no bloquea, corre en thread)
    dns_ok = start_dns_listener()
    dns_status = "ON" if dns_ok else f"ERR ({st.DNS_SERVER.get('error')})"
    dns_port = st.DNS_CONFIG.get("listen_port")
    dns_mode = st.DNS_CONFIG.get("mode")
    
    # Generate example and exception tokens
    try:
        from services import dns_generate_token
        example_token = f"{dns_generate_token()}.{st.DNS_CONFIG.get('domain_base', 'example.com')}".strip(".")
        exception_token = f"{dns_generate_token()}.{st.DNS_CONFIG.get('domain_base', 'example.com')}".strip(".")
        st.DNS_EXCEPTION_TOKEN = exception_token.split('.')[0]  # Store just the token part
        st.DNS_EXAMPLE_TOKEN = example_token  # Store full example token
    except Exception:
        example_token = "(error generating token)"
        exception_token = "(error generating token)"
        st.DNS_EXCEPTION_TOKEN = ""
        st.DNS_EXAMPLE_TOKEN = ""

    banner = f"""
 {st.C['YELLOW']}
 ╔════════════════════════════════════════════════════════════════════╗
 ║             INTROSPECTOR FRAMEWORK  —  HTTP OPS TOOL               ║
 ║         Passive Traps · Callback Intel · Payload Hosting           ║
 ╚════════════════════════════════════════════════════════════════════╝
 {st.C['RESET']}
 [LOG UI] http://{ip}:{admin_port}/{st.LOG_PATH}
 [ADMIN] http://{ip}:{admin_port}
 [PORTS] {ports_str} (main) | {admin_port} (admin)
 [DNS] {dns_status} (udp/{dns_port}) - Mode: {dns_mode}
 [DNS Example] {example_token}
 [DNS Exception] {exception_token}
 [GEOIP] {geoip_status}
 [PERSIST] {persist_status}
 [PAYLOADS] {len(st.RUN_PAYLOADS)} 
 [EVENTS] {len(st.LOGS)} events
 [HOSTED] /{st.HOSTED_PREFIX}/<id>.<ext>
 ────────────────────────────────────────────────────────────────────
 """
    print(banner)

    # Disable werkzeug logging
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    for p in ports:
        start_http_listener(p)

    # Start admin UI server
    start_admin_server(admin_port)

    # Setup readline before starting REPL
    setup_readline()
    start_repl()


if __name__ == "__main__":
    main()
