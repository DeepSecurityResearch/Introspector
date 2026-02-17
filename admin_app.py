# admin_app.py - Admin UI on port 8000

import json
import os
from datetime import datetime
from functools import wraps
from flask import Flask, request, Response, render_template, jsonify

import core_state as st
from services import (
    whois_cached,
    _build_response_raw,
    log_to_console,
    store_log_in_memory,
)

ADMIN_USER = os.environ.get("ADMIN_USER", "introspector")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "beta-admin")

admin_app = Flask(__name__, template_folder="templates")


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != ADMIN_USER or auth.password != ADMIN_PASS:
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin"'}
            )
        return f(*args, **kwargs)
    return decorated


@admin_app.before_request
def check_auth():
    if request.path == "/health":
        return None
    if request.path.startswith("/api/health"):
        return None
    auth = request.authorization
    if not auth or auth.username != ADMIN_USER or auth.password != ADMIN_PASS:
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="Admin"'}
        )


@admin_app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "loaded": len(st.LOGS)})


@admin_app.route("/api/logs", methods=["GET"])
def api_logs():
    logs = list(reversed(st.LOGS))
    return jsonify({"logs": logs})


@admin_app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    try:
        st.LOGS.clear()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@admin_app.route("/api/logs/delete/<int:index>", methods=["DELETE"])
def delete_one(index):
    n = len(st.LOGS)
    real_index = (n - 1) - index 

    if 0 <= real_index < n:
        del st.LOGS[real_index]
        return jsonify({"status": "ok"}), 200

    return jsonify({"status": "error", "message": "Invalid index"}), 404


@admin_app.route("/api/whois", methods=["GET"])
def api_whois():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "missing ip"}), 400
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return jsonify({"ok": True, "text": f"IP privada ({ip}), no hay WHOIS público.", "cached": True})
    except ValueError:
        return jsonify({"ok": False, "error": "invalid ip"}), 400

    res = whois_cached(ip)
    if res.get("ok"):
        return jsonify({"ok": True, "text": res.get("text", ""), "cached": res.get("cached", False)})
    return jsonify({"ok": False, "error": res.get("error", "whois error")}), 504


def serve_logs_ui():
    return render_template("logs_ui.html", log_path=st.LOG_PATH, dns_example=st.DNS_EXAMPLE_TOKEN)


@admin_app.route("/ResponseDesigner", methods=["GET"])
def serve_response_designer():
    return render_template("response_designer.html", log_path=st.LOG_PATH)


@admin_app.route("/api/response-templates", methods=["GET"])
def get_response_templates():
    try:
        with open('response_templates.json', 'r') as f:
            templates = json.load(f)
        return jsonify(templates)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_app.route("/api/response-template/<template_name>", methods=["GET"])
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


@admin_app.route("/api/response-designer/save", methods=["POST"])
def save_response_designer():
    try:
        data = request.json
        
        if not data or not data.get('path'):
            return jsonify({"error": "Path is required"}), 400
            
        response_id = data.get('response_id', 'unknown')
        path = data['path'].lstrip('/')
        
        if not path:
            path = 'response.html'
            
        full_path = f"design/{path}"
        
        with st.RESPONSE_DESIGNER_LOCK:
            existing = st.RESPONSE_DESIGNER_PATHS.get(full_path)
            
            st.RESPONSE_DESIGNER_PATHS[full_path] = {
                'response_id': response_id,
                'name': data.get('name', 'Untitled Response'),
                'headers': data.get('headers', ''),
                'body': data.get('body', ''),
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            if len(st.RESPONSE_DESIGNER_PATHS) > st.MAX_RESPONSE_DESIGNER:
                sorted_items = sorted(
                    st.RESPONSE_DESIGNER_PATHS.items(),
                    key=lambda x: x[1]['updated_at']
                )
                for i in range(len(sorted_items) - st.MAX_RESPONSE_DESIGNER + 1):
                    del st.RESPONSE_DESIGNER_PATHS[sorted_items[i][0]]
        
        return jsonify({
            "success": True,
            "url": f"/{full_path}",
            "path": full_path,
            "message": f"Response saved and available at: /{full_path}"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_app.route("/api/response-designer/list", methods=["GET"])
def list_response_designer():
    try:
        with st.RESPONSE_DESIGNER_LOCK:
            responses = st.RESPONSE_DESIGNER_PATHS.copy()
        
        return jsonify({
            "success": True,
            "responses": responses,
            "total": len(responses)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_app.route("/api/response-designer/debug", methods=["GET"])
def debug_response_designer():
    try:
        with st.RESPONSE_DESIGNER_LOCK:
            responses = st.RESPONSE_DESIGNER_PATHS.copy()
        
        debug_info = {}
        for path, data in responses.items():
            debug_info[path] = {
                'name': data.get('name'),
                'headers_preview': data.get('headers', '')[:100] + '...' if len(data.get('headers', '')) > 100 else data.get('headers', ''),
                'headers_length': len(data.get('headers', '')),
                'body_preview': data.get('body', '')[:100] + '...' if len(data.get('body', '')) > 100 else data.get('body', ''),
                'body_length': len(data.get('body', '')),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at')
            }
        
        return jsonify({
            "success": True,
            "stored_responses": debug_info,
            "total_count": len(responses)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@admin_app.route("/api/response-designer/delete", methods=["POST"])
def delete_response_designer():
    try:
        data = request.json
        
        if not data or not data.get('path'):
            return jsonify({"error": "Path is required"}), 400
            
        path = data['path']
        if not path.startswith('design/'):
            path = f"design/{path.lstrip('/')}"
            
        with st.RESPONSE_DESIGNER_LOCK:
            if path in st.RESPONSE_DESIGNER_PATHS:
                del st.RESPONSE_DESIGNER_PATHS[path]
                return jsonify({
                    "success": True,
                    "message": f"Response {path} deleted successfully"
                })
            else:
                return jsonify({"error": "Response not found"}), 404
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def start_admin_server(port: int):
    if port in st.ACTIVE_SERVERS:
        print(f"[=] Admin already running on port {port}")
        return
    try:
        from werkzeug.serving import make_server
        srv = make_server("0.0.0.0", port, admin_app, threaded=True)
    except OSError as e:
        print(f"[!] Could not bind admin port {port}: {e}")
        return
    
    # Register the log UI route dynamically
    def serve_logs_ui():
        return render_template("logs_ui.html", log_path=st.LOG_PATH, dns_example=st.DNS_EXAMPLE_TOKEN)
    
    admin_app.add_url_rule(f"/{st.LOG_PATH}", view_func=serve_logs_ui, methods=["GET"])
    
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    st.ACTIVE_SERVERS[port] = srv
    print(f"[+] Admin UI started on port {port}")
