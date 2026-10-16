import os
import json
import time
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)

DATA_FILE = "licenses.json"
TOKEN_FILE = "tokens.json"

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "flaxxi123")

def load_tokens():
    if not os.path.exists(TOKEN_FILE):
        return {"tokens": []}
    try:
        with open(TOKEN_FILE, "r") as f:
            return json.load(f)
    except:
        return {"tokens": []}

def save_tokens(data):
    with open(TOKEN_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"keys": []}
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"keys": []}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

@app.route("/")
def index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.route("/api/diagnostics", methods=["GET", "POST"])
def diagnostics():
    return jsonify({
        "status": "online",
        "version": "1.8",
        "message": "Server is up and operational."
    })

@app.route("/api/version", methods=["GET", "POST"])
@app.route("/api/update", methods=["GET", "POST"])
def version_check():
    return jsonify({
        "latest_version": "1.8",
        "update_available": False,
        "url": "",
        "status": "success"
    })

@app.route("/api/login", methods=["POST"])
def login():
    req_data = request.get_json() or {}
    username = req_data.get("username")
    password = req_data.get("password")
    
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = uuid.uuid4().hex
        t_data = load_tokens()
        if token not in t_data["tokens"]:
            t_data["tokens"].append(token)
            save_tokens(t_data)
        return jsonify({"success": True, "token": token})
    else:
        return jsonify({"error": "Invalid username or password."}), 401

@app.route("/api/verify", methods=["POST"])
def verify_token():
    req_data = request.get_json() or {}
    token = req_data.get("token")
    t_data = load_tokens()
    if token and token in t_data["tokens"]:
        return jsonify({"owner": True})
    return jsonify({"owner": False})

@app.route("/api/logout", methods=["POST"])
def logout():
    req_data = request.get_json() or {}
    token = req_data.get("token")
    t_data = load_tokens()
    if token in t_data["tokens"]:
        t_data["tokens"].remove(token)
        save_tokens(t_data)
    return jsonify({"success": True})

@app.route("/api/keys", methods=["GET", "POST"])
def manage_keys():
    token = request.headers.get("X-Token")
    t_data = load_tokens()
    if not token or token not in t_data["tokens"]:
        return jsonify({"error": "Unauthorized access."}), 403

    data = load_data()

    if request.method == "GET":
        return jsonify({"keys": data["keys"]})

    elif request.method == "POST":
        req_data = request.get_json() or {}
        mode = req_data.get("mode")
        custom_key = req_data.get("custom_key")
        label = req_data.get("label", "")
        days = int(req_data.get("days", 30))
        device_limit = int(req_data.get("device_limit", 1))

        if mode == "custom" and custom_key:
            key_id = custom_key.strip()
        else:
            rand_part = uuid.uuid4().hex[:8].upper()
            key_id = f"FLAXXI-{rand_part}"

        for k in data["keys"]:
            if k["id"] == key_id:
                return jsonify({"error": "This key already exists."}), 400

        expires_at = time.time() + (days * 86400)

        new_key = {
            "id": key_id,
            "label": label,
            "expires": expires_at,
            "devices": 0,
            "device_limit": device_limit,
            "revoked": False,
            "bound_devices": []
        }

        data["keys"].insert(0, new_key)
        save_data(data)

        return jsonify({"key": key_id, "expires": expires_at})

@app.route("/api/keys/<path:key_id>", methods=["POST", "DELETE"])
def modify_key(key_id):
    token = request.headers.get("X-Token")
    t_data = load_tokens()
    if not token or token not in t_data["tokens"]:
        return jsonify({"error": "Unauthorized access."}), 403

    data = load_data()
    key_obj = None
    for k in data["keys"]:
        if k["id"] == key_id:
            key_obj = k
            break

    if not key_obj:
        return jsonify({"error": "License key not found."}), 404

    if request.method == "DELETE":
        data["keys"] = [k for k in data["keys"] if k["id"] != key_id]
        save_data(data)
        return jsonify({"success": True})

    elif request.method == "POST":
        req_data = request.get_json() or {}
        action = req_data.get("action")

        if action == "revoke":
            key_obj["revoked"] = True
        elif action == "enable":
            key_obj["revoked"] = False
        elif action == "reset_devices":
            key_obj["devices"] = 0
            key_obj["bound_devices"] = []
        elif action == "edit":
            new_label = req_data.get("label")
            if new_label is not None:
                key_obj["label"] = new_label

        save_data(data)
        return jsonify({"success": True, "key": key_obj})

@app.route("/api/validate", methods=["POST"])
def validate_license():
    req_data = request.get_json() or {}
    key_str = req_data.get("key")
    device_id = req_data.get("device_id", "unknown")

    data = load_data()
    key_obj = None
    for k in data["keys"]:
        if k["id"] == key_str:
            key_obj = k
            break

    if not key_obj:
        return jsonify({"valid": False, "message": "License key not found."}), 404

    if key_obj["revoked"]:
        return jsonify({"valid": False, "message": "License has been blocked/revoked."}), 403

    if key_obj["expires"] <= time.time():
        return jsonify({"valid": False, "message": "License has expired."}), 403

    if device_id not in key_obj["bound_devices"]:
        if len(key_obj["bound_devices"]) >= key_obj["device_limit"]:
            return jsonify({"valid": False, "message": "Device limit reached for this key."}), 403
        key_obj["bound_devices"].append(device_id)
        key_obj["devices"] = len(key_obj["bound_devices"])
        save_data(data)

    return jsonify({"valid": True, "message": "License is active.", "expires": key_obj["expires"]})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
