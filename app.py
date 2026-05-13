# app.py (начало файла)
import os
import json
import socket
import hashlib
import base64
import time
import logging
import struct
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

# ================== 📁 КОНФИГУРАЦИЯ ==================
CONFIG_DIR = os.path.join(os.path.dirname(__file__), 'config')
APP_CONFIG = os.path.join(CONFIG_DIR, 'app.json')
MINERS_CONFIG = os.path.join(CONFIG_DIR, 'miners.json')
os.makedirs(CONFIG_DIR, exist_ok=True)

# 🔄 Кроссплатформенный лок для файлов (работает на Windows и Linux)
file_lock = threading.Lock()

def _load_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return default

def _save_json(path, data):
    with file_lock:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def init_config():
    app_cfg = _load_json(APP_CONFIG, {
        "admin_user": "admin",
        "admin_hash": "",
        "secret_key": "",
        "first_run": True,
        "created_at": None
    })
    if not app_cfg.get("secret_key"):
        import secrets
        app_cfg["secret_key"] = secrets.token_hex(32)
        _save_json(APP_CONFIG, app_cfg)
    app.secret_key = app_cfg["secret_key"]
    return app_cfg

app_config = init_config()

# ================== 🔐 АВТОРИЗАЦИЯ ==================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Требуется авторизация'

class User(UserMixin):
    def __init__(self, user_id): self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    cfg = _load_json(APP_CONFIG, {})
    return User(cfg.get("admin_user")) if user_id == cfg.get("admin_user") else None

@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({"error": "Unauthorized"}), 401
    return redirect(url_for('login'))

# ================== 🧙 МАРШРУТЫ НАСТРОЙКИ ==================
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Мастер первоначальной настройки"""
    cfg = _load_json(APP_CONFIG, {})
    if not cfg.get("first_run") and cfg.get("admin_hash"):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username', 'admin').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        
        if len(password) < 6:
            flash('Пароль должен быть не менее 6 символов', 'error')
        elif password != confirm:
            flash('Пароли не совпадают', 'error')
        else:
            cfg["admin_user"] = username
            cfg["admin_hash"] = generate_password_hash(password)
            cfg["first_run"] = False
            cfg["created_at"] = datetime.now().isoformat()
            _save_json(APP_CONFIG, cfg)
            flash('Настройка завершена! Теперь войдите в систему', 'success')
            return redirect(url_for('login'))
    
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    cfg = _load_json(APP_CONFIG, {})
    if cfg.get("first_run") or not cfg.get("admin_hash"):
        return redirect(url_for('setup'))
    
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        u, p = request.form.get('username','').strip(), request.form.get('password','')
        if u == cfg.get("admin_user") and check_password_hash(cfg.get("admin_hash"), p):
            login_user(User(u))
            return redirect(request.args.get('next') or url_for('index'))
        flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ================== 📡 API WHATSMINER (TCP v3) ==================
API_PORT = 4433
SOCKET_TIMEOUT = 3
MAX_RETRIES = 3
RETRY_DELAY = 0.5

ERROR_CODES = {
    "206": "Power input voltage error",
    "101": "Hashboard communication fault",
    "102": "Hashboard temperature abnormal",
    "201": "Power supply voltage/fan abnormal",
    "202": "Power supply over temperature",
    "301": "Fan speed abnormal / missing",
    "401": "Chip communication fault",
    "501": "Frequency/voltage setting error"
}

def _create_socket(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    s.connect((ip, API_PORT))
    return s

def _send_cmd(s, obj):
    b = json.dumps(obj, separators=(',',':')).encode('ascii')
    s.sendall(struct.pack('<I', len(b)) + b)

def _recv_resp(s):
    ln = s.recv(4)
    if len(ln) < 4: return None
    size = struct.unpack('<I', ln)[0]
    buf, rec = [], 0
    while rec < size:
        chunk = s.recv(min(4096, size-rec))
        if not chunk: break
        buf.append(chunk); rec += len(chunk)
    return json.loads(b''.join(buf).decode('ascii')) if rec == size else None

def _get_cmd(ip, cmd, param=None):
    try:
        s = _create_socket(ip)
        req = {"cmd": cmd}
        if param: req["param"] = param
        _send_cmd(s, req)
        r = _recv_resp(s); s.close()
        return r if r and r.get("code")==0 else None
    except Exception as e:
        logging.warning(f"Read {cmd} @ {ip}: {e}")
        return None

def _get_salt(ip, pwd):
    try:
        s = _create_socket(ip)
        _send_cmd(s, {"cmd":"get.device.info", "param":"salt"})
        r = _recv_resp(s); s.close()
        return r["msg"].get("salt") if r and r.get("code")==0 else None
    except: return None

def _set_cmd(ip, pwd, cmd, param=None):
    try:
        salt = _get_salt(ip, pwd)
        if not salt: return None
        ts = int(time.time())
        tok = base64.b64encode(hashlib.sha256(f"{cmd}{pwd}{salt}{ts}".encode()).digest()).decode()[:8]
        req = {"cmd":cmd, "ts":ts, "token":tok, "account":"super"}
        if param is not None: req["param"] = param
        s = _create_socket(ip)
        _send_cmd(s, req)
        r = _recv_resp(s); s.close()
        return r if r and r.get("code")==0 else None
    except Exception as e:
        logging.warning(f"Write {cmd} @ {ip}: {e}")
        return None

def _do_fetch(dev_id, cfg):
    """Единичный запрос к майнеру с парсингом ошибок"""
    info = _get_cmd(cfg["ip"], "get.device.info")
    if not info or info.get("code") != 0:
        raise ConnectionError("get.device.info failed")
    
    msg = info.get("msg", {})
    miner, power, net, sys = msg.get("miner",{}), msg.get("power",{}), msg.get("network",{}), msg.get("system",{})
    boards = int(miner.get("board-num", 0))

    sett = _get_cmd(cfg["ip"], "get.miner.setting")
    mode = "normal"
    if sett and sett.get("code")==0: mode = sett.get("msg",{}).get("power-mode","normal")

    stat = _get_cmd(cfg["ip"], "get.miner.status", "summary+pools+edevs")
    summ, pools, edevs = {}, [], []
    if stat and stat.get("code")==0:
        m = stat.get("msg", {})
        summ = m.get("summary", {})
        pools = m.get("pools", [])
        edevs = m.get("edevs", [])

    # 🛠️ Сбор ошибок (поддержка двух форматов)
    errors = []
    raw_errs = msg.get("error-code", [])
    if isinstance(raw_errs, list):
        for e in raw_errs:
            if isinstance(e, dict):
                if "reason" in e:  # Формат: {"206": "2026-05-08...", "reason": "..."}
                    for key, value in e.items():
                        if key != "reason" and key.isdigit():
                            code = key
                            desc = e.get("reason", ERROR_CODES.get(code, f"Error {code}"))
                            errors.append({"code": code, "desc": desc, "time": value,
                                          "severity": "critical" if code in ["101","102","201","202","301","206","401"] else "warning"})
                else:  # Формат: {"code": "206", "desc": "..."}
                    code = str(e.get("code") or e.get("error-code") or "")
                    if code:
                        desc = e.get("desc") or e.get("error-desc") or ERROR_CODES.get(code, f"Error {code}")
                        errors.append({"code": code, "desc": desc,
                                      "severity": "critical" if code in ["101","102","201","202","301","206","401"] else "warning"})
            elif isinstance(e, (str, int)):
                code = str(e)
                errors.append({"code": code, "desc": ERROR_CODES.get(code, f"Error {code}"), "severity": "warning"})

    # 📊 Парсинг данных
    hr = summ.get("hash-realtime", summ.get("hash-average", 0))
    fin, fout = summ.get("fan-speed-in", 0), summ.get("fan-speed-out", 0)
    btemps = summ.get("board-temperature", [])

    fp = [{"url": p.get("url", ""), "user": p.get("account", p.get("user", "")),
           "status": "Alive" if p.get("stratum-active") or p.get("status") == "alive" else "Dead",
           "priority": p.get("id", 0), "accepted": p.get("accepted-shares", 0), "rejected": p.get("reject-rate", 0)}
          for p in pools if isinstance(p, dict)]

    bi = [{"id": b.get("id", i), "chips": b.get("effective-chips", 0),
           "temp_avg": b.get("chip-temp-avg", 0), "temp_min": b.get("chip-temp-min", 0),
           "temp_max": b.get("chip-temp-max", 0), "hash": b.get("hash-average", 0)}
          for i, b in enumerate(edevs) if isinstance(b, dict)]

    pcbs = [miner.get(f"pcbsn{i}", "") for i in range(boards)]

    return {
        "status": "online", "hashrate": f"{hr:.1f}" if isinstance(hr, (int, float)) else "N/A",
        "fan_in": int(fin), "fan_out": int(fout),
        "power_realtime": int(summ.get("power-realtime", power.get("pin", 0))),
        "temp_env": summ.get("environment-temperature", power.get("temp0", 0)),
        "board_temps": btemps, "mode": mode.lower(), "ip": cfg["ip"],
        "pools": fp, "errors": errors, "error_count": len(errors),
        "has_critical": any(e.get("severity") == "critical" for e in errors),
        "miner_type": miner.get("type", "Unknown"), "fw_version": sys.get("fwversion", ""),
        "miner_sn": miner.get("miner-sn", ""), "hostname": net.get("hostname", ""), "mac": net.get("mac", ""),
        "uptime": summ.get("elapsed", 0), "boards": bi, "board_pcb_sns": pcbs, "board_count": boards,
        "power_model": power.get("model", ""), "power_sn": power.get("sn", ""),
        "id": dev_id, "group": cfg.get("group", "")
    }

def fetch_single_miner(dev_id, cfg):
    """Обёртка с повторными попытками"""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _do_fetch(dev_id, cfg)
        except Exception as e:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                logging.warning(f"❌ {dev_id} offline after {MAX_RETRIES} attempts: {e}")
    return {"status":"offline", "ip":cfg["ip"], "id":dev_id, "group":cfg.get("group","")}

# ================== 🔄 ФОНОВЫЙ КЭШ ==================
status_cache = {}
cache_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)

def cache_updater():
    while True:
        try:
            miners = _load_json(MINERS_CONFIG, {})
            futures = {}
            for dev_id, cfg in miners.items():
                if cfg.get("enabled", True):
                    futures[executor.submit(fetch_single_miner, dev_id, cfg)] = dev_id
            
            new_cache = {}
            for f in as_completed(futures):
                try:
                    result = f.result()
                    # Обновляем last_seen
                    miners[result["id"]]["last_seen"] = datetime.now().isoformat()
                    new_cache[result["id"]] = result
                except: pass
            
            _save_json(MINERS_CONFIG, miners)
            with cache_lock:
                global status_cache
                status_cache = new_cache
        except Exception as e:
            logging.error(f"Cache loop error: {e}")
        time.sleep(15)

threading.Thread(target=cache_updater, daemon=True).start()

# ================== 🗄️ API УПРАВЛЕНИЯ МАЙНЕРАМИ ==================
@app.route('/api/miners', methods=['GET'])
@login_required
def api_miners_list():
    """Список майнеров (без паролей!)"""
    miners = _load_json(MINERS_CONFIG, {})
    result = []
    for dev_id, cfg in miners.items():
        result.append({
            "id": dev_id,
            "ip": cfg.get("ip"),
            "group": cfg.get("group", ""),
            "enabled": cfg.get("enabled", True),
            "added_at": cfg.get("added_at"),
            "last_seen": cfg.get("last_seen")
        })
    return jsonify(result)

@app.route('/api/miners', methods=['POST'])
@login_required
def api_miners_add():
    """Добавление майнера"""
    data = request.json
    dev_id = data.get("id", "").strip()
    ip = data.get("ip", "").strip()
    password = data.get("password", "")
    group = data.get("group", "Без группы")
    
    if not dev_id or not ip or not password:
        return jsonify({"error": "Все поля обязательны"}), 400
    
    # Проверка подключения (быстрый тест)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, API_PORT))
        s.close()
    except:
        return jsonify({"error": f"Не удалось подключиться к {ip}:{API_PORT}"}), 400
    
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id in miners:
        return jsonify({"error": "Майнер с таким именем уже существует"}), 409
    
    miners[dev_id] = {
        "ip": ip, "password": password, "group": group,
        "added_at": datetime.now().isoformat(),
        "last_seen": None, "enabled": True
    }
    _save_json(MINERS_CONFIG, miners)
    return jsonify({"success": True, "message": "Майнер добавлен"})

@app.route('/api/miners/<dev_id>', methods=['PUT'])
@login_required
def api_miners_update(dev_id):
    """Обновление майнера"""
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id not in miners:
        return jsonify({"error": "Not found"}), 404
    
    data = request.json
    if "ip" in data: miners[dev_id]["ip"] = data["ip"]
    if "password" in data and data["password"]: miners[dev_id]["password"] = data["password"]
    if "group" in data: miners[dev_id]["group"] = data["group"]
    if "enabled" in data: miners[dev_id]["enabled"] = data["enabled"]
    
    _save_json(MINERS_CONFIG, miners)
    return jsonify({"success": True})

@app.route('/api/miners/<dev_id>', methods=['DELETE'])
@login_required
def api_miners_delete(dev_id):
    """Удаление майнера"""
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id in miners:
        del miners[dev_id]
        _save_json(MINERS_CONFIG, miners)
        return jsonify({"success": True})
    return jsonify({"error": "Not found"}), 404

# ================== 🌐 ОСНОВНЫЕ МАРШРУТЫ ==================
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/status')
@login_required
def api_status():
    with cache_lock:
        return jsonify(list(status_cache.values()))

@app.route('/api/device/<dev_id>/mode', methods=['POST'])
@login_required
def change_mode(dev_id):
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id not in miners: return jsonify({"error":"Not found"}), 404
    mode = request.json.get('mode')
    if mode not in ['low','normal','high']: return jsonify({"error":"Invalid"}), 400
    cfg = miners[dev_id]
    if _set_cmd(cfg["ip"], cfg["password"], "set.miner.power_mode", mode):
        return jsonify({"success":True})
    return jsonify({"error":"Failed"}), 500

@app.route('/api/device/<dev_id>/reboot', methods=['POST'])
@login_required
def reboot(dev_id):
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id not in miners: return jsonify({"error":"Not found"}), 404
    cfg = miners[dev_id]
    if _set_cmd(cfg["ip"], cfg["password"], "set.system.reboot"):
        return jsonify({"success":True})
    return jsonify({"error":"Failed"}), 500

@app.route('/api/debug/<dev_id>')
@login_required
def api_debug(dev_id):
    miners = _load_json(MINERS_CONFIG, {})
    if dev_id not in miners: return jsonify({"error": "Not found"}), 404
    cfg = miners[dev_id]
    r = _get_cmd(cfg["ip"], "get.device.info")
    return jsonify({"device":dev_id, "raw": r.get("msg") if r else None})

if __name__ == '__main__':
    logging.info("🚀 Whatsminer Manager started (JSON DB + Setup Wizard)")
    app.run(host='0.0.0.0', port=5000, debug=False)