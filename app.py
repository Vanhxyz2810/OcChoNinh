from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import uuid
from datetime import datetime, timedelta
import json
import os
from dateutil.relativedelta import relativedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Cấu hình rate limiting chống DDOS
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["30 per minute", "5 per second"]
)

# Tạo AES key từ secret key
def generate_aes_key():
    return hashlib.sha256(app.secret_key).digest()

# Mã hóa dữ liệu với AES-GCM
def encrypt_data(data):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(generate_aes_key()), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# Giải mã dữ liệu
def decrypt_data(encrypted_data):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(generate_aes_key()), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# HMAC signature verification
def generate_hmac_signature(data):
    return hmac.new(app.secret_key, data, hashlib.sha512).hexdigest()

# Middleware chống DDOS
@app.before_request
def firewall():
    client_ip = request.remote_addr
    # Implement rate limiting logic
    # ... (có thể tích hợp với Redis để tracking)

# Tên tệp cho các cập nhật của người dùng
def get_user_updates_file(username):
    return f'{username}.json'

# Khởi tạo tệp keys.json nếu không tồn tại
def initialize_keys_file():
    if not os.path.exists('keys.json'):
        with open('keys.json', 'w') as f:
            f.write('{}')  # Ghi một đối tượng JSON rỗng

# Tải keys từ tệp JSON
def load_keys_from_file():
    try:
        with open('keys.json', 'r') as f:
            content = f.read()
            if not content.strip():  # Nếu tệp rỗng, trả về một từ điển rỗng
                return {}
            return json.loads(content)  # Sử dụng loads thay vì load
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("Invalid JSON format in keys.json. Returning empty keys.")
        return {}

# Lưu keys vào tệp JSON
def save_keys_to_file():
    with open('keys.json', 'w') as f:
        json.dump(keys_db, f, indent=4)

# Tải cập nhật từ tệp JSON của người dùng
def load_updates_from_file(username):
    updates_file = get_user_updates_file(username)
    if not os.path.exists(updates_file):
        return {"version": "1.0", "status": "false"}  # Trả về giá trị mặc định nếu tệp không tồn tại
    with open(updates_file, 'r') as f:
        return json.load(f)

# Lưu cập nhật vào tệp JSON của người dùng
def save_updates_to_file(username, updates):
    updates_file = get_user_updates_file(username)
    with open(updates_file, 'w') as f:
        json.dump(updates, f, indent=4)

# Khởi tạo tệp keys.json
initialize_keys_file()  # Đảm bảo keys.json tồn tại
keys_db = load_keys_from_file()

# Cơ sở dữ liệu người dùng giả lập
users_db = {
    'WeansHHN': 'Nakoto1234!',
    'VinhGay': 'VinhGay12345',
    'SonLo': 'SonGay12345',
    'LongKD': 'LongKDAOV',
    'KhoaLor': 'KhoLoa12345',
    'VuTungLam': 'LamVu1234!'
}

def calculate_expiry(period, custom_date=None, from_date=None):
    now = from_date or datetime.now()
    if 'day' in period:
        days = int(period.split()[0])  # Lấy số ngày từ chuỗi
        return now + timedelta(days=days)
    elif 'week' in period:
        weeks = int(period.split()[0])  # Lấy số tuần từ chuỗi
        return now + timedelta(weeks=weeks)
    elif 'month' in period:
        months = int(period.split()[0])  # Lấy số tháng từ chuỗi
        return now + relativedelta(months=+months)
    elif period == 'custom' and custom_date:
        try:
            return datetime.strptime(custom_date, "%Y-%m-%d")  # Định dạng ngày
        except ValueError:
            return None  # Trả về None nếu custom_date không hợp lệ
    try:
        # Kiểm tra xem period đã được định dạng sẵn chưa
        return datetime.strptime(period, "%d-%m-%Y")
    except ValueError:
        pass
    return now + timedelta(days=1)  # Mặc định 1 ngày nếu không khớp

# Hàm để xóa các khóa đã hết hạn
def remove_expired_keys():
    expired_keys = []
    for username, keys in keys_db.items():
        for key, key_info in list(keys.items()):
            if isinstance(key_info, dict) and 'amount' in key_info:
                expiry_date = calculate_expiry(key_info['amount'])  # Tính ngày hết hạn từ amount
                if expiry_date < datetime.now():
                    expired_keys.append((username, key))

    for username, key in expired_keys:
        del keys_db[username][key]

    if expired_keys:
        save_keys_to_file()

# Đường dẫn đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db and users_db[username] == password:
            session['username'] = username
            return redirect(url_for('user_dashboard', username=username))
        else:
            return "Sai tài khoản hoặc mật khẩu"
    
    return render_template('login.html')

# Đường dẫn trang tổng quan của người dùng
@app.route('/dashboard/<username>')
def user_dashboard(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))
    
    remove_expired_keys()
    user_keys = keys_db.get(username, {})
    user_updates = load_updates_from_file(username)
    return render_template('dashboard.html', username=username, keys=user_keys, updates=user_updates)

@app.route('/generate_key', methods=['POST'])
def generate_key():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    prefix = request.form['prefix']
    period = request.form['period']
    custom_date = request.form.get('custom_date')
    max_devices = int(request.form['max_devices'])
    key_count = int(request.form['key_count'])
    
    keys = []
    for _ in range(key_count):
        key = f"{prefix}-{uuid.uuid4().hex}"  # Tạo key theo định dạng "Prefix-UUID"
        keys.append(key)
        
        if session['username'] not in keys_db:
            keys_db[session['username']] = {}

        # Ưu tiên ngày tùy chỉnh nếu `period` là `custom`
        expiry_date = None
        if period == 'custom' and custom_date:
            expiry_date = calculate_expiry(period, custom_date=custom_date)
        else:
            expiry_date = calculate_expiry(period)

        # Kiểm tra trường hợp `custom_date` không hợp lệ
        if not expiry_date:
            flash("Ngày tùy chỉnh không hợp lệ. Vui lòng thử lại.")
            return redirect(url_for('user_dashboard', username=session['username']))
        
        keys_db[session['username']][key] = {
            'user': session['username'],
            'amount': expiry_date.strftime("%d-%m-%Y"),  # Lưu ngày hết hạn dưới dạng chuỗi
            'is_activated': False,
            'activation_date': None,
            'max_devices': max_devices,
            'devices': []
        }

    save_keys_to_file()
    
    return redirect(url_for('user_dashboard', username=session['username'], new_keys=json.dumps(keys)))

# Endpoint kiểm tra key và kích hoạt nếu cần
@app.route('/check_key/<username>', methods=['GET'])
@limiter.limit("10/second")  # Giới hạn request
def check_key(username):
    # Verify HMAC signature
    received_sign = request.headers.get('X-Signature')
    valid_sign = generate_hmac_signature(request.query_string)
    
    if not hmac.compare_digest(received_sign, valid_sign):
        return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401
    
    if username not in keys_db:
        return jsonify({'status': 'error', 'message': 'Người dùng không tồn tại.'})

    remove_expired_keys()
    key = request.args.get('key')
    uuid = request.args.get('uuid')
    user_keys = keys_db.get(username, {})

    if key in user_keys:
        key_info = user_keys[key]

        # Nếu 'is_activated' không tồn tại, khởi tạo nó là False
        if 'is_activated' not in key_info:
            key_info['is_activated'] = False

        # Kiểm tra xem key đã được kích hoạt chưa
        if not key_info['is_activated']:
            activation_date = datetime.now()
            expiry_date = calculate_expiry(key_info['amount'], from_date=activation_date)
            key_info['activation_date'] = activation_date.strftime("%d-%m-%Y")
            key_info['amount'] = expiry_date.strftime("%d-%m-%Y")
            key_info['is_activated'] = True
            save_keys_to_file()

        # Kiểm tra ngày hết hạn
        try:
            expiry_date = datetime.strptime(key_info['amount'], "%d-%m-%Y")
            if expiry_date < datetime.now():
                return jsonify({'status': 'error', 'message': 'Key đã hết hạn.'})
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Ngày hết hạn không hợp lệ.'})

        # Kiểm tra thiết bị
        if uuid not in key_info['devices']:
            if len(key_info['devices']) < key_info['max_devices']:
                key_info['devices'].append(uuid)
                save_keys_to_file()
            else:
                return jsonify({'status': 'error', 'message': 'Đã đạt giới hạn thiết bị cho key này.'})

        return jsonify({'status': 'success', 'activation_date': key_info['activation_date'], 'amount': key_info['amount'], 'message': 'Key hợp lệ.'})

    return jsonify({'status': 'error', 'message': 'Key không hợp lệ.'})
    
# Reset danh sách thiết bị
@app.route('/reset_udid/<key>', methods=['POST'])
def reset_udid(key):
    # Kiểm tra nếu người dùng chưa đăng nhập
    if 'username' not in session:
        return jsonify({"error": "Bạn cần đăng nhập để thực hiện thao tác này."}), 401

    # Lấy danh sách keys của người dùng từ database
    username = session['username']
    user_keys = keys_db.get(username, {})

    # Kiểm tra nếu key tồn tại trong danh sách keys
    if key in user_keys:
        # Reset thông tin của key
        user_keys[key]['devices'] = []  # Xóa danh sách thiết bị liên kết
        user_keys[key]['uuid'] = None  # Xóa UUID
        save_keys_to_file()  # Lưu lại trạng thái vào file hoặc database

        # Trả về phản hồi thành công
        return jsonify({"message": f"Key '{key}' đã được reset thành công."}), 200
    else:
        # Key không tồn tại
        return jsonify({"error": f"Key '{key}' không tồn tại."}), 404

@app.route('/get_keys/<username>', methods=['GET'])
def get_keys_for_user(username):
    # Kiểm tra xem user có đăng nhập không
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))
    
    # Lấy danh sách key cho người dùng từ keys_db
    user_keys = keys_db.get(username, {}).get('keys', [])
    
    # Trả về danh sách key dưới dạng JSON
    return jsonify(user_keys)

# Chức năng cập nhật thông tin phiên bản
@app.route('/update_info', methods=['POST'])
def update_info():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    version = request.form['version']
    status = request.form['status']

    updates = {
        "version": version,
        "status": status
    }

    save_updates_to_file(username, updates)
    return redirect(url_for('user_dashboard', username=username))

# Thêm vào phần định nghĩa Flask
@app.route('/update_json/<username>/<filename>', methods=['GET'])
def serve_user_updates(username, filename):
    # Xác minh người dùng hợp lệ
    if username not in users_db:
        return jsonify({'error': 'Người dùng không hợp lệ.'}), 404

    updates_file = get_user_updates_file(username)
    
    # Kiểm tra nếu tệp JSON tồn tại
    if not os.path.exists(updates_file):
        return jsonify({'error': 'Tệp không tồn tại.'}), 404

    with open(updates_file, 'r') as f:
        updates_data = json.load(f)

    return jsonify(updates_data)

# Xóa khóa
@app.route('/delete_key/<key>', methods=['POST'])
def delete_key(key):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_keys = keys_db.get(session['username'], {})
    if key in user_keys:
        del user_keys[key]
        save_keys_to_file()
    
    return redirect(url_for('user_dashboard', username=session['username']))

# Đường dẫn đăng xuất
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Lưu key với mã hóa
def save_encrypted_keys():
    encrypted = encrypt_data(json.dumps(keys_db).encode())
    with open('keys.enc', 'wb') as f:
        f.write(encrypted)

# Tải key đã giải mã
def load_decrypted_keys():
    try:
        with open('keys.enc', 'rb') as f:
            return json.loads(decrypt_data(f.read()).decode())
    except FileNotFoundError:
        return {}

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

