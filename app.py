import os, sqlite3, psutil, time, threading
from flask import Flask, render_template, request, redirect, url_for, session, abort, send_from_directory, Response
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = "secure_transmission_ultra_2026"

# Support for 500MB uploads
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 

# Automatic engine selection (eventlet/threading)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=None)

UPLOAD_FOLDER = 'static/uploads'
IMG_FOLDER = 'img'

if not os.path.exists(UPLOAD_FOLDER): 
    os.makedirs(UPLOAD_FOLDER)

# --- Database Core ---
def get_db():
    conn = sqlite3.connect('transmission_system.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (role TEXT PRIMARY KEY, password TEXT)')
        conn.execute('''CREATE TABLE IF NOT EXISTS active_receivers 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, 
                         login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
                         last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS security_logs 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, role_tried TEXT, ip TEXT, 
                         timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_name TEXT, 
                         role TEXT, message TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS blacklist 
                        (ip TEXT PRIMARY KEY, reason TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # CLEANUP: Remove "Ghost" users on restart
        conn.execute('DELETE FROM active_receivers')
        
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            conn.execute("INSERT INTO users VALUES ('sender', 'sender123'), ('receiver', 'receiver123'), ('admin', 'admin123')")
        conn.commit()

init_db()

# --- Background Task: 24h File Expiry ---
def auto_cleanup():
    while True:
        now = time.time()
        if os.path.exists(UPLOAD_FOLDER):
            for f in os.listdir(UPLOAD_FOLDER):
                path = os.path.join(UPLOAD_FOLDER, f)
                if os.path.isfile(path) and os.stat(path).st_mtime < now - 86400:
                    try: os.remove(path)
                    except: pass
        time.sleep(3600)

threading.Thread(target=auto_cleanup, daemon=True).start()

# --- WebSocket Events ---

@socketio.on('join_network')
def on_join(data):
    phone, name = data.get('phone'), data.get('name')
    join_room(f"room_{phone}")
    session['user_phone'] = phone 
    socketio.emit('update_user_list', {'name': name, 'phone': phone})

@socketio.on('disconnect')
def on_disconnect():
    phone = session.get('user_phone')
    if phone: socketio.emit('remove_user_list', {'phone': phone})

@socketio.on('heartbeat')
def handle_heartbeat(data):
    with get_db() as conn:
        conn.execute('UPDATE active_receivers SET last_seen = CURRENT_TIMESTAMP WHERE phone=?', (data.get('phone'),))
        conn.commit()

@socketio.on('send_message')
def handle_message(data):
    targets = data.get('targets', ['all'])
    display_name = session.get('user_name', session.get('role', 'Node')).capitalize()
    msg_payload = {'user': display_name, 'msg': data.get('msg'), 'time': time.strftime('%H:%M')}
    if "all" in targets:
        socketio.emit('new_message', msg_payload)
    else:
        for t in targets: socketio.emit('new_message', msg_payload, room=t)
        emit('new_message', msg_payload)

# --- Primary Routes ---

@app.route('/')
def login_page():
    if 'role' in session: return redirect(url_for(session['role']))
    return render_template('login.html', error=request.args.get('error'))

@app.route('/auth', methods=['POST'])
def auth():
    role, password = request.form.get('role'), request.form.get('password')
    name, phone = request.form.get('name', ''), request.form.get('phone', '')
    user_ip = request.remote_addr

    with get_db() as conn:
        if conn.execute('SELECT * FROM blacklist WHERE ip=?', (user_ip,)).fetchone():
            abort(403, description="IP Blocked")

        user = conn.execute('SELECT * FROM users WHERE role=? AND password=?', (role, password)).fetchone()
        if user:
            session['role'] = role
            if role == 'receiver':
                session['user_name'], session['user_phone'] = name, phone
                conn.execute('DELETE FROM active_receivers WHERE phone=?', (phone,))
                conn.execute('INSERT INTO active_receivers (name, phone) VALUES (?, ?)', (name, phone))
            conn.commit()
            return redirect(url_for(role))
        else:
            conn.execute('INSERT INTO security_logs (role_tried, ip) VALUES (?, ?)', (role, user_ip))
            conn.commit()
            return redirect(url_for('login_page', error='true'))

@app.route('/sender')
def sender():
    if session.get('role') != 'sender': return redirect('/')
    with get_db() as conn:
        receivers = conn.execute("SELECT DISTINCT name, phone FROM active_receivers WHERE last_seen > datetime('now', '-2 minutes')").fetchall()
    return render_template('sender.html', receivers=receivers)

@app.route('/receiver')
def receiver():
    if session.get('role') != 'receiver': return redirect('/')
    return render_template('receiver.html', user_name=session.get('user_name'))

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    target_str = request.form.get('target_receiver', 'all') 
    if file:
        filename = "".join([c for c in file.filename if c.isalnum() or c in ('.', '_')]).strip()
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        targets = target_str.split(',')
        if "all" in targets: socketio.emit('notify_receiver', {'filename': filename})
        else:
            for t in targets: socketio.emit('notify_receiver', {'filename': filename}, room=t)
        return redirect(url_for('sender', success='true'))
    return redirect(url_for('sender'))

# --- Admin Functionality Routes ---

@app.route('/admin')
def admin():
    if session.get('role') != 'admin': return redirect('/')
    files = os.listdir(UPLOAD_FOLDER)
    total_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, f)) for f in files if os.path.isfile(os.path.join(UPLOAD_FOLDER, f)))
    health = {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent}
    with get_db() as conn:
        failed_logs = conn.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 20').fetchall()
        feedbacks = conn.execute('SELECT * FROM feedback ORDER BY timestamp DESC').fetchall()
        blacklisted_ips = conn.execute('SELECT * FROM blacklist ORDER BY timestamp DESC').fetchall()
    return render_template('admin.html', files=files, used_mb=round(total_size/(1024*1024),2), 
                           health=health, failed_logs=failed_logs, feedbacks=feedbacks, blacklisted_ips=blacklisted_ips)

@app.route('/delete/<path:filename>')
def delete_file(filename):
    if session.get('role') == 'admin':
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path): os.remove(path)
    return redirect(url_for('admin'))

@app.route('/blacklist_ip/<ip>')
def blacklist_ip(ip):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('INSERT OR IGNORE INTO blacklist (ip, reason) VALUES (?, ?)', (ip, "Admin Block"))
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/unblock_ip/<ip>')
def unblock_ip(ip):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM blacklist WHERE ip=?', (ip,))
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/delete_feedback/<int:id>')
def delete_feedback(id):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM feedback WHERE id = ?', (id,))
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/clear_feedback')
def clear_feedback():
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM feedback')
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/clear_ids')
def clear_ids():
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM security_logs')
            conn.commit()
        return redirect(url_for('admin', ids_cleared='true'))
    return redirect('/')

@app.route('/change_password', methods=['POST'])
def change_password():
    if session.get('role') == 'admin':
        target = request.form.get('target_role')
        new_pass = request.form.get('new_password')
        with get_db() as conn:
            conn.execute('UPDATE users SET password = ? WHERE role = ?', (new_pass, target))
            conn.commit()
        # Redirect with success parameters for the JavaScript alert
        return redirect(url_for('admin', pass_success='true', role=target))
    return redirect('/')

# --- Shared Utilities ---

@app.route('/feedback_page')
def feedback_page():
    if 'role' not in session: return redirect('/')
    return render_template('feedback.html', user_name=session.get('user_name', session.get('role').capitalize()))

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'role' not in session: return redirect('/')
    msg = request.form.get('feedback_msg')
    if msg:
        with get_db() as conn:
            conn.execute('INSERT INTO feedback (sender_name, role, message) VALUES (?, ?, ?)', 
                         (session.get('user_name', 'System'), session.get('role'), msg))
            conn.commit()
    return redirect(url_for(session.get('role')))

@app.route('/file_history')
def file_history():
    if 'role' not in session: return redirect('/')
    files_data = []
    for f in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, f)
        if os.path.isfile(path):
            remaining = int(((os.path.getmtime(path) + 86400) - time.time()) / 3600)
            files_data.append({'name': f, 'remaining': max(0, remaining)})
    return render_template('history.html', files=files_data)

@app.route('/logout')
def logout():
    phone, role = session.get('user_phone'), session.get('role')
    if role == 'receiver' and phone:
        with get_db() as conn:
            conn.execute('DELETE FROM active_receivers WHERE phone = ?', (phone,))
            conn.commit()
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/img/<path:filename>')
def serve_images(filename):
    return send_from_directory(IMG_FOLDER, filename)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("\n" + "="*50)
    print("INKWAKE SECURE HUB v2.0")
    print(f"Server initialized at: http://127.0.0.1:{port}")
    print("="*50 + "\n")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)