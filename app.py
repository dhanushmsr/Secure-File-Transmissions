import os, sqlite3, psutil, time, threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, abort, send_from_directory, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = "secure_transmission_ultra_2026"

# Support for 500MB uploads
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 

# FIXED: Set threading for Windows compatibility and stable WebSockets
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_name TEXT, 
                         role TEXT, message TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS file_permissions 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, target_phone TEXT)''')
        
        # Persistent Login History Table
        conn.execute('''CREATE TABLE IF NOT EXISTS login_history 
                        (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, 
                         timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # CLEANUP: Clear volatile active ghosts on restart
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
                    try: 
                        os.remove(path)
                        with get_db() as conn:
                            conn.execute('DELETE FROM file_permissions WHERE filename = ?', (f,))
                            conn.commit()
                    except: pass
        time.sleep(3600)

threading.Thread(target=auto_cleanup, daemon=True).start()

# --- WebSocket Events (Direct Discovery) ---

@socketio.on('join_network')
def on_join(data):
    phone, name = data.get('phone'), data.get('name')
    if phone:
        join_room(f"room_{phone}")
        session['user_phone'] = phone 
        session['user_name'] = name
        with get_db() as conn:
            conn.execute('DELETE FROM active_receivers WHERE phone=?', (phone,))
            conn.execute('INSERT INTO active_receivers (name, phone) VALUES (?, ?)', (name, phone))
            conn.execute('INSERT INTO login_history (name, phone) VALUES (?, ?)', (name, phone))
            conn.commit()
        socketio.emit('update_user_list', {'name': name, 'phone': phone})

@socketio.on('request_discovery')
def handle_discovery():
    emit('discovery_ping', {}, broadcast=True)

@socketio.on('discovery_pong')
def handle_pong(data):
    socketio.emit('node_online', data)

@socketio.on('disconnect')
def on_disconnect():
    phone = session.get('user_phone')
    if phone:
        socketio.emit('remove_user_list', {'phone': phone})
        with get_db() as conn:
            conn.execute('DELETE FROM active_receivers WHERE phone=?', (phone,))
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

# --- Base Routes ---

@app.route('/')
def login_page():
    if 'role' in session: return redirect(url_for(session['role']))
    return render_template('login.html', error=request.args.get('error'))

@app.route('/auth', methods=['POST'])
def auth():
    role, password = request.form.get('role'), request.form.get('password')
    name, phone = request.form.get('name', ''), request.form.get('phone', '')
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE role=? AND password=?', (role, password)).fetchone()
        if user:
            session['role'] = role
            if role == 'receiver':
                session['user_name'], session['user_phone'] = name, phone
                conn.execute('DELETE FROM active_receivers WHERE phone=?', (phone,))
                conn.execute('INSERT INTO active_receivers (name, phone) VALUES (?, ?)', (name, phone))
                conn.execute('INSERT INTO login_history (name, phone) VALUES (?, ?)', (name, phone))
            conn.commit()
            return redirect(url_for(role))
        else:
            return redirect(url_for('login_page', error='true'))

@app.route('/sender')
def sender():
    if session.get('role') != 'sender': return redirect('/')
    return render_template('sender.html')

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
        with get_db() as conn:
            for t in targets:
                clean_target = t.replace('room_', '')
                conn.execute('INSERT INTO file_permissions (filename, target_phone) VALUES (?, ?)', (filename, clean_target))
            conn.commit()
        if "all" in targets:
            socketio.emit('notify_receiver', {'filename': filename})
        else:
            for t in targets:
                socketio.emit('notify_receiver', {'filename': filename}, room=t)
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "error"}), 400

@app.route('/api/active_nodes')
def get_active_nodes():
    if session.get('role') != 'sender': return jsonify([]), 403
    nodes = []
    with get_db() as conn:
        receivers = conn.execute("SELECT name, phone FROM active_receivers").fetchall()
    for r in receivers:
        nodes.append({"name": r['name'], "phone": r['phone'], "status": "online"})
    return jsonify(nodes)

# --- FIXED ADMIN MANAGEMENT ROUTES ---

@app.route('/admin')
def admin():
    if session.get('role') != 'admin': return redirect('/')
    files = [f for f in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
    total_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, f)) for f in files)
    health = {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent}
    with get_db() as conn:
        feedbacks = conn.execute('SELECT * FROM feedback ORDER BY timestamp DESC').fetchall()
    return render_template('admin.html', files=files, used_mb=round(total_size/(1024*1024),2), 
                           health=health, feedbacks=feedbacks)

@app.route('/delete/<filename>')
def delete_file(filename):
    if session.get('role') == 'admin':
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path): os.remove(path)
        with get_db() as conn:
            conn.execute('DELETE FROM file_permissions WHERE filename = ?', (filename,))
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if session.get('role') == 'admin':
        target = request.form.get('target_role')
        new_pass = request.form.get('new_password')
        with get_db() as conn:
            conn.execute('UPDATE users SET password = ? WHERE role = ?', (new_pass, target))
            conn.commit()
        return redirect(url_for('admin', pass_success='true', role=target))
    return redirect('/')

@app.route('/clear_feedback')
def clear_feedback():
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM feedback')
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/delete_feedback/<int:id>')
def delete_individual_feedback(id):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM feedback WHERE id = ?', (id,))
            conn.commit()
    return redirect(url_for('admin'))

# --- Login History Management ---

@app.route('/admin/history')
def login_history():
    if session.get('role') != 'admin': return redirect('/')
    with get_db() as conn:
        history = conn.execute('SELECT * FROM login_history ORDER BY timestamp DESC').fetchall()
    return render_template('admin_history.html', history=history)

@app.route('/admin/delete_history/<int:id>')
def delete_individual_history(id):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM login_history WHERE id = ?', (id,))
            conn.commit()
    return redirect(url_for('login_history'))

@app.route('/admin/clear_all_history')
def clear_all_history():
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM login_history')
            conn.commit()
    return redirect(url_for('login_history'))

# --- Feedback & History Views ---

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
    role, phone = session.get('role'), session.get('user_phone')
    files_data = []
    with get_db() as conn:
        if role in ['admin', 'sender']:
            allowed_files = conn.execute('SELECT DISTINCT filename FROM file_permissions').fetchall()
        else:
            allowed_files = conn.execute('SELECT DISTINCT filename FROM file_permissions WHERE target_phone = "all" OR target_phone = ?', (phone,)).fetchall()
        
        allowed_list = [f['filename'] for f in allowed_files]
        for f in os.listdir(UPLOAD_FOLDER):
            if f in allowed_list:
                is_public = conn.execute('SELECT 1 FROM file_permissions WHERE filename = ? AND target_phone = "all"', (f,)).fetchone()
                path = os.path.join(UPLOAD_FOLDER, f)
                if os.path.isfile(path):
                    remaining = int(((os.path.getmtime(path) + 86400) - time.time()) / 3600)
                    files_data.append({'name': f, 'remaining': max(0, remaining), 'privacy': 'Public' if is_public else 'Private'})
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
    
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)