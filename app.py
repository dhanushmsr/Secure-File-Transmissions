import os, sqlite3, psutil, time, threading
from flask import Flask, render_template, request, redirect, url_for, session, Response, abort, send_from_directory
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.secret_key = "secure_transmission_ultra_2026"

# Support for 500MB uploads
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 
socketio = SocketIO(app, cors_allowed_origins="*")
UPLOAD_FOLDER = 'static/uploads'
IMG_FOLDER = 'img'

if not os.path.exists(UPLOAD_FOLDER): 
    os.makedirs(UPLOAD_FOLDER)

# --- Database Core ---
def get_db():
    conn = sqlite3.connect('transmission_system.db')
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
    room = f"room_{data.get('phone')}"
    join_room(room)

@socketio.on('heartbeat')
def handle_heartbeat(data):
    with get_db() as conn:
        conn.execute('UPDATE active_receivers SET last_seen = CURRENT_TIMESTAMP WHERE name=? AND phone=?', 
                     (data.get('name'), data.get('phone')))
        conn.commit()

@socketio.on('send_message')
def handle_message(data):
    targets = data.get('targets')
    display_name = session.get('user_name', session.get('role', 'Node')).capitalize()
    msg_payload = {
        'user': display_name, 
        'msg': data.get('msg'), 
        'time': time.strftime('%H:%M')
    }
    
    if "all" in targets:
        socketio.emit('new_message', msg_payload)
    else:
        for t in targets:
            socketio.emit('new_message', msg_payload, room=t)
        emit('new_message', msg_payload)

# --- Routes ---

@app.route('/img/<path:filename>')
def serve_custom_images(filename):
    return send_from_directory(IMG_FOLDER, filename)

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
        blocked = conn.execute('SELECT * FROM blacklist WHERE ip=?', (user_ip,)).fetchone()
        if blocked:
            abort(403, description="IP Blocked")

        user = conn.execute('SELECT * FROM users WHERE role=? AND password=?', (role, password)).fetchone()
        if user:
            session['role'] = role
            if role == 'receiver':
                session['user_name'], session['user_phone'] = name, phone
                conn.execute('INSERT INTO active_receivers (name, phone) VALUES (?, ?)', (name, phone))
            conn.commit()
            return redirect(url_for(role))
        else:
            conn.execute('INSERT INTO security_logs (role_tried, ip) VALUES (?, ?)', (role, user_ip))
            conn.commit()
            return redirect(url_for('login_page', error='true'))

@app.route('/admin')
def admin():
    if session.get('role') != 'admin': return redirect('/')
    files = os.listdir(UPLOAD_FOLDER)
    total_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, f)) for f in files if os.path.isfile(os.path.join(UPLOAD_FOLDER, f)))
    used_mb = round(total_size / (1024 * 1024), 2)
    health = {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent}
    
    with get_db() as conn:
        receivers = conn.execute('''SELECT *, (strftime('%s', last_seen) - strftime('%s', login_time)) / 60 as duration 
                                    FROM active_receivers ORDER BY login_time DESC''').fetchall()
        failed_logs = conn.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 20').fetchall()
        feedbacks = conn.execute('SELECT * FROM feedback ORDER BY timestamp DESC').fetchall()
        blacklisted_ips = conn.execute('SELECT * FROM blacklist ORDER BY timestamp DESC').fetchall()
        
    return render_template('admin.html', files=files, used_mb=used_mb, 
                           percent=min((used_mb/500)*100, 100), health=health, 
                           receivers=receivers, failed_logs=failed_logs, 
                           feedbacks=feedbacks, blacklisted_ips=blacklisted_ips)

@app.route('/file_history')
def file_history():
    if 'role' not in session: return redirect('/')
    
    files_data = []
    if os.path.exists(UPLOAD_FOLDER):
        for f in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, f)
            if os.path.isfile(path):
                mtime = os.path.getmtime(path)
                remaining = int(((mtime + 86400) - time.time()) / 3600)
                files_data.append({
                    'name': f,
                    'remaining': max(0, remaining)
                })
    return render_template('history.html', files=files_data)

@app.route('/delete/<filename>')
def delete_file(filename):
    """FIXED: Admin route to delete files from server storage."""
    if session.get('role') == 'admin':
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path): 
            os.remove(path)
    return redirect(url_for('admin'))

@app.route('/feedback_page')
def feedback_page():
    if 'role' not in session: return redirect('/')
    display_name = session.get('user_name', session.get('role').capitalize())
    return render_template('feedback.html', user_name=display_name)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'role' not in session: return redirect('/')
    name = session.get('user_name', session.get('role').capitalize())
    role = session.get('role')
    msg = request.form.get('feedback_msg')
    if msg:
        with get_db() as conn:
            conn.execute('INSERT INTO feedback (sender_name, role, message) VALUES (?, ?, ?)', (name, role, msg))
            conn.commit()
    return redirect(url_for(role, feedback_success='true'))

@app.route('/delete_feedback/<int:id>')
def delete_feedback(id):
    if session.get('role') == 'admin':
        with get_db() as conn:
            conn.execute('DELETE FROM feedback WHERE id = ?', (id,))
            conn.commit()
    return redirect(url_for('admin'))

@app.route('/receiver')
def receiver():
    if session.get('role') != 'receiver': return redirect('/')
    return render_template('receiver.html', user_name=session.get('user_name'))

@app.route('/sender')
def sender():
    if session.get('role') != 'sender': return redirect('/')
    with get_db() as conn:
        receivers = conn.execute('SELECT DISTINCT name, phone FROM active_receivers WHERE last_seen > datetime("now", "-5 minutes")').fetchall()
    return render_template('sender.html', receivers=receivers)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    targets = request.form.getlist('target_receivers') 
    
    if file:
        filename = "".join([c for c in file.filename if c.isalnum() or c in ('.', '_')]).strip()
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        
        if "all" in targets:
            socketio.emit('notify_receiver', {'filename': filename})
        else:
            for t in targets:
                socketio.emit('notify_receiver', {'filename': filename}, room=t)
            
        return redirect(url_for('sender', success='true'))
    return redirect(url_for('sender'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
