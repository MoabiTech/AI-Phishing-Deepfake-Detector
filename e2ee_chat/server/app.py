#!/usr/bin/env python3
"""
E2EE Chat Server - Relay Only, Cannot Decrypt Messages
"""
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
from datetime import datetime, timezone

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='threading', max_http_buffer_size=16 * 1024 * 1024)

users = {}
MAX_ENCRYPTED_FILE_CHARS = 15 * 1024 * 1024
MAX_ENCRYPTED_MESSAGE_CHARS = 64 * 1024

@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'users_online': len(users),
        'message': 'E2EE Chat Server - Relay Only'
    })

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'sid': request.sid})

@socketio.on('register')
def handle_register(data):
    """Register a display name and public encryption key for this connection."""
    if not isinstance(data, dict):
        emit('user_registered', {'success': False, 'error': 'Invalid registration data.'})
        return

    user_id = data.get('user_id')
    display_name = data.get('display_name')
    public_key = data.get('public_key')
    if (
        not isinstance(user_id, str)
        or not 1 <= len(user_id) <= 80
        or not isinstance(display_name, str)
        or not 2 <= len(display_name.strip()) <= 32
        or not isinstance(public_key, dict)
        or public_key.get('kty') != 'RSA'
        or public_key.get('alg') != 'RSA-OAEP-256'
        or not isinstance(public_key.get('n'), str)
        or not isinstance(public_key.get('e'), str)
    ):
        emit('user_registered', {'success': False, 'error': 'Invalid username or public key.'})
        return

    users[request.sid] = {
        'user_id': user_id,
        'display_name': display_name.strip(),
        'public_key': public_key,
        'sid': request.sid
    }
    emit('user_registered', {'success': True})
    emit('user_list', get_user_list(), broadcast=True)

@socketio.on('get_users')
def handle_get_users():
    emit('user_list', get_user_list())

def get_user_list():
    user_list = []
    for sid, user in users.items():
        user_list.append({
            'sid': sid,
            'display_name': user['display_name'],
            'public_key': user['public_key']
        })
    return user_list

@socketio.on('send_message')
def handle_message(data):
    """Relay ciphertext only; the server has no client private keys."""
    if not isinstance(data, dict) or request.sid not in users:
        emit('message_sent', {'status': 'failed', 'error': 'Register before sending messages.'})
        return

    recipient_sid = data.get('recipient_sid')
    encrypted_message = data.get('encrypted_message')
    encrypted_key = data.get('encrypted_key')
    iv = data.get('iv')
    if (
        not isinstance(recipient_sid, str)
        or not isinstance(encrypted_message, str)
        or len(encrypted_message) > MAX_ENCRYPTED_MESSAGE_CHARS
        or not isinstance(encrypted_key, str)
        or not isinstance(iv, str)
    ):
        emit('message_sent', {'status': 'failed', 'error': 'Invalid encrypted message.'})
        return

    if recipient_sid in users:
        emit('receive_message', {
            'from_sid': request.sid,
            'from_user': users[request.sid]['display_name'],
            'encrypted_message': encrypted_message,
            'encrypted_key': encrypted_key,
            'iv': iv,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message_type': data.get('message_type', 'text')
        }, room=recipient_sid)
        emit('message_sent', {'status': 'delivered'})
    else:
        emit('message_sent', {'status': 'failed', 'error': 'User not found'})

@socketio.on('send_file')
def handle_file(data):
    """Relay a size-limited encrypted file without modifying its bytes."""
    if not isinstance(data, dict) or request.sid not in users:
        emit('file_sent', {'status': 'failed', 'error': 'Register before sending files.'})
        return

    recipient_sid = data.get('recipient_sid')
    encrypted_file = data.get('encrypted_file')
    encrypted_key = data.get('encrypted_key')
    iv = data.get('iv')
    filename = data.get('filename')
    file_type = data.get('file_type')
    if (
        not isinstance(recipient_sid, str)
        or not isinstance(encrypted_file, str)
        or len(encrypted_file) > MAX_ENCRYPTED_FILE_CHARS
        or not isinstance(encrypted_key, str)
        or not isinstance(iv, str)
        or not isinstance(filename, str)
        or not 1 <= len(filename) <= 255
        or not isinstance(file_type, str)
        or len(file_type) > 128
    ):
        emit('file_sent', {'status': 'failed', 'error': 'Invalid or oversized encrypted file.'})
        return

    if recipient_sid in users:
        emit('receive_file', {
            'from_sid': request.sid,
            'from_user': users[request.sid]['display_name'],
            'encrypted_file': encrypted_file,
            'encrypted_key': encrypted_key,
            'iv': iv,
            'filename': filename,
            'file_type': file_type,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=recipient_sid)
        emit('file_sent', {'status': 'delivered'})
    else:
        emit('file_sent', {'status': 'failed'})

@socketio.on('disconnect')
def handle_disconnect():
    user_info = users.get(request.sid)
    if user_info:
        print(f'User disconnected: {user_info.get("user_id")}')
        del users[request.sid]
        emit('user_list', get_user_list(), broadcast=True)
    else:
        print(f'Client disconnected: {request.sid}')

if __name__ == '__main__':
    print('=' * 60)
    print('E2EE Chat Server Starting')
    print('Server acts as RELAY ONLY - cannot decrypt messages')
    print('=' * 60)
    socketio.run(app, debug=False, host='127.0.0.1', port=5000)
