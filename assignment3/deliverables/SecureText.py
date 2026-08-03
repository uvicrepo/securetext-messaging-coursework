#!/usr/bin/env python3
"""
References:

[1] cryptography.io. "Elliptic Curve Diffie-Hellman (ECDH) Key Exchange." https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/

[2] cryptography.io. "AES-GCM (AESGCM)." https://cryptography.io/en/latest/hazmat/primitives/aead/

[3] cryptography.io. "HKDF (HMAC-based Key Derivation Function)." https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF

[4] Krawczyk, H. and Eronen, P. "RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." IETF, 2010. https://www.rfc-editor.org/rfc/rfc5869

[5] NIST. "SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography." 2018. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final

[6] NIST. "SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC." 2007. https://csrc.nist.gov/pubs/sp/800/38/d/final

[7] Certicom Research. "SEC 2: Recommended Elliptic Curve Domain Parameters" (defines secp256r1 / P-256). https://www.secg.org/sec2-v2.pdf

[8] OWASP. "Session Management Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

"""

from email import message
import email
import socket
import threading
import json
import os
import sys
import time
from datetime import datetime
import hashlib
import queue
import hmac
import pyotp
from Crypto.Cipher import AES 
import qrcode
import requests, urllib.parse, secrets, webbrowser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 600000 
KEY = b'securetext_key' 
TOTP_KEY = bytes.fromhex('9b1f3c7a2e5d8041f6a9c3b7e0d24158a7c6f0e3b9d5a1c48f27e6b0d3a95c17')
TOTP_DIGEST = hashlib.sha1 
TOTP_MAX_ATTEMPTS = 2 
TOTP_LOCKOUT_SECONDS = 30 
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = 'http://localhost:8080/oauth/callback'
GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_EMAILS_URL = 'https://api.github.com/user/emails'
SESSION_MAX_ACTIONS = 10  
LOG_FILE = 'security.log' 

# Task 7
ECDH_CURVE = ec.SECP256R1()  # P-256 [1]
HKDF_INFO = b'handshake_data' # [3]

# Task 9
SESSION_TIMEOUT_SECONDS = 60    # short for testing
SESSION_WARNING_SECONDS = 30   # warn when this many seconds remain


def log_event(username, action, outcome, detail=""):
    line = f"{datetime.now().isoformat()} | user={username} | action={action} | outcome={outcome} | {detail}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(line)

def encrypt_totp_secret(secret):
    cipher = AES.new(TOTP_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(secret.encode())
    return (bytes(cipher.nonce) + bytes(tag) + bytes(ciphertext)).hex()

def decrypt_totp_secret(encrypted_secret):
    raw = bytes.fromhex(encrypted_secret)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(TOTP_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def verify_totp(secret, totp_input):
    totp = pyotp.TOTP(secret, digest = TOTP_DIGEST)
    if totp.verify(totp_input, valid_window=1): 
        return True
    else:
        time.sleep(10)
        print(f"[TOTP] VERIFICATION FAILED — Invalid TOTP code")
        return False

def generate_totp_secret():
    """Generate a TOTP secret key."""
    return pyotp.random_base32()

def save_challenge_key(username, key):
    with open(f".securetext_challenge_key_{username}", 'w') as f:
        f.write(key)

def load_challenge_key(username):
    with open(f".securetext_challenge_key_{username}") as f:
        return f.read().strip()

def parse_command_string(content):
    """Parse CMD=VALUE&KEY=VALUE format into a dict."""
    return dict(pair.split('=', 1) for pair in content.split('&') if '=' in pair)

def load_key():
    return KEY

def compute_mac(key, message):
    return hmac.new(key, message.encode('latin-1'), hashlib.sha256).hexdigest()

def verify_mac(key, message, mac):
    expected = compute_mac(key, message)
    result = hmac.compare_digest(expected, mac)
    if not result:
        print(f"[MAC] VERIFICATION FAILED — length extension attack detected")
        print(f"[MAC] Expected : {expected}")
        print(f"[MAC] Received : {mac}")
    return result

def hash_password(password, salt=None):
    """Hash password using PBKDF2 with SHA-256."""
    if salt is None:
        salt = os.urandom(32)  # 32 bytes = 256 bits
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), 
        salt, ITER, dklen=32)

    return salt.hex(), password_hash.hex()

def verify_password(password, stored_salt, stored_hash):
    """Verify password against PBKDF2 hash."""
    _, new_hash = hash_password(password, stored_salt)
    
    return new_hash == stored_hash

    # Helper to remove chrome output in user
def open_browser_quietly(url):
    devnull = os.open(os.devnull, os.O_RDWR)
    old_stdout, old_stderr = os.dup(1), os.dup(2)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    try:
        webbrowser.open(url)
    finally:
        os.dup2(old_stdout, 1)
        os.dup2(old_stderr, 2)
        os.close(old_stdout)
        os.close(old_stderr)
        os.close(devnull)

# region +++++SERVER++++
class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = '../../users.json'
        self.users = self.load_users()
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        self.key = load_key()
        self.totp_attempts = {}  # username -> {'count': int, 'locked_until': epoch timestamp}
        self.oauth_pending_state = {}  # conn -> CSRF state issued for that connection's in-progress OAuth flow
        self.session_type = {}  # username -> 'local' or 'oauth'
        self.pending_challenges = {} # T6.A
        self.session_action_count = {} # T6.B
        self.failed_login_streak = {} # T6.C - track failed login attempts for brute-force detection

        #Task 7
        # username -> PEM-encoded ECDH public key in-memory only. Server never sees a private key.
        self.public_keys = {}

        #Task 9
        self.last_activity = {}  # username -> timestamp of last processed command
        self.warned_users = set() # username set of users who have been warned about impending session expiration

    def generate_challenge(self, conn):
        challenge = secrets.token_hex(16)
        self.pending_challenges[conn] = challenge
        return challenge

    def verify_challenge_response(self, conn, username, response):
        challenge = self.pending_challenges.pop(conn, None)
        challenge_key = decrypt_totp_secret(self.users[username]['challenge_key'])
        return hmac.compare_digest(compute_mac(challenge_key.encode(), challenge), response)

    def load_users(self):
        """Load users from JSON file or create empty dict if file doesn't exist"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
        return {}
    
    def save_users(self):
        """Save users to JSON file with plaintext passwords (INSECURE!)"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def create_account(self, username, password, email):
        if username in self.users:
            return False, "Username already exists", None, None
        
        salt, password_hash = hash_password(password)
        totp_secret = generate_totp_secret()
        encrypted_secret = encrypt_totp_secret(totp_secret)
        challenge_key = secrets.token_hex(32)
        
        self.users[username] = {
            'password': password_hash,
            'salt': salt,
            'totp_secret': encrypted_secret,
            'challenge_key': encrypt_totp_secret(challenge_key),
            'email': email,
            'role': 'user',
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue'
        }
        self.save_users()
        return True, "Account created successfully", totp_secret, challenge_key

    def _record_failed_login(self, username):
        self.failed_login_streak[username] = self.failed_login_streak.get(username, 0) + 1
        if self.failed_login_streak[username] >= 3:
            print(f"ALERT: {self.failed_login_streak[username]} consecutive failed logins for {username}")

    def authenticate(self, username, password, totp_input):
        if username not in self.users:
            return False, "Username or Password is Incorrect"
        
        now = time.time()
        attempt = self.totp_attempts.get(username)
        if attempt and attempt['locked_until'] > now:
            return False, "Too many failed attempts. Try again later."
        
        if not verify_password(password, self.users[username]['salt'], self.users[username]['password']):
            self._record_failed_login(username)
            return False, "Username or Password is Incorrect"
        
        totp_secret = decrypt_totp_secret(self.users[username]['totp_secret'])
        if verify_totp(totp_secret, totp_input):
            self.totp_attempts.pop(username, None)
            self.failed_login_streak[username] = 0
            return True, "Login successful"
        else:
            self._record_failed_login(username)
            attempt = self.totp_attempts.setdefault(username, {'count': 0, 'locked_until': 0})
            attempt['count'] += 1
            if attempt['count'] >= TOTP_MAX_ATTEMPTS:
                attempt['locked_until'] = now + TOTP_LOCKOUT_SECONDS
                attempt['count'] = 0
            return False, "Username or Password is Incorrect"
    
    def build_url(self, state):
        params = {
            'client_id': GITHUB_CLIENT_ID,
            'redirect_uri': GITHUB_REDIRECT_URI,
            'scope': 'read:user user:email',
            'state': state
        }
        return GITHUB_AUTHORIZE_URL + '?' + urllib.parse.urlencode(params)

    def oauth_login(self, conn, redirect_url):
        expected_state = self.oauth_pending_state.pop(conn, None)
        parsed = urllib.parse.urlparse(redirect_url)
        qs = urllib.parse.parse_qs(parsed.query)
        code = qs.get('code', [None])[0]
        returned_state = qs.get('state', [None])[0]
        
        if not expected_state or returned_state != expected_state:
            return False, "OAuth state mismatch - login aborted", None, None
        if not code:
            return False, "No authorization code found in that URL", None, None
        
        token_resp = requests.post(GITHUB_TOKEN_URL, headers={'Accept': 'application/json'}, data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': GITHUB_REDIRECT_URI
        })
        access_token = token_resp.json().get('access_token')
        if not access_token:
            return False, "GitHub did not return an access token", None, None
        
        auth_header = {'Authorization': f'Bearer {access_token}'}
        github_user = requests.get(GITHUB_USER_URL, headers=auth_header).json()
        github_username = github_user.get('login')
        
        emails = requests.get(GITHUB_EMAILS_URL, headers=auth_header).json()
        primary_email = next((e['email'] for e in emails if e.get('primary')), None)
        
        matched_username = None
        if primary_email:
            for uname, record in self.users.items():
                if record.get('email') == primary_email:
                    matched_username = uname
                    break
                
        if matched_username:
            login_username = matched_username
            challenge_key = decrypt_totp_secret(self.users[login_username]['challenge_key'])
        else:
            login_username = github_username
            if login_username in self.users:
                login_username = f"{github_username}_github"
            challenge_key = secrets.token_hex(32)
            self.users[login_username] = {
                'email': primary_email,
                'oauth_provider': 'github',
                'role': 'admin',
                'challenge_key': encrypt_totp_secret(challenge_key),
                'created_at': datetime.now().isoformat()
            }
            self.save_users()
            
        return True, f"Logged in via GitHub as {login_username}", login_username, challenge_key
    
    def reset_password(self, username, new_password):
        """Basic password reset - just requires existing username"""
        if username not in self.users:
            return False, "Username not found"
        
        # SECURITY VULNERABILITY: No proper verification for password reset!
        self.users[username]['password'] = new_password
        self.save_users()
        return True, "Password reset successful"
    
    #region: handle_client
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        print(f"New connection from {addr}")
        current_user = None
        
        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    command = message.get('command')

                    #region: 9session_expiration
                    # Task 9 - time-based session expiration
                    if current_user:
                        now = time.time()
                        elapsed = now - self.last_activity.get(current_user, now)
                        if elapsed >= SESSION_TIMEOUT_SECONDS:
                            log_event(current_user, 'SESSION_TIMEOUT', 'expired')
                            self.active_connections.pop(current_user, None)
                            self.session_type.pop(current_user, None)
                            self.session_action_count.pop(current_user, None)
                            self.last_activity.pop(current_user, None)
                            self.public_keys.pop(current_user, None)
                            self.warned_users.discard(current_user)
                            current_user = None
                            conn.send(json.dumps({'status': 'session_expired', 'message': 'Session expired - log in again'}).encode('utf-8'))
                            continue
                        if command != 'SESSION_STATUS':
                            self.last_activity[current_user] = now
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        email = message.get('email')
                        success, msg, totp_secret, challenge_key = self.create_account(username, password, email)
                        response = {'status': 'success' if success else 'error', 'message': msg,
                                    'totp_secret': totp_secret, 'challenge_key': challenge_key}
                        
                    elif command == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        totp_input = message.get('totp_input')
                        success, msg = self.authenticate(username, password, totp_input)
                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                            self.session_type[username] = 'local'
                            self.session_action_count[username] = 0
                            self.last_activity[username] = time.time() # Task 9 
                            self.warned_users.discard(username) 
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'OAUTH_START':
                        if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
                            response = {'status': 'error', 'message': 'Server missing GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET env vars'}
                        else:
                            state = secrets.token_urlsafe(16)
                            self.oauth_pending_state[conn] = state
                            response = {'status': 'success', 'auth_url': self.build_url(state)}
                            
                    elif command == 'OAUTH_CALLBACK':
                        redirect_url = message.get('redirect_url')
                        success, msg, oauth_username, challenge_key = self.oauth_login(conn, redirect_url)
                        if success:
                            current_user = oauth_username
                            self.active_connections[oauth_username] = conn
                            self.session_type[oauth_username] = 'oauth'
                            self.session_action_count[oauth_username] = 0
                            self.last_activity[oauth_username] = time.time() # Task 9
                            self.warned_users.discard(oauth_username)
                        response = {'status': 'success' if success else 'error', 'message': msg,
                                    'username': oauth_username, 'challenge_key': challenge_key}
                        
                    elif command == 'LOGOUT':
                        if current_user:
                            self.active_connections.pop(current_user, None)
                            self.session_type.pop(current_user, None)
                            self.session_action_count.pop(current_user, None)
                            self.last_activity.pop(current_user, None)
                            self.public_keys.pop(current_user, None)
                            self.warned_users.discard(current_user)
                            response = {'status': 'success', 'message': 'Logged out'}
                            current_user = None
                        else:
                            response = {'status': 'error', 'message': 'Not logged in'}
                            
                    elif command == 'SEND_MESSAGE':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            recipient = message.get('recipient')
                            msg_content = message.get('content')
                            received_mac = message.get('mac')

                            # For demonstarating 4.1.4 Attack
                            #print(f"SERVER VIEW — content: {msg_content}")
                            #print(f"SERVER VIEW — public keys on file: {list(self.public_keys.keys())}")

                            if not verify_mac(self.key, msg_content, received_mac):
                                response = {'status': 'error', 'message': 'Message integrity check failed'}
                                
                            # Send message to recipient if they're online
                            elif recipient in self.active_connections:
                                msg_data = {
                                    'type': 'MESSAGE',
                                    'from': current_user,
                                    'content': msg_content,
                                    'mac': received_mac,
                                    'is_command': message.get('is_command', False),
                                    'timestamp': datetime.now().isoformat()
                                }
                                try:
                                    self.active_connections[recipient].send(
                                        json.dumps(msg_data).encode('utf-8')
                                    )
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except:
                                    # Remove inactive connection
                                    del self.active_connections[recipient]
                                    response = {'status': 'error', 'message': 'Recipient is offline'}
                            else:
                                response = {'status': 'error', 'message': 'Recipient is offline'}

                    #region: 7PUBLISH/GET_KEY
                    elif command == 'PUBLISH_KEY':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            self.public_keys[current_user] = message.get('public_key')
                            response = {'status': 'success', 'message': 'Public key published'}

                    elif command == 'GET_KEY':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            peer = message.get('username')
                            if peer in self.public_keys:
                                response = {'status': 'success', 'public_key': self.public_keys[peer]}
                            else:
                                response = {'status': 'error', 'message': f'No public key on file for {peer}'}

                    #region:9session_status
                    elif command == 'SESSION_STATUS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            remaining = SESSION_TIMEOUT_SECONDS - (time.time() - self.last_activity.get(current_user, time.time()))
                            response = {'status': 'success', 'remaining_seconds': max(0, int(remaining))}

                    elif command == 'RESET_PASSWORD':
                        username = message.get('username')
                        new_password = message.get('new_password')
                        totp_input = message.get('totp_input')
                        if username in self.users and verify_totp(decrypt_totp_secret(self.users[username]['totp_secret']), totp_input):
                            success, msg = self.reset_password(username, new_password)
                            response = {'status': 'success' if success else 'error', 'message': msg}
                        else:
                            response = {'status': 'error', 'message': 'Reset failed'}
                    
                    elif command == 'LIST_USERS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        elif self.users[current_user].get('role') != 'admin':
                            response = {'status': 'error', 'message': 'Admin only'}
                        else:
                            online_users = list(self.active_connections.keys())
                            all_users = list(self.users.keys())
                            response = {'status': 'success', 'online_users': online_users, 'all_users': all_users}
                    
                    elif command == 'VIEW_LOGS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        elif self.users[current_user].get('role') != 'admin':
                            response = {'status': 'error', 'message': 'Admin only'}
                        else:
                            challenge_response = message.get('challenge_response')
                            if challenge_response is None:
                                response = {'status': 'challenge_required', 'challenge': self.generate_challenge(conn)}
                            elif self.verify_challenge_response(conn, current_user, challenge_response):
                                with open(LOG_FILE) as f:
                                    response = {'status': 'success', 'logs': ''.join(f.readlines()[-20:])}
                            else:
                                response = {'status': 'error', 'message': 'Challenge verification failed'}
                                
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}

                    #region: 9session_warning
                    log_event(current_user or message.get('username', 'unknown'), 
                                command, response.get('status', 'unknown'), 
                                response.get('message', ''))
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
        except ConnectionResetError:
            pass
        finally:
            # Clean up connection
            if current_user and current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"Connection from {addr} closed")

    #region:9session_monitor
    # Task 9 - background thread that proactively pushes warnings/expiry to idle
    # sessions, instead of waiting for the client's next command.
    def session_monitor(self):
        while True:
            time.sleep(5)  # how often to check for idle sessions
            now = time.time()
            for username in list(self.active_connections.keys()):
                last = self.last_activity.get(username)
                conn = self.active_connections.get(username)
                if last is None or conn is None:
                    continue

                remaining = SESSION_TIMEOUT_SECONDS - (now - last)

                if remaining <= 0:
                    log_event(username, 'SESSION_TIMEOUT', 'expired')
                    self.active_connections.pop(username, None)
                    self.session_type.pop(username, None)
                    self.session_action_count.pop(username, None)
                    self.last_activity.pop(username, None)
                    self.public_keys.pop(username, None)
                    self.warned_users.discard(username)
                    try:
                        conn.send(json.dumps({'type': 'SESSION_EXPIRED', 'message': 'Session expired - log in again'}).encode('utf-8'))
                    except Exception:
                        pass
                elif remaining <= SESSION_WARNING_SECONDS and username not in self.warned_users:
                    self.warned_users.add(username)
                    try:
                        conn.send(json.dumps({'type': 'SESSION_WARNING', 'message': f'Your session will expire in {int(remaining)} seconds due to inactivity.'}).encode('utf-8'))
                    except Exception:
                        pass
    
    def start_server(self):
        """Start the TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            # Task 9 - start background thread to monitor session expiration
            monitor_thread = threading.Thread(target=self.session_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()

# region +++++CLIENT++++ 
class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False
        self.response_queue = queue.Queue()
        self.key = load_key()

        #Task 7
        self.ecdh_private_key = None
        self.ecdh_public_pem = None
        self.session_keys = {}  # peer username -> derived 32-byte AES key

    #region:9session_status
    def check_session_status(self):
        response = self.send_command({'command': 'SESSION_STATUS'})
        if response.get('status') == 'success':
            minutes = response['remaining_seconds'] // 60 # type: ignore
            seconds = response['remaining_seconds'] % 60
            print(f"Session active. Time remaining: {minutes}m {seconds}s")
        else:
            print(response.get('message', 'Could not retrieve session status'))
        
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            print("Error: Could not connect to server. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def listen_for_messages(self):
        """Listen for incoming messages in a separate thread"""
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8') # type: ignore
                if data:
                    message = json.loads(data)
                    if message.get('type') == 'MESSAGE':
                        mac_status = "VALID" if verify_mac(self.key, message['content'], message.get('mac')) else "INVALID"
                        #region:8AESGCM
                        sender = message['from']
                        shared_key = self.get_shared_key(sender, direct=True)
                        if shared_key:
                            try:
                                raw = bytes.fromhex(message['content'])
                                nonce, ciphertext = raw[:12], raw[12:]
                                plaintext = AESGCM(shared_key).decrypt(nonce, ciphertext, None).decode('utf-8')
                            except Exception:
                                plaintext = "DECRYPTION FAILED"
                        else:
                            plaintext = "NO SHARED KEY"

                        if message.get('is_command'):
                            parsed = parse_command_string(plaintext)
                            print(f"\n{mac_status} [{message['timestamp']}] {sender} (COMMAND): {parsed}")
                        else:
                            print(f"\n{mac_status} [{message['timestamp']}] {sender}: {plaintext}")
                        print(">> ", end="", flush=True)
                    # Task 9 - session warning and expiration messages
                    elif message.get('type') == 'SESSION_WARNING':
                        print(f"\n{message['message']}")
                        print(">> ", end="", flush=True)
                    elif message.get('type') == 'SESSION_EXPIRED':
                        self.logged_in = False
                        self.running = False
                        self.ecdh_private_key = None
                        self.session_keys = {}
                        print(f"\n{message['message']}")
                    else:
                        self.response_queue.put(message)
                        
            except:
                break

    #region:7ecdh_keypair
    # Generates keypair [1]
    def generate_ecdh_keypair(self):
        self.ecdh_private_key = ec.generate_private_key(ECDH_CURVE)
        public_key = self.ecdh_private_key.public_key()
        self.ecdh_public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.session_keys = {}

        print(f"Generated new P-256 key pair for {self.username}")
        response = self.send_command({'command': 'PUBLISH_KEY', 'public_key': self.ecdh_public_pem})
        print(f"ECDH {response['message']}")

    def get_shared_key(self, peer_username, direct=False):
        if peer_username in self.session_keys:
            print(f"Using cached shared session key with {peer_username}: {self.session_keys[peer_username].hex()}")
            return self.session_keys[peer_username]

        if direct:
            # Called from the message-listening thread itself. That thread is the
            # only reader of the socket, so it can't block on response_queue (that
            # queue is only ever filled by this same thread) - send and read directly.
            self.socket.send(json.dumps({'command': 'GET_KEY', 'username': peer_username}).encode('utf-8')) # type: ignore
            response = json.loads(self.socket.recv(4096).decode('utf-8')) # type: ignore
        else:
            response = self.send_command({'command': 'GET_KEY', 'username': peer_username})
        if response['status'] != 'success':
            print(f"ECDH {response['message']}")
            return None

        peer_public_key = serialization.load_pem_public_key(response['public_key'].encode('utf-8'))
        # Actual Diffie-Hellman key exchange to derive a shared secret
        shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key) # type: ignore

        # AES derived key from shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO
        ).derive(shared_secret)

        self.session_keys[peer_username] = derived_key
        print(f"ECDH Derived shared session key with {peer_username}: {derived_key.hex()}")
        return derived_key
    
    def oauth_login(self):
        print("\n=== GitHub Login ===")
        response = self.send_command({'command': 'OAUTH_START'})
        if response['status'] != 'success':
            print(f"{response['message']}")
            return
        
        auth_url = response['auth_url']
        print("Opening your browser to authorize with GitHub...")
        print(f"If it doesn't open automatically, visit:\n{auth_url}")
        open_browser_quietly(auth_url)
        
        redirect_url = input("\nAfter authorizing, paste the full URL you were redirected to here: ").strip()
        
        response = self.send_command({'command': 'OAUTH_CALLBACK', 'redirect_url': redirect_url})
        print(f"{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = response.get('username')
            self.running = True
            save_challenge_key(self.username, response['challenge_key'])
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
            #region:7oauth->ecdh_keypair
            self.generate_ecdh_keypair()

    def send_command(self, command_data):
        """Send command to server and get response"""
        try:
            self.socket.send(json.dumps(command_data).encode('utf-8')) # type: ignore
            if self.running:
                response = self.response_queue.get(timeout=10)
            else:
                response = json.loads(self.socket.recv(4096).decode('utf-8')) # type: ignore
            return response
        except queue.Empty:
            print("Timeout: no response from server")
            return {'status': 'error', 'message': 'Communication timeout'}
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
        
    def view_logs(self):
        response = self.send_command_reauth({'command': 'VIEW_LOGS'})
        print(response.get('logs') or response['message'])

    def send_command_reauth(self, command_data):
        response = self.send_command(command_data)
        if response.get('status') == 'challenge_required':
            key = load_challenge_key(self.username)
            command_data['challenge_response'] = compute_mac(key.encode(), response['challenge'])
            response = self.send_command(command_data)
        return response

    def create_account(self):
        """Create a new account"""
        print("\n=== Create Account ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        email = input("Enter email (used for GitHub account linking, can be fake e.g. alice@example.com): ").strip()

        if not username or not password:
            print("Username and password cannot be empty!")
            return

        command = {
            'command': 'CREATE_ACCOUNT',
            'username': username,
            'password': password,
            'email': email
        }

        response = self.send_command(command)

        if response['status'] == 'success':
            save_challenge_key(username, response['challenge_key'])
            secret = response['totp_secret']
            uri = pyotp.TOTP(secret, digest=TOTP_DIGEST).provisioning_uri(name=username, issuer_name="SecureText")
            print(f"[TOTP] Scan this QR code with your authenticator app (or enter the secret manually: {secret})")
            qr = qrcode.QRCode(border=1) #change this first if QR looks weird
            qr.add_data(uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
    
    def login(self):
        """Login to the system"""
        print("\n=== Login ===")
        
        username = input("Enter username: ").strip()
        password =input("Enter password: ").strip()
        totp_input = input("Enter TOTP code: ").strip()
        
        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password,
            'totp_input': totp_input
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
            self.running = True
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
            #region:7login->ecdh_keypair
            self.generate_ecdh_keypair()
    
    def send_message(self):
        """Send a message with MAC to another user"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
        
        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()
        content = input("Enter message or command: ").strip()
        
        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return
        
        is_command = content.startswith('CMD=')
        #region:8encryptingCommand
        shared_key = self.get_shared_key(recipient)
        if not shared_key:
            print("Could not establish a shared key with recipient. Message not sent.")
            return

        nonce = os.urandom(12)
        aesgcm = AESGCM(shared_key)
        ciphertext = aesgcm.encrypt(nonce, content.encode('utf-8'), None)

        # Testing Attack 4.2.4 - simulate an active attacker tampering with the ciphertext in transit
        #ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        encrypted_content = (nonce + ciphertext).hex()

        #region:9TESTING
        #print(f"Encrypted content sent: {encrypted_content}")

        mac = compute_mac(self.key, encrypted_content)

        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'content': encrypted_content,
            'mac': mac,
            'is_command': is_command
        }
        #region:9session_warning
        response = self.send_command(command)
        print(response.get('message', 'No response message received'))

        if response.get('status') == 'session_expired':
            self.logged_in = False
            self.running = False
            self.ecdh_private_key = None
            self.session_keys = {}
            print("Session expired. Please log in again.")
    
    def list_users(self):
        """List all users and show who's online"""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        command = {'command': 'LIST_USERS'}
        response = self.send_command(command)

        # Task 9 - session expiration and warning
        if response.get('status') == 'session_expired':
            self.logged_in = False
            self.running = False
            self.ecdh_private_key = None
            self.session_keys = {}
        elif response['status'] == 'success':
            print(f"\nOnline users: {', '.join(response['online_users'])}")
            print(f"All users: {', '.join(response['all_users'])}")
        else:
            print(f"Error: {response['message']}")
    
    def reset_password(self):
        """Reset password (basic implementation)"""
        print("\n=== Reset Password ===")
        username = input("Enter username: ").strip()
        new_password = input("Enter new password: ").strip()
        
        command = {
            'command': 'RESET_PASSWORD',
            'username': username,
            'new_password': new_password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        print("=== SecureText Messenger (Insecure Version) ===")
        print("WARNING: This is an intentionally insecure implementation for educational purposes!")
        
        while True:
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Login with GitHub")
                print("4. Reset Password")
                print("5. Exit")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.oauth_login()
                elif choice == '4':
                    self.reset_password()
                elif choice == '5':
                    break
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Logout")
                print("4. View Logs (admin only)")
                # print("5. Derive shared key with a user (Task 7 test)")
                # print("6. Session Status")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                #region: 9manual_logout
                elif choice == '3':
                    self.send_command({'command': 'LOGOUT'})
                    self.logged_in = False
                    self.running = False
                    self.ecdh_private_key = None
                    self.session_keys = {}
                elif choice == '4':
                    self.view_logs()
                # elif choice == '5':
                #     peer = input("Enter username to derive shared key with: ").strip()
                #     self.get_shared_key(peer)
                # elif choice == '6':
                #     self.check_session_status()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run as server
        server = SecureTextServer()
        server.start_server()
    else:
        # Run as client
        client = SecureTextClient()
        client.run()

if __name__ == "__main__":
    main()
