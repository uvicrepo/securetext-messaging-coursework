#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2026
SecureText Console Messenger (Insecure Genesis Version)
A basic console-based messenger application with intentional security vulnerabilities.

Features:
- Account creation with plaintext password storage
- User login
- Send/receive messages via TCP sockets
- Basic password reset functionality

References:
[1] PyOTP: https://pypi.org/project/pyotp/
[2] https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md
[3] https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
[4] https://www.rfc-editor.org/rfc/rfc6238 (Section 1.2)
[5] https://github.com/google/google-authenticator/wiki/Key-Uri-Format
[6] https://pyauth.github.io/pyotp/#quick-overview-of-using-one-time-passwords-on-your-phone
[7] https://pypi.org/project/qrcode/

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
from Crypto.Cipher import AES #[3]
import qrcode
import requests, urllib.parse, secrets, webbrowser

ITER = 600000 
KEY = b'securetext_key'  # Key for HMAC - This is unsafe and should be securely generated and stored in a real application.
TOTP_KEY = bytes.fromhex('9b1f3c7a2e5d8041f6a9c3b7e0d24158a7c6f0e3b9d5a1c48f27e6b0d3a95c17')  # AES-256 key, same caveat as KEY.
# SHA1: RFC 6238 base algorithm; most authenticator apps ignore the otpauth "algorithm" param and assume it.
TOTP_DIGEST = hashlib.sha1 #[4,5]
TOTP_MAX_ATTEMPTS = 2 # 
TOTP_LOCKOUT_SECONDS = 30 # short for testing; increase for real use

# GitHub OAuth [Task 5]
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = 'http://localhost:8080/oauth/callback'
GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_EMAILS_URL = 'https://api.github.com/user/emails'


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
    if totp.verify(totp_input, valid_window=1):  # Allow for a 1-step window to account for clock skew, RFC 6238 Section 5.2
        return True
    else:
        time.sleep(10)
        print(f"[TOTP] VERIFICATION FAILED — Invalid TOTP code")
        return False

def generate_totp_secret():
    """Generate a TOTP secret key."""
    return pyotp.random_base32()

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

# region SERVER
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
            return False, "Username already exists", None

        salt, password_hash = hash_password(password)
        totp_secret = generate_totp_secret()
        encrypted_secret = encrypt_totp_secret(totp_secret)

        self.users[username] = {
            'password': password_hash,
            'salt': salt,
            'totp_secret': encrypted_secret,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue',
            'email' : email
        }
        self.save_users()
        return True, "Account created successfully", totp_secret

    #region authenticate
    # Implementing TOTP [1], and OWASP recommended response [2]
    def authenticate(self, username, password, totp_input):
        if username not in self.users:
            return False, "Username or Password is Incorrect"

        now = time.time()
        attempt = self.totp_attempts.get(username)
        if attempt and attempt['locked_until'] > now:
            return False, "Too many failed attempts. Try again later."

        if not verify_password(password, self.users[username]['salt'], self.users[username]['password']):
            return False, "Username or Password is Incorrect"

        totp_secret = decrypt_totp_secret(self.users[username]['totp_secret'])
        if verify_totp(totp_secret, totp_input):
            self.totp_attempts.pop(username, None)
            return True, "Login successful"
        else:
            attempt = self.totp_attempts.setdefault(username, {'count': 0, 'locked_until': 0})
            attempt['count'] += 1
            if attempt['count'] >= TOTP_MAX_ATTEMPTS:
                attempt['locked_until'] = now + TOTP_LOCKOUT_SECONDS
                attempt['count'] = 0
            return False, "Username or Password is Incorrect"
    
    #region: build_github_authorize_url
    def build_github_authorize_url(self, state):
        params = {
            'client_id': GITHUB_CLIENT_ID,
            'redirect_uri': GITHUB_REDIRECT_URI,
            'scope': 'read:user user:email',
            'state': state
        }
        return GITHUB_AUTHORIZE_URL + '?' + urllib.parse.urlencode(params)

    #region: oauth_login
    def oauth_login(self, conn, redirect_url):
        expected_state = self.oauth_pending_state.pop(conn, None)
        parsed = urllib.parse.urlparse(redirect_url)
        qs = urllib.parse.parse_qs(parsed.query)
        code = qs.get('code', [None])[0]
        returned_state = qs.get('state', [None])[0]

        if not expected_state or returned_state != expected_state:
            return False, "OAuth state mismatch - login aborted", None
        if not code:
            return False, "No authorization code found in that URL", None
        
        token_resp = requests.post(GITHUB_TOKEN_URL, headers={'Accept': 'application/json'}, data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': GITHUB_REDIRECT_URI
        })
        access_token = token_resp.json().get('access_token')
        if not access_token:
            return False, "GitHub did not return an access token", None
        
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
            conflict_note = ""
        else:
            login_username = github_username
            conflict_note = ""
            if login_username in self.users:
                login_username = f"{github_username}_github"
                conflict_note = f" (username '{github_username}' already taken; defaulting to: '{login_username}')"
            if login_username not in self.users:
                self.users[login_username] = {
                    'email': primary_email,
                    'oauth_provider': 'github',
                    'created_at': datetime.now().isoformat()
                }
                self.save_users()

        return True, f"Logged in via GitHub as {login_username}{conflict_note}", login_username

    def reset_password(self, username, new_password):
        """Basic password reset - just requires existing username"""
        if username not in self.users:
            return False, "Username not found"
        
        # SECURITY VULNERABILITY: No proper verification for password reset!
        self.users[username]['password'] = new_password
        self.save_users()
        return True, "Password reset successful"
    
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
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        email = message.get('email')
                        success, msg, totp_secret = self.create_account(username, password, email)
                        response = {'status': 'success' if success else 'error', 
                                    'message': msg,
                                    'totp_secret': totp_secret if success else None}
                        
                    elif command == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        # Implementing TOTP [1]
                        totp_input = message.get('totp_input')
                        totp_actual = message.get('totp_actual')
                        success, msg = self.authenticate(username, password, totp_input)
                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                            self.session_type[username] = 'local'
                        response = {'status': 'success' if success else 'error', 'message': msg}

                    elif command == 'OAUTH_START':
                        if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
                            response = {'status': 'error', 'message': 'Server missing GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET env vars'}
                        else:
                            state = secrets.token_urlsafe(16)
                            self.oauth_pending_state[conn] = state
                            response = {'status': 'success', 'auth_url': self.build_github_authorize_url(state)}

                    elif command == 'OAUTH_CALLBACK':
                        redirect_url = message.get('redirect_url')
                        success, msg, oauth_username = self.oauth_login(conn, redirect_url)
                        if success:
                            current_user = oauth_username
                            self.active_connections[oauth_username] = conn
                            self.session_type[oauth_username] = 'oauth'
                        response = {'status': 'success' if success else 'error', 'message': msg,
                                    'username': oauth_username if success else None}

                    elif command == 'LOGOUT':
                        if current_user:
                            self.active_connections.pop(current_user, None)
                            self.session_type.pop(current_user, None)
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
                    
                    elif command == 'RESET_PASSWORD':
                        username = message.get('username')
                        new_password = message.get('new_password')
                        success, msg = self.reset_password(username, new_password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LIST_USERS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            online_users = list(self.active_connections.keys())
                            all_users = list(self.users.keys())
                            response = {
                                'status': 'success', 
                                'online_users': online_users,
                                'all_users': all_users
                            }
                    
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
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
    
    def start_server(self):
        """Start the TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
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

# region CLIENT
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
                data = self.socket.recv(4096).decode('utf-8')
                if data:
                    message = json.loads(data)
                    if message.get('type') == 'MESSAGE':
                        mac_status = "VALID" if verify_mac(self.key, message['content'], message.get('mac')) else "INVALID"
                        if message.get('is_command'):
                            parsed = parse_command_string(message['content'])
                            print(f"\n{mac_status} [{message['timestamp']}] {message['from']} (COMMAND): {parsed}")
                        else:
                            print(f"\n{mac_status} [{message['timestamp']}] {message['from']}: {message['content']}")
                        print(">> ", end="", flush=True)
            except:
                break
    #region: oauth login
    def oauth_login(self):
        print("\n=== GitHub Login ===")
        response = self.send_command({'command': 'OAUTH_START'})
        if response['status'] != 'success':
            print(f"{response['message']}")
            return

        auth_url = response['auth_url']
        print("Opening your browser to authorize with GitHub...")
        print(f"If it doesn't open automatically, visit:\n{auth_url}")
        webbrowser.open(auth_url)

        redirect_url = input("\nAfter authorizing, paste the full URL you were redirected to here: ").strip()

        response = self.send_command({'command': 'OAUTH_CALLBACK', 'redirect_url': redirect_url})
        print(f"{response['message']}")

        if response['status'] == 'success':
            self.logged_in = True
            self.username = response.get('username')
            self.running = True
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()

    def send_command(self, command_data):
        """Send command to server and get response"""
        try:
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            if self.running:
                response = self.response_queue.get(timeout=10)
            else:
                response = json.loads(self.socket.recv(4096).decode('utf-8'))
            return response
        except queue.Empty:
            print("Timeout: no response from server")
            return {'status': 'error', 'message': 'Communication timeout'}
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
        
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
        print(f"{response['message']}")

        #region QRCode generation for TOTP setup [7]
        if response['status'] == 'success':
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
            
            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
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
        mac = compute_mac(self.key, content)

        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'content': content,
            'mac': mac,
            'is_command': is_command
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def list_users(self):
        """List all users and show who's online"""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        command = {'command': 'LIST_USERS'}
        response = self.send_command(command)
        
        if response['status'] == 'success':
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
        #region Menu
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
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.send_command({'command': 'LOGOUT'})
                    self.logged_in = False
                elif choice == '':
                    # Just wait for messages
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
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
