import socket
from flask import Flask, render_template, request
import threading, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

connected_client_addr = None
sender_public_key_str = None
audio_enc_str = None
aes_enc_str = None
decrypted_aes_str = None
addr_lock = threading.Lock()  # To ensure thread safety

# ------------------------------------------------------- receive view -----------------------------------------------------
def get_ipv4_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return str(e)

def get_generate_key():
    with open("static/assets/keys/private_key.pem", "r") as f:
        lines = f.readlines()
        private_key_str = "".join(lines[1:-1]).replace("\n", "")
        
    with open("static/assets/keys/public_key.pem", "r") as f:
        lines = f.readlines()
        public_key_str = "".join(lines[1:-1]).replace("\n", "")

    return private_key_str, public_key_str

def p2p_server1(your_ip, port=41329):
    global audio_enc_str,connected_client_addr, sender_public_key_str

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((your_ip, port))
    server_socket.listen(5)  # Allows multiple connections

    print(f"P2P Server listening on {your_ip}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")

        # Update the connected client address
        with addr_lock:
            connected_client_addr = addr[0]  # Store only the IP address
        
        with open("static/assets/keys/sender_public_key.pem", "r") as f:
            lines = f.readlines()
            sender_public_key_str = "".join(lines[1:-1]).replace("\n", "")

        with open("received_audio_enc_file.enc", "wb") as file:
            while True:
                data = conn.recv(1024*1000)
                if not data:
                    break
                file.write(data)
        
        with open("received_audio_enc_file.enc", "rb") as f:
            audio_enc_str = f.read()
            
        with open("static\\assets\\keys\\encrypted_aes_key.bin", "wb") as file:
            while True:
                data = conn.recv(1024*1000)
                if not data:
                    break
                file.write(data)

        print("File received successfully from", addr)
        conn.close()
        

def p2p_server2(your_ip, port=41330):
    global aes_enc_str, decrypted_aes_str

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((your_ip, port))
    server_socket.listen(5)  # Allows multiple connections

    print(f"P2P Server listening on {your_ip}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
            
        with open("static\\assets\\keys\\encrypted_aes_key.bin", "wb") as file:
            while True:
                data = conn.recv(1024*1000)
                if not data:
                    break
                file.write(data)
        
        with open("static\\assets\\keys\\encrypted_aes_key.bin", "rb") as f:
            aes_enc_str = f.read()
        
        private_key_path = "static\\assets\\keys\\private_key.pem"
        encrypted_aes_key_path = "static\\assets\\keys\\encrypted_aes_key.bin"
        decrypted_aes_key_path = "static\\assets\\keys\\decrypted_aes_key.pem"

        # Load receiver's private key
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Load encrypted AES key
        with open(encrypted_aes_key_path, "rb") as f:
            encrypted_aes_key = f.read()

        # Decrypt AES key using RSA
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save decrypted AES key
        with open(decrypted_aes_key_path, "wb") as f:
            f.write(decrypted_aes_key)
            
        with open(decrypted_aes_key_path, "r") as f:
            lines = f.readlines()
            decrypted_aes_str = "".join(lines[1:-1]).replace("\n", "")

        print(f"Decrypted AES key saved to {decrypted_aes_key_path}")

        print("File received successfully from", addr)
        conn.close()

# -------------------------------------------------------  Flask -----------------------------------------------------
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    global connected_client_addr

    ipv4_address = get_ipv4_address()
    private_key_str, public_key_str = get_generate_key()
    
    # Start the server thread once
    if not any(t.name == "P2PServerThread" for t in threading.enumerate()):
        t1 = threading.Thread(target=p2p_server1, args=(ipv4_address,), daemon=True, name="P2PServerThread")
        t1.start()
        t2 = threading.Thread(target=p2p_server2, args=(ipv4_address,), daemon=True, name="P2PServerThread")
        t2.start()

    # Get the last connected client address
    with addr_lock:
        client_ip = connected_client_addr if connected_client_addr else "No connection yet"
        sender_pub = sender_public_key_str if connected_client_addr else "No connection yet"
        audio_enc = audio_enc_str if audio_enc_str else "No connection yet"
        aesenc = aes_enc_str if aes_enc_str else "No connection yet"
        aesdec = decrypted_aes_str if aes_enc_str else "No connection yet"

    return render_template("home.html", ip=ipv4_address, pri=private_key_str, pub=public_key_str, addr=client_ip, spub=sender_pub, astr=audio_enc, aes_enc=aesenc, aes_dec=aesdec)

# ------------------------------------------------------- Flask Call -----------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)