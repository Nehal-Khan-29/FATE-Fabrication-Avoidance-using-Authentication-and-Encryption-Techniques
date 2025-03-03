import socket
from flask import Flask, render_template, request
import threading, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
import binascii
import re
import hashlib

connected_client_addr = None
sender_public_key_str = None
audio_enc_str = None
aes_enc_str = None
decrypted_aes_str = None
digest1 = None
digsig = None
digest2 = None
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

        with open("static/assets/audio/received_audio_enc_file.enc", "wb") as file:
            while True:
                data = conn.recv(1024*1000)
                if not data:
                    break
                file.write(data)
        
        with open("static/assets/audio/received_audio_enc_file.enc", "rb") as f:
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
    global aes_enc_str, decrypted_aes_str, digest1

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


        def load_aes_key(key_path):
            """Extracts AES key from a PEM-like file."""
            with open(key_path, "rb") as key_file:
                key_contents = key_file.read()
            
            key_match = re.search(rb"-----BEGIN AES KEY-----\r?\n([\da-fA-F]+)\r?\n-----END", key_contents)
            if key_match:
                return binascii.unhexlify(key_match.group(1))
            else:
                raise ValueError("Invalid AES key format!")

        def decrypt_file(aes_key, encrypted_path, output_path):
            """Decrypts an AES-CBC encrypted file."""
            with open(encrypted_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            
            iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)
            
            # Remove PKCS7 padding
            padding_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-padding_length]
            
            with open(output_path, "wb") as dec_file:
                dec_file.write(decrypted_data)
            
            print(f"Decryption complete. File saved as: {output_path}")

        # Example usage
        aes_key_path = "static\\assets\\keys\\decrypted_aes_key.pem"
        encrypted_audio_path = "static\\assets\\audio\\received_audio_enc_file.enc"
        decrypted_audio_path = "static\\assets\\audio\\decrypted_audio.mp3"

        aes_key = load_aes_key(aes_key_path)
        decrypt_file(aes_key, encrypted_audio_path, decrypted_audio_path)
        
        def sha256_audio():
            sha256 = hashlib.sha256()
            with open("static\\assets\\audio\\decrypted_audio.mp3", 'rb') as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()

        digest1 = sha256_audio()
        print(f"SHA-256 Digest: {digest1}")

        conn.close()

def p2p_server3(your_ip, port=41331):
    global digsig, digest2

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((your_ip, port))
    server_socket.listen(5)  # Allows multiple connections

    print(f"P2P Server listening on {your_ip}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        digsig = conn.recv(1024*1000)
        digsig = digsig.decode()
        print(digsig)
        
        def load_public_key(pem_file):
            with open(pem_file, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            return public_key

        def verify_signature(signature, public_key):
            decoded_signature = base64.b64decode(signature)
            try:
                public_key.verify(
                    decoded_signature,
                    digest1.encode(),  # digest1 should match digest2
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return digest1  # If verification is successful, digest2 = digest1
            except Exception as e:
                print("Verification failed:", e)
                return None

        # Load public key
        public_key_file = "static\\assets\\keys\\sender_public_key.pem"
        public_key = load_public_key(public_key_file)

        # Verify signature and retrieve digest2
        digest2 = verify_signature(digsig, public_key)

        if digest2:
            print("Digest2:", digest2)
        else:
            print("Signature verification failed!")
            
        
    

        
        
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
        t3 = threading.Thread(target=p2p_server3, args=(ipv4_address,), daemon=True, name="P2PServerThread")
        t3.start()

    # Get the last connected client address
    with addr_lock:
        client_ip = connected_client_addr if connected_client_addr else "No connection yet"
        sender_pub = sender_public_key_str if connected_client_addr else "No connection yet"
        audio_enc = audio_enc_str if audio_enc_str else "No connection yet"
        aesenc = aes_enc_str if aes_enc_str else "No connection yet"
        aesdec = decrypted_aes_str if aes_enc_str else "No connection yet"
        dig1 = digest1 if digest1 else "No connection yet"
        ds = digsig if digsig else "No connection yet"
        dig2 = digest2 if digest2 else "No connection yet"

    return render_template("home.html", ip=ipv4_address, pri=private_key_str, pub=public_key_str, addr=client_ip, spub=sender_pub, astr=audio_enc, aes_enc=aesenc, aes_dec=aesdec, d1=dig1, ds=ds, d2=dig2)

# ------------------------------------------------------- Flask Call -----------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)