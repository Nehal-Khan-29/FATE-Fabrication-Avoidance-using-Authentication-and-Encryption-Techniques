import socket
from flask import Flask, render_template,request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket
import threading

# ------------------------------------------------------- send view -----------------------------------------------------
def get_ipv4_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return str(e)


def get_generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("static\\assets\\keys\\private_key.pem", "wb") as f:
        f.write(private_pem)
        
    with open("static\\assets\\keys\\private_key.pem", "r") as f:
        lines = f.readlines()
        private_key_str = "".join(lines[1:-1]).replace("\n", "")

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("static\\assets\\keys\\public_key.pem", "wb") as f:
        f.write(public_pem)
        
    with open("static\\assets\\keys\\public_key.pem", "r") as f:
        lines = f.readlines()
        public_key_str = "".join(lines[1:-1]).replace("\n", "")

    return private_key_str, public_key_str


sender_public_key_str = ""
def p2p_server1(your_ip, port=41329):
    global sender_public_key_str
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((your_ip, port))
    server_socket.listen(5)  # Allows multiple connections

    print(f"P2P Server listening on {your_ip}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        
        with open("sender_public_key.pem", "wb") as file:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                file.write(data)
        
        with open("sender_public_key.pem", "r") as f:
            lines = f.readlines()
            sender_public_key_str = "".join(lines[1:-1]).replace("\n", "")

        print("Key received successfully from", addr)
        conn.close()
        

def p2p_server2(your_ip, port=41330):
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((your_ip, port))
    server_socket.listen(5)  # Allows multiple connections

    print(f"P2P Server listening on {your_ip}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
            
        with open("received_audio.wav", "wb") as file:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                file.write(data)

        print("File received successfully from", addr)
        conn.close()
        

def p2p_client(receiver_ip, filename, port1=41329, port2=41330):

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((receiver_ip, port1))
        with open('static\\assets\\keys\\public_key.pem', 'rb') as file:
            data = file.read()
            client_socket.sendall(data)
        client_socket.close()
        print("Key sent successfully.")
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((receiver_ip, port2))
        with open(filename, 'rb') as file:
            data = file.read()
            client_socket.sendall(data)
        client_socket.close()
        print("File sent successfully.")

    except Exception as e:
        print("Error in sending file:", str(e))



# -------------------------------------------------------  flask -----------------------------------------------------

app = Flask(__name__)

@app.route('/',methods=['GET', 'POST'])
def home():
    ipv4_address = get_ipv4_address()
    private_key_str, public_key_str = get_generate_key()
    
    t1 = threading.Thread(target=p2p_server1, args=(ipv4_address,), daemon=True)
    t1.start()
    t2 = threading.Thread(target=p2p_server2, args=(ipv4_address,), daemon=True)
    t2.start()
    
    receiver_ip=None
    
    if request.method == 'POST':
        receiver_ip = request.form.get("ip2")
        audio_file=request.form.get("audioFile")
        t2 = threading.Thread(target=p2p_client, args=(receiver_ip, audio_file,))
        t2.start()

    return render_template("home.html", ip=ipv4_address, pri=private_key_str, pub=public_key_str, receiver_ip=receiver_ip)



# ------------------------------------------------------- flask call-----------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
