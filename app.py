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

def client_fun(SERVER_IP, FILENAME):
    PORT = 41329
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))

    # Send file
    with open(FILENAME, 'rb') as file:
        data = file.read()
        client_socket.sendall(data)
    client_socket.close()

    print("File sent successfully.")
    
def server_fun(your_ip):
    HOST = your_ip  # Listen on all network interfaces
    PORT = 41329
    OUTPUT_FILE = 'received_audio.wav'

    # Create Server Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"Server listening on port {PORT}...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Receive file
    with open(OUTPUT_FILE, 'wb') as file:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            file.write(data)

    print("File received successfully.")
    conn.close()
    server_socket.close()



# -------------------------------------------------------  flask -----------------------------------------------------

app = Flask(__name__)

@app.route('/',methods=['GET', 'POST'])
def home():
    ipv4_address = get_ipv4_address()
    private_key_str, public_key_str = get_generate_key()
    
    t1 = threading.Thread(target=server_fun, args=(ipv4_address,), daemon=True)
    t1.start()
    
    receiver_ip=None
    
    if request.method == 'POST':
        receiver_ip = request.form.get("ip2")
        audio_file=request.form.get("audioFile")
        client_fun(receiver_ip, audio_file )

    return render_template("home.html", ip=ipv4_address, pri=private_key_str, pub=public_key_str, receiver_ip=receiver_ip)



# ------------------------------------------------------- flask call-----------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)