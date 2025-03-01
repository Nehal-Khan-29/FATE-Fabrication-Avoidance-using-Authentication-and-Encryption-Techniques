import socket
from flask import Flask, render_template,request
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

    with open("static\\assets\\keys\\private_key.pem", "r") as f:
        lines = f.readlines()
        private_key_str = "".join(lines[1:-1]).replace("\n", "")
        
    with open("static\\assets\\keys\\public_key.pem", "r") as f:
        lines = f.readlines()
        public_key_str = "".join(lines[1:-1]).replace("\n", "")

    return private_key_str, public_key_str


def p2p_server(your_ip, port=41329):
    
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

            
# -------------------------------------------------------  flask -----------------------------------------------------

app = Flask(__name__)

@app.route('/',methods=['GET', 'POST'])
def home():
    ipv4_address = get_ipv4_address()
    private_key_str, public_key_str = get_generate_key()
    
    t1 = threading.Thread(target=p2p_server, args=(ipv4_address,), daemon=True)
    t1.start()

    return render_template("home.html", ip=ipv4_address, pri=private_key_str, pub=public_key_str)



# ------------------------------------------------------- flask call-----------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)