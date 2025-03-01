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


def p2p_client(receiver_ip, filename, port=41329):

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((receiver_ip, port))
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