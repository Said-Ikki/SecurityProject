
from flask import Flask, request, render_template
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

private_key = RSA.importKey(open('private.pem').read())
#public = private_key.publickey()
#private_key = RSA.generate(2048)
#f = open('public.pem', 'wb')
#f.write(public.export_key('PEM'))
#f.close()

app = Flask(__name__)

approved_ip_addresses = []

@app.route("/validate", methods=['GET', 'POST'])
def hello_world():
    #print("encrypted in: ", request.data.decode())
    #actual_ip = fernet.decrypt(request.data.decode()).decode()
    #print("decrypted: ", actual_ip)
    ip = request.data
    cipher = PKCS1_OAEP.new(private_key)
    actual_ip = cipher.decrypt(ip).decode()
    approved_ip_addresses.append(actual_ip)
    return actual_ip

@app.route("/", methods=['GET', 'POST'])
def thing():
    if request.remote_addr not in approved_ip_addresses:
        return "no approved IP"
    else:
        return "whats up bro?"

#if __name__ == "__main__":
app.run(host="0.0.0.0", port=5000)