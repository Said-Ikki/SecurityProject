
from flask import Flask, request, render_template
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

private_key = RSA.importKey(open('private.pem').read()) # get decryption key
# code for creating keys if we need to
#public = private_key.publickey()
#private_key = RSA.generate(2048)
#f = open('public.pem', 'wb')
#f.write(public.export_key('PEM'))
#f.close()

app = Flask(__name__)

approved_ip_addresses = []

@app.route("/validate", methods=['GET', 'POST']) # other code sends IP here to get access
def hello_world():
    #print("encrypted in: ", request.data.decode())
    #actual_ip = fernet.decrypt(request.data.decode()).decode()
    #print("decrypted: ", actual_ip)
    ip = request.data # extracts msg
    cipher = PKCS1_OAEP.new(private_key) # sets up decryptor
    actual_ip = cipher.decrypt(ip).decode() # gets original msg
    approved_ip_addresses.append(actual_ip) # adds IP to allowed IPs
    return actual_ip

@app.route("/", methods=['GET', 'POST'])
def thing():
    if request.remote_addr not in approved_ip_addresses: # if this comes from an unvalidated UP
        #return "no approved IP" # show them one screen
        return  render_template("aceess_denied.html")
    else:
        #return "whats up bro?" # show them a different screen
        return render_template("aceess_granted.html")

#if __name__ == "__main__":
app.run(host="0.0.0.0", port=5000)

### DISCLOSURE ###
# THE HTML PAGES ARE CREATED BY CHATGPT
# they are intended to be a stand-in for what the system *could* achieve
# everything else is hand-coded by Said, yours truly
# to see results without the html pages, there is a commented line above each 'return' stmt
# uncomment them