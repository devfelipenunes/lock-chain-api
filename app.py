from flask import Flask, jsonify, request
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

@app.route('/')
def home():
    return jsonify({"message": "Flask API is working!"})



@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    message = data.get("message").encode("utf-8")
    key = data.get("key").encode("utf-8")
    mode = data.get("mode")
    
    if len(key) not in [16, 24, 32]:
        return jsonify({"error": "Key must be 16, 24, or 32 bytes!"}), 400
    
    modes = {
        "AES_CBC": AES.MODE_CBC,
        "AES_OFB": AES.MODE_OFB,
        "AES_CFB": AES.MODE_CFB,
        "AES_CTR": AES.MODE_CTR,
    }
    
    if mode not in modes:
        return jsonify({"error": "Invalid encryption mode!"}), 400
    
    if mode == "AES_CTR":
        ctr = Counter.new(128)
        cipher = AES.new(key, modes[mode], counter=ctr)
        encrypted_message = cipher.encrypt(message)
        iv = b""   
    else:
        iv = key[:16]
        cipher = AES.new(key, modes[mode], iv)
        if mode == "AES_CBC":
            encrypted_message = cipher.encrypt(pad(message, AES.block_size))
        else:
            encrypted_message = cipher.encrypt(message)

    encrypted_message_b64 = base64.b64encode(iv + encrypted_message).decode("utf-8")
    
    return jsonify({"encrypted_message": encrypted_message_b64})



@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted_message_b64 = data.get("encrypted_message")
    key = data.get("key").encode("utf-8")
    mode = data.get("mode")
    
    if len(key) not in [16, 24, 32]:
        return jsonify({"error": "Key must be 16, 24, or 32 bytes!"}), 400
    
    modes = {
        "AES_CBC": AES.MODE_CBC,
        "AES_OFB": AES.MODE_OFB,
        "AES_CFB": AES.MODE_CFB,
        "AES_CTR": AES.MODE_CTR,
    }
    
    if mode not in modes:
        return jsonify({"error": "Invalid encryption mode!"}), 400
    
    encrypted_message = base64.b64decode(encrypted_message_b64)
    
    if mode == "AES_CTR":
        ctr = Counter.new(128)
        cipher = AES.new(key, modes[mode], counter=ctr)
        decrypted_message = cipher.decrypt(encrypted_message)
    else:
        iv = encrypted_message[:16]
        encrypted_message = encrypted_message[16:]
        cipher = AES.new(key, modes[mode], iv)
        try:
            if mode == "AES_CBC":
                decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
            else:
                decrypted_message = cipher.decrypt(encrypted_message)
        except ValueError:
            return jsonify({"error": "Error while decrypting the message."}), 400

    return jsonify({"decrypted_message": decrypted_message.decode("utf-8")})


if __name__ == '__main__':
    app.run(debug=True)
