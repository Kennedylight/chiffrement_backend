from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os
import tempfile
from flask_cors import CORS
from flask_cors import cross_origin

app = Flask(__name__)
CORS(app)
def generate_key(password, key_size, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=key_size // 8, count=100000)
    return key, salt

def aes_encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt_text(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

@app.route('/encrypt-text', methods=['POST'])
@cross_origin()
def encrypt_text():
    data = request.json
    plaintext = data.get("text")
    password = data.get("password")
    key_size = int(data.get("keySize", 256))

    key, salt = generate_key(password, key_size)
    encrypted = aes_encrypt_text(plaintext, key)

    return jsonify({
        "ciphertext": base64.b64encode(encrypted).decode('utf-8'),
        "salt": salt.hex(),
        "key": key.hex()
    })

@app.route('/decrypt-text', methods=['POST'])
@cross_origin()
def decrypt_text():
    data = request.json
    b64_ciphertext = data.get("ciphertext")
    password = data.get("password")
    salt_hex = data.get("salt")
    key_size = int(data.get("keySize", 256))

    salt = bytes.fromhex(salt_hex)
    key, _ = generate_key(password, key_size, salt)
    ciphertext = base64.b64decode(b64_ciphertext)
    
    try:
        decrypted = aes_decrypt_text(ciphertext, key)
        return jsonify({"decrypted": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/encrypt-file', methods=['POST'])
@cross_origin()
def encrypt_file():
    file = request.files['file']
    password = request.form['password']
    key_size = int(request.form.get('keySize', 256))

    key, salt = generate_key(password, key_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = file.read()
    padded = pad(plaintext, AES.block_size)
    encrypted = cipher.encrypt(padded)

    temp_path = tempfile.mktemp(suffix='.aes')
    with open(temp_path, 'wb') as f:
        f.write(iv + encrypted)

    return send_file(temp_path, as_attachment=True, download_name=file.filename + '.aes')

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    password = request.form['password']
    salt_hex = request.form['salt']
    key_size = int(request.form.get('keySize', 256))

    salt = bytes.fromhex(salt_hex)
    key, _ = generate_key(password, key_size, salt)

    content = file.read()
    iv = content[:AES.block_size]
    ciphertext = content[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    temp_path = tempfile.mktemp()
    with open(temp_path, 'wb') as f:
        f.write(decrypted)

    return send_file(temp_path, as_attachment=True, download_name=file.filename.replace('.aes', ''))

if __name__ == '__main__':
    app.run(debug=True)
