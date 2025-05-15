from flask import Flask, request, send_file, render_template
from Crypto.Cipher import DES
from hashlib import md5
import os

app = Flask(__name__)

def pad(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def get_des_key(user_key: str):
    key = md5(user_key.encode()).digest()  # 16 bytes
    return key[:8]  # DES yêu cầu 8 byte

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    action = request.form['action']
    file = request.files['file']
    key = request.form['key']

    des_key = get_des_key(key)
    cipher = DES.new(des_key, DES.MODE_ECB)

    input_data = file.read()
    if action == 'encrypt':
        data = pad(input_data)
        result = cipher.encrypt(data)
    elif action == 'decrypt':
        data = cipher.decrypt(input_data)
        result = unpad(data)
    else:
        return 'Invalid action', 400

    result_path = 'result.bin'
    with open(result_path, 'wb') as f:
        f.write(result)

    return send_file(result_path, as_attachment=True, download_name='result_' + file.filename)

if __name__ == '__main__':
    app.run(debug=True)
