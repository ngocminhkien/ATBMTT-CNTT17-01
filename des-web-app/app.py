from flask import Flask, render_template, request, send_file, jsonify
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import tempfile

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        # Kiểm tra file và key
        if 'file' not in request.files:
            return jsonify({'error': 'Vui lòng chọn file'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Không có file được chọn'}), 400
            
        key = request.form.get('key')
        if not key:
            return jsonify({'error': 'Vui lòng nhập KeyCode'}), 400
        
        operation = request.form.get('operation', 'encrypt')
        
        # Đọc file và chuẩn bị key
        file_data = file.read()
        raw_key = key.encode('utf-8')
        key = hashlib.sha256(raw_key).digest()[:8]
        iv = b'\x00' * 8
        
        # Xử lý mã hóa/giải mã
        if operation == 'encrypt':
            # Mã hóa
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding dữ liệu
            padding_length = 8 - (len(file_data) % 8)
            padded_data = file_data + bytes([padding_length] * padding_length)
            
            processed_data = encryptor.update(padded_data) + encryptor.finalize()
            result_message = "Đã mã hóa thành công. Nhấn 'Tải xuống' để lưu file."
        else:
            # Giải mã
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(file_data) + decryptor.finalize()
            
            # Xử lý padding
            padding_length = decrypted_data[-1]
            processed_data = decrypted_data[:-padding_length]
            result_message = "Đã giải mã thành công. Nhấn 'Tải xuống' để lưu file."
        
        # Lưu file tạm
        filename = f"{os.path.splitext(file.filename)[0]}_{operation}ed{os.path.splitext(file.filename)[1]}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(temp_path, 'wb') as f:
            f.write(processed_data)
        
        return jsonify({
            'success': True,
            'message': result_message,
            'filename': filename,
            'operation': operation
        })
        
    except Exception as e:
        return jsonify({'error': f'Có lỗi xảy ra: {str(e)}'}), 500

@app.route('/download/<filename>')
def download(filename):
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True)