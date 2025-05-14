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
        # Validate input
        if 'file' not in request.files:
            return jsonify({'error': 'Vui lòng chọn file', 'password_error': False}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Không có file được chọn', 'password_error': False}), 400
            
        key = request.form.get('key')
        if not key:
            return jsonify({'error': 'Vui lòng nhập KeyCode', 'password_error': False}), 400
        
        operation = request.form.get('operation', 'encrypt')
        
        # Prepare key and IV
        raw_key = key.encode('utf-8')
        key = hashlib.sha256(raw_key).digest()[:8]
        iv = b'\x00' * 8
        
        # Read file
        file_data = file.read()
        
        if operation == 'encrypt':
            # Encryption process
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padding_length = 8 - (len(file_data) % 8)
            padded_data = file_data + bytes([padding_length] * padding_length)
            
            processed_data = encryptor.update(padded_data) + encryptor.finalize()
            result_message = "Đã mã hóa thành công. Nhấn 'Tải xuống' để lưu file."
        else:
            # Decryption process with password validation
            try:
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                decrypted_data = decryptor.update(file_data) + decryptor.finalize()
                
                # Validate PKCS7 padding
                padding_length = decrypted_data[-1]
                if padding_length > 8 or padding_length < 1:
                    raise ValueError("Invalid padding")
                
                # Check all padding bytes
                expected_padding = bytes([padding_length] * padding_length)
                actual_padding = decrypted_data[-padding_length:]
                
                if actual_padding != expected_padding:
                    raise ValueError("Invalid padding")
                
                processed_data = decrypted_data[:-padding_length]
                result_message = "Đã giải mã thành công. Nhấn 'Tải xuống' để lưu file."
                
            except (ValueError, IndexError):
                return jsonify({
                    'error': 'Mật khẩu giải mã không đúng. Vui lòng kiểm tra lại.',
                    'password_error': True
                }), 400
        
        # Save processed file
        original_name, original_ext = os.path.splitext(file.filename)
        new_filename = f"{original_name}_{operation}ed{original_ext}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        
        with open(temp_path, 'wb') as f:
            f.write(processed_data)
        
        return jsonify({
            'success': True,
            'message': result_message,
            'filename': new_filename,
            'operation': operation
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Có lỗi xảy ra: {str(e)}',
            'password_error': False
        }), 500

@app.route('/download/<filename>')
def download(filename):
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True)