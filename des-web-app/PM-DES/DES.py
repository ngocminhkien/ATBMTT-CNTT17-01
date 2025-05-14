import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class DESEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chương trình mã hóa/giải mã DES")
        self.root.geometry("700x600")
        self.root.resizable(False, False)

        self.selected_file_path = tk.StringVar()
        self.key_code = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.operation = tk.StringVar(value="encrypt")
        self.processed_data = None

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text="MÃ HÓA VÀ GIẢI MÃ DES", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        file_frame = ttk.LabelFrame(main_frame, text="Chọn File", padding="10")
        file_frame.pack(fill=tk.X, pady=10)

        file_entry = ttk.Entry(file_frame, textvariable=self.selected_file_path, width=50)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=5)

        key_frame = ttk.LabelFrame(main_frame, text="Nhập KeyCode", padding="10")
        key_frame.pack(fill=tk.X, pady=10)

        key_entry = ttk.Entry(key_frame, textvariable=self.key_code, width=50, show="*")
        key_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        show_key_button = ttk.Button(key_frame, text="Hiện", command=lambda: self.toggle_key_visibility(key_entry))
        show_key_button.pack(side=tk.RIGHT, padx=5)

        operation_frame = ttk.Frame(main_frame)
        operation_frame.pack(fill=tk.X, pady=10)

        ttk.Radiobutton(operation_frame, text="Mã hóa", variable=self.operation, value="encrypt").pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(operation_frame, text="Giải mã", variable=self.operation, value="decrypt").pack(side=tk.LEFT, padx=20)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        process_button = ttk.Button(button_frame, text="Thực hiện", command=self.process_data, width=20)
        process_button.pack(side=tk.LEFT, padx=10)

        download_button = ttk.Button(button_frame, text="Tải xuống file", command=self.download_file, width=20)
        download_button.pack(side=tk.RIGHT, padx=10)

        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=100, mode="determinate")
        self.progress.pack(fill=tk.X, pady=10)

        result_frame = ttk.LabelFrame(main_frame, text="Kết quả", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=15)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.result_text.config(state=tk.DISABLED)

        self.status_var = tk.StringVar()
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Chọn file cần xử lý")
        if file_path:
            self.selected_file_path.set(file_path)

    def toggle_key_visibility(self, entry_widget):
        current = entry_widget.cget("show")
        entry_widget.config(show="" if current else "*")

    def process_data(self):
        if not self.selected_file_path.get():
            messagebox.showerror("Lỗi", "Vui lòng chọn file đầu vào!")
            return

        if not self.key_code.get():
            messagebox.showerror("Lỗi", "Vui lòng nhập KeyCode!")
            return

        try:
            raw_key = self.key_code.get().encode('utf-8')
            key = hashlib.sha256(raw_key).digest()[:8]

            with open(self.selected_file_path.get(), 'rb') as f:
                data = f.read()

            self.progress["value"] = 20
            self.root.update_idletasks()

            iv = b'\x00' * 8
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())

            if self.operation.get() == "encrypt":
                self.status_var.set("Đang mã hóa...")
                encryptor = cipher.encryptor()

                padding_length = 8 - (len(data) % 8)
                padded_data = data + bytes([padding_length] * padding_length)

                self.processed_data = encryptor.update(padded_data) + encryptor.finalize()

                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Đã mã hóa thành công. Nhấn 'Tải xuống file' để lưu kết quả.")
                self.result_text.config(state=tk.DISABLED)

                self.progress["value"] = 100
                self.status_var.set("Đã mã hóa xong! Nhấn 'Tải xuống file' để lưu kết quả")
                messagebox.showinfo("Thành công", "Đã mã hóa dữ liệu thành công!")

            else:
                self.status_var.set("Đang giải mã...")
                decryptor = cipher.decryptor()

                try:
                    decrypted_data = decryptor.update(data) + decryptor.finalize()

                    padding_length = decrypted_data[-1]
                    if padding_length < 1 or padding_length > 8:
                        raise ValueError("Sai KeyCode hoặc dữ liệu bị lỗi.")

                    if decrypted_data[-padding_length:] != bytes([padding_length] * padding_length):
                        raise ValueError("Sai KeyCode hoặc dữ liệu bị lỗi.")

                    self.processed_data = decrypted_data[:-padding_length]

                    self.result_text.config(state=tk.NORMAL)
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, "Đã giải mã thành công. Nhấn 'Tải xuống file' để lưu kết quả.")
                    self.result_text.config(state=tk.DISABLED)

                    self.progress["value"] = 100
                    self.status_var.set("Đã giải mã xong! Nhấn 'Tải xuống file' để lưu kết quả")
                    messagebox.showinfo("Thành công", "Đã giải mã dữ liệu thành công!")

                except Exception:
                    raise ValueError("Giải mã thất bại: Sai KeyCode hoặc dữ liệu không hợp lệ.")

        except Exception as e:
            self.progress["value"] = 0
            self.status_var.set(f"Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", str(e))
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Lỗi: {str(e)}")
            self.result_text.config(state=tk.DISABLED)

    def download_file(self):
        if not self.processed_data:
            messagebox.showerror("Lỗi", "Không có dữ liệu đã xử lý. Vui lòng thực hiện mã hóa/giải mã trước!")
            return

        initial_dir = os.path.dirname(self.selected_file_path.get()) if self.selected_file_path.get() else os.getcwd()
        file_name = os.path.basename(self.selected_file_path.get())
        base_name, ext = os.path.splitext(file_name)

        if self.operation.get() == "encrypt":
            default_name = f"{base_name}_encrypted{ext}"
        else:
            default_name = f"{base_name}_decrypted{ext}"

        file_path = filedialog.asksaveasfilename(
            title="Chọn vị trí lưu file",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.processed_data)
                messagebox.showinfo("Thành công", f"Đã lưu file thành công tại: {file_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu file: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DESEncryptionGUI(root)
    root.mainloop()








"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class DESEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chương trình mã hóa/giải mã DES")
        self.root.geometry("700x600")
        self.root.resizable(False, False)

        # Thiết lập biến
        self.selected_file_path = tk.StringVar()
        self.key_code = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.operation = tk.StringVar(value="encrypt")
        self.processed_data = None  # Lưu dữ liệu đã xử lý

        # Tạo giao diện
        self.create_widgets()

    def create_widgets(self):
        # Khung chính
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Tiêu đề
        title_label = ttk.Label(main_frame, text="MÃ HÓA VÀ GIẢI MÃ DES", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        # Khung chọn file
        file_frame = ttk.LabelFrame(main_frame, text="Chọn File", padding="10")
        file_frame.pack(fill=tk.X, pady=10)

        file_entry = ttk.Entry(file_frame, textvariable=self.selected_file_path, width=50)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=5)

        # Khung nhập khóa
        key_frame = ttk.LabelFrame(main_frame, text="Nhập KeyCode", padding="10")
        key_frame.pack(fill=tk.X, pady=10)

        key_entry = ttk.Entry(key_frame, textvariable=self.key_code, width=50, show="*")
        key_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        show_key_button = ttk.Button(key_frame, text="Hiện", command=lambda: self.toggle_key_visibility(key_entry))
        show_key_button.pack(side=tk.RIGHT, padx=5)

        # Chọn thao tác (mã hóa/giải mã)
        operation_frame = ttk.Frame(main_frame)
        operation_frame.pack(fill=tk.X, pady=10)

        ttk.Radiobutton(operation_frame, text="Mã hóa", variable=self.operation, value="encrypt").pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(operation_frame, text="Giải mã", variable=self.operation, value="decrypt").pack(side=tk.LEFT, padx=20)

        # Nút thực hiện
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        process_button = ttk.Button(button_frame, text="Thực hiện", command=self.process_data, width=20)
        process_button.pack(side=tk.LEFT, padx=10)

        download_button = ttk.Button(button_frame, text="Tải xuống file", command=self.download_file, width=20)
        download_button.pack(side=tk.RIGHT, padx=10)

        # Thanh tiến trình
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=100, mode="determinate")
        self.progress.pack(fill=tk.X, pady=10)

        # Khung hiển thị kết quả
        result_frame = ttk.LabelFrame(main_frame, text="Kết quả", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=15)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.result_text.config(state=tk.DISABLED) # Disable text editing

        # Trạng thái
        self.status_var = tk.StringVar()
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Chọn file cần xử lý")
        if file_path:
            self.selected_file_path.set(file_path)

    def toggle_key_visibility(self, entry_widget):
        current = entry_widget.cget("show")
        entry_widget.config(show="" if current else "*")

    def process_data(self):
        # Kiểm tra các trường nhập
        if not self.selected_file_path.get():
            messagebox.showerror("Lỗi", "Vui lòng chọn file đầu vào!")
            return

        if not self.key_code.get():
            messagebox.showerror("Lỗi", "Vui lòng nhập KeyCode!")
            return

        try:
            # Chuẩn bị khóa - DES yêu cầu khóa 8 byte
            raw_key = self.key_code.get().encode('utf-8')
            # Tạo hash SHA-256 từ khóa người dùng và lấy 8 byte đầu tiên
            key = hashlib.sha256(raw_key).digest()[:8]

            # Đọc file đầu vào ở chế độ binary
            with open(self.selected_file_path.get(), 'rb') as f:
                data = f.read()

            # Khởi tạo thanh tiến trình
            self.progress["value"] = 20
            self.root.update_idletasks()

            if self.operation.get() == "encrypt":
                # Mã hóa
                self.status_var.set("Đang mã hóa...")

                # Tạo IV (Initial Vector) - sử dụng 8 byte 0
                iv = b'\x00' * 8

                # Thiết lập DES cipher
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Padding dữ liệu để phù hợp với kích thước khối DES (8 bytes)
                padding_length = 8 - (len(data) % 8)
                padded_data = data + bytes([padding_length] * padding_length)

                # Mã hóa dữ liệu
                self.processed_data = encryptor.update(padded_data) + encryptor.finalize()

                # Hiển thị thông báo kết quả
                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Đã mã hóa thành công. Nhấn 'Tải xuống file' để lưu kết quả.")
                self.result_text.config(state=tk.DISABLED)

                self.progress["value"] = 100
                self.status_var.set("Đã mã hóa xong! Nhấn 'Tải xuống file' để lưu kết quả")
                messagebox.showinfo("Thành công", "Đã mã hóa dữ liệu thành công!")

            else:
                # Giải mã
                self.status_var.set("Đang giải mã...")

                # Tạo IV (Initial Vector) - sử dụng 8 byte 0
                iv = b'\x00' * 8

                # Thiết lập DES cipher
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # Giải mã dữ liệu
                decrypted_data = decryptor.update(data) + decryptor.finalize()

                # Xử lý padding
                padding_length = decrypted_data[-1]
                self.processed_data = decrypted_data[:-padding_length]

                # Hiển thị thông báo kết quả
                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Đã giải mã thành công. Nhấn 'Tải xuống file' để lưu kết quả.")
                self.result_text.config(state=tk.DISABLED)

                self.progress["value"] = 100
                self.status_var.set("Đã giải mã xong! Nhấn 'Tải xuống file' để lưu kết quả")
                messagebox.showinfo("Thành công", "Đã giải mã dữ liệu thành công!")

        except Exception as e:
            self.progress["value"] = 0
            self.status_var.set(f"Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Lỗi: {str(e)}")
            self.result_text.config(state=tk.DISABLED)

    def download_file(self):
        if not self.processed_data:
            messagebox.showerror("Lỗi", "Không có dữ liệu đã xử lý. Vui lòng thực hiện mã hóa/giải mã trước!")
            return

        # Yêu cầu người dùng chọn vị trí lưu file
        initial_dir = os.path.dirname(self.selected_file_path.get()) if self.selected_file_path.get() else os.getcwd()
        file_name = os.path.basename(self.selected_file_path.get())
        base_name, ext = os.path.splitext(file_name)

        if self.operation.get() == "encrypt":
            default_name = f"{base_name}_encrypted{ext}"
        else:
            default_name = f"{base_name}_decrypted{ext}"

        file_path = filedialog.asksaveasfilename(
            title="Chọn vị trí lưu file",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.processed_data)
                messagebox.showinfo("Thành công", f"Đã lưu file thành công tại: {file_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu file: {str(e)}")
if __name__ == "__main__":
    root = tk.Tk()
    app = DESEncryptionGUI(root)
    root.mainloop()
"""

























































































































""" import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class DESEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chương trình mã hóa/giải mã DES")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        
        # Thiết lập biến
        self.selected_file_path = tk.StringVar()
        self.key_code = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.operation = tk.StringVar(value="encrypt")
        self.processed_data = None  # Lưu dữ liệu đã xử lý
        
        # Tạo giao diện
        self.create_widgets()
        
    def create_widgets(self):
        # Khung chính
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tiêu đề
        title_label = ttk.Label(main_frame, text="MÃ HÓA VÀ GIẢI MÃ DES", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Khung chọn file
        file_frame = ttk.LabelFrame(main_frame, text="Chọn File", padding="10")
        file_frame.pack(fill=tk.X, pady=10)
        
        file_entry = ttk.Entry(file_frame, textvariable=self.selected_file_path, width=50)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=5)
        
        # Khung nhập khóa
        key_frame = ttk.LabelFrame(main_frame, text="Nhập KeyCode", padding="10")
        key_frame.pack(fill=tk.X, pady=10)
        
        key_entry = ttk.Entry(key_frame, textvariable=self.key_code, width=50, show="*")
        key_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        show_key_button = ttk.Button(key_frame, text="Hiện", command=lambda: self.toggle_key_visibility(key_entry))
        show_key_button.pack(side=tk.RIGHT, padx=5)
        
        # Chọn thao tác (mã hóa/giải mã)
        operation_frame = ttk.Frame(main_frame)
        operation_frame.pack(fill=tk.X, pady=10)
        
        ttk.Radiobutton(operation_frame, text="Mã hóa", variable=self.operation, value="encrypt").pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(operation_frame, text="Giải mã", variable=self.operation, value="decrypt").pack(side=tk.LEFT, padx=20)
        
        # Nút thực hiện
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        process_button = ttk.Button(button_frame, text="Thực hiện", command=self.process_data, width=20)
        process_button.pack(side=tk.LEFT, padx=10)
        
        download_button = ttk.Button(button_frame, text="Tải xuống file", command=self.download_file, width=20)
        download_button.pack(side=tk.RIGHT, padx=10)
        
        # Thanh tiến trình
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=100, mode="determinate")
        self.progress.pack(fill=tk.X, pady=10)
        
        # Khung hiển thị kết quả
        result_frame = ttk.LabelFrame(main_frame, text="Kết quả", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=80, height=15)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Trạng thái
        self.status_var = tk.StringVar()
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=5)
        
    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Chọn file cần xử lý")
        if file_path:
            self.selected_file_path.set(file_path)
    
    def toggle_key_visibility(self, entry_widget):
        current = entry_widget.cget("show")
        entry_widget.config(show="" if current else "*")
    
    def process_data(self):
        # Kiểm tra các trường nhập
        if not self.selected_file_path.get():
            messagebox.showerror("Lỗi", "Vui lòng chọn file đầu vào!")
            return
            
        if not self.key_code.get():
            messagebox.showerror("Lỗi", "Vui lòng nhập KeyCode!")
            return
        
        try:
            # Chuẩn bị khóa - DES yêu cầu khóa 8 byte
            raw_key = self.key_code.get().encode('utf-8')
            # Tạo hash SHA-256 từ khóa người dùng và lấy 8 byte đầu tiên
            key = hashlib.sha256(raw_key).digest()[:8]  
            
            # Đọc file đầu vào
            with open(self.selected_file_path.get(), 'rb') as f:
                data = f.read()
            
            # Khởi tạo thanh tiến trình
            self.progress["value"] = 20
            self.root.update_idletasks()
            
            if self.operation.get() == "encrypt":
                # Mã hóa
                self.status_var.set("Đang mã hóa...")
                
                # Tạo IV (Initial Vector) - sử dụng 8 byte 0
                iv = b'\x00' * 8
                
                # Thiết lập DES cipher
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # Padding dữ liệu để phù hợp với kích thước khối DES (8 bytes)
                padding_length = 8 - (len(data) % 8)
                padded_data = data + bytes([padding_length] * padding_length)
                
                # Mã hóa dữ liệu
                self.processed_data = encryptor.update(padded_data) + encryptor.finalize()
                
                # Hiển thị kết quả (dạng hex)
                hex_data = self.processed_data.hex()
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, hex_data)
                
                self.progress["value"] = 100
                self.status_var.set("Đã mã hóa xong! Nhấn 'Tải xuống file' để lưu kết quả")
                messagebox.showinfo("Thành công", "Đã mã hóa dữ liệu thành công!")
                
            else:
                # Giải mã
                self.status_var.set("Đang giải mã...")
                
                # Tạo IV (Initial Vector) - sử dụng 8 byte 0
                iv = b'\x00' * 8
                
                # Thiết lập DES cipher
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Giải mã dữ liệu
                decrypted_data = decryptor.update(data) + decryptor.finalize()
                
                # Xử lý padding
                padding_length = decrypted_data[-1]
                self.processed_data = decrypted_data[:-padding_length]
                
                # Hiển thị kết quả (dạng text nếu có thể, hex nếu không)
                try:
                    text_data = self.processed_data.decode('utf-8')
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, text_data)
                except UnicodeDecodeError:
                    hex_data = self.processed_data.hex()
                    self.result_text.delete(1.0, tk.END)
                    self.result_text.insert(tk.END, hex_data)
                
                self.progress["value"] = 100
                self.status_var.set("Đã giải mã xong! Nhấn 'Tải xuống file' để lưu kết quả")
                messagebox.showinfo("Thành công", "Đã giải mã dữ liệu thành công!")
                
        except Exception as e:
            self.progress["value"] = 0
            self.status_var.set(f"Lỗi: {str(e)}")
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Lỗi: {str(e)}")
    
    def download_file(self):
        if not self.processed_data:
            messagebox.showerror("Lỗi", "Không có dữ liệu đã xử lý. Vui lòng thực hiện mã hóa/giải mã trước!")
            return
            
        # Yêu cầu người dùng chọn vị trí lưu file
        initial_dir = os.path.dirname(self.selected_file_path.get()) if self.selected_file_path.get() else os.getcwd()
        file_name = os.path.basename(self.selected_file_path.get())
        base_name, ext = os.path.splitext(file_name)
        
        if self.operation.get() == "encrypt":
            default_name = f"{base_name}_encrypted.dat"
        else:
            default_name = f"{base_name}_decrypted{ext}"
        
        file_path = filedialog.asksaveasfilename(
            title="Chọn vị trí lưu file",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.processed_data)
                messagebox.showinfo("Thành công", f"Đã lưu file thành công tại: {file_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu file: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DESEncryptionGUI(root)
    root.mainloop()
 """



