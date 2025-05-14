document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const fileInput = document.getElementById('fileInput');
    const fileName = document.getElementById('fileName');
    const keyInput = document.getElementById('keyInput');
    const toggleKeyBtn = document.getElementById('toggleKeyBtn');
    const processBtn = document.getElementById('processBtn');
    const progressContainer = document.querySelector('.progress-container');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const resultCard = document.querySelector('.result-card');
    const resultContent = document.getElementById('resultContent');
    const downloadBtn = document.getElementById('downloadBtn');
    
    let processedFilename = '';
    let operationType = 'encrypt';
    
    // Update file name when file is selected
    fileInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            fileName.textContent = this.files[0].name;
        } else {
            fileName.textContent = 'Chọn file hoặc kéo thả vào đây';
        }
    });
    
    // Toggle key visibility
    toggleKeyBtn.addEventListener('click', function() {
        const type = keyInput.getAttribute('type') === 'password' ? 'text' : 'password';
        keyInput.setAttribute('type', type);
        this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
    });
    
    // Handle operation selection
    document.querySelectorAll('input[name="operation"]').forEach(radio => {
        radio.addEventListener('change', function() {
            operationType = this.value;
        });
    });
    
    // Process button click
    processBtn.addEventListener('click', function() {
        if (!fileInput.files || !fileInput.files[0]) {
            showAlert('Vui lòng chọn file', 'error');
            return;
        }
        
        if (!keyInput.value) {
            showAlert('Vui lòng nhập KeyCode', 'error');
            return;
        }
        
        processFile();
    });
    
    // Download button click
    downloadBtn.addEventListener('click', function() {
        if (!processedFilename) return;
        window.location.href = `/download/${processedFilename}`;
    });
    
    // Drag and drop functionality
    const fileLabel = document.querySelector('.file-label');
    
    fileLabel.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileLabel.style.borderColor = 'var(--primary-color)';
        fileLabel.style.backgroundColor = 'rgba(74, 107, 255, 0.1)';
    });
    
    fileLabel.addEventListener('dragleave', () => {
        fileLabel.style.borderColor = '#ccc';
        fileLabel.style.backgroundColor = 'transparent';
    });
    
    fileLabel.addEventListener('drop', (e) => {
        e.preventDefault();
        fileLabel.style.borderColor = '#ccc';
        fileLabel.style.backgroundColor = 'transparent';
        
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            fileName.textContent = e.dataTransfer.files[0].name;
        }
    });
    
    // Process file function
    function processFile() {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('key', keyInput.value);
        formData.append('operation', operationType);
        
        // Show progress
        progressContainer.style.display = 'block';
        progressBar.style.width = '30%';
        progressText.textContent = '30%';
        
        // Disable button during processing
        processBtn.disabled = true;
        processBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang xử lý...';
        
        fetch('/process', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    // Special handling for password errors
                    if (err.password_error) {
                        showPasswordError(err.error);
                    } else {
                        throw new Error(err.error || 'Có lỗi xảy ra');
                    }
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Update progress
            progressBar.style.width = '100%';
            progressText.textContent = '100%';
            
            // Show result
            resultContent.textContent = data.message;
            resultCard.style.display = 'block';
            
            if (data.success) {
                processedFilename = data.filename;
                downloadBtn.style.display = 'block';
                showAlert(data.message, 'success');
            }
        })
        .catch(error => {
            if (!error.message.includes('Mật khẩu')) {
                showAlert(error.message, 'error');
            }
            progressBar.style.width = '0%';
            progressText.textContent = '0%';
        })
        .finally(() => {
            processBtn.disabled = false;
            processBtn.innerHTML = '<i class="fas fa-play"></i> Thực Hiện';
        });
    }
    
    // Show password error with special effects
    function showPasswordError(message) {
        const alert = document.createElement('div');
        alert.className = 'alert alert-error password-error';
        alert.innerHTML = `
            <i class="fas fa-exclamation-triangle"></i>
            <span>${message}</span>
        `;
        
        // Add shake effect to password input
        keyInput.classList.add('shake');
        setTimeout(() => keyInput.classList.remove('shake'), 500);
        
        // Focus on password input
        keyInput.focus();
        keyInput.select();
        
        document.body.appendChild(alert);
        
        setTimeout(() => {
            alert.classList.add('fade-out');
            setTimeout(() => alert.remove(), 500);
        }, 5000);
        
        // Reset progress
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        processBtn.disabled = false;
        processBtn.innerHTML = '<i class="fas fa-play"></i> Thực Hiện';
    }
    
    // Show regular alert
    function showAlert(message, type) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        
        document.body.appendChild(alert);
        
        setTimeout(() => {
            alert.classList.add('fade-out');
            setTimeout(() => alert.remove(), 500);
        }, 3000);
    }
});