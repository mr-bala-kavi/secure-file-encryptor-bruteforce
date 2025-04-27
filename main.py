import sys
import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout,
    QWidget, QFileDialog, QLabel, QCheckBox, QInputDialog, QLineEdit
)
from PyQt6.QtCore import Qt

# AES-256 Encryption Details
KEY_LENGTH = 32  # 256 bits
SALT_LENGTH = 16
IV_LENGTH = 12  # Recommended for AESGCM
PBKDF2_ITERATIONS = 310000
backend = default_backend()

# --- Core Encryption Functions ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(password: str, input_filename: str, output_filename: str):
    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)
    key = derive_key(password, salt)

    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    with open(output_filename, 'wb') as f:
        f.write(salt + iv + ciphertext)
    return f"✅ File encrypted successfully: {output_filename}"

def decrypt_file(password: str, input_filename: str, output_filename: str):
    with open(input_filename, 'rb') as f:
        data = f.read()

    salt = data[:SALT_LENGTH]
    iv = data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = data[SALT_LENGTH + IV_LENGTH:]

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
    except Exception:
        return "❌ Decryption failed! Wrong password or corrupted file."

    with open(output_filename, 'wb') as f:
        f.write(plaintext)
    return f"✅ File decrypted successfully: {output_filename}"

# --- PyQt6 GUI Class ---
class EncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔒 Secure File Encryptor / Decryptor")
        self.setGeometry(300, 300, 600, 400)
        
        self.initUI()
    
    def initUI(self):
        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.layout = QVBoxLayout(self.centralWidget)

        # Buttons for Encrypt and Decrypt
        self.encrypt_button = QPushButton("🔒 Encrypt File")
        self.decrypt_button = QPushButton("🔓 Decrypt File")

        self.encrypt_button.clicked.connect(self.encryptFile)
        self.decrypt_button.clicked.connect(self.decryptFile)

        # Toggle for Dark/Light mode
        self.toggle_button = QCheckBox("🌗 Toggle Dark/Light Mode")
        self.toggle_button.stateChanged.connect(self.toggleMode)

        # File path and status
        self.status_label = QLabel("📄 Status: Ready")
        
        # Layout Setup
        self.layout.addWidget(self.encrypt_button)
        self.layout.addWidget(self.decrypt_button)
        self.layout.addWidget(self.toggle_button)
        self.layout.addWidget(self.status_label)

        # Set initial theme
        self.setStyleSheet(self.light_mode_style)

    def encryptFile(self):
        input_file, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if input_file:
            password, ok = QInputDialog.getText(self, "Set Password", "Enter password for encryption:", QLineEdit.EchoMode.Password)
            if ok and password:
                output_file, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File")
                if output_file:
                    result = encrypt_file(password, input_file, output_file)
                    self.status_label.setText(result)
            else:
                self.status_label.setText("❗ Encryption canceled. No password entered.")

    def decryptFile(self):
        input_file, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if input_file:
            password, ok = QInputDialog.getText(self, "Enter Password", "Enter password to decrypt file:", QLineEdit.EchoMode.Password)
            if ok and password:
                output_file, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File")
                if output_file:
                    result = decrypt_file(password, input_file, output_file)
                    self.status_label.setText(result)
            else:
                self.status_label.setText("❗ Decryption canceled. No password entered.")

    def toggleMode(self):
        if self.toggle_button.isChecked():
            self.setStyleSheet(self.dark_mode_style)
        else:
            self.setStyleSheet(self.light_mode_style)

    # --- Light and Dark Mode Styles ---
    light_mode_style = """
    QWidget {
        background-color: #ffffff;
        color: #000000;
        font-family: Arial;
        font-size: 16px;
    }
    QPushButton {
        background-color: #3498db;
        color: white;
        border-radius: 8px;
        padding: 10px;
    }
    QLineEdit {
        background-color: #f0f0f0;
        color: #000000;
        border-radius: 8px;
        padding: 10px;
    }
    QLabel {
        color: #333333;
    }
    QCheckBox {
        color: #333333;
        padding: 5px;
    }
    """

    dark_mode_style = """
    QWidget {
        background-color: #2e2e2e;
        color: #ffffff;
        font-family: Arial;
        font-size: 16px;
    }
    QPushButton {
        background-color: #4a90e2;
        color: white;
        border-radius: 8px;
        padding: 10px;
    }
    QLineEdit {
        background-color: #444444;
        color: white;
        border-radius: 8px;
        padding: 10px;
    }
    QLabel {
        color: #ffffff;
    }
    QCheckBox {
        color: #ffffff;
        padding: 5px;
    }
    """

# --- Main App Runner ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())
