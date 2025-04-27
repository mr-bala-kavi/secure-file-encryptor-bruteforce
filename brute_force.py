import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Constants matching the encryption script
KEY_LENGTH = 32  # 256 bits
SALT_LENGTH = 16  # Salt length (16 bytes)
IV_LENGTH = 12  # Recommended for AESGCM
PBKDF2_ITERATIONS = 310000
backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=backend
    )
    return kdf.derive(password.encode())

def read_passwords_from_file(file_path):
    """Reads a list of passwords from a file."""
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def brute_force_decrypt(password_list, encrypted_file):
    """Attempts to decrypt the file using passwords from the list."""
    # Read the encrypted file data
    with open(encrypted_file, 'rb') as f:
        data = f.read()

    salt = data[:SALT_LENGTH]
    iv = data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = data[SALT_LENGTH + IV_LENGTH:]

    # Try all passwords from the list
    for password in password_list:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            print(f"Password found: {password}")
            with open("decrypted_file", 'wb') as output_file:
                output_file.write(plaintext)
            return
        except Exception as e:
            pass  # Ignore errors and continue to the next password

    print("Brute force failed. No matching password found.")

if __name__ == '__main__':
    # Read passwords from the 'common_passwords.txt' file
    common_passwords = read_passwords_from_file('password.txt')

    # Run brute force attack
    brute_force_decrypt(common_passwords, 'test1')  # Provide the encrypted file here
