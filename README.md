---

# Secure File Encryptor & Brute Force Decryptor

This repository contains two scripts:

1. **file_encryptor.py**: A tool for securely encrypting and decrypting files using AES-256 encryption.
2. **brute_force_decryptor.py**: A brute-force decryption tool that attempts to decrypt a file using a list of common passwords.

## Features

- **file_encryptor.py**:
  - Encrypts files using AES-256-GCM encryption.
  - Supports encrypting files with a user-defined password.
  - Decrypts encrypted files using the correct password.

- **brute_force_decryptor.py**:
  - Brute-force decrypts files encrypted with AES-256-GCM.
  - Uses a list of common passwords (`passwords.txt`) to attempt decryption.

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/mr-bala-kavi/secure-file-encryptor-bruteforce.git
cd secure-file-encryptor-bruteforce
```

### Step 2: Install the Required Dependencies

Ensure you have **Python 3.10 or above** installed (tested on Python 3.13.2).

```bash
pip install -r requirements.txt
```

## Usage

### Encrypt a File

1. Run the `file_encryptor.py` script to encrypt a file with AES-256 encryption:

```bash
python file_encryptor.py
```

2. When prompted:
   - Enter the password you wish to use to encrypt the file.
   - Select the file you want to encrypt.
   - Choose a location to save the encrypted file.

### Brute Force Decrypt a File

1. Run the `brute_force.py` script:

```bash
python brute_force.py
```

2. When prompted:
   - Provide the encrypted file.
   - Provide the file path to the `passwords.txt` file (containing common passwords).

3. The script will attempt to decrypt the file using each password from the list.

## Example

### Encrypt Example

```bash
python file_encryptor.py
```
- Password: `my_secure_password`
- Select file: `document.pdf`
- Save encrypted file as: `document_encrypted.enc`

### Brute Force Decrypt Example

```bash
python brute_force_decryptor.py
```
- Encrypted file: `document_encrypted.enc`
- Passwords file: `passwords.txt`

### Example of passwords.txt

The `passwords.txt` file should contain a list of potential passwords, one per line:

```
password123
123456
qwerty
letmein
```

> **Tip:** You can find large common password lists online (like "rockyou.txt"), or create your own.

## Screenshots

You can find screenshots of the encryption and decryption process inside the `Screen Shots/` folder for a visual reference.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

> This repository is for educational purposes only.
>
> Always ensure you have proper authorization before attempting any decryption activities.
>
> Unauthorized brute-force attacks are illegal in many jurisdictions.

## Contributions

Feel free to open an issue if you encounter problems or have suggestions for improvements. Pull requests are welcome!

---

