
---

# Secure File Encryptor & Brute Force Decryptor

This repository contains two scripts:
1. **main.py**: A tool for securely encrypting and decrypting files using AES-256 encryption.
2. **brute_force.py**: A brute-force decryption tool that attempts to decrypt a file using a list of common passwords.

## Features
- **main.py**:
  - Encrypts files using AES-256-GCM encryption.
  - Supports encrypting files with a user-defined password.
  - Decrypts encrypted files using the correct password.
- **brute_force.py**:
  - Brute-force decrypts files encrypted with AES-256-GCM.
  - Uses a list of common passwords (`password.txt`) to attempt decryption.

## Installation

### Step 1: Clone the repository
```bash
git clone https://github.com/mr-bala-kavi/secure-file-encryptor-bruteforce.git
cd secure-file-encryptor-bruteforce
```

### Step 2: Install the required dependencies
Ensure you have Python 3.10 and above installed(This is tested in Python 3.13.2). Then install the required libraries using pip:
```bash
pip install -r requirements.txt
```

## Usage

### Encrypt a file:

1. Run the `main.py` script to encrypt a file with AES-256 encryption:
   ```bash
   python main.py
   ```
2. When prompted, enter the password you wish to use to encrypt the file.
3. Select the file you want to encrypt from your file system.
4. Choose a location to save the encrypted file.

### Decrypt a file:

1. To decrypt an encrypted file, run the `brute_force.py` script:
   ```bash
   python brute_force.py
   ```
2. Provide the encrypted file when prompted.
3. Specify the file path of the `passwords.txt` file (which should contain a list of common passwords).
4. The script will attempt to decrypt the file using each password from the list.

### Example:

#### Encrypt:
```bash
python main.py
```
- Password: `my_secure_password`
- Select file: `document.pdf`
- Save encrypted file: `document_encrypted.enc`

#### Brute Force Decrypt:
```bash
python brute_force.py
```
- Encrypted file: `document_encrypted.enc`
- Password file: `password.txt`

### Example of common_passwords.txt:

The `password.txt` should contain a list of potential passwords, one per line: (I used 10k sample passwords)
```
password123
123456
qwerty
letmein
```
### Screen Shots

You can find screenshots of the encryption and decryption process inside the `Screen Shots/` folder for a visual reference.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
This repository is for educational purposes only. Ensure you have the proper authorization before attempting any decryption activities. Using brute-force techniques on unauthorized data is illegal in many jurisdictions.

## Contributions
Feel free to open an issue if you encounter problems or have suggestions for improvements. Pull requests are also welcome!

---