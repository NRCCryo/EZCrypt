# EZCrypt
Very simple encryption tool.


# EZCrypt: File Encryption/Decryption Tool

EZCrypt is a graphical user interface (GUI) tool for encrypting and decrypting files and folders using various encryption methods. It supports standard password-based encryption, file-based encryption, and asymmetric encryption (using RSA keys). The tool is built using Python and Tkinter for the GUI, and it leverages the `cryptography` library for encryption functionalities.

## Features

- **Standard Encryption:**
  - Encrypt and decrypt files using a password.
  - Encrypt and decrypt entire folders using a password.
  
- **File-Based Encryption:**
  - Encrypt and decrypt files using a combination of a password and a seed file.
  
- **Asymmetric Encryption:**
  - Generate RSA key pairs (public and private keys).
  - Encrypt files using a public key.
  - Decrypt files using a private key.
  
- **Key Management:**
  - Load and save public and private keys.
  - Display the status of loaded keys (public and private).

________________________________________________________________________

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/NRCCryo/EZCrypt.git
   cd EZCrypt
Install the required packages:

Make sure you have pip installed, then run:

bash
Copy code
pip install -r requirements.txt
Run the application:

bash
Copy code
python Crypt-Alone.py
Usage
Standard Encryption

Encrypt File: Encrypt a file using a password.

Decrypt File: Decrypt a file using a password.

Encrypt Folder: Encrypt an entire folder using a password.

Decrypt Folder: Decrypt an encrypted folder using a password.

File-Based Encryption

Encrypt File: Encrypt a file using a password and a seed file.

Decrypt File: Decrypt a file using a password and a seed file.
Asymmetric Encryption

Encrypt File: Encrypt a file using a public key.

Decrypt File: Decrypt a file using a private key.

Key Management

Generate RSA Key Pair: Generate a new RSA key pair (public and private keys) and save them to files.

Load Public Key: Load an existing public key from a file.

Load Private Key: Load an existing private key from a file.

Contributing
Fork the repository.
Create your feature branch.
Commit your changes.
Push to the branch.
Open a pull request.


Acknowledgements
Tkinter for the GUI.
cryptography library for encryption functionalities.
