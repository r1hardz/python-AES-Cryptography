# Python-AES-Cryptography

A Python-based tool for AES-CBC encryption and decryption with a modern GUI interface.

## 🛠️ Tech Stack
* **Python 3**
* `tkinter` - for the GUI
* `os` - for system operations
* Custom AES implementation

## 💡 Main Features
* AES-128 encryption with CBC mode
* Text and file encryption/decryption
* Modern user interface with tabbed design
* Support for custom initialization vectors (IV)
* File system integration

## Usage

### Text Encryption
Enter your secret 16-character key, optionally specify an IV (or generate a random one), input your plain text, and encrypt it with a single click.

### Text Decryption
Enter the same 16-character key that was used for encryption, paste the encrypted text, and decrypt to recover the original message.

### File Operations
Encrypt any file on your system using a key and IV. The encrypted file will be saved with an ".encrypted" extension. Decrypt previously encrypted files to recover the original content.

## Setup
> 1. Clone the repository
> 2. Ensure Python 3.7+ is installed
> 3. Run `python gui.py`

## Screenshots

<details>
  <summary>Click to expand screenshots</summary>
  
  ### File Encryption Example
  
  #### Original File
  <img src="images/test_file.png" width="600"/>
  
  #### Encrypted File
  <img src="images/test_file.txt.png" width="600"/>
  
  #### Decrypted File
  <img src="images/test_file_decrypted.png" width="600"/>
  
  ### Application Interface
  
  #### Text Decrypt Tab
  <img src="images/Image_4.png" width="600"/>
  
  #### Text Encrypt Tab
  <img src="images/Image_5.png" width="600"/>
  
  #### File Encryption/Decryption Tab
  <img src="images/Image_6.png" width="600"/>
  
  #### File Encryption in Action
  <img src="images/Image_7.png" width="600"/>
</details>
