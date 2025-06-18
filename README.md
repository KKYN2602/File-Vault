
# 🔐 FileVault

**FileVault** is a secure file vault CLI application written in Java. It allows users to hide, encrypt, and manage personal files using AES encryption and PBKDF2-based master password protection.

---

## 🧩 Features

- 🔐 AES-256 encryption (CBC mode with PKCS5Padding)
- 🔑 Master password security using PBKDF2WithHmacSHA256
- 🗂️ Hidden vault directory for storing secure files
- 🧪 CLI menu to:
  - Hide & encrypt files
  - View all stored vault files
  - Unhide/decrypt specific files
  - Reset the vault securely

---

## 🔧 Technologies Used

- **Java I/O and NIO**
- **AES Encryption**
- **PBKDF2 with SHA-256**
- **CLI-based Interface**

---

## 📂 Folder Structure

- `~/.new/` → stores encrypted/hidden files
- `~/.vaul` → stores master password (plain or encrypted — up to you to improve)

---

## 🚀 Getting Started

### 1. Compile
```bash
javac FileVault.java
```

### 2. Run
```bash
java FileVault
```

---

## 🛡️ Security Notes

- The application uses a fixed salt for key derivation (can be randomized & stored securely for better protection).
- Encrypts files using AES/CBC/PKCS5Padding with a zero IV.
- Vault reset securely wipes the stored password and deletes all vault contents.

---

## 📸 Sample Menu Output

```
Welcome to the file vault!!!
Enter your Master Password : ******
Welcome Back

Enter 1 to hide a file
Enter 2 to unhide a file
Enter 3 to view hidden files
Enter 4 to Exit
Enter 5 to Reset the vault and delete all of its contents
```

---

## 📜 License

This project is for **educational use only**. You're free to modify and improve the code.

---

## 👨‍💻 Author

**Karthikeyan Sathyamurthy**  
[GitHub Profile](https://github.com/KKYN2602)
