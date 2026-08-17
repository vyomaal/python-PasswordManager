# 🔐 Secure Password Manager

## Python Cybersecurity Final Project

A desktop-based password manager developed using Python.

The application securely stores account credentials in an encrypted SQLite database and provides tools for generating and evaluating strong passwords.

---

## 🎯 Project Objective

The goal of this project is to demonstrate practical cybersecurity concepts using Python.

The application demonstrates:

- Password hashing
- Salted password storage
- Symmetric encryption
- Secure random password generation
- Authentication
- Input validation
- Clipboard security
- Access control

---

## 🚀 Features

### 🔑 Master Password

The application requires a master password before the vault can be accessed.

The master password is not stored directly.

Instead, the application uses:

```text
PBKDF2-HMAC-SHA256