# Radiocrypt – A Secure Digital Platform for Tunisian Radiologists 🇹🇳🔐

## Project Overview

Radiocrypt is a secure, centralized digital platform developed to protect the integrity and confidentiality of medical IRM (MRI) images in Tunisia’s healthcare system. Built with cybersecurity principles in mind, it allows radiologists to encrypt, store, and transmit sensitive data securely.

---

## 🩻 Problem Overview

In Tunisia, many radiologists still store and share sensitive IRM (MRI) images using insecure devices or channels. This exposes patients’ medical data to unauthorized access and tampering, risking diagnosis integrity and doctor-patient trust.

---

## 🛡️ Solution: Radiocrypt

Radiocrypt offers a robust, Python-based application with the following features:

- 🔐 **Image Encryption/Decryption** using AES, RSA, XOR, or DES algorithms.
- 🔓 **Secure Login System** with hospital-specific credentials.
- 📲 **QR Code Key Sharing** for secure decryption.
- 🧠 **Intuitive UI** for ease of use.
- 🗃️ **MongoDB Integration** to log operations and manage hospital metadata.

---

## 👨‍⚕️ User Journey

### 1. Authentication

- User logs in using their hospital-provided ID and password.

### 2. Choose Operation: Encrypt or Decrypt

#### If "Encrypt" is selected:
- Upload an IRM image.
- Choose encryption algorithm.
- System generates a key, encrypts the image, and outputs:
  - Encrypted image file
  - `.bin` binary file
  - QR code containing the decryption key

#### If "Decrypt" is selected:
- Upload the `.bin` file
- Input the key manually
- Select the algorithm used during encryption
- If valid, the image is restored; else, a corrupted version is shown as feedback

---

## 💡 Why It Matters

Radiocrypt is a step toward secure, ethical, and efficient digital health practices in Tunisia.

> “As we encrypt images, we decrypt fears.  
> As we share keys, we unlock trust.”

**Radiocrypt – because privacy should never be optional.**

_"Il n’y a pas de santé sans confidentialité.  
Et il n’y a pas de confidentialité sans sécurité."_

---

## 👩‍💻 Made by

- Samar Kilani  
- Yessin Jribi  
- Maryam Khdhiri  
- Eya Haj Hassan  
- Yessin Ghouil

**Supervised by:** Dr. Manel Abdelkader  
**Academic Year:** 2024–2025
# Security-Project
