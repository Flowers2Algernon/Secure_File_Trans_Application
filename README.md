<h1 align="center">🛡️ SecureShare AI: Next-Gen Secure File Sharing 🛡️</h1>

<p align="center">
  <i>A cutting-edge secure file sharing platform leveraging AI-powered monitoring, robust encryption, and RSA key distribution for unparalleled data privacy and protection.</i>
</p>

<p align="center">
  <a href="LINK_TO_YOUR_PROJECT_STATUS_BADGE_OR_REMOVE">
    <img src="https://img.shields.io/badge/Status-Prototype%20Complete-brightgreen" alt="Project Status"/>
  </a>
  <a href="LICENSE_FILE_PATH_OR_REMOVE">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"/>
  </a>
  <a href="LINK_TO_PYTHON_VERSION_BADGE_OR_REMOVE">
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python Version"/>
  </a>
  <a href="LINK_TO_DJANGO_VERSION_BADGE_OR_REMOVE">
    <img src="https://img.shields.io/badge/Django-3.2%2B-green.svg" alt="Django Version"/>
  </a>
</p>

---

## ✨ Overview

SecureShare AI is not just another file sharing tool; it's a comprehensive solution designed from the ground up with **security and user privacy at its core**. This project demonstrates how modern cryptographic techniques (AES-256-GCM, RSA) can be seamlessly integrated with **Artificial Intelligence** to create a resilient and intelligent platform for exchanging confidential information.

Our system empowers users through **client-side decryption**, ensuring that only the intended recipient, possessing their unique private key, can access the original file content. We've tackled the complex challenge of key distribution using **RSA cryptography** and enhanced proactive security with **AI-driven virus scanning** during uploads .

## 🚀 Key Features

*   🔑 **End-to-End Encryption Principle:** Files are encrypted with **AES-256-GCM**, providing military-grade confidentiality and authenticated integrity.
*   🛡️ **RSA Key Distribution:** Securely exchanges symmetric encryption keys using RSA public-key cryptography, eliminating insecure key sharing.
*   🕵️ **Client-Side Decryption:** Empowers receivers with full control over their private keys and decrypted data, enhancing privacy by keeping plaintext off the server.
*   🦠 **AI-Powered Virus Scanning (Upload):** Proactively scans uploaded files for malware *before* encryption and sharing (conceptual AI integration).
*   ⏱️ **6-Digit Access Codes:** User-friendly, time-limited access codes for initial encrypted file retrieval.
*   🤝 **Receiver-Initiated Workflow:** Enhances control and security by allowing receivers to initiate secure file requests and provide their public keys.
*   💻 **Modern Tech Stack:** Built with Django (Python) for a robust backend and JavaScript/Bootstrap for a responsive frontend.

## 🛠️ Technologies Used

*   **Backend:**
    *   🐍 **Python 3.8+**
    *   <img src="https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white" alt="Django"/>: Core web framework.
    *   **Django REST Framework**: For building robust APIs.
    *   **Cryptography Library (Python)**: For AES & RSA operations.
    *   **PostgreSQL (Recommended)**: Database for metadata storage.
*   **Frontend:**
    *   <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript"/>: Client-side logic and key generation.
    *   <img src="https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white" alt="Bootstrap"/>: Responsive UI framework.
    *   **HTML5 & CSS3**: Web fundamentals.
    *   **jsrsasign / forge.js (or similar)**: For client-side RSA key pair generation.
*   **AI (Conceptual Integration):**
    *   Placeholders for future integration of real Machine Learning models for virus scanning and anomaly detection.

## ⚙️ Setup & Installation

> 💡 **Prerequisites:** Python 3.8+, Pip, Virtualenv (recommended), PostgreSQL (or other Django-compatible DB).

1.  **Clone the Sanctuary:**
    ```bash
    git clone https://bitbucket.org/comp6002_group5/fullstack/src/main/
    cd secure-share-ai
    ```

2.  **Ignite the Backend (Django):**
    ```bash
    cd # your Django project root
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # venv\Scripts\activate    # Windows
    pip install -r requirements.txt
    python manage.py makemigrations your_app_name # e.g., fileshare
    python manage.py migrate
    python manage.py createsuperuser # Optional, for admin access
    # Configure your database in settings.py
    python manage.py runserver
    ```

3.  **Assemble the Frontend:**
    *   Frontend files (HTML, CSS, JS) are typically served by Django's static file handling. Ensure `STATIC_URL` and `STATICFILES_DIRS` are correctly configured in `settings.py`.
    *   If you have a separate frontend build process (e.g., with Node.js), follow its specific instructions.

4.  **Database Configuration:**
    *   Update `backend/your_project_name/settings.py` with your database credentials.

5.  **Launch!**
    *   Access the application via `http://localhost:8000` (or your configured port).

## 📖 How It Works (The Secure Journey)

1.  **The Request (Receiver):**
    *   A user (Receiver) initiates a file request.
    *   Their browser generates a unique **RSA Public/Private Key Pair**. The Private Key *never* leaves their device.
    *   The Receiver's **Public Key** is sent with the request to the backend.
2.  **The Notification (Backend):**
    *   The backend notifies the intended Sender, providing the Receiver's Public Key.
3.  **The Upload (Sender):**
    *   The Sender accesses the upload page, provides the Receiver's Public Key, and selects the file.
    *   **AI Virus Scan:** The backend's AI scans the file for threats.
    *   **Encryption Magic:** If clean, the backend:
        *   Generates a random **AES-256 key**.
        *   **RSA-Encrypts** this AES key using the Receiver's Public Key.
        *   **AES-256-GCM Encrypts** the file content using the random AES key.
    *   A **6-Digit Access Code** is generated and given to the Sender.
4.  **The Download (Receiver):**
    *   The Receiver uses the 6-Digit Access Code on the download page.
    *   **AI Access Monitoring:** The backend's AI analyzes the attempt for suspicious activity.
    *   If all checks pass, the **encrypted file** is served.
5.  **The Unveiling (Receiver - Client-Side Decryption):**
    *   The Receiver uses a separate **decryption tool/script** (outside this web app).
    *   This tool uses the Receiver's **RSA Private Key** to decrypt the RSA-encrypted AES key (retrieved securely from a backend API).
    *   With the recovered AES key, the tool performs **AES-256-GCM decryption** on the downloaded file, revealing the original content.

## 🔮 Future Enhancements

*   🚀 **Real AI Model Integration:** Replace placeholders with trained ML models for superior virus scanning and anomaly detection.
*   🔑 **Advanced PKI:** Implement a more robust Public Key Infrastructure for seamless key management.
*   🎨 **UI/UX Overhaul:** Further polish the user interface for an even smoother experience.
*   👥 **User Roles & Permissions:** Introduce granular access controls for different user types.
*   📊 **Comprehensive Auditing:** Detailed security and activity logging for administrators.


---

<p align="center">
  <i>Built with ❤️ and a passion for security.</i>
</p>
