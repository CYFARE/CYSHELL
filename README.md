<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/CYFARE/CYSHELL/main/logo.png" alt="CYSHELL Logo">
  <br>
  CYSHELL
  <br>
</h1>

<h4 align="center">A modern, feature-rich, and single-file web shell for penetration testers and security professionals.</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Language-PHP-8892BF?style=for-the-badge&logo=php&logoColor=white" alt="Language: PHP">
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" alt="License: GPL v3">
  <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge" alt="Version: 1.0">
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation--usage">Installation & Usage</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

**CYSHELL** is a powerful, self-contained PHP web shell designed for modern web environments. It packs a comprehensive suite of features into a single file, providing a clean, responsive, and intuitive interface for remote server management, post-exploitation, and privilege escalation.

---

## ✨ Features

<h4 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/CYFARE/CYSHELL/main/CYSHELL_Demo_Play.png" alt="CYSHELL Demo">
  <br>
  <a href="https://youtube.com/cyfarelabs/DEMO_VIDEO">Video Demo)</a>
  <br>
</h4>

CYSHELL comes equipped with a variety of tools to streamline your workflow on a target system.

| Feature                 | Description                                                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **🔐 Auth Protected** | Secure login page to prevent unauthorized access. **Remember to change the default password!** |
| **📂 File Explorer** | A full-featured, AJAX-powered file manager to navigate, view, edit, and manage files and directories. Supports create, delete, and modify. |
| **💻 Command Execution** | Execute shell commands directly on the target server with a persistent output terminal.                                                  |
| **🧠 System Information** | Gathers detailed system, user, and network information for both Linux/Unix and Windows targets.                                          |
| **🚀 Privesc Tools Hub** | One-click downloader for popular privilege escalation scripts like `linPEAS`, `winPEAS`, and `PowerSploit`. Also supports custom URLs.    |
| **📝 Built-in Editor** | Edit files on the fly with a CodeMirror-powered editor featuring syntax highlighting.                                                    |
| **💅 Modern UI** | Built with TailwindCSS and Alpine.js for a responsive, single-page application experience without page reloads.                          |
| **📦 Single File** | All functionality is packed into a single, easy-to-deploy PHP file.                                                                      |

---

## 🚀 Installation & Usage

Getting started with CYSHELL is incredibly simple.

1.  **Change Password:** Open `CYSHELL.php` and change the default password on line 7:
    
    ```php
    const APP_PASSWORD = 'YOUR_NEW_PASSWORD_HERE';
    ```
2.  **Permissions:** Change file permission for execution rights (optional).

3.  **Upload:** Place the `CYSHELL.php` file onto your target web server.

4.  **Access:** Navigate to the script's URL in your web browser (e.g., `http://target-server.com/CYSHELL.php`).

5.  **Login:** Use the password you set to log in and access the shell's features.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Unauthorized use of this tool on systems you do not own or have explicit permission to test is **illegal**. The author is not responsible for any misuse or damage caused by this script. Always act ethically and responsibly.
