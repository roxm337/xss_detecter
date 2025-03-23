# XSS Scanner by r10xM37

### Automated XSS Detection Tool

This is an advanced XSS scanner that detects **Reflected**, **Stored**, and **DOM-based XSS** vulnerabilities in web applications.

---

## ⚡ Features
✅ **Reflected XSS Detection** – Tests URL parameters for reflection vulnerabilities.  
✅ **Stored XSS Detection** – Submits payloads into forms to check for stored XSS.  
✅ **DOM-based XSS Detection** – Uses Selenium to identify client-side JavaScript vulnerabilities.  
✅ **Custom Headers Spoofing** – Bypasses simple bot protections.  
✅ **Logging Support** – Saves scan results in `xss_report.txt`.  
✅ **Headless Selenium Mode** – For efficient browser-based testing.  

---

## 📦 Requirements

### Install dependencies:
```bash
pip install requests beautifulsoup4 selenium

```
## Install Firefox and Geckodriver (Required for Selenium):
### Linux:
```bash
sudo apt install firefox
wget https://github.com/mozilla/geckodriver/releases/latest/download/geckodriver-linux64.tar.gz
tar -xvzf geckodriver-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/
```
### MacOS:
```bash
brew install geckodriver
```
Windows:

    Download Geckodriver from Mozilla GitHub Releases.

    Extract and add it to your system PATH.
    
🚀 Usage

Run the scanner:

python xss_scanner.py

Enter the target URL when prompted.
Example:
Enter target URL: https://example.com/search?q=test

📜 How It Works

    Reflected XSS: Injects payloads into URL parameters and checks if they appear in the response.

    Stored XSS: Submits payloads into forms and verifies if they persist in the page.

    DOM-based XSS: Loads the URL in Selenium, injects payloads into the URL fragment, and checks for JavaScript execution.

⚠️ Disclaimer

This tool is for educational and security testing purposes only.
Do not use it on websites without permission. Unauthorized testing is illegal!

🔗 Author

r10xM37 – Ethical Hacker & Security Researcher


This README covers installation, usage, and key details. Let me know if you need modifications! 🚀
