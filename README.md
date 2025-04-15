# WSAM - Web Security & Advanced Mapper

**WSAM** is an all-in-one, terminal-based reconnaissance & vulnerability analysis tool written in Python.  
It helps security researchers, bug bounty hunters, and penetration testers **automate the discovery** of vulnerabilities, leaks, misconfigurations, and more—**without relying on any external APIs or tools**.

---

## Features

- Deep website crawling (HTML, JavaScript, sitemaps, robots.txt)
- Sensitive file discovery (`.env`, `.gitignore`, `backup.zip`, etc.)
- Subdomain and hidden directory enumeration
- Full port scanning (with banner grabbing)
- SSL/TLS certificate analyzer
- Security headers and cookies inspector
- CSRF, CORS, and HTTP Methods check
- Leak scanner (emails, API keys, JWTs, AWS keys, etc.)
- Advanced vulnerability fuzzing (XSS, SQLi, LFI, RCE, SSTI, Open Redirect)
- Detection of login and file upload forms
- WAF/CDN detection
- Final summarized report in terminal

> All of that, with zero dependencies on external tools or APIs like Shodan, Censys, or Tor.

---

## Usage

```bash
python3 WSAM_TOOL_v5.0.py
```

Enter the target URL when prompted. Results will be displayed in the terminal after the scan finishes.

---

## Why WSAM?

Unlike many recon tools, WSAM is:

- **Fully self-contained** – no API keys, no accounts, no external services.
- **Modular and readable** – designed for easy modifications and extensions.
- **Focused on results** – packed with features to help you find bugs faster.

---

## Screenshot

![wsam screenshot](https://user-images.githubusercontent.com/YOUR-ID/preview.png)

---

## License

This project is open-source and free to use under the MIT License.
