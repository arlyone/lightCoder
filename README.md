# 🔥 LightCoder — Recon & Pentest Automation Tool

**LightCoder** is a lightweight recon and penetration-testing automation toolkit built for bug bounty hunters and security researchers.  
It automates common reconnaissance workflows — from subdomain discovery to screenshots and Nmap scanning — all in a single run.

It comes with **two modes**:

- **`lightcoder.sh`** → one-run mode (automates the entire recon process start to finish)  
- **`lightcoder-menu.sh`** → menu-driven mode (optional, allows running individual modules interactively)

---

## ⚙️ Requirements

Make sure these dependencies are installed before running LightCoder:

- **bash**, **curl**, **wget**, **git**
- **Python3** & **pip3**
- **Go toolchain** (`go install` required)
- **nmap**, **ruby**, **unzip**
- Tools: `subfinder`, `sublist3r`, `assetfinder`, `httpx`, `httprobe`, `aquatone`, `eyewitness`
- Optional: `waybackurls`, `relative-url-extractor`, etc.

> 💡 You can run the included installer script to automatically set up most of these dependencies.

---

## 🛠 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/arlyone/lightcoder.git
   cd lightcoder
   chmod +x lightcoder.sh lightcoder-menu.sh
   ./installer.sh

🚀 Usage
  ```bash
  ./lightcoder.sh domain.com
  # or
  ./lightcoder-menu.sh domain.com


## 👨‍💻 Author
Arlyone
