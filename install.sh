#!/bin/bash -i
# install_lightcoder.sh
# Author: arlyone
# NOTE: Run this script as root.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use: sudo $0"
    exit 1
fi

echo -e "
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           LightCoder              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
AUTHOR: Lightcoder
INSTALLER FOR LIGHTCODER
USAGE: sudo ./install.sh
"

# -------------------------
# APT update & installations
# -------------------------
echo "[*] Updating APT and installing packages..."
apt-get update -y

apt-get install -y \
    python3-pip \
    python3-venv \
    build-essential \
    dkms \
    linux-headers-$(uname -r) \
    curl \
    wget \
    git \
    vim \
    tmux \
    openjdk-jre \
    unzip \
    jq \
    phantomjs \
    libpcap-dev \
    make

# -------------------------
# Create directories
# -------------------------
echo "[*] Creating directory structure..."
mkdir -p "$HOME/Pentest/Tools/GoTools" \
         "$HOME/Pentest/Tools/Others" \
         "$HOME/Pentest/Tools/Smuggler" \
         "$HOME/Pentest/Tools/GitHubTool" \
         "$HOME/Pentest/Targets" \
         "$HOME/app/bin" \
         "$HOME/work"

BIN_DIR="$HOME/app/bin"
GOTOP="$HOME/Pentest/Tools/GoTools"
OTHERS="$HOME/Pentest/Tools/Others"

# -------------------------
# PATH and environment
# -------------------------
echo "[*] Configuring environment variables..."
# Add PATH and GOPATH to ~/.bashrc if not present
if ! grep -q "export GOPATH=\$HOME/Pentest/Tools/GoTools" ~/.bashrc 2>/dev/null; then
    echo "export GOPATH=\$HOME/Pentest/Tools/GoTools" >> ~/.bashrc
fi
if ! grep -q "export PATH=\$PATH:\$GOPATH/bin" ~/.bashrc 2>/dev/null; then
    echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bashrc
fi
if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
    echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
fi
if ! grep -q "$BIN_DIR" ~/.bashrc 2>/dev/null; then
    echo "export PATH=\$PATH:$BIN_DIR" >> ~/.bashrc
fi

# Source bashrc to pick up changes for this shell session
# (Note: in non-interactive shells this might not apply; user can run `source ~/.bashrc` later)
source ~/.bashrc || true

# -------------------------
# PIP installs
# -------------------------
echo "[*] Installing pip packages..."
pip3 install --upgrade pip
pip3 install colored dnsgen shodan webscreenshot

# -------------------------
# Install Go (1.19.7)
# -------------------------
if ! command -v go &>/dev/null; then
    echo "[*] Installing Go 1.19.7..."
    cd /tmp
    GO_TAR="go1.19.7.linux-amd64.tar.gz"
    wget -q "https://golang.org/dl/${GO_TAR}"
    tar -C /usr/local -xzf "${GO_TAR}"
    rm -f "${GO_TAR}"
    export PATH=$PATH:/usr/local/go/bin
    echo "Go installed."
else
    echo "[*] Go already installed: $(go version)"
fi

# Ensure GOPATH exists
mkdir -p "$GOTOP/bin"

# -------------------------
# Install Go tools (go install @latest)
# -------------------------
echo "[*] Installing Go tools..."
# list of module paths to install via `go install <path>@latest`
go_tools=(
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/dwisiswant0/cf-check@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/hacks/filter-resolved@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/lc/gau@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/tomnomnom/hacks/html-tool@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/jaeles-project/jaeles@latest"
    "github.com/hiddengearz/jsubfinder@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/j3ssie/metabigor@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/shenwei356/rush@latest"
    "github.com/tomnomnom/hacks/tojson@latest"
    "github.com/003random/getJS@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/lc/subjs@latest"
    "github.com/dwisiswant0/unew@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/notify/cmd/intercept@latest"
    "github.com/deletescape/goop@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/OWASP/Amass/v3/...@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/otxurls@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/subfinder/cmd/subfinder@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/haccer/subjack@latest"
    "github.com/rverton/webanalyze/...@latest"
    "github.com/anshumanbh/tko-subs@latest"
)

# Run go install for each tool
for t in "${go_tools[@]}"; do
    echo "[*] go install $t"
    # Use `env` to ensure GOPATH is set for go install in this script
    env GOPATH="$GOTOP" PATH="$PATH" go install "$t" || {
        echo "[!] Failed to install $t (continuing)..."
    }
done

# Move GOPATH binaries to user PATH (GOPATH/bin is already in ~/.bashrc)
echo "[*] Go tool installation attempted. Check $GOTOP/bin for binaries."

# -------------------------
# Additional tool installations (non-go)
# -------------------------
cd "$HOME/Pentest/Tools" || exit 1

# findomain (binary)
if ! command -v findomain &>/dev/null; then
    echo "[*] Installing findomain..."
    wget -q https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O findomain
    chmod +x findomain
    mv findomain /usr/local/bin/findomain
fi

# aquatone
if [[ ! -f "$GOTOP/bin/aquatone" ]]; then
    echo "[*] Installing aquatone..."
    cd /tmp
    wget -q "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip"
    unzip -q aquatone_linux_amd64_1.7.0.zip
    rm -f aquatone_linux_amd64_1.7.0.zip README.md LICENSE.txt
    mv aquatone "$GOTOP/bin/" || mv aquatone /usr/local/bin/ || true
    cd -
fi

# subjack fingerprints
if [[ ! -f "$OTHERS/fingerprints.json" ]]; then
    echo "[*] Downloading subjack fingerprints..."
    wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O "$OTHERS/fingerprints.json"
fi

# tko-subs providers data
if [[ ! -f "$OTHERS/providers-data.csv" ]]; then
    echo "[*] Downloading tko-subs providers data..."
    wget -q https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv -O "$OTHERS/providers-data.csv"
fi

# Smuggler (python)
if [[ ! -f "$HOME/Pentest/Tools/Smuggler/smuggler.py" ]]; then
    echo "[*] Installing Smuggler..."
    wget -q https://raw.githubusercontent.com/gwen001/pentest-tools/master/smuggler.py -O "$HOME/Pentest/Tools/Smuggler/smuggler.py"
    chmod +x "$HOME/Pentest/Tools/Smuggler/smuggler.py" || true
fi

# GitHub endpoints script
if [[ ! -f "$HOME/Pentest/Tools/GitHubTool/github-endpoints.py" ]]; then
    echo "[*] Installing github-endpoints script..."
    wget -q https://raw.githubusercontent.com/gwen001/github-search/master/github-endpoints.py -O "$HOME/Pentest/Tools/GitHubTool/github-endpoints.py"
    chmod +x "$HOME/Pentest/Tools/GitHubTool/github-endpoints.py" || true
fi

# Massdns
if [[ ! -d "Massdns" ]]; then
    echo "[*] Installing massdns..."
    git clone --depth 1 https://github.com/blechschmidt/massdns.git Massdns || true
    pushd Massdns >/dev/null || true
    make || true
    popd >/dev/null || true
fi

# LinkFinder
if [[ ! -d "LinkFinder" ]]; then
    echo "[*] Installing LinkFinder..."
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git LinkFinder || true
    pushd LinkFinder >/dev/null || true
    python3 setup.py install || true
    popd >/dev/null || true
fi

# Finddomain / chrome installer from earlier script (chrome)
if ! command -v google-chrome &>/dev/null; then
    echo "[*] Downloading and installing Google Chrome..."
    wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb
    apt-get install -y /tmp/google-chrome-stable_current_amd64.deb || dpkg -i /tmp/google-chrome-stable_current_amd64.deb || true
    rm -f /tmp/google-chrome-stable_current_amd64.deb
fi

# -------------------------
# Optional installers that require local installer files
# (The script will attempt to run them if found in current dir)
# -------------------------
if [[ -f "./burpsuite_community_linux_v2021_4_3.sh" ]]; then
    echo "[*] Installing Burp Suite (local installer detected)..."
    chmod +x ./burpsuite_community_linux_v2021_4_3.sh
    ./burpsuite_community_linux_v2021_4_3.sh || true
else
    echo "[*] Burp Suite installer not found in current dir. Skipping (place burpsuite installer next to this script to auto-run)."
fi

if [[ -f "./ZAP_2_10_0_unix.sh" ]]; then
    echo "[*] Installing OWASP ZAP (local installer detected)..."
    chmod +x ./ZAP_2_10_0_unix.sh
    ./ZAP_2_10_0_unix.sh || true
else
    echo "[*] ZAP installer not found in current dir. Skipping (place ZAP installer next to this script to auto-run)."
fi

# -------------------------
# Final touches
# -------------------------
echo "[*] Ensuring GOPATH/bin is in PATH for this session..."
export GOPATH="$GOTOP"
export PATH="$PATH:$GOTOP/bin:/usr/local/go/bin:$BIN_DIR"

echo -e "\nINSTALLATION IS FINISHED."
echo "Please restart your shell or run: source ~/.bashrc"
echo "Check $GOTOP/bin and $HOME/Pentest/Tools for installed tools."

exit 0
