#!/usr/bin/env bash
# lightcoder.sh - lightweight automated recon
# Usage: ./lightcoder.sh domain.com
# Requires: sublist3r or subfinder, assetfinder, httprobe or httpx, httpx, waybackurls, aquatone, eyewitness (optional), nmap, curl, ruby (for relative-url-extractor), jq

# Automate the pentest and recon stuffs with this tool. 

echo -e "                                                      
 _     ___ ____ _   _ _____    ____ ___  ____  _____ ____  
| |   |_ _/ ___| | | |_   _|  / ___/ _ \|  _ \| ____|  _ \ 
| |    | | |  _| |_| | | |   | |  | | | | | | |  _| | |_) |
| |___ | | |_| |  _  | | |   | |__| |_| | |_| | |___|  _ < 
|_____|___\____|_| |_| |_|    \____\___/|____/|_____|_| \_\
                                                           
AUTHOR: Arlyone"
        
echo -e "RECON TOOL FOR PENETRATION TESTING"
echo "USAGE:./lightcoder.sh domain.com"

echo -e "\e[31m[STARTING]\e[0m"

set -euo pipefail
IFS=$'\n\t'

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 target.tld"
    exit 2
fi

# config
WORKDIR="$(pwd)/recon_${TARGET}"
DOMAINS_FILE="$WORKDIR/domains.txt"
LIVE_FILE="$WORKDIR/final.txt"
IPS_FILE="$WORKDIR/ips.txt"
HEADERS_DIR="$WORKDIR/headers"
RESP_DIR="$WORKDIR/responsebody"
SCRIPTS_DIR="$WORKDIR/scripts"
SCRIPTS_RSP_DIR="$WORKDIR/scriptsresponse"
ENDPOINTS_DIR="$WORKDIR/endpoints"
NMAP_DIR="$WORKDIR/nmapscans"
SCREENSHOT_DIR="$HOME/${TARGET}_screenshots"

mkdir -p "$WORKDIR" "$HEADERS_DIR" "$RESP_DIR" "$SCRIPTS_DIR" "$SCRIPTS_RSP_DIR" "$ENDPOINTS_DIR" "$NMAP_DIR" "$SCREENSHOT_DIR"

echo -e "\n[+] Recon run for: $TARGET"
echo "[+] Output directory: $WORKDIR"

# Helper: check command exists
require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[!] Required command not found: $1"
        MISSING=true
    fi
}

MISSING=false
for cmd in curl awk sort uniq sort sed grep httprobe httpx assetfinder sublist3r subfinder waybackurls aquatone eyewitness nmap ruby; do
    # Not all are mandatory: we'll check a subset below more carefully
    true
done

# Check core required tools (best-effort)
for cmd in curl httpx assetfinder httprobe nmap; do
    require_cmd "$cmd"
done

if [[ "$MISSING" == true ]]; then
    echo "[!] One or more required commands are missing. Install them and re-run the script."
    echo "    Recommended: assetfinder, subfinder/sublist3r, httpx/httprobe, waybackurls, aquatone, eyewitness, nmap"
    # continue anyway so user can run partial recon if they want
fi

echo -e "\n[STARTING] passive discovery..."

# 1) Subdomain discovery (try multiple tools, append results)
> "$DOMAINS_FILE"
# prefer subfinder if available, else sublist3r, else assetfinder only
if command -v subfinder &>/dev/null; then
    echo "[*] running subfinder..."
    subfinder -d "$TARGET" -silent -o "$WORKDIR/subfinder.txt" || true
    cat "$WORKDIR/subfinder.txt" >> "$DOMAINS_FILE" || true
elif command -v sublist3r &>/dev/null; then
    echo "[*] running sublist3r..."
    sublist3r -d "$TARGET" -o "$WORKDIR/sublist3r.txt" -v || true
    cat "$WORKDIR/sublist3r.txt" >> "$DOMAINS_FILE" || true
fi

if command -v assetfinder &>/dev/null; then
    echo "[*] running assetfinder..."
    assetfinder --subs-only "$TARGET" | tee -a "$DOMAINS_FILE" >/dev/null || true
fi

# dedupe & normalize (ensure scheme)
sort -u "$DOMAINS_FILE" -o "$DOMAINS_FILE" || true

# 2) Probe for alive hosts (http/https)
echo -e "\n[+] Checking for alive domains..."
if command -v httpx &>/dev/null; then
    # httpx outputs the full URL by default with scheme
    httpx -l "$DOMAINS_FILE" -silent -threads 200 -o "$LIVE_FILE" || true
elif command -v httprobe &>/dev/null; then
    cat "$DOMAINS_FILE" | httprobe -s -p http:80 -p https:443 -t 3000 | sed 's|^|http://|' > "$LIVE_FILE" || true
else
    # fallback: attempt simple curl check (slower)
    > "$LIVE_FILE"
    while read -r d; do
        for scheme in "https://" "http://"; do
            if curl -k --max-time 5 -sI "${scheme}${d}" | head -n1 | grep -qi "HTTP/"; then
                echo "${scheme}${d}" >> "$LIVE_FILE"
                break
            fi
        done
    done < "$DOMAINS_FILE"
fi

sort -u "$LIVE_FILE" -o "$LIVE_FILE" || true
echo "[*] Alive count: $(wc -l < "$LIVE_FILE" || echo 0)"

# 3) Convert alive domains to IPs
echo -e "\n[+] Resolving IPs..."
> "$IPS_FILE"
while read -r url; do
    host=$(echo "$url" | awk -F/ '{print $3}')
    # handle multiple addresses
    mapfile -t addrs < <(getent hosts "$host" 2>/dev/null | awk '{print $1}' || true)
    if [[ ${#addrs[@]} -eq 0 ]]; then
        # try host command
        mapfile -t addrs < <(host "$host" 2>/dev/null | awk '/has address/ {print $4}')
    fi
    for ip in "${addrs[@]}"; do
        echo "$ip" >> "$IPS_FILE"
    done
done < "$LIVE_FILE"
sort -u "$IPS_FILE" -o "$IPS_FILE" || true
echo "[*] IPs found: $(wc -l < "$IPS_FILE" || echo 0)"

# 4) Test PUT upload method (non-intrusive demonstration)
echo -e "\n[+] Testing PUT (non-destructive) against alive hosts..."
> "$WORKDIR/put.txt"
while read -r url; do
    # attempt PUT to a random filename under controlled payload; do NOT upload large payloads
    rand="lc_$(date +%s)_$RANDOM.txt"
    out=$(curl -ks -o /dev/null -w "URL:%{url_effective} CODE:%{response_code}\n" -X PUT -d "lightcoder-test" "${url}/${rand}" || true)
    echo "$out" >> "$WORKDIR/put.txt"
done < "$LIVE_FILE"

# 5) CORS check using httpx + custom header test (best-effort)
echo -e "\n[+] Checking simple CORS reflection via httpx + curl..."
> "$WORKDIR/cors.txt"
if command -v httpx &>/dev/null; then
    # httpx prints urls; we test them via curl for Access-Control-Allow-Origin with a malicious Origin
    while read -r url; do
        res=$(curl -ks -I -H "Origin: evil.com" -m 7 "$url" || true)
        if echo "$res" | grep -qi "Access-Control-Allow-Origin: *evil.com"; then
            echo "[VULN_CORS] $url" >> "$WORKDIR/cors.txt"
        fi
    done < "$LIVE_FILE"
fi

# 6) Store headers and full responses
echo -e "\n[+] Collecting headers and response bodies..."
while read -r url; do
    host=$(echo "$url" | awk -F/ '{print $3}')
    curl -ks -I -H "X-Forwarded-For: evil.com" "$url" -o "$HEADERS_DIR/$host.headers" || true
    curl -ks -L -H "X-Forwarded-For: evil.com" "$url" -o "$RESP_DIR/$host.body" || true
done < "$LIVE_FILE"

# 7) Collect JS files and save them
echo -e "\n[+] Collecting JavaScript files (from response bodies)..."
while read -r filepath; do
    host=$(basename "$filepath")
    mkdir -p "$SCRIPTS_RSP_DIR/$host"
    # Extract src attributes (basic heuristic)
    mapfile -t srcs < <(grep -Eo 'src=["'\''][^"'\'' ]+' "$filepath" 2>/dev/null | sed -E 's/src=("|'\'')//g' || true)
    for src in "${srcs[@]}"; do
        # normalize absolute vs relative
        if [[ "$src" =~ ^https?:// ]]; then
            url="$src"
        else
            url="https://${host}${src}"
        fi
        fname=$(basename "${url%%\?*}")
        # attempt download
        curl -ks -L "$url" -o "$SCRIPTS_RSP_DIR/$host/$fname" || true
        echo "$url" >> "$SCRIPTS_DIR/$host"
    done
done < <(ls -1 "$RESP_DIR" 2>/dev/null | sed "s|^|$RESP_DIR/|g")

# 8) Extract endpoints from JS using relative-url-extractor (if present)
echo -e "\n[+] Extracting endpoints from JS (relative-url-extractor)..."
if [[ -d "$HOME/relative-url-extractor" ]] && command -v ruby &>/dev/null; then
    for domain in $(ls -1 "$SCRIPTS_RSP_DIR"); do
        mkdir -p "$ENDPOINTS_DIR/$domain"
        for file in "$SCRIPTS_RSP_DIR/$domain"/*; do
            if [[ -f "$file" ]]; then
                ruby "$HOME/relative-url-extractor/extract.rb" "$file" >> "$ENDPOINTS_DIR/$domain/$(basename "$file").endpoints" || true
            fi
        done
    done
else
    echo "[*] relative-url-extractor not found in \$HOME or ruby missing. Skipping JS endpoint extraction."
fi

# 9) Screenshots via aquatone + eyewitness (best-effort)
echo -e "\n[+] Taking screenshots with aquatone (if available)..."
if command -v aquatone &>/dev/null; then
    cat "$LIVE_FILE" | aquatone -out "$SCREENSHOT_DIR" || true
else
    echo "[*] aquatone not found. Skipping screenshots."
fi

if command -v eyewitness &>/dev/null; then
    eyewitness --web -f "$LIVE_FILE" -d "$SCREENSHOT_DIR/eyewitness" || true
fi

# 10) Nmap scans (basic)
echo -e "\n[+] Running light Nmap scans (default scripts)..."
while read -r url; do
    host=$(echo "$url" | awk -F/ '{print $3}')
    safe_name=$(echo "$host" | sed 's/[:\/]/_/g')
    nmap -sC -sV "$host" -oN "$NMAP_DIR/${safe_name}.nmap" -Pn -T4 || true
done < "$LIVE_FILE"

# 11) Optional: Wayback + gf patterns (enumeration helpers)
echo -e "\n[+] Gathering Wayback URLs and running light gf checks..."
if command -v waybackurls &>/dev/null; then
    while read -r domain; do
        waybackurls "$domain" >> "$WORKDIR/wayback_urls.txt" || true
    done < "$DOMAINS_FILE"
fi

echo -e "\n[+] Recon complete. Summary:"
echo "  Domains discovered: $(wc -l < "$DOMAINS_FILE" || echo 0)"
echo "  Alive hosts:        $(wc -l < "$LIVE_FILE" || echo 0)"
echo "  IPs resolved:       $(wc -l < "$IPS_FILE" || echo 0)"
echo "  Screenshots dir:    $SCREENSHOT_DIR"
echo "  Full output folder: $WORKDIR"

echo -e "\n[!] IMPORTANT: Review all findings and do not perform intrusive testing without written permission."


# echo "Adding more features...."
# echo "-----More Features coming soon------"

