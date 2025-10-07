#!/usr/bin/env bash
#==============================================================#
#  LightCoder - Interactive Recon Tool                         #
#  Author: Arlyone                                             #
#  Description: Menu-driven recon & enumeration automation      #
#==============================================================#

set -euo pipefail
IFS=$'\n\t'

#-----------------------------------------#
# COLORS
#-----------------------------------------#
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#-----------------------------------------#
# ASCII Banner
#-----------------------------------------#
banner() {
    echo -e "${CYAN}
 _     ___ ____ _   _ _____    ____ ___  ____  _____ ____  
| |   |_ _/ ___| | | |_   _|  / ___/ _ \\|  _ \\| ____|  _ \\ 
| |    | | |  _| |_| | | |   | |  | | | | | | |  _| | |_) |
| |___ | | |_| |  _  | | |   | |__| |_| | |_| | |___|  _ < 
|_____|___\\____|_| |_| |_|    \\____\\___/|____/|_____|_| \\_\\
${NC}
  ${GREEN}Interactive Recon & Enumeration Tool${NC}
  ${YELLOW}Author: Arlyone${NC}
--------------------------------------------------------------"
}

#-----------------------------------------#
# SETUP
#-----------------------------------------#
setup_env() {
    TARGET="${1:-}"
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] Usage:${NC} $0 target.com"
        exit 1
    fi

    WORKDIR="$(pwd)/recon_${TARGET}"
    mkdir -p "$WORKDIR"
    echo -e "${GREEN}[+] Output directory:${NC} $WORKDIR"
}

#-----------------------------------------#
# SUMMARY FUNCTION
#-----------------------------------------#
show_summary() {
    echo -e "\n${CYAN}====================[ RESULTS SUMMARY ]====================${NC}"
    [[ -f "$WORKDIR/domains.txt" ]] && echo -e "${YELLOW}Subdomains Found:${NC} $(wc -l < "$WORKDIR/domains.txt")"
    [[ -f "$WORKDIR/alive.txt" ]] && echo -e "${YELLOW}Alive Hosts:${NC} $(wc -l < "$WORKDIR/alive.txt")"
    [[ -f "$WORKDIR/ips.txt" ]] && echo -e "${YELLOW}Resolved IPs:${NC} $(wc -l < "$WORKDIR/ips.txt")"
    [[ -f "$WORKDIR/cors.txt" ]] && echo -e "${YELLOW}CORS Vulnerable URLs:${NC} $(wc -l < "$WORKDIR/cors.txt")"
    [[ -f "$WORKDIR/put_test.txt" ]] && echo -e "${YELLOW}PUT Tests Run:${NC} $(wc -l < "$WORKDIR/put_test.txt")"
    [[ -d "$WORKDIR/screenshots" ]] && echo -e "${YELLOW}Screenshots Saved:${NC} $(find "$WORKDIR/screenshots" -type f | wc -l)"
    [[ -d "$WORKDIR/nmapscans" ]] && echo -e "${YELLOW}Nmap Reports:${NC} $(find "$WORKDIR/nmapscans" -type f | wc -l)"
    echo -e "${CYAN}===========================================================${NC}\n"
}

#-----------------------------------------#
# FUNCTIONS
#-----------------------------------------#
discover_subdomains() {
    echo -e "\n${YELLOW}[+] Starting Subdomain Discovery...${NC}"
    cd "$WORKDIR"
    > domains.txt

    if command -v subfinder &>/dev/null; then
        subfinder -d "$TARGET" -silent -o subfinder.txt || true
        cat subfinder.txt >> domains.txt
    fi

    if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$TARGET" | tee -a domains.txt >/dev/null
    fi

    sort -u domains.txt -o domains.txt
    echo -e "${GREEN}[+] Subdomain Discovery Completed.${NC}"
    show_summary
}

check_alive() {
    echo -e "\n${YELLOW}[+] Checking Alive Hosts...${NC}"
    cd "$WORKDIR"
    [[ ! -f domains.txt ]] && { echo "[!] domains.txt not found. Run discovery first."; return; }

    if command -v httpx &>/dev/null; then
        httpx -l domains.txt -silent -threads 200 -o alive.txt
    elif command -v httprobe &>/dev/null; then
        cat domains.txt | httprobe | tee alive.txt
    else
        echo "[!] httpx or httprobe not installed."
    fi

    echo -e "${GREEN}[+] Alive domains saved to:${NC} $WORKDIR/alive.txt"
    show_summary
}

resolve_ips() {
    echo -e "\n${YELLOW}[+] Resolving IPs...${NC}"
    cd "$WORKDIR"
    [[ ! -f alive.txt ]] && { echo "[!] alive.txt not found. Run Alive Check first."; return; }

    > ips.txt
    while read -r url; do
        host=$(echo "$url" | awk -F/ '{print $3}')
        getent hosts "$host" | awk '{print $1}' >> ips.txt || true
    done < alive.txt

    sort -u ips.txt -o ips.txt
    echo -e "${GREEN}[+] Resolved IPs saved to:${NC} $WORKDIR/ips.txt"
    show_summary
}

test_put_method() {
    echo -e "\n${YELLOW}[+] Testing for PUT upload method...${NC}"
    cd "$WORKDIR"
    [[ ! -f alive.txt ]] && { echo "[!] alive.txt not found."; return; }

    > put_test.txt
    while read -r url; do
        rand="lc_$(date +%s)_$RANDOM.txt"
        curl -ks -o /dev/null -w "URL:%{url_effective} CODE:%{response_code}\n" -X PUT -d "LightCoderTest" "${url}/${rand}" >> put_test.txt
    done < alive.txt

    echo -e "${GREEN}[+] PUT results saved to:${NC} $WORKDIR/put_test.txt"
    show_summary
}

check_cors() {
    echo -e "\n${YELLOW}[+] Checking for CORS vulnerabilities...${NC}"
    cd "$WORKDIR"
    [[ ! -f alive.txt ]] && { echo "[!] alive.txt not found."; return; }

    > cors.txt
    while read -r url; do
        res=$(curl -ks -I -H "Origin: evil.com" -m 7 "$url")
        if echo "$res" | grep -qi "Access-Control-Allow-Origin: evil.com"; then
            echo "[VULN] $url" >> cors.txt
        fi
    done < alive.txt

    echo -e "${GREEN}[+] CORS results saved to:${NC} $WORKDIR/cors.txt"
    show_summary
}

collect_headers() {
    echo -e "\n${YELLOW}[+] Collecting headers and bodies...${NC}"
    cd "$WORKDIR"
    mkdir -p headers responsebody

    while read -r url; do
        host=$(echo "$url" | awk -F/ '{print $3}')
        curl -ks -I "$url" -o "headers/$host.headers"
        curl -ks -L "$url" -o "responsebody/$host.body"
    done < alive.txt

    echo -e "${GREEN}[+] Headers saved in:${NC} $WORKDIR/headers/"
    show_summary
}

screenshots() {
    echo -e "\n${YELLOW}[+] Taking Screenshots...${NC}"
    cd "$WORKDIR"

    if command -v aquatone &>/dev/null; then
        cat alive.txt | aquatone -out screenshots || true
    elif command -v eyewitness &>/dev/null; then
        eyewitness --web -f alive.txt -d screenshots
    else
        echo "[!] aquatone or eyewitness not installed."
    fi

    echo -e "${GREEN}[+] Screenshots saved to:${NC} $WORKDIR/screenshots/"
    show_summary
}

run_nmap() {
    echo -e "\n${YELLOW}[+] Running Nmap scans...${NC}"
    cd "$WORKDIR"
    mkdir -p nmapscans

    while read -r url; do
        host=$(echo "$url" | awk -F/ '{print $3}')
        safe=$(echo "$host" | sed 's/[:\/]/_/g')
        nmap -sC -sV "$host" -oN "nmapscans/${safe}.nmap" -Pn -T4 || true
    done < alive.txt

    echo -e "${GREEN}[+] Nmap results saved to:${NC} $WORKDIR/nmapscans/"
    show_summary
}

#-----------------------------------------#
# MENU
#-----------------------------------------#
main_menu() {
    clear
    banner
    PS3=$'\n'"${CYAN}Choose an option:${NC} "
    options=(
        "1. Subdomain Discovery"
        "2. Check Alive Domains"
        "3. Resolve IPs"
        "4. Test PUT Upload"
        "5. Check CORS"
        "6. Collect Headers & Bodies"
        "7. Screenshots"
        "8. Run Nmap Scans"
        "9. Run Full Recon"
        "10. Exit"
    )
    select opt in "${options[@]}"; do
        case $REPLY in
            1) discover_subdomains ;;
            2) check_alive ;;
            3) resolve_ips ;;
            4) test_put_method ;;
            5) check_cors ;;
            6) collect_headers ;;
            7) screenshots ;;
            8) run_nmap ;;
            9)
                discover_subdomains
                check_alive
                resolve_ips
                test_put_method
                check_cors
                collect_headers
                screenshots
                run_nmap
                echo -e "${GREEN}Full Recon Completed!${NC}"
                show_summary
                ;;
            10)
                echo -e "${GREEN}Exiting LightCoder.${NC}"
                break
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
        echo -e "\n${YELLOW}Press Enter to return to the menu...${NC}"
        read -r
        clear
        banner
        echo -e "${CYAN}Target:${NC} $TARGET"
        echo
        echo "${options[@]}"
    done
}

#-----------------------------------------#
# EXECUTION
#-----------------------------------------#
banner
setup_env "$@"
main_menu
