#!/bin/bash

# ============================================================
# Web App Pentest Toolkit Installer for Arch Linux
# Complete Edition - Zero Friction Setup
# ============================================================

set -e # Exit immediately if a command exits with a non-zero status

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to clone or pull git repos
git_clone_or_update() {
    local repo_url=""
    local dest_dir="$2"
    if [ -d "$dest_dir" ]; then
        echo -e "${YELLOW}[*] Updating $(basename "$dest_dir")...${NC}"
        (cd "$dest_dir" && git pull) || echo -e "${RED}[!] Failed to update $(basename "$dest_dir")${NC}"
    else
        echo -e "${GREEN}[*] Cloning $(basename "$dest_dir")...${NC}"
        git clone "$repo_url" "$dest_dir"
    fi
}

echo -e "${GREEN}[*] Web App Pentest Toolkit Installer${NC}"
echo -e "${GREEN}[*] Starting installation...${NC}"
echo ""

# ============================================================
# System Update & Base Dependencies
# ============================================================
echo -e "${YELLOW}[*] Updating System and Installing Base Dependencies...${NC}"
sudo pacman -Syu --noconfirm
sudo pacman -S --needed --noconfirm base-devel git curl wget python python-pip python-pipx \
go docker docker-compose tmux screen ruby nmap jq

# Setup Docker
echo -e "${YELLOW}[*] Configuring Docker...${NC}"
sudo systemctl enable --now docker.service || true
if ! getent group docker > /dev/null; then
    sudo groupadd docker
fi
sudo usermod -aG docker "$USER" || true

# Setup Go Environment
echo -e "${YELLOW}[*] Setting up Go environment...${NC}"
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p "$GOPATH/bin"

# Setup Tool Directory
TOOL_DIR="$HOME/Pentest-Tools"
mkdir -p "$TOOL_DIR"
echo -e "${GREEN}[*] Tools will be cloned to $TOOL_DIR${NC}"

# ============================================================
# 1. Core Suite & Foundation
# ============================================================
echo -e "${YELLOW}[*] Installing Core Suite...${NC}"
sudo pacman -S --needed --noconfirm burpsuite nikto

# ============================================================
# 2. Recon & Enumeration Stack (Go-based)
# ============================================================
echo -e "${YELLOW}[*] Installing Recon Tools (Go-based)...${NC}"

# Define Go tools to install
go_tools=(
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/cmd/amass@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/hahwul/dalfox/v2@latest"
)

for tool in "${go_tools[@]}"; do
    echo -e "    ...installing ${tool%%@*}"
    go install "$tool"
done

echo -e "${YELLOW}[*] Updating Nuclei templates...${NC}"
"$GOPATH/bin/nuclei" -update-templates || true

# Rust-based tools
echo -e "${YELLOW}[*] Installing Rust-based tools...${NC}"
sudo pacman -S --needed --noconfirm feroxbuster

# Masscan
sudo pacman -S --needed --noconfirm masscan

# Waymore (Python)
echo -e "${YELLOW}[*] Installing Python-based recon tools...${NC}"
pipx install git+https://github.com/xnl-h4ck3r/waymore.git --force

# ============================================================
# 3. Exploitation Tools
# ============================================================
echo -e "${YELLOW}[*] Installing Exploitation Tools...${NC}"

# SQLMap
sudo pacman -S --needed --noconfirm sqlmap

# Wfuzz
sudo pacman -S --needed --noconfirm wfuzz

# XSStrike (Must be cloned - not pipx compatible)
echo -e "${YELLOW}[*] Installing XSStrike...${NC}"
git_clone_or_update "https://github.com/s0md3v/XSStrike.git" "$TOOL_DIR/XSStrike"
cd "$TOOL_DIR/XSStrike"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt || echo -e "${RED}[!] XSStrike requirements failed${NC}"
deactivate
cd - > /dev/null

# Commix
echo -e "${YELLOW}[*] Installing Commix...${NC}"
pipx install commix --force

# Ysoserial (Java Deserialization)
echo -e "${YELLOW}[*] Downloading Ysoserial...${NC}"
mkdir -p "$TOOL_DIR/ysoserial"
if [ ! -f "$TOOL_DIR/ysoserial/ysoserial-all.jar" ]; then
    wget -O "$TOOL_DIR/ysoserial/ysoserial-all.jar" \
    "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" 2>/dev/null || \
    echo -e "${RED}[!] Ysoserial download failed - get manually from GitHub releases${NC}"
else
    echo -e "${GREEN}[+] Ysoserial already downloaded.${NC}"
fi

# Evil-WinRM (Ruby Gem)
echo -e "${YELLOW}[*] Installing Evil-WinRM...${NC}"
if ! gem list -i evil-winrm > /dev/null; then
    sudo gem install evil-winrm
fi

# CrackMapExec (via Pipx)
pipx install crackmapexec --force

# Responder
echo -e "${YELLOW}[*] Installing Responder...${NC}"
git_clone_or_update "https://github.com/lgandx/Responder.git" "$TOOL_DIR/Responder"

# ============================================================
# 4. Specialized & JWT Tools
# ============================================================
echo -e "${YELLOW}[*] Installing Specialized Tools...${NC}"

# JWT Tool (Must be cloned)
echo -e "${YELLOW}[*] Installing jwt_tool...${NC}"
git_clone_or_update "https://github.com/ticarpi/jwt_tool.git" "$TOOL_DIR/jwt_tool"
cd "$TOOL_DIR/jwt_tool"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt || echo -e "${RED}[!] jwt_tool requirements failed${NC}"
deactivate
chmod +x jwt_tool.py
# Create a symlink for easy access - use wrapper to use venv
sudo rm -f /usr/local/bin/jwt_tool
echo "#!/bin/bash
cd $TOOL_DIR/jwt_tool
source venv/bin/activate
python3 jwt_tool.py \"\$@\"
deactivate
" | sudo tee /usr/local/bin/jwt_tool > /dev/null
sudo chmod +x /usr/local/bin/jwt_tool
cd - > /dev/null

# Arjun (Parameter Discovery)
pipx install arjun --force

# ParamSpider (via pipx)
pipx install git+https://github.com/devanshbatham/ParamSpider --force

# CeWL (Wordlist generator)
sudo pacman -S --needed --noconfirm cewl

# theHarvester
pipx install theHarvester --force

# recon-ng
pipx install recon-ng --force

# ============================================================
# 5. AI Red Teaming Tools
# ============================================================
echo -e "${YELLOW}[*] Installing AI Red Team Tools...${NC}"

# Garak (LLM Scanner)
pipx install garak --force

# Promptmap (Python tool - not Go)
echo -e "${YELLOW}[*] Installing Promptmap...${NC}"
git_clone_or_update "https://github.com/utkusen/promptmap.git" "$TOOL_DIR/promptmap"
cd "$TOOL_DIR/promptmap"
if [ -f requirements.txt ]; then
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    pip install -r requirements.txt || echo -e "${RED}[!] Promptmap requirements failed${NC}"
    deactivate
fi
cd - > /dev/null

# Rebuff (Defensive AI)
git_clone_or_update "https://github.com/protectai/rebuff.git" "$TOOL_DIR/rebuff"

# ============================================================
# 6. GF Patterns Setup
# ============================================================
echo -e "${YELLOW}[*] Setting up GF patterns...${NC}"
mkdir -p ~/.gf

# Clone GF examples
git_clone_or_update "https://github.com/tomnomnom/gf.git" "$TOOL_DIR/gf-source"
if [ -d "$TOOL_DIR/gf-source/examples" ]; then
    cp "$TOOL_DIR/gf-source/examples/"*.json ~/.gf/ 2>/dev/null || true
fi

# Clone additional community patterns
git_clone_or_update "https://github.com/1ndianl33t/Gf-Patterns" "$TOOL_DIR/Gf-Patterns"
if [ -d "$TOOL_DIR/Gf-Patterns" ]; then
    cp "$TOOL_DIR/Gf-Patterns/"*.json ~/.gf/ 2>/dev/null || true
fi

# ============================================================
# 7. Wordlists & Resources
# ============================================================
echo -e "${YELLOW}[*] Downloading Wordlists (This may take time)...${NC}"
mkdir -p "$TOOL_DIR/Wordlists"

# SecLists (Pacman package)
sudo pacman -S --needed --noconfirm seclists
ln -sf /usr/share/seclists "$TOOL_DIR/Wordlists/SecLists"

# PayloadsAllTheThings
git_clone_or_update "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "$TOOL_DIR/Wordlists/PayloadsAllTheThings"

# FuzzDB
git_clone_or_update "https://github.com/fuzzdb-project/fuzzdb.git" "$TOOL_DIR/Wordlists/FuzzDB"

# ============================================================
# 8. Auxiliary Tools
# ============================================================
echo -e "${YELLOW}[*] Installing Auxiliary Tools...${NC}"

# Wireshark
sudo pacman -S --needed --noconfirm wireshark-qt
sudo groupadd wireshark 2>/dev/null || true
sudo usermod -a -G wireshark "$USER" || true

# ============================================================
# 9. Docker Vulnerable Applications
# ============================================================
echo -e "${YELLOW}[*] Pulling vulnerable app containers...${NC}"
sudo systemctl start docker
docker pull vulnerables/web-dvwa || true
docker pull bkimminich/juice-shop || true
docker pull webgoat/webgoat || true

# ============================================================
# 10. Spiderfoot (Docker)
# ============================================================
echo -e "${YELLOW}[*] Pulling Spiderfoot container...${NC}"
docker pull spiderfoot/spiderfoot || true

# ============================================================
# Post-Installation Setup
# ============================================================
echo -e "${YELLOW}[*] Creating tool reference documentation...${NC}"

# Generate Obsidian-compatible markdown reference
cat > "$TOOL_DIR/TOOLKIT_REFERENCE.md" << EOF
# Web App Pentest Toolkit Reference
Last Updated: $(date +"%Y-%m-%d %H:%M:%S")

## Installation Locations
- **Go tools**: \`$GOPATH/bin\` (~/.go/bin or ~/go/bin)
- **Pipx tools**: \`~/.local/bin\`
- **Git clones**: \`~/Pentest-Tools/\`
- **Wordlists**: \`~/Pentest-Tools/Wordlists/\`

## Installed Tools by Category

### Recon & Enumeration
- **ffuf** - Fast web fuzzer
- **gobuster** - Directory/DNS/vhost brute-forcing
- **nuclei** - Vulnerability scanner (templates in ~/.nuclei-templates)
- **subfinder** - Subdomain discovery
- **amass** - In-depth subdomain enumeration
- **assetfinder** - Subdomain discovery
- **httpx** - HTTP toolkit
- **httprobe** - Probe for live HTTP/HTTPS servers
- **waybackurls** - Fetch URLs from Wayback Machine
- **gau** - Get All URLs from various sources
- **hakrawler** - Web crawler
- **gospider** - Fast web spider
- **katana** - Next-gen crawling framework
- **dnsx** - Fast DNS toolkit
- **feroxbuster** - Recursive content discovery
- **masscan** - Fast port scanner
- **waymore** - Archive crawler

### Exploitation
- **sqlmap** - SQL injection automation
- **wfuzz** - Web application fuzzer
- **dalfox** - XSS scanner
- **XSStrike** - XSS detection/exploitation (\`~/Pentest-Tools/XSStrike/xsstrike.py\`)
- **commix** - Command injection exploitation
- **ysoserial** - Java deserialization exploits (\`~/Pentest-Tools/ysoserial/\`)
- **evil-winrm** - WinRM shell
- **crackmapexec** - Post-exploitation tool
- **Responder** - LLMNR/NBT-NS poisoning (\`~/Pentest-Tools/Responder/\`)
- **nikto** - Web server scanner

### Specialized Tools
- **jwt_tool** - JWT manipulation (\`jwt_tool\` command or \`~/Pentest-Tools/jwt_tool/jwt_tool.py\`)
- **arjun** - HTTP parameter discovery
- **ParamSpider** - Parameter miner
- **anew** - Append without duplicates
- **qsreplace** - Query string replacer
- **unfurl** - URL aprser
- **gf** - Grep for patterns (patterns in ~/.gf/)
- **cewl** - Custom wordlist generator
- **theHarvester** - OSINT gathering
- **recon-ng** - Recon framework

### AI Red Team Tools
- **garak** - LLM vulnerability scanner
- **promptmap** - Prompt injection testing (\`~/Pentest-Tools/promptmap/\`)
- **rebuff** - Prompt injection defense (\`~/Pentest-Tools/rebuff/\`)

### Wordlists
- **SecLists** - \`/usr/share/seclists\` (symlinked to \`~/Pentest-Tools/Wordlists/\`)
- **PayloadsAllTheThings** - \`~/Pentest-Tools/Wordlists/PayloadsAllTheThings/\`
- **FuzzDB** - \`~/Pentest-Tools/Wordlists/FuzzDB/\`

### Vulnerable Apps (Docker)
\`\`\`bash
# DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# WebGoat
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat

# Spiderfoot
docker run -d -p 5001:5001 spiderfoot/spiderfoot
\`\`\`

## Quick Start Methodology

### 1. Recon Phase
\`\`\`bash
# Subdomain enumeration
subfinder -d target.com | httpx -silent | nuclei -t ~/nuclei-templates/

# Archive mining
waybackurls target.com | gf xss | dalfox pipe
\`\`\`

### 2. Discovery Phase
\`\`\`bash
# Content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Crawling
hakrawler -url https://target.com -depth 3
\`\`\`

### 3. Analysis Phase
\`\`\`bash
# Parameter discovery
arjun -u https://target.com/endpoint

# Pattern matching
cat urls.txt | gf sqli | qsreplace "' OR 1=1--"
\`\`\`

### 4. Exploitation Phase
\`\`\`bash
# SQL injection
sqlmap -u "https://target.com/vuln?id=1" --batch --dbs

# XSS testing
dalfox url https://target.com/search?q=FUZZ
\`\`\`

## PATH Configuration
Add to \`~/.bashrc\` or \`~/.zshrc\`:
\`\`\`bash
export GOPATH=\$HOME/go
export PATH=\$PATH:\$GOPATH/bin:\$HOME/.local/bin
\`\`\`

## Group Permissions
Log out and back in for these to take effect:
- Docker group (for running containers)
- Wireshark group (for packet capture)
EOF

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${YELLOW}Post-Installation Steps:${NC}"
echo ""
echo "1. Add these lines to your ~/.bashrc or ~/.zshrc:"
echo -e "${GREEN} export GOPATH=\$HOME/go${NC}"
echo -e "${GREEN} export PATH=\$PATH:\$GOPATH/bin:\$HOME/.local/bin${NC}"
echo ""
echo "2. Source your shell config or restart your terminal:"
echo -e "${GREEN} source ~/.bashrc${NC} # or source ~/.zshrc"
echo ""
echo "3. Log out and log back in for Docker and Wireshark group permissions"
echo ""
echo "4. Tool reference documentation created at:"
echo -e "${GREEN} $TOOL_DIR/TOOLKIT_REFERENCE.md${NC}"
echo ""
echo "5. Test your setup:"
echo -e "${GREEN} nuclei -version${NC}"
echo -e "${GREEN} ffuf -version${NC}"
echo -e "${GREEN} docker ps${NC}"
echo ""
echo -e "${YELLOW}Pro tip:${NC} Copy TOOLKIT_REFERENCE.md to your Obsidian vault for quick reference"
echo ""
echo -e "${GREEN}============================================================${NC}"