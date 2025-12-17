#!/bin/bash

# Arch Linux Bare Bones Post-Install Script
# Intelligent Desktop Environment (DE) Bootstrapping & Alternative Detection

set -e # Exit immediately if a command exits with a non-zero status.

# Colors for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}>>> Starting Post-Install Setup...${NC}"

# Helper function: Check if ANY package in a list is installed
# Usage: check_alternatives "Generic Name" "pkg1" "pkg2" "pkg3" ...
check_alternatives() {
    local category="$1"
    shift
    local found=0
    
    for pkg in "$@"; do
        if pacman -Qi "$pkg" &> /dev/null; then
            echo -e "    ${GREEN}[+]${NC} $category: Found '$pkg'. Skipping others."
            found=1
            break
        fi
    done

    if [ $found -eq 0 ]; then
        # None found, install the first one in the list as default
        local default_pkg="$1"
        echo -e "    ${YELLOW}[-]${NC} $category: None found. Installing default: '$default_pkg'..."
        sudo pacman -S --noconfirm "$default_pkg"
    fi
}

# Helper function for single packages
install_if_missing() {
    local pkg_name="$1"
    if pacman -Qi "$pkg_name" &> /dev/null; then
        echo -e "    ${GREEN}[+]${NC} $pkg_name is already installed. Skipping."
    else
        echo -e "    ${YELLOW}[-]${NC} $pkg_name not found. Installing..."
        sudo pacman -S --noconfirm "$pkg_name"
    fi
}

# 1. Update System
echo -e "${CYAN}>>> Updating system repositories and packages...${NC}"
sudo pacman -Syu --noconfirm

# 2. Setup User Directories
echo -e "${CYAN}>>> Setting up XDG user directories...${NC}"
install_if_missing "xdg-user-dirs"
xdg-user-dirs-update
mkdir -p ~/Desktop ~/Downloads ~/Templates ~/Public ~/Documents ~/Music ~/Pictures ~/Videos

# 3. Essential Tools (The absolute minimum to function)
echo -e "${CYAN}>>> Checking Essential CLI utilities...${NC}"
for pkg in git wget curl unzip zip unrar htop btop fastfetch man-db; do
    install_if_missing "$pkg"
done

# Additional Essential Tools
echo -e "${CYAN}>>> Installing additional essentials...${NC}"
for pkg in vim neovim p7zip rsync tree; do
    install_if_missing "$pkg"
done

# Python (needed even outside pentest work)
install_if_missing "python"
install_if_missing "python-pip"

# ==============================================================================
# DESKTOP ENVIRONMENT DETECTION & INSTALLATION
# ==============================================================================

# Check for existing sessions (Wayland or X11)
EXISTING_SESSIONS=$(ls /usr/share/xsessions/*.desktop /usr/share/wayland-sessions/*.desktop 2>/dev/null || true)

if [ -n "$EXISTING_SESSIONS" ]; then
    echo -e "${GREEN}>>> Desktop Environment Detected!${NC}"
    echo "    Found sessions: $EXISTING_SESSIONS"
    echo "    Skipping DE installation to avoid conflicts."
else
    echo -e "${YELLOW}>>> No Desktop Environment detected.${NC}"
    echo -e "${CYAN}>>> You are currently in a headless/TTY state.${NC}"
    echo
    
    # Prompt for Minerva Rice
    echo -e "${CYAN}>>> Option 1: Install 'Minerva Rice' (Custom i3 Setup)${NC}"
    echo "    repo: https://github.com/Expert21/Minerva-Rice"
    read -p "    Install Minerva Rice? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}>>> Installing Minerva Rice...${NC}"
        RICE_DIR="$HOME/Minerva-Rice-Install"
        if [ -d "$RICE_DIR" ]; then rm -rf "$RICE_DIR"; fi
        git clone https://github.com/Expert21/Minerva-Rice "$RICE_DIR"
        cd "$RICE_DIR"
        chmod +x setup.sh
        ./setup.sh
        cd "$HOME"
        echo -e "${GREEN}>>> Minerva Rice installation complete!${NC}"
    else
        # Prompt for Fallback (XFCE)
        echo -e "${CYAN}>>> Option 2: Install Fallback Desktop (XFCE + SDDM)${NC}"
        read -p "    Install XFCE4 + SDDM? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}>>> Installing XFCE4 and SDDM...${NC}"
            sudo pacman -S --needed --noconfirm xfce4 xfce4-goodies
            
            # Check for Display Manager (Ly vs SDDM vs GDM vs LightDM)
            echo ">>> Checking Display Manager..."
            # If we don't have ly, gdm, or lightdm, install sddm
            check_alternatives "Display Manager" "sddm" "ly" "gdm" "lightdm"
            
            # Only enable sddm if we actually installed it or it's the chosen one
            if pacman -Qi sddm &> /dev/null; then
                 # minimal check to see if a display-manager service is already linked
                 if ! systemctl is-enabled display-manager &> /dev/null; then
                    sudo systemctl enable sddm
                 fi
            fi
            
            echo -e "${GREEN}>>> XFCE4 Installed.${NC}"
        else
            echo -e "${YELLOW}>>> Skipping Desktop Environment installation.${NC}"
        fi
    fi
fi

# ==============================================================================
# REMAINING "MUST HAVE" APPS (With Alternative Checks)
# ==============================================================================

echo -e "${CYAN}>>> Verifying 'Must Have' Applications...${NC}"

# 4. Terminal Emulator
# Default: alacritty. Alts: kitty, gnome-terminal, konsole, xfce4-terminal
check_alternatives "Terminal Emulator" "alacritty" "kitty" "gnome-terminal" "konsole" "xfce4-terminal" "wezterm"

# 5. File Manager (GUI)
# Default: thunar. Alts: dolphin, nautilus, pcmanfm, nemo
check_alternatives "GUI File Manager" "thunar" "dolphin" "nautilus" "pcmanfm" "nemo"

# 6. File Manager (Terminal)
# Default: ranger. Alts: yazi, mc, nnn
check_alternatives "Terminal File Manager" "ranger" "yazi" "mc" "nnn"

# 7. Usability Layer
install_if_missing "polkit-gnome"         # Auth Agent (Generic enough to keep)
install_if_missing "pavucontrol"          # Volume Mixer
install_if_missing "network-manager-applet" # Network Tray

# Notifications
# Default: dunst. Alts: mako (wayland), xfce4-notifyd
check_alternatives "Notification Daemon" "dunst" "mako" "xfce4-notifyd"

# Screenshots
# Default: flameshot. Alts: grim (wayland), scrot, spectacle, gnome-screenshot
check_alternatives "Screenshot Tool" "flameshot" "grim" "scrot" "spectacle" "gnome-screenshot"

# 8. Media Viewers
# Image Viewer / Wallpaper Setter
# Default: feh. Alts: nitrogen (wallpaper), viewnior, eog, ristretto, imv
check_alternatives "Image Viewer/Wallpaper" "feh" "nitrogen" "viewnior" "eog" "ristretto" "imv"

# Video Player
# Default: mpv. Alts: vlc, totem
check_alternatives "Video Player" "mpv" "vlc" "totem"

# 9. Fonts
echo -e "${CYAN}>>> Checking Fonts...${NC}"
for pkg in noto-fonts noto-fonts-cjk noto-fonts-emoji ttf-liberation ttf-dejavu; do
    install_if_missing "$pkg"
done

# 10. Audio (Pipewire)
echo -e "${CYAN}>>> Checking Audio...${NC}"
# Pipewire is structural, safer to check directly.
for pkg in pipewire pipewire-pulse wireplumber; do
    install_if_missing "$pkg"
done

# 11. Web Browser
# Default: firefox. Alts: chromium, brave-bin, google-chrome
check_alternatives "Web Browser" "firefox" "chromium" "brave-bin" "google-chrome" "vivaldi"

# 12. Optional: AUR Helper (yay)
echo -e "${CYAN}>>> Checking AUR Helper...${NC}"
# Check for yay or paru
if command -v yay &> /dev/null; then
    echo -e "    ${GREEN}[+]${NC} AUR Helper: Found 'yay'."
elif command -v paru &> /dev/null; then
    echo -e "    ${GREEN}[+]${NC} AUR Helper: Found 'paru'."
else
    echo -e "    ${YELLOW}[-]${NC} AUR Helper not found."
    read -p "    Install 'yay' (AUR Helper)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "    >>> Installing yay..."
        sudo pacman -S --needed --noconfirm base-devel
        git clone https://aur.archlinux.org/yay.git
        cd yay
        makepkg -si --noconfirm
        cd ..
        rm -rf yay
    fi
fi

# 13. Optional: Gaming (Steam)
echo -e "${CYAN}>>> Checking Gaming Support (Steam)...${NC}"
if pacman -Qi steam &> /dev/null; then
    echo -e "    ${GREEN}[+]${NC} Steam is already installed."
else
    echo -e "    ${YELLOW}[-]${NC} Steam not found."
    read -p "    Enable 'multilib' repo and install Steam? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "    >>> Enabling [multilib] repository..."
        # Uncomment [multilib] and the following Include line in pacman.conf
        sudo sed -i "/\[multilib\]/,/Include/"'s/^#//' /etc/pacman.conf
        
        echo "    >>> Updating repositories..."
        sudo pacman -Syu --noconfirm
        
        echo "    >>> Installing Steam..."
        sudo pacman -S --noconfirm steam
        
        # Install recommended font for Steam if missing (often ttf-liberation, but we have that)
        # Maybe 32-bit drivers? Arch wiki says 'steam' pulls most deps, 
        # but GPU drivers (vulkan-radeon, nvidia-utils) might need lib32 versions.
        # For a "bare bones" script, just steam is usually enough to get the UI open.
    else
        echo "    >>> Skipping Steam."
    fi
fi

# 14. GPU Drivers (Auto-Detect: AMD vs Nvidia)
echo -e "${CYAN}>>> Checking GPU Drivers...${NC}"

# Need lspci for detection
if ! command -v lspci &> /dev/null; then
    echo "    >>> Installing pciutils for GPU detection..."
    sudo pacman -S --noconfirm pciutils
fi

GPU_INFO=$(lspci -k | grep -A 2 -E "(VGA|3D)")
MULTILIB_ENABLED=0
if grep -q "^\[multilib\]" /etc/pacman.conf; then
    MULTILIB_ENABLED=1
fi

if echo "$GPU_INFO" | grep -qi "nvidia"; then
    echo -e "    ${GREEN}[+]${NC} NVIDIA GPU detected."
    
    # Base Nvidia packages
    NVIDIA_PKGS="nvidia nvidia-utils nvidia-settings"
    
    # 32-bit support (if multilib is on)
    if [ $MULTILIB_ENABLED -eq 1 ]; then
        echo -e "    ${GREEN}[+]${NC} Multilib enabled: Adding 32-bit Nvidia drivers."
        NVIDIA_PKGS="$NVIDIA_PKGS lib32-nvidia-utils"
    else
        echo -e "    ${YELLOW}[!]${NC} Multilib disabled: Skipping 32-bit drivers."
    fi

    # Check/Install
    if pacman -Qi nvidia-utils &> /dev/null; then
         echo -e "    ${GREEN}[+]${NC} Nvidia drivers seems installed. Skipping."
    else
         echo -e "    ${YELLOW}[-]${NC} Installing Nvidia Drivers..."
         sudo pacman -S --noconfirm $NVIDIA_PKGS
    fi

elif echo "$GPU_INFO" | grep -qi "amd\|ati"; then
    echo -e "    ${GREEN}[+]${NC} AMD GPU detected."
    
    # Base AMD packages
    AMD_PKGS="mesa xf86-video-amdgpu vulkan-radeon"
    
    # 32-bit support
    if [ $MULTILIB_ENABLED -eq 1 ]; then
        echo -e "    ${GREEN}[+]${NC} Multilib enabled: Adding 32-bit AMD drivers."
        AMD_PKGS="$AMD_PKGS lib32-mesa lib32-vulkan-radeon"
    else
        echo -e "    ${YELLOW}[!]${NC} Multilib disabled: Skipping 32-bit drivers."
    fi

    # Check/Install (checking vulkan-radeon as a proxy for 'gaming drivers')
    if pacman -Qi vulkan-radeon &> /dev/null; then
         echo -e "    ${GREEN}[+]${NC} AMD Gaming Drivers (Vulkan) seems installed. Skipping."
    else
         echo -e "    ${YELLOW}[-]${NC} Installing AMD Drivers..."
         sudo pacman -S --noconfirm $AMD_PKGS
    fi

else
    echo -e "    ${YELLOW}[!]${NC} No discrete AMD or Nvidia GPU detected (Intel or VM?). Skipping specific drivers."
fi


# ==============================================================================
# 15. Web App Pentest Tools (via webapptestscript.sh)
# ==============================================================================
echo -e "${CYAN}>>> Checking for and running Web App Pentest Tools installer...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PENTEST_SCRIPT="$SCRIPT_DIR/webapptestscript.sh"

if [ -f "$PENTEST_SCRIPT" ] && [ -x "$PENTEST_SCRIPT" ]; then
    echo -e "    ${GREEN}[+]${NC} Found '$PENTEST_SCRIPT'. Executing..."
    "$PENTEST_SCRIPT"
    echo -e "${GREEN}>>> Web App Pentest Tools installation complete!${NC}"
else
    echo -e "    ${YELLOW}[!]${NC} '$PENTEST_SCRIPT' not found or not executable. Skipping."
fi

echo -e "${GREEN}>>> Post-install setup complete!${NC}"
echo ">>> If you installed a DE/Rice, please REBOOT."
