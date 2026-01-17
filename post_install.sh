#!/bin/bash

# Arch Linux Bare Bones Post-Install Script
# Intelligent Desktop Environment (DE) Bootstrapping & Alternative Detection

set -e # Exit immediately if a command exits with a non-zero status.

# --- SUDO KEEP-ALIVE ---
# Ask for the password immediately
echo "Please authenticate to start the installation process:"
sudo -v

# Update the sudo timestamp every 60 seconds in the background
while true; do 
  sudo -n true
  sleep 60
  kill -0 "$$" || exit
done 2>/dev/null &
# -----------------------

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

# Helper function: Ensure a display manager is installed and enabled
# If none found, install ly and enable on tty7
ensure_display_manager() {
    echo -e "${CYAN}>>> Checking for Display Manager...${NC}"
    
    # Check for existing display managers
    for dm in ly sddm gdm lightdm lxdm; do
        if pacman -Qi "$dm" &> /dev/null; then
            echo -e "    ${GREEN}[+]${NC} Display Manager: Found '$dm'."
            # Enable if not already enabled
            if ! systemctl is-enabled display-manager &> /dev/null; then
                echo "    >>> Enabling $dm..."
                if [ "$dm" = "ly" ]; then
                    sudo systemctl enable ly@tty7
                else
                    sudo systemctl enable "$dm"
                fi
            fi
            return 0
        fi
    done
    
    # No display manager found, install ly
    echo -e "    ${YELLOW}[-]${NC} No Display Manager found. Installing 'ly'..."
    sudo pacman -S --needed --noconfirm ly
    sudo systemctl enable ly@tty7
    echo -e "    ${GREEN}[+]${NC} ly installed and enabled."
}

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
    
    # Display menu for DE selection
    echo -e "${CYAN}>>> Select a Desktop Environment to install:${NC}"
    echo "    1) Minerva-Rice (Custom i3 Setup)"
    echo "       repo: https://github.com/Expert21/Minerva-Rice"
    echo "    2) Minerva-Hyprland (Custom Hyprland Setup)"
    echo "       repo: https://github.com/Expert21/Minerva-hyprland"
    echo "    3) KDE Plasma"
    echo "    4) Skip - Do not install any DE"
    echo
    read -p "    Enter your choice [1-4]: " DE_CHOICE
    echo
    
    case "$DE_CHOICE" in
        1)
            # Minerva Rice (i3)
            echo -e "${CYAN}>>> Installing Minerva Rice (i3)...${NC}"
            RICE_DIR="$HOME/Minerva-Rice-Install"
            if [ -d "$RICE_DIR" ]; then 
                echo "    Removing old installation directory..."
                rm -rf "$RICE_DIR"
            fi
            
            if git clone https://github.com/Expert21/Minerva-Rice "$RICE_DIR"; then
                cd "$RICE_DIR"
                if [ -f "setup.sh" ]; then
                    # Fix potential Windows CRLF line endings
                    sed -i 's/\r$//' setup.sh
                    chmod +x setup.sh
                    ./setup.sh
                    echo -e "${GREEN}>>> Minerva Rice installation complete!${NC}"
                else
                    echo -e "${YELLOW}[!] setup.sh not found in the cloned repository.${NC}"
                    echo "    Listing files in $RICE_DIR:"
                    ls -F
                fi
                cd "$HOME"
            else
                echo -e "${YELLOW}[!] Failed to clone Minerva Rice repository.${NC}"
            fi
            
            # Ensure display manager
            ensure_display_manager
            ;;
        2)
            # Minerva Hyprland
            echo -e "${CYAN}>>> Installing Minerva Hyprland...${NC}"
            HYPR_DIR="$HOME/Minerva-Hyprland-Install"
            if [ -d "$HYPR_DIR" ]; then
                echo "    Removing old installation directory..."
                rm -rf "$HYPR_DIR"
            fi
            
            if git clone https://github.com/Expert21/Minerva-hyprland "$HYPR_DIR"; then
                cd "$HYPR_DIR"
                # Try common setup script names
                SETUP_SCRIPT=""
                for script in setup.sh install.sh INSTALL.sh; do
                    if [ -f "$script" ]; then
                        SETUP_SCRIPT="$script"
                        break
                    fi
                done
                
                if [ -n "$SETUP_SCRIPT" ]; then
                    # Fix potential Windows CRLF line endings
                    sed -i 's/\r$//' "$SETUP_SCRIPT"
                    chmod +x "$SETUP_SCRIPT"
                    ./"$SETUP_SCRIPT"
                    echo -e "${GREEN}>>> Minerva Hyprland installation complete!${NC}"
                else
                    echo -e "${YELLOW}[!] No setup script found in the cloned repository.${NC}"
                    echo "    Listing files in $HYPR_DIR:"
                    ls -F
                fi
                cd "$HOME"
            else
                echo -e "${YELLOW}[!] Failed to clone Minerva Hyprland repository.${NC}"
            fi
            
            # Ensure display manager
            ensure_display_manager
            ;;
        3)
            # KDE Plasma
            echo -e "${CYAN}>>> Installing KDE Plasma...${NC}"
            sudo pacman -S --needed --noconfirm plasma-meta kde-applications-meta
            
            # Ensure display manager (SDDM is preferred for KDE)
            if ! pacman -Qi sddm &> /dev/null; then
                echo -e "${CYAN}>>> Installing SDDM (recommended for KDE)...${NC}"
                sudo pacman -S --needed --noconfirm sddm
            fi
            
            if ! systemctl is-enabled display-manager &> /dev/null; then
                sudo systemctl enable sddm
            fi
            
            echo -e "${GREEN}>>> KDE Plasma installation complete!${NC}"
            ;;
        4|*)
            echo -e "${YELLOW}>>> Skipping Desktop Environment installation.${NC}"
            ;;
    esac
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
