#!/bin/bash
# ╔═══════════════════════════════════════════════════════════╗
# ║  MINERVA RICE - UNINSTALLER                               ║
# ║  Removes configs, packages, and resets system state       ║
# ║  Use this to cleanly test fresh installs                  ║
# ╚═══════════════════════════════════════════════════════════╝

# -------------------------
# COLORS
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

say() { echo -e "${CYAN}$*${NC}"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
die() { echo -e "${RED}❌${NC} $*"; exit 1; }

# -------------------------
# PRE-FLIGHT
# -------------------------
if [ "${EUID}" -eq 0 ]; then
  die "Don't run as root. Script uses sudo when needed."
fi

echo
echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║           MINERVA RICE UNINSTALLER                        ║${NC}"
echo -e "${RED}║  This will REMOVE all rice configs and optionally pkgs    ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}This script will:${NC}"
echo "  1. Remove all Minerva config files from ~/.config"
echo "  2. Remove zsh setup (oh-my-zsh, plugins, pure prompt)"
echo "  3. Remove dotfiles (.zshrc, .xinitrc, .nanorc, .profile edits)"
echo "  4. Remove wallpapers from ~/Pictures/Wallpapers"
echo "  5. Remove rice-switch from ~/.local/bin"
echo "  6. Disable and remove emptty display manager config"
echo "  7. (Optional) Uninstall all Minerva-specific packages"
echo
read -p "Are you sure you want to continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# -------------------------
# OPTIONS
# -------------------------
echo
read -p "Also UNINSTALL packages (pacman/AUR)? This is more aggressive. [y/N] " -n 1 -r
echo
REMOVE_PACKAGES=false
if [[ $REPLY =~ ^[Yy]$ ]]; then
  REMOVE_PACKAGES=true
fi

read -p "Reset shell back to bash? [y/N] " -n 1 -r
echo
RESET_SHELL=false
if [[ $REPLY =~ ^[Yy]$ ]]; then
  RESET_SHELL=true
fi

echo
say "Starting uninstall..."
echo

# -------------------------
# 1) REMOVE CONFIG DIRECTORIES
# -------------------------
say "[1/7] Removing Minerva config directories..."

# List of config dirs the rice creates/owns
CONFIG_DIRS=(
  "$HOME/.config/i3"
  "$HOME/.config/polybar"
  "$HOME/.config/rofi"
  "$HOME/.config/dunst"
  "$HOME/.config/picom"
  "$HOME/.config/kitty"
  "$HOME/.config/alacritty"
  "$HOME/.config/cava"
  "$HOME/.config/conky"
  "$HOME/.config/ranger"
  "$HOME/.config/hyfetch"
  "$HOME/.config/yazi"
  "$HOME/.config/gtk-3.0"
  "$HOME/.config/gtk-4.0"
)

for dir in "${CONFIG_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    rm -rf "$dir"
    ok "Removed $dir"
  fi
done
echo

# -------------------------
# 2) REMOVE ZSH ECOSYSTEM
# -------------------------
say "[2/7] Removing Zsh ecosystem..."

# Oh-My-Zsh
if [ -d "$HOME/.oh-my-zsh" ]; then
  rm -rf "$HOME/.oh-my-zsh"
  ok "Removed ~/.oh-my-zsh"
fi

# Pure prompt
if [ -d "$HOME/.zsh" ]; then
  rm -rf "$HOME/.zsh"
  ok "Removed ~/.zsh (pure prompt)"
fi
echo

# -------------------------
# 3) REMOVE DOTFILES
# -------------------------
say "[3/7] Removing dotfiles..."

DOTFILES=(
  "$HOME/.zshrc"
  "$HOME/.xinitrc"
  "$HOME/.nanorc"
)

for file in "${DOTFILES[@]}"; do
  if [ -f "$file" ]; then
    rm -f "$file"
    ok "Removed $file"
  fi
done

# Clean QT_QPA_PLATFORMTHEME from .profile (but don't delete .profile)
if [ -f "$HOME/.profile" ]; then
  if grep -q "QT_QPA_PLATFORMTHEME=qt5ct" "$HOME/.profile"; then
    sed -i '/QT_QPA_PLATFORMTHEME=qt5ct/d' "$HOME/.profile"
    ok "Removed QT_QPA_PLATFORMTHEME line from ~/.profile"
  fi
fi
echo

# -------------------------
# 4) REMOVE WALLPAPERS
# -------------------------
say "[4/7] Removing wallpapers..."

if [ -d "$HOME/Pictures/Wallpapers" ]; then
  rm -rf "$HOME/Pictures/Wallpapers"
  ok "Removed ~/Pictures/Wallpapers"
fi

# betterlockscreen cache
if [ -d "$HOME/.cache/betterlockscreen" ]; then
  rm -rf "$HOME/.cache/betterlockscreen"
  ok "Removed betterlockscreen cache"
fi
echo

# -------------------------
# 5) REMOVE rice-switch
# -------------------------
say "[5/7] Removing rice-switch..."

if [ -f "$HOME/.local/bin/rice-switch" ]; then
  rm -f "$HOME/.local/bin/rice-switch"
  ok "Removed ~/.local/bin/rice-switch"
fi
echo

# -------------------------
# 6) DISABLE + REMOVE DISPLAY MANAGER
# -------------------------
say "[6/7] Removing display manager setup..."

# Disable all display managers we may have used
sudo systemctl disable emptty 2>/dev/null || true
sudo systemctl disable ly 2>/dev/null || true
sudo systemctl disable lemurs 2>/dev/null || true
ok "Disabled display manager services"

# Remove emptty config
if [ -d "/etc/emptty" ]; then
  sudo rm -rf /etc/emptty
  ok "Removed /etc/emptty"
fi

# Clean up ly config
if [ -d "/etc/ly" ]; then
  sudo rm -rf /etc/ly
  ok "Removed /etc/ly"
fi

# Clean up lemurs config
if [ -d "/etc/lemurs" ]; then
  sudo rm -rf /etc/lemurs
  ok "Removed /etc/lemurs"
fi
echo

# -------------------------
# 7) UNINSTALL PACKAGES (OPTIONAL)
# -------------------------
if [ "$REMOVE_PACKAGES" = true ]; then
  say "[7/7] Uninstalling Minerva packages..."
  
  # Core packages from setup.sh (careful selection - only rice-specific ones)
  # NOT removing things like git, curl, networkmanager that the user might need
  RICE_PACKAGES=(
    # Window Manager & Bar
    i3-wm
    polybar
    rofi
    dunst
    picom
    
    # Terminals (user might want to keep one)
    kitty
    alacritty
    
    # Rice-specific tools
    conky
    cava
    hyfetch
    feh
    nitrogen
    
    # Lockscreen
    i3lock-color
    xautolock
    betterlockscreen
    
    # AUR packages
    rofi-greenclip
    picom-animations-git
    arc-gtk-theme
    emptty
    
    # Display managers (old versions)
    ly
    lemurs
    
    # Theming
    lxappearance
    qt5ct
    kvantum
    papirus-icon-theme
  )
  
  # Yazi helpers (probably safe to remove)
  YAZI_PACKAGES=(
    yazi
    ffmpegthumbnailer
    # keeping: jq, fd, ripgrep, fzf, zoxide - these are useful CLI tools
  )
  
  # Combine lists
  ALL_PACKAGES=("${RICE_PACKAGES[@]}" "${YAZI_PACKAGES[@]}")
  
  # Filter to only installed packages
  INSTALLED=()
  for pkg in "${ALL_PACKAGES[@]}"; do
    if pacman -Qi "$pkg" &>/dev/null; then
      INSTALLED+=("$pkg")
    fi
  done
  
  if [ ${#INSTALLED[@]} -gt 0 ]; then
    echo "Will remove: ${INSTALLED[*]}"
    echo
    read -p "Proceed with package removal? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      # Use yay if available (handles AUR packages), otherwise pacman
      if command -v yay &>/dev/null; then
        yay -Rns --noconfirm "${INSTALLED[@]}" 2>/dev/null || true
      else
        sudo pacman -Rns --noconfirm "${INSTALLED[@]}" 2>/dev/null || true
      fi
      ok "Packages removed"
    else
      warn "Skipped package removal"
    fi
  else
    ok "No rice-specific packages found to remove"
  fi
else
  say "[7/7] Skipping package removal (configs only mode)"
fi
echo

# -------------------------
# 8) RESET SHELL (OPTIONAL)
# -------------------------
if [ "$RESET_SHELL" = true ]; then
  say "Resetting shell to bash..."
  chsh -s /bin/bash || true
  ok "Shell reset to bash (applies next login)"
  echo
fi

# -------------------------
# DONE
# -------------------------
echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           UNINSTALL COMPLETE                              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${CYAN}What's left:${NC}"
echo "  • System packages (git, curl, networkmanager, etc.) - kept"
echo "  • ~/Pictures, ~/Documents, etc. - kept (only Wallpapers removed)"
echo "  • Any personal data in ~/ - kept"
echo
echo -e "${YELLOW}To fully reset for a fresh rice install:${NC}"
echo "  1. Reboot (or switch to a TTY with Ctrl+Alt+F2)"
echo "  2. Run setup.sh from the Minerva-rice repo"
echo
echo -e "${CYAN}If you want to go back to a basic TTY login:${NC}"
echo "  sudo systemctl set-default multi-user.target"
echo "  (After reboot you'll get a plain login prompt)"
echo
