#!/bin/bash
# ╔═══════════════════════════════════════════════════════════╗
# ║  DESKTOP ENVIRONMENT - UNINSTALLER                        ║
# ║  Removes configs, packages, and resets system state       ║
# ║  Supports: Minerva-Rice (i3), Minerva-Hyprland, KDE       ║
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
# DETECT INSTALLED RICES
# -------------------------
detect_rices() {
    local found=()
    
    # Check for i3 (Minerva-Rice)
    if [ -d "$HOME/.config/i3" ] || [ -d "$HOME/.config/polybar" ]; then
        found+=("minerva-i3")
    fi
    
    # Check for Hyprland (Minerva-Hyprland)
    if [ -d "$HOME/.config/hypr" ]; then
        found+=("minerva-hyprland")
    fi
    
    # Check for KDE Plasma
    if [ -d "$HOME/.config/plasma-org.kde.plasma.desktop-appletsrc" ] || \
       pacman -Qi plasma-desktop &>/dev/null 2>&1; then
        found+=("kde")
    fi
    
    echo "${found[@]}"
}

# -------------------------
# PRE-FLIGHT
# -------------------------
if [ "${EUID}" -eq 0 ]; then
  die "Don't run as root. Script uses sudo when needed."
fi

echo
echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║           DESKTOP ENVIRONMENT UNINSTALLER                 ║${NC}"
echo -e "${RED}║  Removes configs and optionally packages for any rice    ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
echo

# Detect what's installed
DETECTED_RICES=$(detect_rices)
if [ -n "$DETECTED_RICES" ]; then
    echo -e "${CYAN}Detected installations:${NC} $DETECTED_RICES"
    echo
fi

# -------------------------
# SELECT WHAT TO UNINSTALL
# -------------------------
echo -e "${CYAN}>>> Select what to uninstall:${NC}"
echo "    1) Minerva-Rice (i3 + Polybar setup)"
echo "    2) Minerva-Hyprland (Hyprland + Waybar setup)"
echo "    3) KDE Plasma"
echo "    4) All (uninstall everything)"
echo "    5) Common Only (zsh, wallpapers, display manager)"
echo "    0) Cancel"
echo
read -p "    Enter your choice [0-5]: " UNINSTALL_CHOICE
echo

case "$UNINSTALL_CHOICE" in
    0)
        echo "Aborted."
        exit 0
        ;;
    1) UNINSTALL_TARGET="minerva-i3" ;;
    2) UNINSTALL_TARGET="minerva-hyprland" ;;
    3) UNINSTALL_TARGET="kde" ;;
    4) UNINSTALL_TARGET="all" ;;
    5) UNINSTALL_TARGET="common" ;;
    *)
        die "Invalid choice."
        ;;
esac

echo -e "${YELLOW}This script will remove configurations for: ${UNINSTALL_TARGET}${NC}"
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
say "Starting uninstall for: $UNINSTALL_TARGET"
echo

# -------------------------
# CONFIG DIRECTORIES BY RICE TYPE
# -------------------------
I3_CONFIG_DIRS=(
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
)

HYPRLAND_CONFIG_DIRS=(
  "$HOME/.config/hypr"
  "$HOME/.config/waybar"
  "$HOME/.config/rofi"
  "$HOME/.config/dunst"
  "$HOME/.config/mako"
  "$HOME/.config/wezterm"
  "$HOME/.config/kitty"
  "$HOME/.config/alacritty"
  "$HOME/.config/swappy"
  "$HOME/.config/yazi"
  "$HOME/.config/ranger"
  "$HOME/.config/btop"
  "$HOME/.config/cava"
  "$HOME/.config/hyfetch"
  "$HOME/.config/quickshell"
)

KDE_CONFIG_DIRS=(
  "$HOME/.config/plasma-org.kde.plasma.desktop-appletsrc"
  "$HOME/.config/kwinrc"
  "$HOME/.config/kdeglobals"
  "$HOME/.config/konsolerc"
  "$HOME/.config/dolphinrc"
  "$HOME/.config/kglobalshortcutsrc"
  "$HOME/.local/share/plasma"
  "$HOME/.local/share/kwalletd"
)

COMMON_CONFIG_DIRS=(
  "$HOME/.config/gtk-3.0"
  "$HOME/.config/gtk-4.0"
)

# -------------------------
# PACKAGES BY RICE TYPE
# -------------------------
I3_PACKAGES=(
  i3-wm
  polybar
  rofi
  dunst
  picom
  kitty
  alacritty
  conky
  cava
  hyfetch
  feh
  nitrogen
  i3lock-color
  xautolock
  betterlockscreen
  rofi-greenclip
  picom-animations-git
)

HYPRLAND_PACKAGES=(
  hyprland
  waybar
  rofi-wayland
  dunst
  mako
  wezterm
  kitty
  alacritty
  swww
  hyprpaper
  hyprlock
  hypridle
  hyprshot
  swappy
  wl-clipboard
  cliphist
  xdg-desktop-portal-hyprland
  quickshell
)

KDE_PACKAGES=(
  plasma-meta
  kde-applications-meta
  plasma-desktop
  plasma-workspace
  dolphin
  konsole
  kate
  ark
  spectacle
  gwenview
  okular
)

COMMON_PACKAGES=(
  yazi
  ranger
  ffmpegthumbnailer
  lxappearance
  qt5ct
  kvantum
  papirus-icon-theme
  arc-gtk-theme
  ly
  lemurs
  emptty
)

# -------------------------
# FUNCTION: Remove config directories
# -------------------------
remove_configs() {
  local dirs=("$@")
  for dir in "${dirs[@]}"; do
    if [ -d "$dir" ] || [ -f "$dir" ]; then
      rm -rf "$dir"
      ok "Removed $dir"
    fi
  done
}

# -------------------------
# 1) REMOVE CONFIG DIRECTORIES
# -------------------------
say "[1/7] Removing config directories..."

case "$UNINSTALL_TARGET" in
  minerva-i3)
    remove_configs "${I3_CONFIG_DIRS[@]}" "${COMMON_CONFIG_DIRS[@]}"
    ;;
  minerva-hyprland)
    remove_configs "${HYPRLAND_CONFIG_DIRS[@]}" "${COMMON_CONFIG_DIRS[@]}"
    ;;
  kde)
    remove_configs "${KDE_CONFIG_DIRS[@]}" "${COMMON_CONFIG_DIRS[@]}"
    ;;
  all)
    remove_configs "${I3_CONFIG_DIRS[@]}" "${HYPRLAND_CONFIG_DIRS[@]}" "${KDE_CONFIG_DIRS[@]}" "${COMMON_CONFIG_DIRS[@]}"
    ;;
  common)
    remove_configs "${COMMON_CONFIG_DIRS[@]}"
    ;;
esac
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

# Pure prompt / Starship
if [ -d "$HOME/.zsh" ]; then
  rm -rf "$HOME/.zsh"
  ok "Removed ~/.zsh (pure/starship prompt)"
fi

# Starship config
if [ -f "$HOME/.config/starship.toml" ]; then
  rm -f "$HOME/.config/starship.toml"
  ok "Removed starship.toml"
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

# hyprlock cache
if [ -d "$HOME/.cache/hyprlock" ]; then
  rm -rf "$HOME/.cache/hyprlock"
  ok "Removed hyprlock cache"
fi

# swww cache
if [ -d "$HOME/.cache/swww" ]; then
  rm -rf "$HOME/.cache/swww"
  ok "Removed swww cache"
fi
echo

# -------------------------
# 5) REMOVE SCRIPTS
# -------------------------
say "[5/7] Removing scripts..."

SCRIPTS=(
  "$HOME/.local/bin/rice-switch"
  "$HOME/.local/bin/switch-mode.sh"
  "$HOME/.local/bin/generate-themes.sh"
  "$HOME/.local/bin/wallpaper.sh"
)

for script in "${SCRIPTS[@]}"; do
  if [ -f "$script" ]; then
    rm -f "$script"
    ok "Removed $script"
  fi
done

# Remove installation directories
for dir in "$HOME/Minerva-Rice-Install" "$HOME/Minerva-Hyprland-Install"; do
  if [ -d "$dir" ]; then
    rm -rf "$dir"
    ok "Removed $dir"
  fi
done
echo

# -------------------------
# 6) DISABLE + REMOVE DISPLAY MANAGER
# -------------------------
say "[6/7] Removing display manager setup..."

# Disable all display managers we may have used
sudo systemctl disable emptty 2>/dev/null || true
sudo systemctl disable ly 2>/dev/null || true
sudo systemctl disable ly@tty7 2>/dev/null || true
sudo systemctl disable lemurs 2>/dev/null || true
sudo systemctl disable sddm 2>/dev/null || true
sudo systemctl disable gdm 2>/dev/null || true
sudo systemctl disable lightdm 2>/dev/null || true
ok "Disabled display manager services"

# Remove display manager configs
for dm_conf in /etc/emptty /etc/ly /etc/lemurs; do
  if [ -d "$dm_conf" ]; then
    sudo rm -rf "$dm_conf"
    ok "Removed $dm_conf"
  fi
done
echo

# -------------------------
# 7) UNINSTALL PACKAGES (OPTIONAL)
# -------------------------
if [ "$REMOVE_PACKAGES" = true ]; then
  say "[7/7] Uninstalling packages..."
  
  # Build package list based on target
  PACKAGES_TO_REMOVE=()
  
  case "$UNINSTALL_TARGET" in
    minerva-i3)
      PACKAGES_TO_REMOVE=("${I3_PACKAGES[@]}" "${COMMON_PACKAGES[@]}")
      ;;
    minerva-hyprland)
      PACKAGES_TO_REMOVE=("${HYPRLAND_PACKAGES[@]}" "${COMMON_PACKAGES[@]}")
      ;;
    kde)
      PACKAGES_TO_REMOVE=("${KDE_PACKAGES[@]}" "${COMMON_PACKAGES[@]}")
      ;;
    all)
      PACKAGES_TO_REMOVE=("${I3_PACKAGES[@]}" "${HYPRLAND_PACKAGES[@]}" "${KDE_PACKAGES[@]}" "${COMMON_PACKAGES[@]}")
      ;;
    common)
      PACKAGES_TO_REMOVE=("${COMMON_PACKAGES[@]}")
      ;;
  esac
  
  # Filter to only installed packages
  INSTALLED=()
  for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
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
      elif command -v paru &>/dev/null; then
        paru -Rns --noconfirm "${INSTALLED[@]}" 2>/dev/null || true
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
echo -e "${YELLOW}To fully reset for a fresh install:${NC}"
echo "  1. Reboot (or switch to a TTY with Ctrl+Alt+F2)"
echo "  2. Run your preferred rice's setup script"
echo
echo -e "${CYAN}If you want to go back to a basic TTY login:${NC}"
echo "  sudo systemctl set-default multi-user.target"
echo "  (After reboot you'll get a plain login prompt)"
echo
