# Installation Scripts and Tools

This repository contains essential scripts for system post-installation and web application penetration testing tool setup.

## Scripts:

### `post_install.sh`

This script handles the core post-installation setup for an Arch Linux system. It performs:
*   System updates
*   XDG user directory setup
*   Installation of essential CLI utilities
*   Intelligent detection and installation of a Desktop Environment (either a custom i3 setup via Minerva Rice from GitHub, or a fallback XFCE setup)
*   Verification and installation of "must-have" applications (terminal emulator, file managers, volume control, notifications, screenshot tools, media viewers, fonts, audio stack, web browser)
*   Optional AUR helper (`yay`) installation
*   Optional Steam installation
*   GPU driver auto-detection and installation (AMD vs. Nvidia)

### `webapptestscript.sh`

This script automates the installation of a comprehensive web application penetration testing toolkit for Arch Linux. It covers:
*   System updates and base dependencies (git, curl, python, go, docker, ruby, nmap, jq, etc.)
*   Docker setup
*   Go environment configuration
*   Installation of various recon & enumeration tools (ffuf, nuclei, subfinder, amass, etc.)
*   Installation of exploitation tools (sqlmap, wfuzz, XSStrike, commix, evil-winrm, crackmapexec, Responder)
*   Installation of specialized and JWT tools
*   AI Red Teaming tools (garak, promptmap, rebuff)
*   GF patterns setup
*   Wordlists and resources (SecLists, PayloadsAllTheThings, FuzzDB)
*   Auxiliary tools (Wireshark)
*   Pulling Docker vulnerable applications (DVWA, Juice Shop, WebGoat)
*   Pulling Spiderfoot container
*   Generates a `TOOLKIT_REFERENCE.md` with usage instructions.
