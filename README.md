# VLAN Changer

A modern Windows app for managing VLANs and port modes on Cisco switches. Features live interface status, secure credential storage, and a responsive UI. Easily change VLANs or port modes—no CLI needed. Build as a portable .exe for any PC.

## Features
- One-click VLAN and port mode changes
- Live auto-refreshing interface status
- Secure password storage (keyring)
- Modern, responsive UI (ttkbootstrap)
- Portable: build as a standalone .exe

## Getting Started

### Requirements
- Python 3.10+
- Packages: `netmiko`, `ttkbootstrap`, `keyring`

### Installation
1. Clone this repo:
   ```
   git clone https://github.com/moatazmaahmoud/vlan_Changer.git
   cd vlan_Changer
   ```
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

### Build the .exe
```
pyinstaller --onefile --noconsole --icon="media/network.ico" "vlan changer.py"
```
- The `.exe` will be in the `dist` folder.

## Usage
- Double-click the `.exe` or run the script with Python.
- Enter switch IP, username, and password.
- Manage VLANs and port modes easily.

## License
MIT
