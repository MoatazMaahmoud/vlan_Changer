import tkinter as tk
from tkinter import messagebox
from ttkbootstrap import Style, ttk
from ttkbootstrap.widgets import Entry, Combobox
from netmiko import ConnectHandler
import re
import json
import os
import threading
from cryptography.fernet import Fernet

# Globals
net_connect = None
settings_file = "settings.json"
key_file = "secret.key"

# ===== Encryption Helpers =====
def load_key():
    """Load or generate encryption key."""
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()
    return key

fernet = Fernet(load_key())

def encrypt_text(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# ===== Threading Wrapper =====
def run_in_thread(func, *args):
    threading.Thread(target=func, args=args, daemon=True).start()

# ===== UI State Helpers =====
def set_loading(is_loading, msg=""):
    widgets = [interface_dropdown, vlan_entry, apply_vlan_btn, refresh_btn]
    for w in widgets:
        try:
            w.config(state="disabled" if is_loading else "normal")
        except Exception:
            pass
    loading_var.set(msg if is_loading else "")

# ===== Settings =====
def save_settings():
    try:
        if remember_var.get() == 1:
            settings = {
                "ip": ip_entry.get(),
                "username": user_entry.get(),
                "password": encrypt_text(pass_entry.get())  # Encrypted
            }
            with open(settings_file, "w") as f:
                json.dump(settings, f)
        else:
            if os.path.exists(settings_file):
                os.remove(settings_file)
    except Exception as e:
        print(f"[!] Save settings error: {e}")

def load_settings():
    try:
        if os.path.exists(settings_file):
            with open(settings_file, "r") as f:
                settings = json.load(f)
                ip_entry.insert(0, settings.get("ip", ""))
                user_entry.insert(0, settings.get("username", ""))
                enc_pass = settings.get("password", "")
                if enc_pass:
                    pass_entry.insert(0, decrypt_text(enc_pass))
                remember_var.set(1)
    except Exception as e:
        print(f"[!] Load settings error: {e}")

# ===== Connection =====
def connect_switch():
    run_in_thread(_connect_switch)

def _connect_switch():
    global net_connect
    set_loading(True, "Connecting...")
    try:
        device = {
            "device_type": "cisco_ios",
            "ip": ip_entry.get().strip(),
            "username": user_entry.get().strip(),
            "password": pass_entry.get().strip(),
        }
        net_connect = ConnectHandler(**device)
        save_settings()

        hostname_output = net_connect.send_command("show running-config | include hostname")
        hostname_match = re.search(r"hostname\s+(\S+)", hostname_output)

        if hostname_match:
            hostname_label.config(text=f"📟 {hostname_match.group(1)}", bootstyle="info")

        status_label.config(text=f"✅ Connected to {device['ip']}", bootstyle="success")

        interface_dropdown.config(state="readonly")
        vlan_entry.config(state="normal")
        apply_vlan_btn.config(state="normal")
        disconnect_btn.config(state="normal")

        get_interfaces()

    except Exception as e:
        net_connect = None
        messagebox.showerror("Connection Error", str(e))
        status_label.config(text="❌ Connection failed", bootstyle="danger")
    finally:
        set_loading(False)

def disconnect_switch():
    global net_connect
    if net_connect:
        try:
            net_connect.disconnect()
        except Exception:
            pass
    net_connect = None
    status_label.config(text="🔌 Disconnected", bootstyle="secondary")
    hostname_label.config(text="")
    interface_dropdown['values'] = []
    vlan_entry.delete(0, tk.END)
    apply_vlan_btn.config(state="disabled")
    disconnect_btn.config(state="disabled")

# ===== Interface Management =====
def parse_interfaces_status(output):
    interfaces = []
    for line in output.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        intf = parts[0]
        if re.match(r'^(Fa|Gi|Te|Eth|GigabitEthernet|FastEthernet)', intf, re.IGNORECASE):
            interfaces.append(line.strip())
    return interfaces

def get_interfaces():
    run_in_thread(_get_interfaces)

def _get_interfaces():
    global net_connect
    if not net_connect:
        return
    set_loading(True, "Loading interfaces...")
    try:
        output = net_connect.send_command("show interfaces status")
        parsed = parse_interfaces_status(output)
        interface_items = []
        for entry in parsed:
            parts = entry.split()
            intf = parts[0]
            status_text = " ".join(parts[1:]).lower()
            if "connected" in status_text:
                state = "UP"
            elif "notconnect" in status_text or "not connect" in status_text:
                state = "DOWN"
            elif "disabled" in status_text:
                state = "ADMIN DOWN"
            else:
                state = parts[1] if len(parts) > 1 else "UNKNOWN"
            try:
                sw_output = net_connect.send_command(f"show interfaces {intf} switchport")
                mode_match = re.search(r"Administrative Mode:\s+(\w+)", sw_output, re.IGNORECASE)
                mode = mode_match.group(1).capitalize() if mode_match else "Unknown"
            except Exception:
                mode = "Unknown"
            interface_items.append(f"{intf} | {state} | {mode}")

        root.after(0, lambda: update_interface_dropdown(interface_items))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to get interfaces: {e}")
    finally:
        set_loading(False)

def update_interface_dropdown(interface_items):
    interface_dropdown['values'] = interface_items
    if interface_items:
        interface_dropdown.current(0)
        show_current_vlan()
        show_port_mode()

# ===== VLAN Management =====
def show_current_vlan(event=None):
    global net_connect
    if not net_connect:
        current_vlan.set("")
        return
    iface = interface_var.get().split()[0] if interface_var.get() else ""
    if not iface:
        current_vlan.set("")
        return
    set_loading(True, "Getting VLAN...")
    try:
        output = net_connect.send_command(f"show interfaces {iface} switchport")
        vlan_match = re.search(r"Access Mode VLAN:\s+(\d+)", output, re.IGNORECASE)
        if vlan_match:
            current_vlan.set(vlan_match.group(1))
            return
        vlan_match = re.search(r"Access VLAN:\s+(\d+)", output, re.IGNORECASE)
        if vlan_match:
            current_vlan.set(vlan_match.group(1))
            return
        current_vlan.set("Unknown")
    except Exception:
        current_vlan.set("Error")
    finally:
        set_loading(False)

def change_vlan():
    global net_connect
    if not net_connect:
        messagebox.showwarning("Not connected", "Please connect to a switch first.")
        return
    iface = interface_var.get().split()[0] if interface_var.get() else ""
    vlan_id = vlan_entry.get().strip()
    if not iface:
        messagebox.showerror("Input Error", "No interface selected")
        return
    if not vlan_id.isdigit():
        messagebox.showerror("Input Error", "VLAN ID must be a number")
        return
    set_loading(True, "Changing VLAN...")
    try:
        commands = [
            f"interface {iface}",
            f"switchport access vlan {vlan_id}"
        ]
        net_connect.send_config_set(commands)
        try:
            net_connect.save_config()
        except Exception:
            net_connect.send_command("write memory")
        messagebox.showinfo("Success", f"VLAN changed to {vlan_id} on {iface}")
        current_vlan.set(vlan_id)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to change VLAN: {e}")
    finally:
        set_loading(False)

# ===== Port Mode =====
def show_port_mode(event=None):
    global net_connect
    if not net_connect:
        port_mode_var.set("")
        return
    iface = interface_var.get().split()[0] if interface_var.get() else ""
    if not iface:
        port_mode_var.set("")
        return
    try:
        sw_output = net_connect.send_command(f"show interfaces {iface} switchport")
        mode_match = re.search(r"Administrative Mode:\s+(\w+)", sw_output, re.IGNORECASE)
        mode = mode_match.group(1).lower() if mode_match else "access"
        port_mode_var.set("trunk" if "trunk" in mode else "access")
    except Exception:
        port_mode_var.set("")

def change_port_mode():
    global net_connect
    if not net_connect:
        messagebox.showwarning("Not connected", "Please connect to a switch first.")
        return
    iface = interface_var.get().split()[0] if interface_var.get() else ""
    mode = port_mode_var.get()
    if not iface or not mode:
        messagebox.showerror("Input Error", "Interface or mode not selected")
        return
    set_loading(True, "Changing port mode...")
    try:
        commands = [
            f"interface {iface}",
            f"switchport mode {mode}"
        ]
        net_connect.send_config_set(commands)
        try:
            net_connect.save_config()
        except Exception:
            net_connect.send_command("write memory")
        messagebox.showinfo("Success", f"Port mode changed to {mode} on {iface}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to change port mode: {e}")
    finally:
        set_loading(False)

# ===== Theme =====
def toggle_theme():
    current_theme = style.theme.name
    if current_theme in ["flatly", "cosmo", "minty", "pulse"]:
        style.theme_use("darkly")
        toggle_btn.config(text="☀")
    else:
        style.theme_use("flatly")
        toggle_btn.config(text="🌙")

# ===== UI Setup =====
style = Style(theme="darkly")
root = style.master
root.title("VLAN Changer")
root.geometry("700x820")

# Top bar
frame_topbar = ttk.Frame(root)
frame_topbar.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
frame_topbar.columnconfigure(0, weight=1)
toggle_btn = ttk.Button(frame_topbar, text="☀", command=lambda: toggle_theme())
toggle_btn.grid(row=0, column=1, sticky="e")
disconnect_btn = ttk.Button(frame_topbar, text="Disconnect", bootstyle="danger-outline", command=disconnect_switch, state="disabled")
disconnect_btn.grid(row=0, column=0, sticky="w")

# Main content (same as before)
main_frame = ttk.Frame(root)
main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
main_frame.columnconfigure(0, weight=1)

# Connection frame
frame_conn = ttk.Labelframe(main_frame, text="🔌 Switch Connection", padding=12, bootstyle="info")
frame_conn.grid(row=0, column=0, sticky="ew", pady=5)
frame_conn.columnconfigure(0, weight=1)

ttk.Label(frame_conn, text="Switch IP:").grid(row=0, column=0, sticky="w")
ip_entry = Entry(frame_conn, font=("Segoe UI", 11))
ip_entry.grid(row=1, column=0, sticky="ew", pady=5)

ttk.Label(frame_conn, text="Username:").grid(row=2, column=0, sticky="w")
user_entry = Entry(frame_conn, font=("Segoe UI", 11))
user_entry.grid(row=3, column=0, sticky="ew", pady=5)

ttk.Label(frame_conn, text="Password:").grid(row=4, column=0, sticky="w")
pass_entry = Entry(frame_conn, show="*", font=("Segoe UI", 11))
pass_entry.grid(row=5, column=0, sticky="ew", pady=5)

remember_var = tk.IntVar()
remember_check = ttk.Checkbutton(frame_conn, text="Remember Me", variable=remember_var, bootstyle="secondary")
remember_check.grid(row=6, column=0, sticky="w", pady=5)

ttk.Button(frame_conn, text="Connect to Switch", bootstyle="success-outline", command=connect_switch).grid(row=7, column=0, pady=8, sticky="ew")

status_label = ttk.Label(frame_conn, text="", font=("Segoe UI", 9, "italic"))
status_label.grid(row=8, column=0, sticky="w")
hostname_label = ttk.Label(frame_conn, text="", font=("Segoe UI", 11, "bold"))
hostname_label.grid(row=9, column=0, sticky="w", pady=3)

# Interface frame
frame_int = ttk.Labelframe(main_frame, text="📡 Interface Selection", padding=12, bootstyle="primary")
frame_int.grid(row=1, column=0, sticky="ew", pady=5)
frame_int.columnconfigure(0, weight=1)

interface_var = tk.StringVar()
interface_dropdown = Combobox(frame_int, textvariable=interface_var, state="disabled", font=("Segoe UI", 11))
interface_dropdown.grid(row=0, column=0, sticky="ew", pady=5)
refresh_btn = ttk.Button(frame_int, text="🔄 Refresh Ports", bootstyle="info-outline", command=get_interfaces)
refresh_btn.grid(row=0, column=1, padx=5, pady=5, sticky="e")

port_mode_var = tk.StringVar()
frame_mode = ttk.Frame(frame_int)
frame_mode.grid(row=3, column=0, sticky="ew", pady=5)
ttk.Label(frame_mode, text="Port Mode:", font=("Segoe UI", 10, "bold")).pack(side="left")
ttk.Radiobutton(frame_mode, text="Access", variable=port_mode_var, value="access", command=change_port_mode).pack(side="left", padx=10)
ttk.Radiobutton(frame_mode, text="Trunk", variable=port_mode_var, value="trunk", command=change_port_mode).pack(side="left", padx=10)

ttk.Label(frame_int, text="Current VLAN:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=3)
current_vlan = tk.StringVar()
current_vlan_label = ttk.Label(frame_int, textvariable=current_vlan, font=("Segoe UI", 12, "bold"), bootstyle="warning", anchor="center")
current_vlan_label.grid(row=2, column=0, pady=5, sticky="ew")

# VLAN frame
frame_vlan = ttk.Labelframe(main_frame, text="🎯 Change VLAN", padding=12, bootstyle="warning")
frame_vlan.grid(row=2, column=0, sticky="ew", pady=5)
frame_vlan.columnconfigure(0, weight=1)

ttk.Label(frame_vlan, text="Enter New VLAN ID:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
vlan_entry = Entry(frame_vlan, font=("Segoe UI", 12), state="disabled")
vlan_entry.grid(row=1, column=0, sticky="ew", pady=5)

apply_vlan_btn = ttk.Button(frame_vlan, text="Apply VLAN Change", bootstyle="danger-outline", command=change_vlan, state="disabled")
apply_vlan_btn.grid(row=2, column=0, pady=8, sticky="ew")

# Loading indicator
loading_var = tk.StringVar()
loading_label = ttk.Label(main_frame, textvariable=loading_var, font=("Segoe UI", 10, "italic"), bootstyle="secondary")
loading_label.grid(row=3, column=0, sticky="ew", pady=5)

# Final wiring
interface_dropdown.bind("<<ComboboxSelected>>", lambda e: [show_current_vlan(), show_port_mode()])
load_settings()
root.mainloop()
