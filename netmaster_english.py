#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import re
import time
import json
import random
from datetime import datetime

class Colors:
    """Colors for interface"""
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class NetMaster:
    def __init__(self):
        self.devices = []
        self.original_mac = None
        self.current_interface = None
        self.config_file = "netmaster_config.json"
        self.log_file = "netmaster_log.txt"
        
    def clear_screen(self):
        """Clear screen"""
        os.system('clear')
        
    def show_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.RED}   _   _      _   __  __           _           {Colors.RESET}
{Colors.RED}  | \\ | | ___| |_|  \\/  | ___   __| | ___ _ __ {Colors.RESET}
{Colors.YELLOW}  |  \\| |/ _ \\ __| |\\/| |/ _ \\ / _` |/ _ \\ '__| {Colors.RESET}
{Colors.GREEN}  | |\\  |  __/ |_| |  | | (_) | (_| |  __/ |   {Colors.RESET}
{Colors.BLUE}  |_| \\_|\\___\\__|_|  |_|\\___/ \\__,_|\\___|_|   {Colors.RESET}

{Colors.CYAN}      🔹 Network Management - NetMaster 🔹{Colors.RESET}
{Colors.CYAN}      🔹 NetMaster Lite AutoScan 🔹{Colors.RESET}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
        print(banner)
        
    def log_action(self, action):
        """Log operations"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {action}\n")
            
    def save_config(self):
        """Save configuration"""
        config = {
            "original_mac": self.original_mac,
            "current_interface": self.current_interface
        }
        with open(self.config_file, "w") as f:
            json.dump(config, f)
            
    def load_config(self):
        """Load configuration"""
        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                self.original_mac = config.get("original_mac")
                self.current_interface = config.get("current_interface")
        except FileNotFoundError:
            pass
            
    def check_root(self):
        """Check root privileges"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}❌ This tool requires root privileges!{Colors.RESET}")
            print(f"{Colors.YELLOW}Use: sudo python3 netmaster_english.py{Colors.RESET}")
            sys.exit(1)
            
    def get_all_interfaces(self):
        """Get all available network interfaces"""
        interfaces = []
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if ':' in line and not line.startswith(' '):
                    # Extract interface name
                    parts = line.split(':')
                    if len(parts) >= 2:
                        interface_name = parts[1].strip()
                        
                        # Skip loopback
                        if interface_name == 'lo':
                            continue
                            
                        # Get interface status
                        status = "DOWN"
                        if 'UP' in line:
                            status = "UP"
                        elif 'LOWER_UP' in line:
                            status = "UP"
                            
                        # Get interface type
                        interface_type = "Unknown"
                        if interface_name.startswith(('wlan', 'wlp')):
                            interface_type = "WiFi"
                        elif interface_name.startswith(('eth', 'enp', 'ens')):
                            interface_type = "Ethernet"
                        elif interface_name.startswith('usb'):
                            interface_type = "USB"
                        elif interface_name.startswith('tun'):
                            interface_type = "VPN"
                            
                        # Get MAC address
                        mac = self.get_interface_mac(interface_name)
                        
                        interfaces.append({
                            'name': interface_name,
                            'type': interface_type,
                            'status': status,
                            'mac': mac
                        })
                        
        except Exception as e:
            print(f"{Colors.RED}Error getting interfaces: {e}{Colors.RESET}")
            
        return interfaces
        
    def get_interface_mac(self, interface):
        """Get MAC address for specific interface"""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    mac = line.split()[1]
                    return mac.upper()
        except Exception:
            pass
        return "N/A"
        
    def show_interfaces_menu(self):
        """Display interface selection menu"""
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            print(f"{Colors.RED}❌ No network interfaces found{Colors.RESET}")
            return None
            
        print(f"\n{Colors.CYAN}🔍 Available Interfaces:{Colors.RESET}")
        print(f"{Colors.WHITE}{'No.':<6} {'Name':<12} {'Type':<10} {'Status':<8} {'MAC Address'}{Colors.RESET}")
        print(f"{Colors.WHITE}{'-'*65}{Colors.RESET}")
        
        for i, interface in enumerate(interfaces, 1):
            name_colored = f"{Colors.BLUE}{interface['name']:<12}{Colors.RESET}"
            type_colored = f"{Colors.YELLOW}{interface['type']:<10}{Colors.RESET}"
            
            if interface['status'] == 'UP':
                status_colored = f"{Colors.GREEN}{interface['status']:<8}{Colors.RESET}"
            else:
                status_colored = f"{Colors.RED}{interface['status']:<8}{Colors.RESET}"
                
            mac_colored = f"{Colors.MAGENTA}{interface['mac']}{Colors.RESET}"
            
            print(f"{Colors.WHITE}[{i}]{Colors.RESET}   {name_colored} {type_colored} {status_colored} {mac_colored}")
            
        print(f"{Colors.WHITE}{'-'*65}{Colors.RESET}")
        
        while True:
            try:
                choice = input(f"\n{Colors.WHITE}Select interface number (0 to exit): {Colors.RESET}")
                
                if choice == '0':
                    return None
                    
                interface_num = int(choice)
                if 1 <= interface_num <= len(interfaces):
                    selected = interfaces[interface_num - 1]
                    
                    if selected['status'] != 'UP':
                        print(f"{Colors.YELLOW}⚠️  Interface {selected['name']} is not active{Colors.RESET}")
                        confirm = input(f"{Colors.WHITE}Do you want to continue? (y/n): {Colors.RESET}")
                        if confirm.lower() not in ['y', 'yes']:
                            continue
                    
                    self.current_interface = selected['name']
                    print(f"{Colors.GREEN}✔ Selected interface: {selected['name']} ({selected['type']}){Colors.RESET}")
                    return selected['name']
                else:
                    print(f"{Colors.RED}❌ Invalid number{Colors.RESET}")
                    
            except ValueError:
                print(f"{Colors.RED}❌ Please enter a valid number{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operation cancelled{Colors.RESET}")
                return None
        
    def get_current_mac(self):
        """Get current MAC address"""
        if not self.current_interface:
            return None
            
        try:
            result = subprocess.run(['ip', 'link', 'show', self.current_interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    mac = line.split()[1]
                    return mac.upper()
        except Exception:
            pass
        return None
        
    def scan_network(self):
        """Scan network for connected devices"""
        print(f"{Colors.CYAN}Scanning network... ⏳{Colors.RESET}")
        
        try:
            # Get network address
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            network = None
            for line in result.stdout.split('\n'):
                if self.current_interface in line and '/' in line:
                    parts = line.split()
                    for part in parts:
                        if '/' in part and not part.startswith('169.254'):
                            network = part
                            break
                    if network:
                        break
                        
            if not network:
                print(f"{Colors.RED}❌ Network not found{Colors.RESET}")
                return False
                
            print(f"{Colors.YELLOW}Scanning network: {network}{Colors.RESET}")
            
            # Use nmap to scan network
            nmap_cmd = ['nmap', '-sn', network]
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=30)
            
            # Extract IP addresses
            ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', result.stdout)
            
            self.devices = []
            for ip in ips:
                mac = self.get_mac_for_ip(ip)
                if mac:
                    device_name = self.get_device_name(mac)
                    self.devices.append({
                        'ip': ip,
                        'mac': mac,
                        'name': device_name
                    })
                    
            return len(self.devices) > 0
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}❌ Network scan timeout{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}❌ Network scan error: {e}{Colors.RESET}")
            return False
            
    def get_mac_for_ip(self, ip):
        """Get MAC address for specific IP address"""
        try:
            # Ping to ensure device is in ARP table
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
            
            # Read ARP table
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ip in line and ':' in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part.upper()
        except Exception:
            pass
        return None
        
    def get_device_name(self, mac):
        """Guess device type from MAC address"""
        mac_prefixes = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            '28:CF:E9': 'Apple',
            '3C:07:54': 'Apple',
            '40:A6:D9': 'Apple',
            '58:55:CA': 'Apple',
            '70:56:81': 'Apple',
            '7C:6D:62': 'Apple',
            '88:63:DF': 'Apple',
            'A4:5E:60': 'Apple',
            'A8:86:DD': 'Apple',
            'AC:87:A3': 'Apple',
            'B8:E8:56': 'Apple',
            'BC:52:B7': 'Apple',
            'D0:81:7A': 'Apple',
            'E0:F8:47': 'Apple',
            'F0:18:98': 'Apple',
            'F4:0F:24': 'Apple',
            'F8:1E:DF': 'Apple',
            '00:15:5D': 'Microsoft',
            '00:03:FF': 'Microsoft',
            '28:18:78': 'Samsung',
            '34:23:87': 'Samsung',
            '38:AA:3C': 'Samsung',
            '40:4E:36': 'Samsung',
            '44:4E:6D': 'Samsung',
            '5C:0A:5B': 'Samsung',
            '78:1F:DB': 'Samsung',
            '8C:77:12': 'Samsung',
            'A0:21:B7': 'Samsung',
            'C8:19:F7': 'Samsung',
            'E8:50:8B': 'Samsung',
            'EC:1F:72': 'Samsung',
            'F4:7B:5E': 'Samsung',
        }
        
        mac_prefix = mac[:8]
        return mac_prefixes.get(mac_prefix, 'Unknown Device')
        
    def show_devices_table(self):
        """Display devices table"""
        if not self.devices:
            print(f"{Colors.RED}❌ No devices found on network{Colors.RESET}")
            return
            
        print(f"\n{Colors.GREEN}Found {len(self.devices)} device(s) on network ✅{Colors.RESET}")
        print(f"{Colors.WHITE}{'No.':<6} {'IP Address':<15} {'MAC Address':<18} {'Device'}{Colors.RESET}")
        print(f"{Colors.WHITE}{'-'*60}{Colors.RESET}")
        
        for i, device in enumerate(self.devices, 1):
            ip_colored = f"{Colors.BLUE}{device['ip']:<15}{Colors.RESET}"
            mac_colored = f"{Colors.GREEN}{device['mac']:<18}{Colors.RESET}"
            name_colored = f"{Colors.YELLOW}{device['name']}{Colors.RESET}"
            print(f"{Colors.WHITE}[{i}]{Colors.RESET}   {ip_colored} {mac_colored} {name_colored}")
            
        print(f"{Colors.WHITE}{'-'*60}{Colors.RESET}")
        
    def show_main_menu(self):
        """Display main menu"""
        print(f"\n{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        print(f"{Colors.MAGENTA}Current Interface: {self.current_interface}{Colors.RESET}")
        print(f"{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        print(f"{Colors.CYAN}[1] Select MAC from devices table{Colors.RESET}")
        print(f"{Colors.CYAN}[2] Enter MAC manually{Colors.RESET}")
        print(f"{Colors.CYAN}[3] Generate random MAC{Colors.RESET}")
        print(f"{Colors.CYAN}[4] Restore original MAC{Colors.RESET}")
        print(f"{Colors.CYAN}[5] Rescan network{Colors.RESET}")
        print(f"{Colors.CYAN}[6] Show current MAC{Colors.RESET}")
        print(f"{Colors.CYAN}[7] Change interface{Colors.RESET}")
        print(f"{Colors.RED}[0] Exit{Colors.RESET}")
        print(f"{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
    def change_mac(self, new_mac):
        """Change MAC address"""
        if not self.current_interface:
            print(f"{Colors.RED}❌ No network interface found{Colors.RESET}")
            return False
            
        try:
            # Save original MAC if not saved
            if not self.original_mac:
                self.original_mac = self.get_current_mac()
                self.save_config()
                
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 'down'], 
                         check=True)
            
            # Change MAC
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 
                          'address', new_mac], check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 'up'], 
                         check=True)
            
            # Wait a bit to ensure changes are applied
            time.sleep(2)
            
            # Verify the change
            current_mac = self.get_current_mac()
            if current_mac and current_mac.lower() == new_mac.lower():
                print(f"{Colors.GREEN}✔ MAC Address changed to: {new_mac}{Colors.RESET}")
                self.log_action(f"MAC changed to: {new_mac}")
                return True
            else:
                print(f"{Colors.RED}❌ Failed to change MAC Address{Colors.RESET}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}❌ Error changing MAC: {e}{Colors.RESET}")
            return False
            
    def restore_original_mac(self):
        """Restore original MAC address"""
        if not self.original_mac:
            print(f"{Colors.RED}❌ No original MAC saved{Colors.RESET}")
            return False
            
        if self.change_mac(self.original_mac):
            print(f"{Colors.GREEN}✔ Original MAC Address restored successfully{Colors.RESET}")
            self.log_action("Original MAC restored")
            return True
        return False
        
    def generate_random_mac(self):
        """Generate random MAC address"""
        # Use Local Administered OUI
        mac = "02"
        for _ in range(5):
            mac += ":" + "%02x" % random.randint(0, 255)
        return mac.upper()
        
    def validate_mac(self, mac):
        """Validate MAC address format"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(pattern, mac) is not None
        
    def select_device_mac(self):
        """Select MAC from devices table"""
        if not self.devices:
            print(f"{Colors.RED}❌ No devices in table{Colors.RESET}")
            return
            
        print(f"\n{Colors.CYAN}Select device to change MAC Address to:{Colors.RESET}")
        self.show_devices_table()
        
        try:
            choice = input(f"\n{Colors.WHITE}Select device number (0 to go back): {Colors.RESET}")
            
            if choice == '0':
                return
                
            device_num = int(choice)
            if 1 <= device_num <= len(self.devices):
                selected_device = self.devices[device_num - 1]
                new_mac = selected_device['mac']
                
                print(f"\n{Colors.YELLOW}MAC will be changed to: {new_mac}{Colors.RESET}")
                print(f"{Colors.YELLOW}Device: {selected_device['name']} ({selected_device['ip']}){Colors.RESET}")
                
                confirm = input(f"{Colors.WHITE}Are you sure? (y/n): {Colors.RESET}")
                if confirm.lower() in ['y', 'yes']:
                    self.change_mac(new_mac)
                else:
                    print(f"{Colors.YELLOW}Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Invalid number{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}❌ Please enter a valid number{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Operation cancelled{Colors.RESET}")
            
    def manual_mac_input(self):
        """Manual MAC input"""
        try:
            mac = input(f"{Colors.WHITE}Enter MAC Address (example: AA:BB:CC:DD:EE:FF): {Colors.RESET}")
            
            if self.validate_mac(mac):
                mac = mac.upper()
                print(f"\n{Colors.YELLOW}MAC will be changed to: {mac}{Colors.RESET}")
                
                confirm = input(f"{Colors.WHITE}Are you sure? (y/n): {Colors.RESET}")
                if confirm.lower() in ['y', 'yes']:
                    self.change_mac(mac)
                else:
                    print(f"{Colors.YELLOW}Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Invalid MAC format{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Operation cancelled{Colors.RESET}")
            
    def show_current_mac(self):
        """Show current MAC address"""
        current_mac = self.get_current_mac()
        if current_mac:
            print(f"\n{Colors.CYAN}Current MAC Address: {Colors.GREEN}{current_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}Network Interface: {Colors.GREEN}{self.current_interface}{Colors.RESET}")
            
            if self.original_mac:
                if current_mac == self.original_mac:
                    print(f"{Colors.GREEN}✔ This is the original MAC{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}Original MAC: {self.original_mac}{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ MAC not found{Colors.RESET}")
            
    def run(self):
        """Main application runner"""
        self.clear_screen()
        self.show_banner()
        
        # Check privileges
        self.check_root()
        
        # Load configuration
        self.load_config()
        
        # Show interface selection menu
        selected_interface = self.show_interfaces_menu()
        if not selected_interface:
            print(f"{Colors.RED}❌ No network interface selected{Colors.RESET}")
            sys.exit(1)
        
        # Auto scan network
        if not self.scan_network():
            print(f"{Colors.YELLOW}⚠ No devices found, you can continue with other options{Colors.RESET}")
        else:
            self.show_devices_table()
            
        # Main menu loop
        while True:
            try:
                self.show_main_menu()
                choice = input(f"\n{Colors.WHITE}Select an option: {Colors.RESET}")
                
                if choice == '1':
                    self.select_device_mac()
                elif choice == '2':
                    self.manual_mac_input()
                elif choice == '3':
                    random_mac = self.generate_random_mac()
                    print(f"\n{Colors.YELLOW}Random MAC: {random_mac}{Colors.RESET}")
                    confirm = input(f"{Colors.WHITE}Do you want to use it? (y/n): {Colors.RESET}")
                    if confirm.lower() in ['y', 'yes']:
                        self.change_mac(random_mac)
                elif choice == '4':
                    self.restore_original_mac()
                elif choice == '5':
                    print(f"\n{Colors.CYAN}Rescanning network...{Colors.RESET}")
                    if self.scan_network():
                        self.show_devices_table()
                    else:
                        print(f"{Colors.YELLOW}No new devices found{Colors.RESET}")
                elif choice == '6':
                    self.show_current_mac()
                elif choice == '7':
                    print(f"\n{Colors.CYAN}Changing interface...{Colors.RESET}")
                    new_interface = self.show_interfaces_menu()
                    if new_interface:
                        # Reset discovered devices
                        self.devices = []
                        print(f"{Colors.GREEN}✔ Interface changed successfully{Colors.RESET}")
                elif choice == '0':
                    print(f"\n{Colors.GREEN}Thank you for using NetMaster! 👋{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}❌ Invalid option{Colors.RESET}")
                    
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.GREEN}Thank you for using NetMaster! 👋{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}❌ Unexpected error: {e}{Colors.RESET}")

if __name__ == "__main__":
    netmaster = NetMaster()
    netmaster.run()