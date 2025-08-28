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
        self.is_termux = self.check_termux()
        
    def check_termux(self):
        """Check if running on Termux"""
        return os.path.exists('/data/data/com.termux') or 'TERMUX_VERSION' in os.environ
        
    def clear_screen(self):
        """Clear screen"""
        os.system('clear')
        
    def show_banner(self):
        """Display tool banner"""
        termux_info = f"{Colors.GREEN}[Termux Compatible]{Colors.RESET}" if self.is_termux else ""
        banner = f"""
{Colors.RED}   _   _      _   __  __           _           {Colors.RESET}
{Colors.RED}  | \\ | | ___| |_|  \\/  | ___   __| | ___ _ __ {Colors.RESET}
{Colors.YELLOW}  |  \\| |/ _ \\ __| |\\/| |/ _ \\ / _` |/ _ \\ '__| {Colors.RESET}
{Colors.GREEN}  | |\\  |  __/ |_| |  | | (_) | (_| |  __/ |   {Colors.RESET}
{Colors.BLUE}  |_| \\_|\\___\\__|_|  |_|\\___/ \\__,_|\\___|_|   {Colors.RESET}

{Colors.CYAN}      🔹 Network Management - NetMaster 🔹{Colors.RESET}
{Colors.CYAN}      🔹 NetMaster Termux Edition 🔹{Colors.RESET} {termux_info}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}"""
        
        if self.is_termux:
            banner += f"""
{Colors.YELLOW}📦 Required Termux Packages:{Colors.RESET}
{Colors.WHITE}┌─ Install these packages for full functionality:{Colors.RESET}
{Colors.GREEN}├─ pkg update && pkg upgrade{Colors.RESET}
{Colors.GREEN}├─ pkg install python nmap iproute2 net-tools{Colors.RESET}
{Colors.GREEN}├─ pkg install tsu{Colors.WHITE} (for root access){Colors.RESET}
{Colors.GREEN}└─ pkg install iputils{Colors.WHITE} (for ping){Colors.RESET}

{Colors.CYAN}🔧 Root Access Setup:{Colors.RESET}
{Colors.WHITE}┌─ For MAC address changing:{Colors.RESET}
{Colors.YELLOW}├─ Install Magisk or SuperSU on rooted device{Colors.RESET}
{Colors.YELLOW}├─ Run: sudo python netmaster_termux.py{Colors.RESET}
{Colors.YELLOW}└─ Or use: su -c "python netmaster_termux.py"{Colors.RESET}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}"""
        else:
            banner += f"""
{Colors.YELLOW}📦 Required Linux Packages:{Colors.RESET}
{Colors.WHITE}┌─ Install these packages:{Colors.RESET}
{Colors.GREEN}├─ sudo apt update && sudo apt upgrade{Colors.RESET}
{Colors.GREEN}├─ sudo apt install python3 nmap iproute2 net-tools{Colors.RESET}
{Colors.GREEN}└─ sudo apt install iputils-ping{Colors.RESET}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}"""
        
        print(banner)
        
        # Check package status if in Termux
        if self.is_termux:
            self.check_required_packages()
        
    def check_required_packages(self):
        """Check if required packages are installed in Termux"""
        required_packages = ['nmap', 'ip', 'ifconfig', 'ping', 'su']
        missing_packages = []
        
        print(f"\n{Colors.CYAN}🔍 Checking required packages...{Colors.RESET}")
        
        for package in required_packages:
            result = self.run_command(['which', package], timeout=2)
            if result and result.returncode == 0:
                print(f"{Colors.GREEN}✓ {package:<12} - Installed{Colors.RESET}")
            else:
                print(f"{Colors.RED}✗ {package:<12} - Missing{Colors.RESET}")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n{Colors.YELLOW}⚠️  Missing packages detected!{Colors.RESET}")
            print(f"{Colors.WHITE}Run these commands to install:{Colors.RESET}")
            if 'nmap' in missing_packages:
                print(f"{Colors.GREEN}pkg install nmap{Colors.RESET}")
            if any(pkg in missing_packages for pkg in ['ip', 'ifconfig']):
                print(f"{Colors.GREEN}pkg install iproute2 net-tools{Colors.RESET}")
            if 'ping' in missing_packages:
                print(f"{Colors.GREEN}pkg install iputils{Colors.RESET}")
            if 'su' in missing_packages:
                print(f"{Colors.GREEN}pkg install tsu{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ All required packages are installed!{Colors.RESET}")
        
        print(f"{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
    def log_action(self, action):
        """Log operations"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {action}\n")
        except Exception:
            pass  # Silent fail for logging
            
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                "original_mac": self.original_mac,
                "current_interface": self.current_interface
            }
            with open(self.config_file, "w") as f:
                json.dump(config, f)
        except Exception:
            pass  # Silent fail for config saving
            
    def load_config(self):
        """Load configuration"""
        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                self.original_mac = config.get("original_mac")
                self.current_interface = config.get("current_interface")
        except FileNotFoundError:
            pass
        except Exception:
            pass
            
    def check_root(self):
        """Check root privileges - Modified for Termux"""
        if self.is_termux:
            # In Termux, check if we have root access
            try:
                result = subprocess.run(['su', '-c', 'id'], capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    print(f"{Colors.RED}❌ Root access required!{Colors.RESET}")
                    print(f"{Colors.YELLOW}Please install and configure root access in Termux{Colors.RESET}")
                    print(f"{Colors.CYAN}Commands to install root:{Colors.RESET}")
                    print(f"{Colors.WHITE}pkg install tsu{Colors.RESET}")
                    print(f"{Colors.WHITE}Then run: sudo python netmaster_termux.py{Colors.RESET}")
                    sys.exit(1)
            except subprocess.TimeoutExpired:
                print(f"{Colors.RED}❌ Root check timeout{Colors.RESET}")
                sys.exit(1)
            except FileNotFoundError:
                print(f"{Colors.RED}❌ Root not available{Colors.RESET}")
                print(f"{Colors.YELLOW}Please install root access: pkg install tsu{Colors.RESET}")
                sys.exit(1)
        else:
            # Standard Linux root check
            if os.geteuid() != 0:
                print(f"{Colors.RED}❌ This tool requires root privileges!{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: sudo python3 netmaster_termux.py{Colors.RESET}")
                sys.exit(1)
                
    def run_command(self, cmd, timeout=10):
        """Run command with proper root handling for Termux"""
        try:
            if self.is_termux:
                # Use su -c for root commands in Termux
                if isinstance(cmd, list):
                    cmd_str = ' '.join(cmd)
                else:
                    cmd_str = cmd
                result = subprocess.run(['su', '-c', cmd_str], 
                                      capture_output=True, text=True, timeout=timeout)
            else:
                # Standard command execution
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None
            
    def get_all_interfaces(self):
        """Get all available network interfaces - Termux compatible"""
        interfaces = []
        try:
            # Try different methods to get interfaces
            methods = [
                ['ip', 'link', 'show'],
                ['ifconfig'],
                ['cat', '/proc/net/dev']
            ]
            
            result = None
            for method in methods:
                result = self.run_command(method)
                if result and result.returncode == 0:
                    break
            
            if not result or result.returncode != 0:
                print(f"{Colors.RED}❌ Cannot get network interfaces{Colors.RESET}")
                return interfaces
            
            lines = result.stdout.split('\n')
            
            # Parse ip link output
            if 'ip link' in ' '.join(methods[0]):
                for line in lines:
                    if ':' in line and not line.startswith(' '):
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
                            elif interface_name.startswith(('usb', 'rndis')):
                                interface_type = "USB"
                            elif interface_name.startswith('tun'):
                                interface_type = "VPN"
                            elif interface_name.startswith('rmnet'):
                                interface_type = "Mobile"
                                
                            # Get MAC address
                            mac = self.get_interface_mac(interface_name)
                            
                            interfaces.append({
                                'name': interface_name,
                                'type': interface_type,
                                'status': status,
                                'mac': mac
                            })
            
            # Fallback: parse /proc/net/dev
            elif not interfaces:
                for line in lines:
                    if ':' in line and not line.strip().startswith('Inter-'):
                        interface_name = line.split(':')[0].strip()
                        if interface_name != 'lo':
                            mac = self.get_interface_mac(interface_name)
                            interfaces.append({
                                'name': interface_name,
                                'type': "Unknown",
                                'status': "Unknown",
                                'mac': mac
                            })
                        
        except Exception as e:
            print(f"{Colors.RED}Error getting interfaces: {e}{Colors.RESET}")
            
        return interfaces
        
    def get_interface_mac(self, interface):
        """Get MAC address for specific interface - Termux compatible"""
        try:
            # Try multiple methods
            methods = [
                ['ip', 'link', 'show', interface],
                ['ifconfig', interface],
                ['cat', f'/sys/class/net/{interface}/address']
            ]
            
            for method in methods:
                result = self.run_command(method)
                if result and result.returncode == 0:
                    output = result.stdout
                    
                    # Parse ip link output
                    if 'link/ether' in output:
                        for line in output.split('\n'):
                            if 'link/ether' in line:
                                mac = line.split()[1]
                                return mac.upper()
                    
                    # Parse ifconfig output
                    elif 'ether' in output or 'HWaddr' in output:
                        for line in output.split('\n'):
                            if 'ether' in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part == 'ether' and i + 1 < len(parts):
                                        return parts[i + 1].upper()
                            elif 'HWaddr' in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part == 'HWaddr' and i + 1 < len(parts):
                                        return parts[i + 1].upper()
                    
                    # Direct file read
                    elif len(output.strip()) == 17 and ':' in output:
                        return output.strip().upper()
                        
        except Exception:
            pass
        return "N/A"
        
    def show_interfaces_menu(self):
        """Display interface selection menu"""
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            print(f"{Colors.RED}❌ No network interfaces found{Colors.RESET}")
            return None
            
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║                    🔍 Available Interfaces                       ║{Colors.RESET}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.WHITE}║ {'No.':<4} │ {'Name':<12} │ {'Type':<10} │ {'Status':<8} │ {'MAC Address':<17} ║{Colors.RESET}")
        print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        
        for i, interface in enumerate(interfaces, 1):
            name_colored = f"{Colors.BLUE}{interface['name']:<12}{Colors.RESET}"
            type_colored = f"{Colors.YELLOW}{interface['type']:<10}{Colors.RESET}"
            
            if interface['status'] == 'UP':
                status_colored = f"{Colors.GREEN}{interface['status']:<8}{Colors.RESET}"
            else:
                status_colored = f"{Colors.RED}{interface['status']:<8}{Colors.RESET}"
                
            mac_colored = f"{Colors.MAGENTA}{interface['mac']:<17}{Colors.RESET}"
            
            print(f"{Colors.WHITE}║ [{i}]  │ {name_colored} │ {type_colored} │ {status_colored} │ {mac_colored} ║{Colors.RESET}")
            
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        while True:
            try:
                choice = input(f"\n{Colors.CYAN}┌─ Enter your choice{Colors.RESET}\n{Colors.WHITE}└─ Select interface number (0 to exit): {Colors.YELLOW}")
                print(Colors.RESET, end="")
                
                if choice == '0':
                    return None
                    
                interface_num = int(choice)
                if 1 <= interface_num <= len(interfaces):
                    selected = interfaces[interface_num - 1]
                    
                    if selected['status'] != 'UP' and selected['status'] != 'Unknown':
                        print(f"{Colors.YELLOW}⚠️  Interface {selected['name']} may not be active{Colors.RESET}")
                        confirm = input(f"{Colors.CYAN}┌─ Confirmation required{Colors.RESET}\n{Colors.WHITE}└─ Do you want to continue? (y/n): {Colors.YELLOW}")
                        print(Colors.RESET, end="")
                        if confirm.lower() not in ['y', 'yes']:
                            continue
                    
                    self.current_interface = selected['name']
                    print(f"{Colors.GREEN}└─ ✔ Selected interface: {selected['name']} ({selected['type']}){Colors.RESET}")
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
        return self.get_interface_mac(self.current_interface)
        
    def show_progress_bar(self, message, duration=3):
        """Show animated progress bar"""
        print(f"\n{Colors.CYAN}┌─ {message}{Colors.RESET}")
        
        # Progress bar characters
        bar_length = 50
        fill_char = "█"
        empty_char = "░"
        
        for i in range(bar_length + 1):
            # Calculate percentage
            percent = (i / bar_length) * 100
            
            # Create progress bar
            filled = fill_char * i
            empty = empty_char * (bar_length - i)
            
            # Display progress bar
            print(f"\r{Colors.YELLOW}└─ [{filled}{empty}] {percent:3.0f}%{Colors.RESET}", end="", flush=True)
            
            # Sleep for animation effect
            time.sleep(duration / bar_length)
        
        print()  # New line after completion
        
    def scan_network(self):
        """Fast network scan for connected devices - Termux compatible"""
        print(f"{Colors.CYAN}┌─ 🔍 Initializing network scan...{Colors.RESET}")
        self.show_progress_bar("🔍 Detecting network configuration...", 2)
        
        try:
            # Get network address using different methods
            network = None
            
            # Method 1: ip route
            result = self.run_command(['ip', 'route'])
            if result and result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if self.current_interface in line and '/' in line:
                        parts = line.split()
                        for part in parts:
                            if '/' in part and not part.startswith('169.254'):
                                network = part
                                break
                        if network:
                            break
            
            # Method 2: ifconfig (fallback)
            if not network:
                result = self.run_command(['ifconfig', self.current_interface])
                if result and result.returncode == 0:
                    # Extract network from ifconfig output
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'inet ' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'inet' and i + 1 < len(parts):
                                    ip = parts[i + 1]
                                    # Simple network calculation (assuming /24)
                                    ip_parts = ip.split('.')
                                    if len(ip_parts) == 4:
                                        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                    break
                            break
                        
            if not network:
                print(f"{Colors.RED}❌ Network not found{Colors.RESET}")
                return False
                
            print(f"{Colors.GREEN}└─ ✔ Network detected: {network}{Colors.RESET}")
            
            # Initialize devices list
            self.devices = []
            
            # Method 1: Quick ARP table check first
            print(f"{Colors.CYAN}└─ 🔍 Checking ARP table...{Colors.RESET}")
            self.show_progress_bar("📋 Reading ARP cache...", 1)
            arp_devices = self.quick_arp_scan()
            if arp_devices:
                self.devices.extend(arp_devices)
            
            # Method 2: Fast nmap scan (if available)
            print(f"{Colors.CYAN}└─ 🔍 Performing network scan...{Colors.RESET}")
            self.show_progress_bar("🚀 Network discovery...", 3)
            try:
                nmap_result = self.run_command(['nmap', '-sn', network], timeout=30)
                if nmap_result and nmap_result.returncode == 0:
                    # Extract IP addresses
                    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', nmap_result.stdout)
                    
                    # Track found devices to avoid duplicates
                    found_ips = {device['ip'] for device in self.devices}
                    
                    for ip in ips:
                        if ip not in found_ips:
                            mac = self.get_mac_for_ip(ip)
                            if mac and mac != "N/A":
                                device_name = self.get_device_name(mac)
                                self.devices.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'name': device_name
                                })
                                found_ips.add(ip)
            except:
                # If nmap fails, use ping sweep as fallback
                print(f"{Colors.YELLOW}└─ ⚠ Using alternative scan method...{Colors.RESET}")
                self.show_progress_bar("🔄 Alternative discovery...", 2)
                network_base = network.split('/')[0].rsplit('.', 1)[0]
                found_ips = {device['ip'] for device in self.devices}
                
                for i in range(1, 255):
                    ip = f"{network_base}.{i}"
                    if ip not in found_ips:
                        ping_result = self.run_command(['ping', '-c', '1', '-W', '1', ip], timeout=2)
                        if ping_result and ping_result.returncode == 0:
                            mac = self.get_mac_for_ip(ip)
                            if mac and mac != "N/A":
                                device_name = self.get_device_name(mac)
                                self.devices.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'name': device_name
                                })
                                found_ips.add(ip)
            
            # Sort devices by IP
            self.devices.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
            
            return len(self.devices) > 0
            
        except Exception as e:
            print(f"{Colors.RED}❌ Network scan error: {e}{Colors.RESET}")
            return False
            
    def quick_arp_scan(self):
        """Quick ARP table scan"""
        devices = []
        try:
            # Try different ARP commands
            arp_commands = [
                ['arp', '-a'],
                ['ip', 'neigh', 'show'],
                ['cat', '/proc/net/arp']
            ]
            
            for cmd in arp_commands:
                result = self.run_command(cmd)
                if result and result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        # Parse ARP output
                        if ':' in line and ('ether' in line.lower() or len([x for x in line.split() if ':' in x and len(x) == 17]) > 0):
                            # Extract IP and MAC
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                            
                            if ip_match and mac_match:
                                ip = ip_match.group(1)
                                mac = mac_match.group(0).upper().replace('-', ':')
                                
                                # Skip invalid IPs
                                if not ip.startswith('169.254') and ip != '0.0.0.0':
                                    device_name = self.get_device_name(mac)
                                    devices.append({
                                        'ip': ip,
                                        'mac': mac,
                                        'name': device_name
                                    })
                    break  # If one command works, don't try others
                    
        except Exception:
            pass
        return devices
            
    def get_mac_for_ip(self, ip):
        """Get MAC address for specific IP address - Termux compatible"""
        try:
            # Method 1: ARP table
            result = self.run_command(['arp', '-n', ip])
            if result and result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.upper()
            
            # Method 2: /proc/net/arp
            result = self.run_command(['cat', '/proc/net/arp'])
            if result and result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            mac = parts[3]
                            if ':' in mac and len(mac) == 17:
                                return mac.upper()
                                
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
            
        print(f"\n{Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.GREEN}║              📡 Found {len(self.devices)} device(s) on network ✅              ║{Colors.RESET}")
        print(f"{Colors.GREEN}╠═══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.WHITE}║ {'No.':<4} │ {'IP Address':<15} │ {'MAC Address':<17} │ {'Device':<15} ║{Colors.RESET}")
        print(f"{Colors.GREEN}╠═══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        
        for i, device in enumerate(self.devices, 1):
            ip_colored = f"{Colors.BLUE}{device['ip']:<15}{Colors.RESET}"
            mac_colored = f"{Colors.MAGENTA}{device['mac']:<17}{Colors.RESET}"
            name_colored = f"{Colors.YELLOW}{device['name']:<15}{Colors.RESET}"
            print(f"{Colors.WHITE}║ [{i}]  │ {ip_colored} │ {mac_colored} │ {name_colored} ║{Colors.RESET}")
            
        print(f"{Colors.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
    def show_main_menu(self):
        """Display main menu"""
        print(f"\n{Colors.BLUE}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BLUE}║                        🔧 NetMaster Menu                        ║{Colors.RESET}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.WHITE}║  Current Interface: {Colors.MAGENTA}{self.current_interface:<43}{Colors.WHITE} ║{Colors.RESET}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[1]{Colors.WHITE} Select MAC from devices table                        ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[2]{Colors.WHITE} Enter MAC manually                                   ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[3]{Colors.WHITE} Generate random MAC                                  ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[4]{Colors.WHITE} Restore original MAC                                 ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[5]{Colors.WHITE} Rescan network                                       ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[6]{Colors.WHITE} Show current MAC                                     ║{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.CYAN}[7]{Colors.WHITE} Change interface                                     ║{Colors.RESET}")
        print(f"{Colors.BLUE}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.WHITE}║  {Colors.RED}[0]{Colors.WHITE} Exit                                                 ║{Colors.RESET}")
        print(f"{Colors.BLUE}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
    def change_mac(self, new_mac):
        """Change MAC address - Termux compatible"""
        if not self.current_interface:
            print(f"{Colors.RED}❌ No network interface found{Colors.RESET}")
            return False
            
        try:
            # Save original MAC if not saved
            if not self.original_mac:
                self.original_mac = self.get_current_mac()
                self.save_config()
                
            self.show_progress_bar("🔄 Changing MAC address...", 2)
            
            # Method 1: ip link (preferred)
            down_result = self.run_command(['ip', 'link', 'set', 'dev', self.current_interface, 'down'])
            if down_result and down_result.returncode == 0:
                mac_result = self.run_command(['ip', 'link', 'set', 'dev', self.current_interface, 'address', new_mac])
                if mac_result and mac_result.returncode == 0:
                    up_result = self.run_command(['ip', 'link', 'set', 'dev', self.current_interface, 'up'])
                    if up_result and up_result.returncode == 0:
                        time.sleep(2)
                        current_mac = self.get_current_mac()
                        if current_mac and current_mac.lower() == new_mac.lower():
                            print(f"{Colors.GREEN}✔ MAC Address changed to: {new_mac}{Colors.RESET}")
                            self.log_action(f"MAC changed to: {new_mac}")
                            return True
            
            # Method 2: ifconfig (fallback)
            print(f"{Colors.YELLOW}└─ ⚠ Trying alternative method...{Colors.RESET}")
            self.show_progress_bar("🔄 Using ifconfig method...", 2)
            ifconfig_result = self.run_command(['ifconfig', self.current_interface, 'hw', 'ether', new_mac])
            if ifconfig_result and ifconfig_result.returncode == 0:
                time.sleep(2)
                current_mac = self.get_current_mac()
                if current_mac and current_mac.lower() == new_mac.lower():
                    print(f"{Colors.GREEN}✔ MAC Address changed to: {new_mac}{Colors.RESET}")
                    self.log_action(f"MAC changed to: {new_mac}")
                    return True
            
            print(f"{Colors.RED}❌ Failed to change MAC Address{Colors.RESET}")
            return False
                
        except Exception as e:
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
            choice = input(f"\n{Colors.CYAN}┌─ Enter your choice{Colors.RESET}\n{Colors.WHITE}└─ Select device number (0 to go back): {Colors.YELLOW}")
            print(Colors.RESET, end="")
            
            if choice == '0':
                return
                
            device_num = int(choice)
            if 1 <= device_num <= len(self.devices):
                selected_device = self.devices[device_num - 1]
                new_mac = selected_device['mac']
                
                print(f"\n{Colors.YELLOW}MAC will be changed to: {new_mac}{Colors.RESET}")
                print(f"{Colors.YELLOW}Device: {selected_device['name']} ({selected_device['ip']}){Colors.RESET}")
                
                confirm = input(f"{Colors.CYAN}┌─ Confirmation required{Colors.RESET}\n{Colors.WHITE}└─ Are you sure? (y/n): {Colors.YELLOW}")
                print(Colors.RESET, end="")
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
            mac = input(f"{Colors.CYAN}┌─ Enter MAC Address{Colors.RESET}\n{Colors.WHITE}└─ Format (AA:BB:CC:DD:EE:FF): {Colors.YELLOW}")
            print(Colors.RESET, end="")
            
            if self.validate_mac(mac):
                mac = mac.upper()
                print(f"\n{Colors.YELLOW}MAC will be changed to: {mac}{Colors.RESET}")
                
                confirm = input(f"{Colors.CYAN}┌─ Confirmation required{Colors.RESET}\n{Colors.WHITE}└─ Are you sure? (y/n): {Colors.YELLOW}")
                print(Colors.RESET, end="")
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
            print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.CYAN}║                     📋 Current MAC Information                  ║{Colors.RESET}")
            print(f"{Colors.CYAN}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.WHITE}║  Interface:     {Colors.GREEN}{self.current_interface:<45}{Colors.WHITE} ║{Colors.RESET}")
            print(f"{Colors.WHITE}║  Current MAC:   {Colors.GREEN}{current_mac:<45}{Colors.WHITE} ║{Colors.RESET}")
            
            if self.original_mac:
                if current_mac == self.original_mac:
                    print(f"{Colors.WHITE}║  Status:        {Colors.GREEN}{'✔ Original MAC (Unchanged)':<45}{Colors.WHITE} ║{Colors.RESET}")
                else:
                    print(f"{Colors.WHITE}║  Original MAC:  {Colors.YELLOW}{self.original_mac:<45}{Colors.WHITE} ║{Colors.RESET}")
                    print(f"{Colors.WHITE}║  Status:        {Colors.YELLOW}{'⚠ MAC has been changed':<45}{Colors.WHITE} ║{Colors.RESET}")
            else:
                print(f"{Colors.WHITE}║  Status:        {Colors.BLUE}{'ℹ No original MAC saved':<45}{Colors.WHITE} ║{Colors.RESET}")
                
            print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}")
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
            print(f"{Colors.YELLOW}└─ ⚠ No devices found, you can continue with other options{Colors.RESET}")
        else:
            self.show_devices_table()
            
        # Main menu loop
        while True:
            try:
                self.show_main_menu()
                choice = input(f"\n{Colors.CYAN}┌─ Enter your choice{Colors.RESET}\n{Colors.WHITE}└─ Select an option (0-7): {Colors.YELLOW}")
                print(Colors.RESET, end="")
                
                if choice == '1':
                    self.select_device_mac()
                elif choice == '2':
                    self.manual_mac_input()
                elif choice == '3':
                    random_mac = self.generate_random_mac()
                    print(f"\n{Colors.YELLOW}Random MAC: {random_mac}{Colors.RESET}")
                    confirm = input(f"{Colors.CYAN}┌─ Confirmation required{Colors.RESET}\n{Colors.WHITE}└─ Do you want to use it? (y/n): {Colors.YELLOW}")
                    print(Colors.RESET, end="")
                    if confirm.lower() in ['y', 'yes']:
                        self.change_mac(random_mac)
                elif choice == '4':
                    self.restore_original_mac()
                elif choice == '5':
                    if self.scan_network():
                        self.show_devices_table()
                    else:
                        print(f"{Colors.YELLOW}└─ ⚠ No new devices found{Colors.RESET}")
                elif choice == '6':
                    self.show_current_mac()
                elif choice == '7':
                    self.show_progress_bar("🔄 Changing interface...", 1)
                    new_interface = self.show_interfaces_menu()
                    if new_interface:
                        # Reset discovered devices
                        self.devices = []
                        print(f"{Colors.GREEN}└─ ✔ Interface changed successfully{Colors.RESET}")
                elif choice == '0':
                    print(f"\n{Colors.GREEN}Thank you for using NetMaster! 👋{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}❌ Invalid option{Colors.RESET}")
                    
                input(f"\n{Colors.CYAN}┌─ Press any key to continue{Colors.RESET}\n{Colors.WHITE}└─ Press Enter: {Colors.YELLOW}")
                print(Colors.RESET, end="")
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.GREEN}Thank you for using NetMaster! 👋{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}❌ Unexpected error: {e}{Colors.RESET}")

if __name__ == "__main__":
    netmaster = NetMaster()
    netmaster.run()