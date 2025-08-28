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
    """ألوان للواجهة"""
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
        """مسح الشاشة"""
        os.system('clear')
        
    def show_banner(self):
        """عرض شعار الأداة"""
        banner = f"""
{Colors.RED}   _   _      _   __  __           _           {Colors.RESET}
{Colors.RED}  | \\ | | ___| |_|  \\/  | ___   __| | ___ _ __ {Colors.RESET}
{Colors.YELLOW}  |  \\| |/ _ \\ __| |\\/| |/ _ \\ / _` |/ _ \\ '__| {Colors.RESET}
{Colors.GREEN}  | |\\  |  __/ |_| |  | | (_) | (_| |  __/ |   {Colors.RESET}
{Colors.BLUE}  |_| \\_|\\___\\__|_|  |_|\\___/ \\__,_|\\___|_|   {Colors.RESET}

{Colors.CYAN}      🔹 إدارة الشبكة - NetMaster 🔹{Colors.RESET}
{Colors.CYAN}      🔹 NetMaster Lite AutoScan 🔹{Colors.RESET}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
        print(banner)
        
    def log_action(self, action):
        """تسجيل العمليات"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {action}\n")
            
    def save_config(self):
        """حفظ الإعدادات"""
        config = {
            "original_mac": self.original_mac,
            "current_interface": self.current_interface
        }
        with open(self.config_file, "w") as f:
            json.dump(config, f)
            
    def load_config(self):
        """تحميل الإعدادات"""
        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                self.original_mac = config.get("original_mac")
                self.current_interface = config.get("current_interface")
        except FileNotFoundError:
            pass
            
    def check_root(self):
        """التحقق من صلاحيات الروت"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}❌ هذه الأداة تحتاج صلاحيات الروت!{Colors.RESET}")
            print(f"{Colors.YELLOW}استخدم: sudo python3 netmaster.py{Colors.RESET}")
            sys.exit(1)
            
    def get_all_interfaces(self):
        """الحصول على جميع واجهات الشبكة المتاحة"""
        interfaces = []
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if ':' in line and not line.startswith(' '):
                    # استخراج اسم الواجهة
                    parts = line.split(':')
                    if len(parts) >= 2:
                        interface_name = parts[1].strip()
                        
                        # تجاهل loopback
                        if interface_name == 'lo':
                            continue
                            
                        # الحصول على حالة الواجهة
                        status = "DOWN"
                        if 'UP' in line:
                            status = "UP"
                        elif 'LOWER_UP' in line:
                            status = "UP"
                            
                        # الحصول على نوع الواجهة
                        interface_type = "Unknown"
                        if interface_name.startswith(('wlan', 'wlp')):
                            interface_type = "WiFi"
                        elif interface_name.startswith(('eth', 'enp', 'ens')):
                            interface_type = "Ethernet"
                        elif interface_name.startswith('usb'):
                            interface_type = "USB"
                        elif interface_name.startswith('tun'):
                            interface_type = "VPN"
                            
                        # الحصول على MAC address
                        mac = self.get_interface_mac(interface_name)
                        
                        interfaces.append({
                            'name': interface_name,
                            'type': interface_type,
                            'status': status,
                            'mac': mac
                        })
                        
        except Exception as e:
            print(f"{Colors.RED}خطأ في الحصول على الواجهات: {e}{Colors.RESET}")
            
        return interfaces
        
    def get_interface_mac(self, interface):
        """الحصول على MAC address لواجهة محددة"""
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
        """عرض قائمة الواجهات للاختيار"""
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            print(f"{Colors.RED}❌ لم يتم العثور على واجهات شبكة{Colors.RESET}")
            return None
            
        print(f"\n{Colors.CYAN}🔍 الواجهات المتاحة:{Colors.RESET}")
        print(f"{Colors.WHITE}{'رقم':<6} {'الاسم':<12} {'النوع':<10} {'الحالة':<8} {'MAC Address'}{Colors.RESET}")
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
                choice = input(f"\n{Colors.WHITE}اختر رقم الواجهة (0 للخروج): {Colors.RESET}")
                
                if choice == '0':
                    return None
                    
                interface_num = int(choice)
                if 1 <= interface_num <= len(interfaces):
                    selected = interfaces[interface_num - 1]
                    
                    if selected['status'] != 'UP':
                        print(f"{Colors.YELLOW}⚠️  الواجهة {selected['name']} غير نشطة{Colors.RESET}")
                        confirm = input(f"{Colors.WHITE}هل تريد المتابعة؟ (y/n): {Colors.RESET}")
                        if confirm.lower() not in ['y', 'yes', 'نعم']:
                            continue
                    
                    self.current_interface = selected['name']
                    print(f"{Colors.GREEN}✔ تم اختيار الواجهة: {selected['name']} ({selected['type']}){Colors.RESET}")
                    return selected['name']
                else:
                    print(f"{Colors.RED}❌ رقم غير صحيح{Colors.RESET}")
                    
            except ValueError:
                print(f"{Colors.RED}❌ يرجى إدخال رقم صحيح{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}تم إلغاء العملية{Colors.RESET}")
                return None
        
    def get_current_mac(self):
        """الحصول على MAC الحالي"""
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
        """فحص الشبكة للأجهزة المتصلة"""
        print(f"{Colors.CYAN}جاري فحص الشبكة... ⏳{Colors.RESET}")
        
        try:
            # الحصول على عنوان الشبكة
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
                print(f"{Colors.RED}❌ لم يتم العثور على شبكة{Colors.RESET}")
                return False
                
            print(f"{Colors.YELLOW}فحص الشبكة: {network}{Colors.RESET}")
            
            # استخدام nmap لفحص الشبكة
            nmap_cmd = ['nmap', '-sn', network]
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=30)
            
            # استخراج عناوين IP
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
            print(f"{Colors.RED}❌ انتهت مهلة فحص الشبكة{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}❌ خطأ في فحص الشبكة: {e}{Colors.RESET}")
            return False
            
    def get_mac_for_ip(self, ip):
        """الحصول على MAC address لعنوان IP محدد"""
        try:
            # ping للتأكد من وجود الجهاز في ARP table
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
            
            # قراءة ARP table
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
        """تخمين نوع الجهاز من MAC address"""
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
        """عرض جدول الأجهزة"""
        if not self.devices:
            print(f"{Colors.RED}❌ لم يتم العثور على أجهزة في الشبكة{Colors.RESET}")
            return
            
        print(f"\n{Colors.GREEN}تم العثور على {len(self.devices)} جهاز في الشبكة ✅{Colors.RESET}")
        print(f"{Colors.WHITE}{'رقم':<6} {'IP Address':<15} {'MAC Address':<18} {'الجهاز'}{Colors.RESET}")
        print(f"{Colors.WHITE}{'-'*60}{Colors.RESET}")
        
        for i, device in enumerate(self.devices, 1):
            ip_colored = f"{Colors.BLUE}{device['ip']:<15}{Colors.RESET}"
            mac_colored = f"{Colors.GREEN}{device['mac']:<18}{Colors.RESET}"
            name_colored = f"{Colors.YELLOW}{device['name']}{Colors.RESET}"
            print(f"{Colors.WHITE}[{i}]{Colors.RESET}   {ip_colored} {mac_colored} {name_colored}")
            
        print(f"{Colors.WHITE}{'-'*60}{Colors.RESET}")
        
    def show_main_menu(self):
        """عرض القائمة الرئيسية"""
        print(f"\n{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        print(f"{Colors.MAGENTA}الواجهة الحالية: {self.current_interface}{Colors.RESET}")
        print(f"{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        print(f"{Colors.CYAN}[1] اختيار MAC من جدول الأجهزة{Colors.RESET}")
        print(f"{Colors.CYAN}[2] إدخال MAC يدوياً{Colors.RESET}")
        print(f"{Colors.CYAN}[3] توليد MAC عشوائي{Colors.RESET}")
        print(f"{Colors.CYAN}[4] استرجاع MAC الأصلي{Colors.RESET}")
        print(f"{Colors.CYAN}[5] إعادة فحص الشبكة{Colors.RESET}")
        print(f"{Colors.CYAN}[6] عرض MAC الحالي{Colors.RESET}")
        print(f"{Colors.CYAN}[7] تغيير الواجهة{Colors.RESET}")
        print(f"{Colors.RED}[0] خروج{Colors.RESET}")
        print(f"{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
    def change_mac(self, new_mac):
        """تغيير MAC address"""
        if not self.current_interface:
            print(f"{Colors.RED}❌ لم يتم العثور على واجهة شبكة{Colors.RESET}")
            return False
            
        try:
            # حفظ MAC الأصلي إذا لم يكن محفوظاً
            if not self.original_mac:
                self.original_mac = self.get_current_mac()
                self.save_config()
                
            # إيقاف الواجهة
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 'down'], 
                         check=True)
            
            # تغيير MAC
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 
                          'address', new_mac], check=True)
            
            # تشغيل الواجهة
            subprocess.run(['ip', 'link', 'set', 'dev', self.current_interface, 'up'], 
                         check=True)
            
            # انتظار قليل للتأكد من التطبيق
            time.sleep(2)
            
            # التحقق من نجاح التغيير
            current_mac = self.get_current_mac()
            if current_mac and current_mac.lower() == new_mac.lower():
                print(f"{Colors.GREEN}✔ تم تغيير MAC Address إلى: {new_mac}{Colors.RESET}")
                self.log_action(f"تم تغيير MAC إلى: {new_mac}")
                return True
            else:
                print(f"{Colors.RED}❌ فشل في تغيير MAC Address{Colors.RESET}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}❌ خطأ في تغيير MAC: {e}{Colors.RESET}")
            return False
            
    def restore_original_mac(self):
        """استرجاع MAC الأصلي"""
        if not self.original_mac:
            print(f"{Colors.RED}❌ لا يوجد MAC أصلي محفوظ{Colors.RESET}")
            return False
            
        if self.change_mac(self.original_mac):
            print(f"{Colors.GREEN}✔ تم استرجاع MAC Address الأصلي بنجاح{Colors.RESET}")
            self.log_action("تم استرجاع MAC الأصلي")
            return True
        return False
        
    def generate_random_mac(self):
        """توليد MAC عشوائي"""
        # استخدام OUI محلي (Local Administered)
        mac = "02"
        for _ in range(5):
            mac += ":" + "%02x" % random.randint(0, 255)
        return mac.upper()
        
    def validate_mac(self, mac):
        """التحقق من صحة MAC address"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(pattern, mac) is not None
        
    def select_device_mac(self):
        """اختيار MAC من جدول الأجهزة"""
        if not self.devices:
            print(f"{Colors.RED}❌ لا توجد أجهزة في الجدول{Colors.RESET}")
            return
            
        print(f"\n{Colors.CYAN}اختر الجهاز لتغيير MAC Address إليه:{Colors.RESET}")
        self.show_devices_table()
        
        try:
            choice = input(f"\n{Colors.WHITE}اختر رقم الجهاز (0 للعودة): {Colors.RESET}")
            
            if choice == '0':
                return
                
            device_num = int(choice)
            if 1 <= device_num <= len(self.devices):
                selected_device = self.devices[device_num - 1]
                new_mac = selected_device['mac']
                
                print(f"\n{Colors.YELLOW}سيتم تغيير MAC إلى: {new_mac}{Colors.RESET}")
                print(f"{Colors.YELLOW}الجهاز: {selected_device['name']} ({selected_device['ip']}){Colors.RESET}")
                
                confirm = input(f"{Colors.WHITE}هل أنت متأكد؟ (y/n): {Colors.RESET}")
                if confirm.lower() in ['y', 'yes', 'نعم']:
                    self.change_mac(new_mac)
                else:
                    print(f"{Colors.YELLOW}تم إلغاء العملية{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ رقم غير صحيح{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}❌ يرجى إدخال رقم صحيح{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}تم إلغاء العملية{Colors.RESET}")
            
    def manual_mac_input(self):
        """إدخال MAC يدوياً"""
        try:
            mac = input(f"{Colors.WHITE}أدخل MAC Address (مثال: AA:BB:CC:DD:EE:FF): {Colors.RESET}")
            
            if self.validate_mac(mac):
                mac = mac.upper()
                print(f"\n{Colors.YELLOW}سيتم تغيير MAC إلى: {mac}{Colors.RESET}")
                
                confirm = input(f"{Colors.WHITE}هل أنت متأكد؟ (y/n): {Colors.RESET}")
                if confirm.lower() in ['y', 'yes', 'نعم']:
                    self.change_mac(mac)
                else:
                    print(f"{Colors.YELLOW}تم إلغاء العملية{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ تنسيق MAC غير صحيح{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}تم إلغاء العملية{Colors.RESET}")
            
    def show_current_mac(self):
        """عرض MAC الحالي"""
        current_mac = self.get_current_mac()
        if current_mac:
            print(f"\n{Colors.CYAN}MAC Address الحالي: {Colors.GREEN}{current_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}واجهة الشبكة: {Colors.GREEN}{self.current_interface}{Colors.RESET}")
            
            if self.original_mac:
                if current_mac == self.original_mac:
                    print(f"{Colors.GREEN}✔ هذا هو MAC الأصلي{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}MAC الأصلي: {self.original_mac}{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ لم يتم العثور على MAC{Colors.RESET}")
            
    def run(self):
        """تشغيل الأداة الرئيسي"""
        self.clear_screen()
        self.show_banner()
        
        # التحقق من الصلاحيات
        self.check_root()
        
        # تحميل الإعدادات
        self.load_config()
        
        # عرض قائمة الواجهات للاختيار
        selected_interface = self.show_interfaces_menu()
        if not selected_interface:
            print(f"{Colors.RED}❌ لم يتم اختيار واجهة شبكة{Colors.RESET}")
            sys.exit(1)
        
        # فحص الشبكة تلقائياً
        if not self.scan_network():
            print(f"{Colors.YELLOW}⚠ لم يتم العثور على أجهزة، يمكنك المتابعة بالخيارات الأخرى{Colors.RESET}")
        else:
            self.show_devices_table()
            
        # القائمة الرئيسية
        while True:
            try:
                self.show_main_menu()
                choice = input(f"\n{Colors.WHITE}اختر خياراً: {Colors.RESET}")
                
                if choice == '1':
                    self.select_device_mac()
                elif choice == '2':
                    self.manual_mac_input()
                elif choice == '3':
                    random_mac = self.generate_random_mac()
                    print(f"\n{Colors.YELLOW}MAC عشوائي: {random_mac}{Colors.RESET}")
                    confirm = input(f"{Colors.WHITE}هل تريد استخدامه؟ (y/n): {Colors.RESET}")
                    if confirm.lower() in ['y', 'yes', 'نعم']:
                        self.change_mac(random_mac)
                elif choice == '4':
                    self.restore_original_mac()
                elif choice == '5':
                    print(f"\n{Colors.CYAN}إعادة فحص الشبكة...{Colors.RESET}")
                    if self.scan_network():
                        self.show_devices_table()
                    else:
                        print(f"{Colors.YELLOW}لم يتم العثور على أجهزة جديدة{Colors.RESET}")
                elif choice == '6':
                    self.show_current_mac()
                elif choice == '7':
                    print(f"\n{Colors.CYAN}تغيير الواجهة...{Colors.RESET}")
                    new_interface = self.show_interfaces_menu()
                    if new_interface:
                        # إعادة تعيين الأجهزة المكتشفة
                        self.devices = []
                        print(f"{Colors.GREEN}✔ تم تغيير الواجهة بنجاح{Colors.RESET}")
                elif choice == '0':
                    print(f"\n{Colors.GREEN}شكراً لاستخدام NetMaster! 👋{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}❌ خيار غير صحيح{Colors.RESET}")
                    
                input(f"\n{Colors.WHITE}اضغط Enter للمتابعة...{Colors.RESET}")
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.GREEN}شكراً لاستخدام NetMaster! 👋{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}❌ خطأ غير متوقع: {e}{Colors.RESET}")

if __name__ == "__main__":
    netmaster = NetMaster()
    netmaster.run()