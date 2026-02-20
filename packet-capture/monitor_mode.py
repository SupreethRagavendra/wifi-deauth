import os
import subprocess
import shutil
import time
from typing import List
from colorama import Fore, Style

def check_root() -> bool:
    """Check if running as root (required for monitor mode)"""
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This script must be run as root to manage network interfaces.{Style.RESET_ALL}")
        return False
    return True

def get_wireless_interfaces() -> List[str]:
    """Get list of wireless interfaces using 'iw dev'"""
    try:
        # check if iw is installed
        if not shutil.which("iw"):
            print(f"{Fore.RED}Error: 'iw' command not found. Please install wireless-tools.{Style.RESET_ALL}")
            return []

        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if "Interface" in line:
                interfaces.append(line.split()[1])
        return interfaces
    except Exception as e:
        print(f"{Fore.RED}Error getting interfaces: {e}{Style.RESET_ALL}")
        return []

def enable_monitor_mode(interface: str) -> bool:
    """Enable monitor mode on interface"""
    
    # Check if already in monitor mode
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout or "Mode: Monitor" in result.stdout:
            print(f"{Fore.GREEN}Interface {interface} is already in monitor mode.{Style.RESET_ALL}")
            # Ensure it is UP to prevent 'Network is down' errors
            try:
                subprocess.run(['ifconfig', interface, 'up'], check=True)
            except:
                pass
            return True
    except Exception:
        pass

    # Expert Fix: Kill wpa_supplicant to stop channel hopping absolutely
    try:
        subprocess.run(['pkill', 'wpa_supplicant'], capture_output=True)
    except:
        pass

    print(f"{Fore.CYAN}Enabling monitor mode on {interface}...{Style.RESET_ALL}")
    
    commands = [
        ['ifconfig', interface, 'down'],
        ['iwconfig', interface, 'mode', 'monitor'],
        ['ifconfig', interface, 'up']
    ]
    
    try:
        # Check if tools exist
        if not shutil.which("ifconfig") or not shutil.which("iwconfig"):
             print(f"{Fore.RED}Error: 'ifconfig' or 'iwconfig' not found. Please install wireless-tools / net-tools.{Style.RESET_ALL}")
             return False

        for cmd in commands:
            subprocess.run(cmd, check=True, capture_output=True)
            
        time.sleep(2) # Wait for interface to settle
            
        # Stop NetworkManager from interfering
        if shutil.which("nmcli"):
            try:
                subprocess.run(['nmcli', 'dev', 'set', interface, 'managed', 'no'], capture_output=True)
            except:
                pass

        return True
    except subprocess.CalledProcessError as e:
        # Re-check if it actually worked or was already fine despite the error
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout or "Mode: Monitor" in result.stdout:
                print(f"{Fore.GREEN}Interface {interface} is in monitor mode (despite error).{Style.RESET_ALL}")
                return True
        except:
            pass
            
        print(f"{Fore.RED}Failed to enable monitor mode on {interface}: {e}{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        return False

def disable_monitor_mode(interface: str) -> bool:
    """Restore managed mode"""
    print(f"{Fore.CYAN}Restoring managed mode on {interface}...{Style.RESET_ALL}")
    
    commands = [
        ['ifconfig', interface, 'down'],
        ['iwconfig', interface, 'mode', 'managed'],
        ['ifconfig', interface, 'up']
    ]
    
    try:
        for cmd in commands:
            subprocess.run(cmd, check=True, capture_output=True)
            
        # Restore NetworkManager
        if shutil.which("nmcli"):
            try:
                subprocess.run(['nmcli', 'dev', 'set', interface, 'managed', 'yes'], capture_output=True)
            except:
                pass
                
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to disable monitor mode on {interface}: {e}{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        return False

def set_channel(interface: str, channel: int) -> bool:
    """Set monitoring channel (1-165)"""
    if not (1 <= channel <= 165):
        print(f"{Fore.RED}Invalid channel {channel}. Must be between 1 and 165.{Style.RESET_ALL}")
        return False
        
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to set channel {channel} on {interface}: {e}{Style.RESET_ALL}")
        return False
