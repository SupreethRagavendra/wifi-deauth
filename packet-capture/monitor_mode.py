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


def _if_down(interface: str):
    """Bring interface down — tries ifconfig then ip link as fallback."""
    try:
        subprocess.run(['ifconfig', interface, 'down'],
                       check=True, capture_output=True, timeout=5)
        return
    except Exception:
        pass
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'],
                       check=True, capture_output=True, timeout=5)
    except Exception:
        pass  # best-effort


def _if_up(interface: str):
    """Bring interface up — tries ifconfig then ip link as fallback."""
    try:
        subprocess.run(['ifconfig', interface, 'up'],
                       check=True, capture_output=True, timeout=5)
        return True
    except Exception:
        pass
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'up'],
                       check=True, capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _reload_driver(interface: str):
    """
    Last-resort: unload + reload the kernel module for the adapter.
    Equivalent to physically replugging the USB dongle.
    Works for RTL8188 / ath9k_htc / mt7601u / rtl8xxxu etc.
    """
    # Find which module owns this interface
    try:
        result = subprocess.run(
            ['readlink', f'/sys/class/net/{interface}/device/driver'],
            capture_output=True, text=True
        )
        module = os.path.basename(result.stdout.strip())
    except Exception:
        module = None

    if module and module not in ('', '.', '..'):
        print(f"{Fore.YELLOW}⟳ Reloading driver module '{module}'...{Style.RESET_ALL}")
        subprocess.run(['modprobe', '-r', module], capture_output=True)
        time.sleep(1)
        subprocess.run(['modprobe', module], capture_output=True)
        time.sleep(3)  # wait for interface to re-appear
    else:
        # Fallback: reset via usbreset if it's a USB device
        try:
            usb_path = os.path.realpath(f'/sys/class/net/{interface}/device')
            # Find the USB device path
            result = subprocess.run(
                ['find', '/dev/bus/usb', '-type', 'c'],
                capture_output=True, text=True
            )
        except Exception:
            pass


def enable_monitor_mode(interface: str) -> bool:
    """Enable monitor mode on interface."""

    # Kill processes that fight over the interface
    for proc in ['wpa_supplicant', 'NetworkManager']:
        try:
            subprocess.run(['pkill', '-f', proc], capture_output=True)
        except Exception:
            pass

    # Tell NetworkManager to unmanage this interface
    if shutil.which("nmcli"):
        try:
            subprocess.run(['nmcli', 'dev', 'set', interface, 'managed', 'no'],
                           capture_output=True, timeout=3)
        except Exception:
            pass

    print(f"{Fore.CYAN}Enabling monitor mode on {interface}...{Style.RESET_ALL}")

    # Check if already in monitor mode
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        already_monitor = ("Mode:Monitor" in result.stdout or "Mode: Monitor" in result.stdout)
    except Exception:
        already_monitor = False

    if already_monitor:
        print(f"{Fore.GREEN}Interface {interface} is already in monitor mode.{Style.RESET_ALL}")
        _if_up(interface)
        return True

    # Bring down → set monitor → bring up
    _if_down(interface)
    time.sleep(0.5)

    # Try iw first (more reliable than iwconfig for modern drivers)
    set_ok = False
    if shutil.which("iw"):
        try:
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'],
                           check=True, capture_output=True, timeout=5)
            set_ok = True
        except Exception:
            pass

    if not set_ok and shutil.which("iwconfig"):
        try:
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'],
                           check=True, capture_output=True, timeout=5)
            set_ok = True
        except Exception:
            pass

    if not set_ok:
        print(f"{Fore.RED}✗ Could not set monitor mode on {interface}{Style.RESET_ALL}")
        return False

    up_ok = _if_up(interface)
    if not up_ok:
        # Interface may have been renamed (e.g. wlan1mon) after monitor mode switch
        # Try reloading the driver
        print(f"{Fore.YELLOW}⚠ Interface up failed — reloading driver...{Style.RESET_ALL}")
        _reload_driver(interface)
        _if_down(interface)
        time.sleep(0.3)
        if shutil.which("iw"):
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'],
                           capture_output=True)
        elif shutil.which("iwconfig"):
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'],
                           capture_output=True)
        up_ok = _if_up(interface)
        if not up_ok:
            print(f"{Fore.RED}✗ Failed to bring {interface} up{Style.RESET_ALL}")
            return False

    time.sleep(1)  # let the interface settle

    # Verify
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout or "Mode: Monitor" in result.stdout:
            return True
    except Exception:
        pass

    # Final check via iw
    try:
        result = subprocess.run(['iw', 'dev', interface, 'info'],
                                capture_output=True, text=True)
        if 'monitor' in result.stdout.lower():
            return True
    except Exception:
        pass

    print(f"{Fore.RED}✗ Monitor mode verification failed for {interface}{Style.RESET_ALL}")
    return False


def disable_monitor_mode(interface: str) -> bool:
    """Restore managed mode."""
    print(f"{Fore.CYAN}Restoring managed mode on {interface}...{Style.RESET_ALL}")

    _if_down(interface)

    # Try iw first
    set_ok = False
    if shutil.which("iw"):
        try:
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'],
                           check=True, capture_output=True, timeout=5)
            set_ok = True
        except Exception:
            pass

    if not set_ok and shutil.which("iwconfig"):
        try:
            subprocess.run(['iwconfig', interface, 'mode', 'managed'],
                           check=True, capture_output=True, timeout=5)
            set_ok = True
        except Exception:
            pass

    _if_up(interface)

    # Restore NetworkManager
    if shutil.which("nmcli"):
        try:
            subprocess.run(['nmcli', 'dev', 'set', interface, 'managed', 'yes'],
                           capture_output=True, timeout=3)
        except Exception:
            pass

    return set_ok


def set_channel(interface: str, channel: int) -> bool:
    """Set monitoring channel (1-165)"""
    if not (1 <= channel <= 165):
        print(f"{Fore.RED}Invalid channel {channel}. Must be between 1 and 165.{Style.RESET_ALL}")
        return False

    # Try iw first
    if shutil.which("iw"):
        try:
            subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)],
                           check=True, capture_output=True, timeout=3)
            return True
        except subprocess.CalledProcessError:
            pass

    # Fallback: iwconfig
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)],
                       check=True, capture_output=True, timeout=3)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to set channel {channel} on {interface}: {e}{Style.RESET_ALL}")
        return False
