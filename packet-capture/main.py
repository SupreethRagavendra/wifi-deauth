#!/usr/bin/env python3
"""
Wi-Fi Deauthentication Packet Capture Engine
Sends captured frames to Java backend for analysis
"""

import signal
import sys
import time
from colorama import Fore, Style, init

from config import Config
from monitor_mode import (
    check_root,
    get_wireless_interfaces,
    enable_monitor_mode,
    set_channel,
    disable_monitor_mode
)
from packet_sniffer import PacketSniffer
from frame_parser import build_packet_json, calculate_sequence_gap
from data_sender import DataSender

# Initialize colorama for colored terminal output
init(autoreset=True)

# Global state
sniffer = None
data_sender = None
last_sequence = {}  # Track last sequence per MAC
monitor_interface = None

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Fore.YELLOW}Stopping capture engine...{Style.RESET_ALL}")
    if sniffer:
        sniffer.stop()
    

    if monitor_interface:
        disable_monitor_mode(monitor_interface)
        print(f"{Fore.GREEN}✓ Monitor mode disabled{Style.RESET_ALL}")
    
    sys.exit(0)

def packet_callback(packet_data: dict):
    """Called for each captured deauth frame"""
    global last_sequence, data_sender
    
    # Calculate sequence gap
    source_mac = packet_data.get('source_mac')
    current_seq = packet_data.get('sequence', 0)
    
    if source_mac and source_mac in last_sequence:
        seq_gap = calculate_sequence_gap(current_seq, last_sequence[source_mac])
        packet_data['sequence_gap'] = seq_gap
    else:
        packet_data['sequence_gap'] = 0

    # Inject channel
    packet_data['channel'] = Config.CHANNEL
        
    last_sequence[source_mac] = current_seq
    
    # Build JSON and send
    packet_json = build_packet_json(packet_data)
    data_sender.add_packet(packet_json)
    
    # Print to console
    print(f"{Fore.CYAN}Deauth: {packet_data['source_mac']} → {packet_data['dest_mac']} "
          f"(RSSI: {packet_data['rssi']} dBm, Seq Gap: {packet_data['sequence_gap']}){Style.RESET_ALL}")

def main():
    global sniffer, data_sender, monitor_interface
    
    print(f"{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}  Wi-Fi Deauth Packet Capture Engine - Module 2")
    print(f"{Fore.GREEN}{'='*60}\n")
    
    # Step 1: Check root
    if not check_root():
        print(f"{Fore.RED}✗ Must run as root (use: sudo python3 main.py){Style.RESET_ALL}")
        sys.exit(1)
    
    # Step 2: Check interface strategy
    # Try to find the interface from config
    target_interface = Config.INTERFACE
    interfaces = get_wireless_interfaces()
    
    if target_interface not in interfaces:
        # Check if maybe it's already in monitor mode and name changed (e.g., wlan0mon)
        # But simple check:
        print(f"{Fore.YELLOW}⚠ Interface {target_interface} not detected in standard list, processing anyway...{Style.RESET_ALL}")
        print(f"Available interfaces: {', '.join(interfaces)}")
        # sys.exit(1) # Don't exit, trust the config
    
    # Step 3: Enable monitor mode
    print(f"{Fore.YELLOW}Enabling monitor mode on {target_interface}...{Style.RESET_ALL}")
    if not enable_monitor_mode(target_interface):
        print(f"{Fore.RED}✗ Failed to enable monitor mode{Style.RESET_ALL}")
        sys.exit(1)
    
    monitor_interface = target_interface
    print(f"{Fore.GREEN}✓ Monitor mode enabled{Style.RESET_ALL}")
    
    # Step 4: Set channel
    print(f"{Fore.YELLOW}Setting channel to {Config.CHANNEL}...{Style.RESET_ALL}")
    set_channel(target_interface, Config.CHANNEL)
    print(f"{Fore.GREEN}✓ Channel set{Style.RESET_ALL}")
    
    # Step 5: Initialize components
    data_sender = DataSender(Config.BACKEND_URL)
    sniffer = PacketSniffer(target_interface, packet_callback)
    
    # Step 6: Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Step 7: Start capture
    print(f"\n{Fore.GREEN}✓ Capture engine started{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Monitoring {target_interface} on channel {Config.CHANNEL}...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Backend: {Config.BACKEND_URL}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Press Ctrl+C to stop\n{Style.RESET_ALL}")
    
    sniffer.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass # Handled by signal handler, but this catches the sleep interruption

if __name__ == "__main__":
    main()
