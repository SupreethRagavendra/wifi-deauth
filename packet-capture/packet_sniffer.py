from scapy.all import sniff, Dot11, Dot11Deauth, RadioTap
import threading
import time
from typing import Callable
from colorama import Fore, Style

class PacketSniffer:
    def __init__(self, interface: str, callback: Callable):
        """
        Args:
            interface: Wireless interface in monitor mode
            callback: Function to call when deauth frame captured
        """
        self.interface = interface
        self.callback = callback
        self.running = False
        self.sniff_thread = None
        
    def packet_handler(self, packet):
        """
        Process each captured packet
        
        Logic:
        1. Check if packet has Dot11Deauth layer
        2. If yes, extract details
        3. Call self.callback with extracted data
        """
        if not self.running:
            return

        if packet.haslayer(Dot11Deauth):
            try:
                # Extract basic fields
                # addr1: Destination (Receiver)
                # addr2: Source (Transmitter)
                # addr3: BSSID
                dest_mac = packet.addr1
                source_mac = packet.addr2
                bssid = packet.addr3
                
                # Sequence number is in Dot11 layer (SC field, fragment number is lower 4 bits)
                sequence = 0
                if packet.haslayer(Dot11):
                    sequence = packet.SC >> 4
                
                # RSSI is typically in RadioTap header
                rssi = -100 # Default/Missing value
                if packet.haslayer(RadioTap):
                    # dbm_antsignal is the standard field for RSSI in scapy
                    # Note: precise field name can vary by driver/scapy version, usually dBm_AntSignal
                    try:
                        # dbm_antsignal might be present but None
                        val = packet.dBm_AntSignal
                        if val is not None:
                            rssi = val
                    except AttributeError:
                        # Sometimes hidden in extra fields or not parsed
                        pass
                
                # Reason code
                reason = 0
                if packet.haslayer(Dot11Deauth):
                    reason = packet.reason
                
                packet_data = {
                    'source_mac': source_mac,
                    'dest_mac': dest_mac,
                    'bssid': bssid,
                    'sequence': sequence,
                    'rssi': rssi,
                    'reason': reason,
                    'timestamp': time.time()
                }
                
                self.callback(packet_data)
                
            except Exception as e:
                # Avoid crashing the sniffer on a bad packet
                print(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")

    def _sniff_loop(self):
        """Internal loop for sniffing"""
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                monitor=True,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"{Fore.RED}Sniffer error: {e}{Style.RESET_ALL}")
            self.running = False

    def start(self):
        """Start sniffing packets in a separate thread"""
        if self.running:
            return
            
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        
    def stop(self):
        """Stop sniffing and wait for the thread to exit cleanly."""
        self.running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=3)  # wait for scapy to release the socket
