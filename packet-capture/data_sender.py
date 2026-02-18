import requests
import time
import queue
import threading
from typing import List
from colorama import Fore, Style
from config import Config

class DataSender:
    def __init__(self, backend_url: str):
        self.backend_url = backend_url
        self.queue = queue.Queue()
        self.running = True
        self.start_worker()
        
    def start_worker(self):
        """Start the background sender thread"""
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
    def add_packet(self, packet_json: dict):
        """Add packet to queue (non-blocking)"""
        self.queue.put(packet_json)
        
    def _worker_loop(self):
        """Background loop to process queue and send batches"""
        batch = []
        last_send_time = time.time()
        
        while self.running:
            try:
                # Wait briefly for items
                try:
                    # Determine block time based on if we have items
                    item = self.queue.get(timeout=0.1)
                    batch.append(item)
                except queue.Empty:
                    pass
                
                # Check flush conditions
                time_diff = time.time() - last_send_time
                is_full = len(batch) >= Config.BUFFER_SIZE
                is_timeout = time_diff >= Config.SEND_INTERVAL and len(batch) > 0
                
                if is_full or is_timeout:
                    success = self._send_batch_internal(batch)
                    if success:
                        batch = [] # Clear on success
                    else:
                        batch = [] # Drop on failure to avoid stale loop
                    last_send_time = time.time()
                    
            except Exception as e:
                print(f"{Fore.RED}Sender thread error: {e}{Style.RESET_ALL}")
                time.sleep(1)

    def _send_batch_internal(self, batch: List[dict]) -> bool:
        """
        Send buffered packets to backend (Synchronous/Blocking - runs in worker thread)
        """
        if not batch:
            return True
            
        payload = {"packets": batch}
        count = len(batch)
        
        for attempt in range(1, Config.MAX_RETRIES + 1):
            try:
                response = requests.post(
                    Config.PACKET_ENDPOINT,
                    json=payload,
                    timeout=5,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    description = f"{Fore.GREEN}✓ Sent {count} packets{Style.RESET_ALL}"
                    # Only print large batches or occasionally to avoid spam
                    if count >= 10: 
                        print(description)
                    elif count > 0 and count < 10:
                        # Print sometimes? Or always for debug now?
                        # Always print for now so user sees activity
                        print(description)
                    return True
                else:
                    print(f"{Fore.RED}✗ Backend returned {response.status_code}{Style.RESET_ALL}")
                    
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}✗ Attempt {attempt} failed: {e}{Style.RESET_ALL}")
                if attempt < Config.MAX_RETRIES:
                    time.sleep(Config.RETRY_DELAY)
                
        print(f"{Fore.RED}✗ Dropped {count} packets after failures{Style.RESET_ALL}")
        return False
    
    def send_to_detection(self, packet_data: dict) -> dict:
        """
        Send a single packet to the detection API for analysis.
        (Legacy/Direct method)
        """
        # Map packet fields to detection request DTO
        detection_request = {
            "networkId": packet_data.get('network_id', ''),
            "sourceMac": packet_data.get('source_mac', ''),
            "destinationMac": packet_data.get('dest_mac', ''),
            "bssid": packet_data.get('bssid', ''),
            "sequenceNumber": packet_data.get('sequence', 0),
            "rssi": packet_data.get('rssi', -50),
            "frameType": "DEAUTH"
        }
        
        try:
            response = requests.post(
                Config.DETECTION_ENDPOINT,
                json=detection_request,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                verdict = result.get('data', {}).get('threatLevel', 'UNKNOWN')
                score = result.get('data', {}).get('layer1Score', 0)
                
                # Color-coded output based on verdict  
                if verdict == 'CRITICAL' or verdict == 'HIGH':
                    print(f"{Fore.RED}⚠ ATTACK: {packet_data.get('source_mac')} | Score: {score}/100{Style.RESET_ALL}")
                elif verdict == 'MEDIUM':
                    print(f"{Fore.YELLOW}⚠ SUSPICIOUS: {packet_data.get('source_mac')} | Score: {score}/100{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}✓ NORMAL: {packet_data.get('source_mac')} | Score: {score}/100{Style.RESET_ALL}")
                    
                return result
            else:
                print(f"{Fore.RED}✗ Detection API returned {response.status_code}{Style.RESET_ALL}")
                return {}
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}✗ Detection API error: {e}{Style.RESET_ALL}")
            return {}
