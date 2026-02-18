from colorama import Fore, Style
import datetime

def log_info(message: str):
    """Log info message with timestamp"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.GREEN}[{timestamp}] {message}{Style.RESET_ALL}")

def log_error(message: str):
    """Log error message with timestamp"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.RED}[{timestamp}] ERROR: {message}{Style.RESET_ALL}")

def log_warning(message: str):
    """Log warning message with timestamp"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.YELLOW}[{timestamp}] WARN: {message}{Style.RESET_ALL}")
