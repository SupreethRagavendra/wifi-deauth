# 📡 WiFi Deauth Pro

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)]()

> **⚠️ Educational Purposes Only** - This tool is intended for authorized security testing and educational purposes only.

A powerful WiFi deauthentication tool for network security testing and wireless network analysis.

---

## 🚀 Features

- **Network Scanning** - Discover nearby WiFi networks and connected clients
- **Targeted Deauth** - Send deauthentication packets to specific devices
- **Multiple Modes** - Support for various attack modes and configurations
- **Real-time Monitoring** - Live updates on network activity
- **User-Friendly Interface** - Clean and intuitive UI for easy operation

---

## 📋 Prerequisites

Before using this tool, ensure you have:

- Linux operating system (Kali Linux recommended)
- Python 3.8 or higher
- Wireless adapter with monitor mode support
- Root/sudo privileges

---

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/SupreethRagavendra/wifi-deauth.git

# Navigate to the directory
cd wifi-deauth

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

```bash
# Enable monitor mode on your wireless interface
sudo airmon-ng start wlan0

# Run the tool
sudo python3 main.py
```

---

## ⚠️ Legal Disclaimer

**This tool is provided for educational and authorized security testing purposes only.**

- ❌ Do NOT use this tool on networks you don't own or have explicit permission to test
- ❌ Unauthorized interception of network traffic is illegal
- ✅ Always obtain proper authorization before testing
- ✅ Use responsibly and ethically

The developer assumes no liability for misuse of this software. Users are responsible for complying with all applicable laws.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Supreeth Ragavendra**

- GitHub: [@SupreethRagavendra](https://github.com/SupreethRagavendra)

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>
