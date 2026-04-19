# Linux Diagnostic Toolkit (LDT)

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

**A comprehensive command-line toolkit for Linux system diagnostics, security auditing, and network analysis.**

---

## 🚀 Features

### System Diagnostics
- **CPU Monitoring**: Real-time CPU usage by process with percentage tracking
- **Memory Analysis**: RAM and swap usage with automatic alerts
- **Port Scanning**: Detect all listening ports and associated processes
- **Security Logs**: Monitor failed SSH login attempts

### Network Analysis
- **Interface Discovery**: List all network interfaces with IP addresses
- **Active Connections**: Monitor all active TCP/UDP connections
- **Public IP Detection**: Identify connections to public IP addresses
- **WiFi Security Auditing**: Scan and audit wireless networks *(coming soon)*

### Forensics & Security
- **SUID Binary Detection**: Find suspicious setuid binaries
- **Persistence Mechanisms**: Detect backdoors in cron jobs and shell configs
- **MITRE ATT&CK Mapping**: All findings mapped to MITRE framework
- **Severity Scoring**: Automatic risk assessment (LOW/MEDIUM/HIGH)

### Threat Intelligence
- **IP Reputation**: Query AbuseIPDB for IP threat scores
- **TOR Detection**: Identify TOR exit nodes
- **ISP Lookup**: Determine ISP and geolocation info

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- Linux operating system
- Root/sudo access (for some features)

### Option 1: Install from source (recommended for development)

```bash
# Clone the repository
git clone https://github.com/Emiranda1302/linux_diagnostic_tool.git
cd linux_diagnostic_tool

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Option 2: Install as package

```bash
pip install git+https://github.com/Emiranda1302/linux_diagnostic_tool.git
```

### Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Add your API keys:
```bash
nano .env
```

```
ABUSEIPDB_API_KEY=your_actual_api_key_here
```

Get a free API key at: https://www.abuseipdb.com/api

---

## 🎯 Usage

### System Commands

```bash
# Monitor CPU usage (top 10 processes)
ldt system --cpu

# Check memory usage
ldt system --memory

# List all listening ports
ldt system --ports

# View failed SSH login attempts
ldt system --logins
```

### Network Commands

```bash
# List all network interfaces
ldt network interfaces --list

# Show active connections
ldt network connections --active

# Scan WiFi networks (requires wireless adapter)
ldt network wifi --scan

# Audit your own WiFi network
sudo ldt network wifi --audit "YourNetworkName" -i wlan0
```

### Forensics Commands

```bash
# Find suspicious SUID binaries
sudo ldt forensics --suid

# Check for cron persistence mechanisms
sudo ldt forensics --cron

# Audit .bashrc files for malicious code
sudo ldt forensics --bashrc
```

### Threat Intelligence Commands

```bash
# Check IP reputation
ldt threat_intel --ip 8.8.8.8

# Check suspicious IP from logs
ldt threat_intel --ip 192.0.2.1
```

---

## 📊 Example Output

### CPU Monitoring
```
PID     NAME                     USUARIO        CPU %     MEM%      STATUS
--------------------------------------------------------------------------------
1234    chrome                   user           75.2      12.3      running  [!]
5678    python3                  user           45.1      8.7       running
9012    firefox                  user           32.4      15.2      sleeping
```

### SUID Binary Detection
```
[!] 12 SUSPICIOUS SUID BINARIES FOUND
--------------------------------------------------------------------------------
FILE:    /tmp/suspicious_binary
OWNER:   root (Perms: 4755)
SEVERITY:   HIGH[!!!][!!!][!!!][!!!][!!!][!!!][!!!][!!!][!!!]
MITRE:   T1548.001 - Setuid and Setgid
------------------------------------------------------------
```

### Threat Intelligence
```
IP                   SCORE    REPORTS    COUNTRY    TOR    ISP
--------------------------------------------------------------------------------
185.220.101.1        95       847        NL         True   AS-CHOOPA [!]

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
⚠️  SECURITY ALERT  ⚠️
- Anonymous TOR connection detected
- Reported IP: score 95%
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 🛠️ Development

### Project Structure
```
linux_diagnostic_tool/
├── src/ldt/
│   ├── main.py              # CLI entry point
│   └── modules/
│       ├── system.py        # System diagnostics
│       ├── forensics.py     # Security auditing
│       ├── threat_intel.py  # IP intelligence
│       └── network/
│           ├── interfaces.py
│           ├── connections.py
│           └── wifi/        # WiFi auditing
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Adding New Modules

1. Create a new file in `src/ldt/modules/`
2. Implement these two functions:
   - `register_parser(subparsers)` - Register CLI arguments
   - `run(args)` - Execute module logic
3. The module will be automatically discovered

Example:
```python
def register_parser(subparsers):
    parser = subparsers.add_parser("mymodule", help="My new module")
    parser.add_argument("--option", help="An option")
    parser.set_defaults(func=run)

def run(args):
    if args.option:
        print("Running my module!")
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=ldt tests/
```

---

## 📋 Roadmap

- [x] System diagnostics (CPU, memory, processes)
- [x] Network interface monitoring
- [x] Forensics (SUID, cron, bashrc)
- [x] Threat intelligence integration
- [ ] WiFi security auditing
- [ ] Automated report generation (JSON/HTML)
- [ ] Integration with SIEM systems
- [ ] Docker support
- [ ] Web dashboard
- [ ] Scheduled scans with cron

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure:
- Code follows PEP 8 style guide
- All tests pass
- New features include tests
- Documentation is updated

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.**

- Only test systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this software
- Always comply with local laws and regulations

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process utilities
- [AbuseIPDB](https://www.abuseipdb.com/) - IP threat intelligence
- [MITRE ATT&CK](https://attack.mitre.org/) - Security framework

---

## 📧 Contact

**Author:** EMA  
**GitHub:** [@Emiranda1302](https://github.com/Emiranda1302)  
**Project Link:** [https://github.com/Emiranda1302/linux_diagnostic_tool](https://github.com/Emiranda1302/linux_diagnostic_tool)

---

## 🐛 Bug Reports

Found a bug? Please open an issue with:
- Your OS version
- Python version
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

---

**⭐ Star this repo if you find it useful!**
