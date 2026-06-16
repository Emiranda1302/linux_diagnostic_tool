# Linux Diagnostic Toolkit (LDT)

[![Tests](https://github.com/Emiranda1302/linux_diagnostic_tool/actions/workflows/tests.yml/badge.svg)](https://github.com/Emiranda1302/linux_diagnostic_tool/actions/workflows/tests.yml)
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

### Install from source

```bash
# Clone the repository
git clone https://github.com/Emiranda1302/linux_diagnostic_tool.git
cd linux_diagnostic_tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Add your API key:
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

# Check suspicious IP
ldt threat_intel --ip 185.220.101.1
```

### Full Scan Commands

```bash
# Run complete system scan
ldt scan --all

# Save current state as baseline
ldt scan --save-baseline

# Compare against saved baseline
ldt scan --compare-baseline

# Hash critical system binaries
ldt scan --hash-binaries

# Verify binary integrity
ldt scan --verify-hashes

# Generate executive summary
ldt scan --executive-summary

# Save report to file
ldt scan --all --output report.json
```

---

## 📊 Example Output

### CPU Monitoring
```
PID     NAME                     USER           CPU%      MEM%      STATUS
--------------------------------------------------------------------------------
1234    chrome                   user           75.2      12.3      running  [!]
5678    python3                  user           45.1      8.7       running
```

### SUID Binary Detection
```
[!] Detected 1 suspicious SUID binary
--------------------------------------------------------------------------------
FILE:     /tmp/backdoor
OWNER:    root (Perms: 4755)
SEVERITY: HIGH[!!!][!!!][!!!]
MITRE:    T1548.001 - Setuid and Setgid
```

### Threat Intelligence
```
IP                   SCORE    REPORTS    COUNTRY    TOR    ISP
--------------------------------------------------------------------------------
185.220.101.1        100      45         DE         True   Artikel10 e.V. [!]

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
⚠️  SECURITY ALERT  ⚠️
- Anonymous TOR connection detected
- Reported IP: score 100%
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 🛠️ Development

### Project Structure
```
linux_diagnostic_tool/
├── src/ldt/
│   ├── main.py              # CLI entry point (auto-discovers modules)
│   ├── modules/
│   │   ├── system.py        # System diagnostics
│   │   ├── forensics.py     # Security auditing + MITRE ATT&CK
│   │   ├── threat_intel.py  # IP reputation via AbuseIPDB
│   │   ├── scanner.py       # Full scan with multithreading
│   │   └── network/
│   │       ├── interfaces.py
│   │       └── connections.py
│   └── utils/
│       └── whitelist.py     # False positive filtering
├── tests/
│   └── test_system.py
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

- [x] System diagnostics (CPU, memory, processes, ports)
- [x] Network interface monitoring
- [x] Active connection analysis
- [x] Forensics (SUID, cron, bashrc) with MITRE ATT&CK mapping
- [x] Threat intelligence integration (AbuseIPDB)
- [x] Full scan with multithreading
- [x] Baseline comparison
- [x] Binary integrity verification
- [x] CI/CD with GitHub Actions
- [ ] Automated report generation (HTML/PDF)
- [ ] WiFi security auditing (planned)
- [ ] SIEM integration
- [ ] Scheduled scans

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

**⭐ Star this repo if you find it useful!**
