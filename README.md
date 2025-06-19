# kbfi

[![PyPI version](https://img.shields.io/pypi/v/kbfi.svg)](https://pypi.org/project/kbfi/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/pypi/pyversions/kbfi.svg)](https://pypi.org/project/kbfi/)

A comprehensive WiFi and MAC address scanning toolkit with vendor lookup capabilities. This tool allows you to scan for WiFi networks and connected clients, with automatic vendor identification for MAC addresses.

## Quick Start

```bash
pip install kbfi
kbfi-scan
```

## Features

- Scan for WiFi networks and their details (SSID, BSSID, signal strength, encryption, etc.)
- Scan for connected clients and their MAC addresses
- Automatic vendor lookup for MAC addresses
- Support for Windows and Linux systems
- Multiple output formats (JSON, CSV, text)
- Command-line interface with various options
- Automatic wireless interface detection
- Vendor database auto-update capability

## Installation

```bash
pip install kbfi
```

## Usage

### Basic Usage

```bash
# Scan both WiFi networks and connected clients
kbfi-scan

# Scan only WiFi networks
kbfi-scan --scan-type wifi

# Scan only connected clients
kbfi-scan --scan-type clients
```

### Advanced Options

```bash
# Specify wireless interface
kbfi-scan --interface wlan0

# Output to file in JSON format
kbfi-scan --output scan_results --format json

# Update vendor database before scanning
kbfi-scan --update-vendor-db

# Set minimum signal strength
kbfi-scan --min-signal -70
```

### Command-line Options

- `--interface`, `-i`: Specify wireless interface (default: auto-detect)
- `--scan-type`, `-t`: Type of scan to perform (wifi/clients/both)
- `--output`, `-o`: Output file (default: stdout)
- `--format`, `-f`: Output format (json/csv/text)
- `--update-vendor-db`, `-u`: Update vendor database before scanning
- `--min-signal`, `-s`: Minimum signal strength to include (default: -100)

## Requirements

- Python 3.8 or higher
- Windows or Linux operating system
- Administrative/root privileges for scanning
- `requests` package for vendor database updates

## Development

```bash
# Clone the repository
git clone https://github.com/itskbagain/kbfi.git
cd kbfi

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8
mypy .
```

## Troubleshooting

- **Permission denied / No networks found:** Ensure you are running the tool with administrative/root privileges.
- **No wireless interface detected:** Use `--interface` to specify your WiFi adapter manually.
- **Vendor lookup fails:** Use `--update-vendor-db` to refresh the vendor database. Ensure you have an internet connection.
- **Windows users:** Run your terminal as Administrator for best results.
- **Linux users:** Use `sudo` for scanning commands.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This tool requires administrative/root privileges to perform network scanning. Use responsibly and only on networks you own or have permission to scan.

## Author

Kaustubh Bhattacharyya  
Email: kb01tech@gmail.com
