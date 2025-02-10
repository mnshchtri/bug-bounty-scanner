# Bug Bounty Scanner v2.0

An automated reconnaissance suite designed for bug bounty hunters and security researchers. This tool combines multiple security tools to automate the initial reconnaissance phase of security assessments.

## Features

- **Subdomain Enumeration**: Discover subdomains using subfinder
- **Live Host Detection**: Verify live hosts with httpx
- **Service Fingerprinting**: Identify web technologies and services
- **Additional Recon Options**:
  - Port Scanning (using naabu)
  - Directory Bruteforce (using ffuf)
  - Vulnerability Scanning (using nuclei)
  - Screenshot Capture (using gowitness)
- **Result Management**:
  - Automatic saving of results
  - Scan history tracking
  - Detailed output files

## Prerequisites

### Required Python Packages
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [naabu](https://github.com/projectdiscovery/naabu)
- [ffuf](https://github.com/ffuf/ffuf)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [gowitness](https://github.com/sensepost/gowitness)

You can install these tools using:

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mnshchtri/bug-bounty-scanner.git
cd bug-bounty-scanner
```

2. Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

## Usage

1. Run the scanner:
```bash
python3 ScanCore.py
```

2. Select from the main menu options:
   - Scan: Perform full reconnaissance
   - Recon: Individual reconnaissance tools
   - History: View past scan results
   - Config: Configure scanner settings
   - Quit: Exit the program

3. For scanning, enter the target domain when prompted and select scan type:
   - Fast: Quick scan with default settings
   - Deep: Thorough scan with extended timeout
   - Passive: Non-intrusive reconnaissance

## Output Files

The scanner generates several output files:
- `{target}_all_subdomains.txt`: List of all discovered subdomains
- `{target}_live_hosts.txt`: Detailed information about live hosts
- `scan_results_{target}_{timestamp}.json`: Complete scan results in JSON format
- `scan_history.json`: History of all scans performed

## Configuration

Default configuration is provided in `config.yaml`. You can modify scan settings such as:
- Timeout values
- Thread counts
- Tool-specific settings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational purposes only. Ensure you have explicit permission to test any target systems.

## Author

- **Neox**

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Requirements
- Python 3.8+
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [Gowitness](https://github.com/sensepost/gowitness)