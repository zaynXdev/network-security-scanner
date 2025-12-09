# Network Security Scanner & Firewall Visualizer

A comprehensive desktop/web-based tool for network security scanning and firewall rule simulation.

![Network Security Scanner](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Network Scanning**: TCP SYN, UDP, and Full Connect scans
- **Port Discovery**: Identify open ports and running services
- **Firewall Simulation**: Create and test firewall rules
- **Visualization**: Network topology and traffic flow diagrams
- **User-Friendly Interface**: Web-based GUI built with Bootstrap

## Screenshot

![Application Screenshot](screenshot.png)

## Installation

### Prerequisites
- Python 3.10 or higher
- Nmap (optional, for advanced scanning)
- Git

### Steps

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/network-security-scanner.git
cd network-security-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```bash
http://localhost:5000
```

## Usage
Network Scanning
Enter target IP or hostname
Select scan type (TCP SYN, UDP, or Full Connect)
Specify port range (e.g., 1-1000 or 80,443,22)
Click "Start Scan"

## Firewall Rules
Create allow/deny rules with specific parameters
Test packets against your rule set
Visualize traffic flow through the firewall

## Project Structure
```bash
network-security-scanner/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── .gitignore           # Git ignore rules
├── scanner/             # Core modules
│   ├── network_scanner.py
│   ├── firewall_simulator.py
│   └── visualization.py
├── static/              # Static assets
│   ├── css/style.css
│   └── js/script.js
└── templates/           # HTML templates
    ├── base.html
    └── index.html
```

## Technologies Used
Backend: Python, Flask
Frontend: HTML5, CSS3, JavaScript, Bootstrap 5
Libraries: python-nmap, scapy, matplotlib, networkx
Tools: Nmap (for advanced scanning)


## Contributing
Fork the repository
Create a feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

## Acknowledgments
Inspired by nmap and other network security tools
Icons by Font Awesome
UI components by Bootstrap
