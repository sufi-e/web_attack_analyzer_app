# 🛡️ Web Server Attack Log Analyzer

A powerful Python-based security tool that detects and analyzes OWASP Top 10 web attacks in Nginx server logs. Featuring both a modern web interface and command-line version for flexibility.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Web Security](https://img.shields.io/badge/Web-Security-red)

## ✨ Features

- **🔍 OWASP Top 10 Detection**: SQL Injection, XSS, LFI/RFI, and 7 other attack types
- **🌐 Dual Interface**: Beautiful web GUI + powerful CLI
- **📊 Visual Analytics**: Interactive charts and detailed reports
- **⬆️ Drag & Drop Support**: Modern file upload interface
- **💾 Large File Support**: Handles logs up to 612MB
- **📁 CSV Export**: Comprehensive attack reports
- **⚡ Real-time Processing**: Instant analysis results
- **🔒 Secure Design**: Automatic file cleanup

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- sudo/root access (for log file access)
- Nginx web server logs

### Installation

```bash
# Clone the repository
sudo git clone https://github.com/sufi-e/web_attack_analyzer_app.git

# Navigate to project directory
cd web_attack_analyzer_app

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install flask

# Start the web server
python3 app.py

# Access at: http://your-server-ip:5000
```

### CLI Usage

```bash
# Basic analysis
python3 attack_analyzer_cli.py /var/log/nginx/access.log

# With custom output file
python3 attack_analyzer_cli.py /var/log/nginx/access.log -o my_report.csv

# Show help
python3 attack_analyzer_cli.py --help
```

### Project Structure

```bash
web_attack_analyzer_app/
├── app.py                 # Flask web application
├── attack_analyzer_cli.py # Command-line interface
├── analyzer.py           # Core analysis engine
├── templates/
│   └── index.html        # Web interface template
├── uploads/              # Temporary upload directory
├── reports/              # Generated CSV reports
└── venv/                 # Python virtual environment
```

### Web Interface Feature

- Drag & Drop file upload
- Interactive Pie Charts with Chart.js
- Real-time Analysis progress
- Downloadable CSV Reports
- Responsive Design for all devices
- Attack Statistics and visualizations
- Top Attacker IPs listing

### CLI Feature
```bash
# Example output
[*] Analyzing log file: /var/log/nginx/access.log
[*] Processed 100000 lines...
[*] Analysis complete!
    Total lines processed: 150342
    Successfully parsed: 148921
    Attacks detected: 47

--- ATTACKS BY TYPE ---
  SQL Injection: 23
  XSS: 12
  LFI: 8
  RFI: 4

--- TOP 5 ATTACKING IPs ---
  192.168.1.23: 15 attacks
  103.45.67.89: 9 attacks
  45.76.123.98: 7 attacks
```
### Configuration
Web App Settings
- Max File Size: 612MB
- Port: 5000
- Host: 0.0.0.0 (network accessible)
- Allowed Extensions: .log, .txt

### Building from Source

```bash
git clone https://github.com/sufi-e/web_attack_analyzer_app.git
cd web_attack_analyzer_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### Performance
- File Size: Up to 612MB
- Processing Speed: ~50,000-1,00,000 lines/Second
- Memory Usage: Optimized Streaming Processing
- Progress Updates: Real-time for Large File
