# analyzer.py
import re
from datetime import datetime
from collections import Counter
import csv

# OWASP Top 10 attack patterns (refined patterns)
attack_patterns = {
    'SQL Injection': [
        r"union\s+select",
        r"1\s*=\s*1",
        r"';?\s*(?:--|#)",
        r"exec\(|eval\(|sleep\(\s*\d+\s*\)",
        r"benchmark\(\s*\d+\s*,\s*[a-z]+\)",
        r"order by \d+--",
        r"insert into.*values",
        r"drop table",
    ],
    'Cross-Site Scripting (XSS)': [
        r"<script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"alert\(|prompt\(|confirm\(",
        r"<iframe>",
        r"<img src=.*onerror=.*>",
    ],
    'Local File Inclusion (LFI) / Path Traversal': [
        r"\.\./\.\./",
        r"\.\.%2f",
        r"\/etc\/passwd",
        r"\/etc\/hosts",
        r"\/proc\/self\/environ",
        r"\.\.\\\.\.\\",  # Windows style
    ],
    'Remote File Inclusion (RFI)': [
        r"(?:http|ftp):\/\/.*\.(?:php|txt|exe)",
        r"\?.*=(?:http|ftp):\/\/",
        r"include=.*(?:http|ftp):",
    ],
    'Sensitive Data Exposure Probe': [
        r"\.env",
        r"config\.php",
        r"\.git\/",
        r"\.DS_Store",
        r"\.htaccess",
        r"\/phpinfo\.php",
    ],
    'Common Web Shell Access': [
        r"cmd\.php",
        r"wso\.php",
        r"c99\.php",
        r"r57\.php",
        r"b374k\.php",
    ],
    'Broken Access Control (Forced Browsing)': [
        r"\/\.git\/",
        r"\/wp-admin\/",
        r"\/admin\/config\.php",
        r"\/\.env",
    ]
}

def parse_nginx_log(log_entry):
    # Regex for Nginx Combined Log Format:
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, log_entry)
    
    if match:
        try:
            ip_address = match.group(1)
            timestamp_str = match.group(2)
            http_method = match.group(3)
            requested_url = match.group(4)
            status_code = match.group(5)
            referer = match.group(7)
            user_agent = match.group(8)
            
            return {
                'ip': ip_address,
                'timestamp_str': timestamp_str,
                'method': http_method,
                'url': requested_url,
                'status': status_code,
                'referer': referer,
                'user_agent': user_agent,
                'raw_log': log_entry.strip()
            }
        except (IndexError, ValueError) as e:
            print(f"[WARNING] Error parsing log entry: {e}")
            print(f"Problematic entry: {log_entry[:100]}...")
            return None
    else:
        return None

def detect_attack(log_data):
    """
    Analyzes parsed log data for attack patterns.
    Returns the attack type if detected, otherwise None.
    """
    # Combine key fields for pattern matching
    analysis_string = f"{log_data['method']} {log_data['url']} {log_data['user_agent']} {log_data['referer']}"
    
    for attack_name, patterns in attack_patterns.items():
        for pattern in patterns:
            if re.search(pattern, analysis_string, re.IGNORECASE):
                return attack_name
    return None

def analyze_log_file(log_file_path):
    """Main function to analyze the log file. Returns a rich results dictionary."""
    
    attacks_detected = []
    line_count = 0
    parsed_count = 0
    attack_count = 0
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line_count += 1
                log_data = parse_nginx_log(line)
                if not log_data:
                    continue
                parsed_count += 1
                
                # Convert timestamp
                try:
                    timestamp = datetime.strptime(log_data['timestamp_str'], '%d/%b/%Y:%H:%M:%S %z')
                    log_data['timestamp'] = timestamp
                except ValueError:
                    try:
                        timestamp = datetime.strptime(log_data['timestamp_str'].split()[0], '%d/%b/%Y:%H:%M:%S')
                        log_data['timestamp'] = timestamp
                    except ValueError:
                        continue
                
                # Detect attacks
                attack_type = detect_attack(log_data)
                if attack_type:
                    attack_count += 1
                    log_data['attack_type'] = attack_type
                    attacks_detected.append(log_data)
        
    except Exception as e:
        return {"error": f"Error reading file: {str(e)}"}
    
    # Prepare summary statistics
    attack_counts = Counter(attack['attack_type'] for attack in attacks_detected)
    ip_attacks = Counter(attack['ip'] for attack in attacks_detected)
    
    # Format data for Chart.js (for the pie chart)
    chart_labels = list(attack_counts.keys())
    chart_data = list(attack_counts.values())
    
    # Create a unique report filename
    report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    report_path = f"reports/{report_filename}"
    
    # Generate the CSV report
    if attacks_detected:
        try:
            with open(report_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'ip', 'method', 'url', 'status', 'attack_type', 'user_agent']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for attack in attacks_detected:
                    writer.writerow({
                        'timestamp': attack['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        'ip': attack['ip'],
                        'method': attack['method'],
                        'url': attack['url'],
                        'status': attack['status'],
                        'attack_type': attack['attack_type'],
                        'user_agent': attack['user_agent'][:100]
                    })
        except Exception as e:
            report_filename = None

    # Return all results for the web template
    return {
        "success": True,
        "line_count": line_count,
        "parsed_count": parsed_count,
        "attack_count": attack_count,
        "attack_breakdown": dict(attack_counts),
        "top_attackers": dict(ip_attacks.most_common(10)),
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "report_filename": report_filename,
        "detailed_attacks": attacks_detected[:50]
    }
