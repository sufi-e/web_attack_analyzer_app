import re
from datetime import datetime
from collections import defaultdict, Counter
import csv
import argparse

# 1. Refined and Expanded OWASP Top 10 attack patterns
# Structured as a list of patterns per attack type to reduce false positives
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
    'Sensitive Data Exposure Probe': [  # Renamed from 'Sensitive Data Exposure'
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

# 2. Robust Nginx log parser (Handles Combined Log Format)
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
            requested_url = match.group(4)  # The URL target is crucial
            status_code = match.group(5)
            # body_bytes_sent = match.group(6)  # Available if needed
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
            # Handle parsing errors gracefully
            print(f"[WARNING] Error parsing log entry: {e}")
            print(f"Problematic entry: {log_entry[:100]}...")
            return None
    else:
        # Log entry doesn't match the expected format
        return None

# 3. Enhanced attack detection function
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

# 4. Function to generate and display reports
def generate_reports(attacks_detected, output_file=None):
    """Generates text and CSV reports from detected attacks."""
    
    # Count attacks by type
    attack_counts = Counter(attack['attack_type'] for attack in attacks_detected)
    
    # Count attacks by IP
    ip_attacks = Counter(attack['ip'] for attack in attacks_detected)
    
    # Print summary to console
    print("\n" + "="*60)
    print("WEB SERVER ATTACK ANALYSIS REPORT")
    print("="*60)
    print(f"Time of Analysis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Attacks Detected: {len(attacks_detected)}")
    
    print("\n--- ATTACKS BY TYPE ---")
    for attack_type, count in attack_counts.most_common():
        print(f"  {attack_type}: {count}")
    
    print("\n--- TOP 10 ATTACKING IPs ---")
    for ip, count in ip_attacks.most_common(10):
        print(f"  {ip}: {count} attacks")
    
    # Generate CSV report if requested
    if output_file:
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
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
                        'user_agent': attack['user_agent'][:100]  # Truncate long UAs
                    })
            print(f"\nDetailed report saved to: {output_file}")
        except Exception as e:
            print(f"[ERROR] Could not write CSV report: {e}")

# 5. Main analysis function
def analyze_log_file(log_file_path, output_csv=None):
    """Main function to analyze the log file."""
    
    attacks_detected = []
    line_count = 0
    parsed_count = 0
    attack_count = 0
    
    print(f"[*] Analyzing log file: {log_file_path}")
    print("[*] This may take a while for large files...")
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line_count += 1
                
                # Parse the log entry
                log_data = parse_nginx_log(line)
                if not log_data:
                    continue  # Skip unparseable lines
                parsed_count += 1
                
                # Convert timestamp string to datetime object
                try:
                    timestamp = datetime.strptime(log_data['timestamp_str'], '%d/%b/%Y:%H:%M:%S %z')
                    log_data['timestamp'] = timestamp
                except ValueError:
                    # If timezone parsing fails, try without timezone
                    try:
                        timestamp = datetime.strptime(log_data['timestamp_str'].split()[0], '%d/%b/%Y:%H:%M:%S')
                        log_data['timestamp'] = timestamp
                    except ValueError:
                        continue  # Skip if timestamp can't be parsed
                
                # Detect attacks
                attack_type = detect_attack(log_data)
                if attack_type:
                    attack_count += 1
                    log_data['attack_type'] = attack_type
                    attacks_detected.append(log_data)
                    
                    # Print immediate alert for serious attacks
                    if attack_type in ['SQL Injection', 'Remote File Inclusion', 'Common Web Shell Access']:
                        print(f"[!] CRITICAL: {attack_type} from {log_data['ip']} at {timestamp} - {log_data['method']} {log_data['url']}")
                
                # Progress update for large files
                if line_count % 10000 == 0:
                    print(f"[*] Processed {line_count} lines...")
        
    except FileNotFoundError:
        print(f"[ERROR] File not found: {log_file_path}")
        return
    except Exception as e:
        print(f"[ERROR] Unexpected error reading file: {e}")
        return
    
    # Generate reports
    print(f"\n[*] Analysis complete!")
    print(f"    Total lines processed: {line_count}")
    print(f"    Successfully parsed: {parsed_count}")
    print(f"    Attacks detected: {attack_count}")
    
    if attacks_detected:
        generate_reports(attacks_detected, output_csv)
    else:
        print("\nNo attacks detected in the log file.")

# 6. Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description='Web Server Attack Log Analyzer - Detects OWASP Top 10 attacks in Nginx logs')
    parser.add_argument('logfile', help='Path to the Nginx access log file to analyze')
    parser.add_argument('-o', '--output', help='Output CSV file for detailed results', default='attack_report.csv')
    parser.add_argument('-q', '--quiet', help='Quiet mode (suppress immediate alerts)', action='store_true')
    
    args = parser.parse_args()
    
    # Run the analysis
    analyze_log_file(args.logfile, args.output)

if __name__ == "__main__":
    main()
