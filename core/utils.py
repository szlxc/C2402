# -*- coding: utf-8 -*-
"""
核心工具函数
"""

import os
import sys
import socket
import re
import json
import time
import threading
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime
from core.colors import *


def is_valid_ip(ip):
    """检查是否为有效IP地址"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    """检查是否为有效域名"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None


def is_valid_url(url):
    """检查是否为有效URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_port(port):
    """检查是否为有效端口"""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def normalize_url(url):
    """标准化URL"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')


def get_domain_from_url(url):
    """从URL提取域名"""
    parsed = urlparse(url)
    return parsed.netloc or parsed.hostname


def get_ip_from_domain(domain):
    """从域名获取IP"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def expand_ip_range(ip_range):
    """展开IP范围，返回IP列表"""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        try:
            # 尝试 CIDR 格式
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
        return []


def port_range_to_list(port_range):
    """将端口范围转为列表，如 '1-1000' 或 '80,443,8080'"""
    ports = []
    if ',' in port_range:
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    elif '-' in port_range:
        start, end = port_range.split('-')
        ports.extend(range(int(start), int(end) + 1))
    else:
        ports.append(int(port_range))
    return ports


def common_ports():
    """返回常见端口列表"""
    return [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 993, 995, 1433, 1521, 2049, 2082, 2083, 2181, 2375,
        3306, 3389, 3690, 4444, 4848, 5000, 5432, 5555, 5632, 5900,
        5901, 5984, 5985, 5986, 6379, 7001, 7002, 8000, 8001, 8080,
        8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090, 8443, 8888,
        9000, 9001, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000,
        10001, 11211, 27017, 27018, 50000, 50030, 50070,
    ]


def common_web_ports():
    """返回常见Web端口"""
    return [80, 443, 8080, 8081, 8082, 8443, 8888, 9000, 9090, 9443]


def check_port(host, port, timeout=2):
    """检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_service_name(port):
    """根据端口号获取常见服务名称"""
    services = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        111: 'RPC', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS',
        139: 'SMB', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-trap',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        500: 'IKE', 514: 'Syslog', 636: 'LDAPS', 873: 'Rsync',
        993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
        1352: 'Lotus', 1433: 'MSSQL', 1521: 'Oracle', 1526: 'Oracle',
        1723: 'PPTP', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL',
        2181: 'ZooKeeper', 2375: 'Docker', 3128: 'Squid', 3306: 'MySQL',
        3389: 'RDP', 3690: 'SVN', 4333: 'mSQL', 4444: 'Metasploit',
        4848: 'GlassFish', 5000: 'HTTP-alt', 5432: 'PostgreSQL',
        5555: 'Android ADB', 5632: 'pcAnywhere', 5900: 'VNC',
        5901: 'VNC-1', 5984: 'CouchDB', 5985: 'WinRM HTTP',
        5986: 'WinRM HTTPS', 6379: 'Redis', 7001: 'WebLogic',
        7002: 'WebLogic-SSL', 8000: 'HTTP-alt', 8080: 'HTTP-proxy',
        8081: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-alt',
        9000: 'HTTP-alt', 9090: 'HTTP-alt', 9200: 'Elasticsearch',
        9300: 'Elasticsearch', 9418: 'Git', 9999: 'HTTP-alt',
        10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB',
        27018: 'MongoDB', 50000: 'SAP', 50070: 'Hadoop',
    }
    return services.get(int(port), 'Unknown')


def banner_grab(host, port, timeout=5):
    """抓取服务Banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        # 发送探测
        if int(port) in [80, 8080, 8000, 443, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif int(port) == 21:
            pass  # FTP会自动发送banner
        elif int(port) == 25:
            sock.send(b"EHLO test\r\n")
        elif int(port) == 110:
            sock.send(b"USER test\r\n")
        elif int(port) == 143:
            sock.send(b"a1 LOGIN test test\r\n")
        elif int(port) == 22:
            pass  # SSH会自动发送banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else None
        except:
            sock.close()
            return None
    except Exception:
        return None


def get_os_from_ttl(ttl):
    """根据TTL值猜测操作系统"""
    if ttl is None:
        return "Unknown"
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux/Unix (TTL <= 64)"
    elif ttl <= 128:
        return "Windows (TTL <= 128)"
    elif ttl <= 255:
        return "Cisco/Network (TTL <= 255)"
    return "Unknown"


def get_ttl(host, timeout=3):
    """获取目标TTL值"""
    try:
        # 使用ping获取TTL
        if os.name == 'nt':
            cmd = f"ping -n 1 -w {timeout*1000} {host}"
        else:
            cmd = f"ping -c 1 -W {timeout} {host}"

        if os.name == 'nt':
            result = os.popen(cmd).read()
        else:
            result = os.popen(cmd).read()

        if os.name == 'nt':
            match = re.search(r'TTL=(\d+)', result, re.IGNORECASE)
        else:
            match = re.search(r'ttl=(\d+)', result, re.IGNORECASE)

        if match:
            return int(match.group(1))
        return None
    except Exception:
        return None


def save_results(filename, data, format_type='txt'):
    """保存结果到文件"""
    try:
        # 确保output目录存在
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)

        if format_type == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                if isinstance(data, list):
                    for item in data:
                        f.write(str(item) + '\n')
                else:
                    f.write(str(data))

        print_success(f"结果已保存到: {filepath}")
        return filepath
    except Exception as e:
        print_error(f"保存文件失败: {e}")
        return None


def get_timestamp():
    """获取时间戳字符串"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def user_agents():
    """返回常用User-Agent列表"""
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ]


def get_random_ua():
    """获取随机User-Agent"""
    import random
    return random.choice(user_agents())


class ProgressBar:
    """进度条类"""

    def __init__(self, total, prefix='', length=50, fill='█'):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.fill = fill
        self.current = 0

    def update(self, step=1):
        """更新进度"""
        self.current += step
        percent = self.current / self.total
        filled = int(self.length * percent)
        bar = self.fill * filled + '░' * (self.length - filled)
        print(f'\r{self.prefix} |{bar}| {self.current}/{self.total} ({percent*100:.1f}%)', end='')
        if self.current >= self.total:
            print()


def scan_port_thread(host, port, results, timeout=2):
    """线程端口扫描函数"""
    if check_port(host, port, timeout):
        service = get_service_name(port)
        results.append((port, service))