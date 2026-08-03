# -*- coding: utf-8 -*-
"""
信息收集模块 - 提供各类信息收集工具
"""

import socket
import ssl
import dns.resolver
import dns.zone
import dns.query
import dns.name
import requests
import json
import re
import time
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.colors import *
from core.utils import *


class InfoGathering:
    """信息收集类 - 提供多种信息收集工具"""

    def __init__(self, target):
        """
        初始化信息收集器
        :param target: 目标域名、IP或URL
        """
        self.target = target.strip()
        self.domain = None
        self.ip = None
        self._resolve_target()

    def _resolve_target(self):
        """解析目标，提取域名和IP"""
        # 检查是否为URL
        if self.target.startswith(('http://', 'https://')):
            self.domain = get_domain_from_url(self.target)
            self.target = self.domain
        # 检查是否为IP
        elif is_valid_ip(self.target):
            self.ip = self.target
            self.domain = self.target
        # 否则视为域名
        else:
            self.domain = self.target
            self.ip = get_ip_from_domain(self.domain)

    def _get_http_session(self, timeout=10):
        """创建HTTP会话"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        })
        session.timeout = timeout
        return session

    # ==================== 1. WHOIS查询 ====================

    def whois_lookup(self):
        """
        WHOIS查询 - 使用socket连接WHOIS服务器查询域名注册信息
        """
        results = {}
        print_section("WHOIS 查询")

        try:
            if is_valid_ip(self.domain):
                print_error("WHOIS查询不支持IP地址")
                return results

            print_info(f"查询WHOIS信息: {self.domain}")

            # WHOIS服务器列表
            whois_servers = {
                'com': 'whois.verisign-grs.com',
                'net': 'whois.verisign-grs.com',
                'org': 'whois.pir.org',
                'info': 'whois.afilias.net',
                'cn': 'whois.cnnic.cn',
                'edu': 'whois.educause.edu',
                'gov': 'whois.dotgov.gov',
                'mil': 'whois.nic.mil',
                'biz': 'whois.neulevel.biz',
                'name': 'whois.nic.name',
                'me': 'whois.nic.me',
                'io': 'whois.nic.io',
                'cc': 'whois.nic.cc',
                'tv': 'whois.nic.tv',
                'co': 'whois.nic.co',
                'uk': 'whois.nic.uk',
                'de': 'whois.denic.de',
                'jp': 'whois.jprs.jp',
                'ru': 'whois.tcinet.ru',
                'au': 'whois.auda.org.au',
                'xyz': 'whois.nic.xyz',
                'top': 'whois.nic.top',
                'club': 'whois.nic.club',
                'win': 'whois.nic.win',
                'online': 'whois.nic.online',
                'site': 'whois.nic.site',
                'shop': 'whois.nic.shop',
                'fun': 'whois.nic.fun',
                'store': 'whois.nic.store',
            }

            # 提取TLD
            tld = self.domain.rsplit('.', 1)[-1].lower()
            whois_server = whois_servers.get(tld, 'whois.verisign-grs.com')

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect((whois_server, 43))
                sock.send(f"{self.domain}\r\n".encode())

                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                sock.close()

                whois_text = response.decode('utf-8', errors='ignore')

                if whois_text:
                    # 提取关键信息
                    results['raw'] = whois_text
                    results['domain'] = self.domain

                    # 解析常见字段
                    patterns = {
                        'registrar': [r'Registrar:\s*(.+)', r'registrar:\s*(.+)'],
                        'creation_date': [r'Creation Date:\s*(.+)', r'created:\s*(.+)',
                                          r'Creation date:\s*(.+)'],
                        'expiration_date': [r'Registry Expiry Date:\s*(.+)', r'Expiration Date:\s*(.+)',
                                            r'expire:\s*(.+)', r'Expiry date:\s*(.+)'],
                        'updated_date': [r'Updated Date:\s*(.+)', r'updated:\s*(.+)',
                                         r'Last update:\s*(.+)'],
                        'name_servers': [r'Name Server:\s*(.+)', r'nserver:\s*(.+)',
                                         r'Name server:\s*(.+)'],
                        'status': [r'Domain Status:\s*(.+)', r'status:\s*(.+)'],
                        'registrant_org': [r'Registrant Organization:\s*(.+)',
                                           r'org:\s*(.+)', r'person:\s*(.+)'],
                        'registrant_country': [r'Registrant Country:\s*(.+)',
                                               r'country:\s*(.+)'],
                        'admin_email': [r'Admin Email:\s*(.+)', r'e-mail:\s*(.+)',
                                        r'[Ee]mail:\s*(.+)'],
                    }

                    for key, pat_list in patterns.items():
                        for pat in pat_list:
                            matches = re.findall(pat, whois_text)
                            if matches:
                                values = [m.strip() for m in matches if m.strip()]
                                if values:
                                    results[key] = values if len(values) > 1 else values[0]
                                    break

                    print_success(f"注册商: {results.get('registrar', 'N/A')}")
                    print_info(f"创建时间: {results.get('creation_date', 'N/A')}")
                    print_info(f"过期时间: {results.get('expiration_date', 'N/A')}")
                    if 'name_servers' in results:
                        ns_list = results['name_servers']
                        if isinstance(ns_list, str):
                            ns_list = [ns_list]
                        for ns in ns_list[:5]:
                            print_info(f"DNS服务器: {ns}")
                else:
                    print_warning("WHOIS服务器无返回数据")

            except socket.timeout:
                print_error("WHOIS查询超时")
            except socket.error as e:
                print_error(f"Socket连接失败: {e}")
            except Exception as e:
                print_error(f"WHOIS查询失败: {e}")

        except Exception as e:
            print_error(f"WHOIS查询异常: {e}")

        return results

    # ==================== 2. DNS枚举 ====================

    def dns_enum(self):
        """
        DNS枚举 - 查询A, AAAA, MX, NS, TXT, SOA, CNAME记录
        """
        results = {}
        print_section("DNS 枚举")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        # 如果目标是IP，直接提示
        if is_valid_ip(self.domain):
            print_warning("目标是IP地址，跳过DNS枚举")
            # 尝试反向DNS
            try:
                hostname, _, _ = socket.gethostbyaddr(self.domain)
                print_info(f"反向DNS: {hostname}")
                results['PTR'] = hostname
            except (socket.herror, socket.gaierror):
                print_info("无反向DNS记录")
            return results

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype in record_types:
                try:
                    print_info(f"查询 {rtype} 记录...")
                    answers = resolver.resolve(self.domain, rtype)

                    records = []
                    for rdata in answers:
                        record_str = rdata.to_text()
                        records.append(record_str)

                    if records:
                        results[rtype] = records
                        print_success(f"找到 {len(records)} 条 {rtype} 记录:")
                        for rec in records:
                            print_info(f"  {rec}")
                    else:
                        print_info(f"无 {rtype} 记录")

                except dns.resolver.NoAnswer:
                    print_info(f"无 {rtype} 记录")
                except dns.resolver.NXDOMAIN:
                    print_error(f"域名 {self.domain} 不存在")
                    break
                except dns.resolver.Timeout:
                    print_warning(f"{rtype} 查询超时")
                except dns.exception.DNSException as e:
                    print_warning(f"{rtype} 查询失败: {e}")

        except dns.resolver.NoNameservers:
            print_error("无法找到DNS服务器")
        except dns.exception.DNSException as e:
            print_error(f"DNS解析器初始化失败: {e}")
        except Exception as e:
            print_error(f"DNS枚举异常: {e}")

        return results

    # ==================== 3. 子域名枚举 ====================

    def subdomain_enum(self, wordlist=None):
        """
        子域名枚举 - 基于常见子域名列表暴力枚举
        :param wordlist: 子域名列表，为None时使用内置常见列表
        """
        results = []
        print_section("子域名枚举")

        if is_valid_ip(self.domain):
            print_error("IP地址无法进行子域名枚举")
            return results

        # 内置常见子域名列表
        common_subdomains = wordlist or [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'cdn', 'api', 'dev', 'test',
            'm', 'ftp', 'news', 'download', 'pop', 'mail2', 'dns', 'dns2',
            'email', 'forum', 'static', 'mx', 'img', 'video', 'wap', 'chat',
            'my', 'shop', 'support', 'mobile', 'help', 'host', 'hosting',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki', 'status',
            'portal', 'app', 'stage', 'staging', 'demo', 'beta', 'store',
            'cp', 'cpanel', 'whm', 'web', 'link', 'info', 'service', 'panel',
            'direct', 'direct-connect', 'ssl', 'autodiscover', 'owa', 'exchange',
            'owa', 'lyncdiscover', 'sip', 'meet', 'dialin', 'webconf',
            'remote', 'radius', 'vpn', 'vpn2', 'ns', 'ns0', 'ns1', 'ns2', 'ns3',
            'mail1', 'mail2', 'mail3', 'smtp', 'smtp2', 'pop3', 'imap',
            'search', 'api', 'api2', 'docs', 'intranet', 'cloud', 's3',
            'download', 'upload', 'files', 'static', 'media', 'assets',
            'analytics', 'tracking', 'track', 'monitor', 'monitoring',
            'dashboard', 'backup', 'db', 'database', 'sql', 'mysql',
            'redis', 'cache', 'memcache', 'broker', 'mq', 'amq',
            'gateway', 'proxy', 'balancer', 'lb', 'loadbalancer',
            'auth', 'login', 'sso', 'cas', 'oauth', 'oidc',
            'registry', 'nexus', 'artifactory', 'docker', 'k8s',
            'kube', 'kubernetes', 'istio', 'grafana', 'prometheus',
            'alertmanager', 'kibana', 'elastic', 'logstash',
            'splunk', 'zabbix', 'nagios', 'cacti', 'observium',
            'librenms', 'netbox', 'phpmyadmin', 'phpmyadmin',
            'adminer', 'pma', 'mysqladmin',
            'test', 'dev', 'develop', 'development', 'sandbox',
            'preprod', 'pre-production', 'qa', 'uat', 'staging',
            'beta', 'alpha', 'demo', 'trial', 'lab', 'labs',
            'office', 'portal', 'sharepoint', 'teams', 'skype',
            'lync', 'zoom', 'webex', 'gotomeeting', 'adobeconnect',
            'redmine', 'trac', 'bugzilla', 'mantis', 'gitlab',
            'bitbucket', 'gitea', 'gogs', 'code', 'source',
            'jenkins', 'build', 'ci', 'cd', 'pipeline', 'runner',
            'sonar', 'sonarqube', 'coverity', 'fortify', 'checkmarx',
            'harbor', 'quay', 'ecr', 'acr', 'gcr',
            'zoom', 'teams', 'webex', 'skype', 'meet',
            'cal', 'calendar', 'drive', 'docs', 'sheets', 'slides',
            'forms', 'sites', 'groups', 'classroom',
            'printer', 'print', 'scan', 'scanner', 'fax',
            'camera', 'cam', 'webcam', 'nvr', 'dvr', 'cctv',
            'iot', 'sensor', 'sensors', 'gateway', 'hub',
            'mqtt', 'coap', 'lwm2m', 'modbus', 'bacnet',
            'router', 'switch', 'firewall', 'fortigate', 'paloalto',
            'checkpoint', 'cisco', 'juniper', 'ruijie', 'huawei',
            'h3c', 'zte', 'netgear', 'tp-link', 'tplink',
            'dlink', 'linksys', 'asus', 'mikrotik', 'ubnt',
            'unifi', 'meraki', 'ruckus', 'aruba', 'aerohive',
            'sophos', 'barracuda', 'sonicwall', 'watchguard',
            'kaspersky', 'symantec', 'mcafee', 'trendmicro',
            'eset', 'bitdefender', 'avast', 'avg', 'norton',
            'palo', 'forti', 'fortinet', 'pfsense', 'opnsense',
            'vyos', 'openwrt', 'dd-wrt', 'tomato', 'gargoyle',
            'proxy', 'squid', 'haproxy', 'nginx', 'apache',
            'iis', 'tomcat', 'jboss', 'wildfly', 'glassfish',
            'payara', 'weblogic', 'websphere', 'jetty', 'undertow',
            'gunicorn', 'uwsgi', 'passenger', 'puma', 'unicorn',
            'thin', 'rainbows', 'node', 'io', 'socketio',
            'websocket', 'ws', 'wss', 'rtmp', 'rtsp', 'hls',
            'dash', 'stream', 'streaming', 'live', 'vod',
            'cdn', 'static', 'assets', 'img', 'images', 'css',
            'js', 'fonts', 'media', 'upload', 'uploads',
            'download', 'downloads', 'files', 'file', 'storage',
            's3', 'bucket', 'blob', 'container', 'object',
            'oss', 'cos', 'minio', 'ceph', 'swift', 'glance',
            'nova', 'neutron', 'cinder', 'keystone', 'horizon',
            'heat', 'ceilometer', 'aodh', 'gnocchi', 'panko',
            'rally', 'tempest', 'zaqar', 'manila', 'designate',
            'barbican', 'magnum', 'trove', 'sahara', 'ironic',
            'cyborg', 'octavia', 'vitrage', 'watcher', 'senlin',
            'congress', 'karbor', 'masakari', 'tacker', 'mistral',
            'zaqar', 'searchlight', 'freezer', 'cloudkitty',
            'adjutant', 'smaug', 'kuryr', 'mogan', 'qinling',
        ]

        print_info(f"开始子域名枚举，共 {len(common_subdomains)} 个常见子域名...")
        print_info(f"目标域名: {self.domain}")

        found_count = 0
        try:
            for sub in common_subdomains:
                full_domain = f"{sub}.{self.domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    results.append({'subdomain': full_domain, 'ip': ip})
                    found_count += 1
                    print_success(f"发现: {full_domain} -> {ip}")
                except socket.gaierror:
                    pass
                except socket.error:
                    pass

            if found_count > 0:
                print_success(f"子域名枚举完成，共发现 {found_count} 个子域名")
            else:
                print_warning("未发现子域名")

        except Exception as e:
            print_error(f"子域名枚举异常: {e}")

        return results

    # ==================== 4. 端口扫描 ====================

    def port_scan(self, ports=None, timeout=2, max_workers=50):
        """
        端口扫描 - TCP连接扫描
        :param ports: 端口列表，为None时使用common_ports()
        :param timeout: 超时时间
        :param max_workers: 最大线程数
        """
        results = []
        print_section("端口扫描")

        if ports is None:
            ports = common_ports()

        # 获取目标IP
        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析域名: {self.domain}")
                return results

        print_info(f"目标: {self.domain} ({target_ip})")
        print_info(f"扫描端口数: {len(ports)}")
        print_info(f"超时时间: {timeout}s")
        print_info("开始端口扫描...")

        try:
            scan_results = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(check_port, target_ip, port, timeout): port
                    for port in ports
                }
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        if future.result():
                            service = get_service_name(port)
                            scan_results.append((port, service))
                    except Exception:
                        pass

            # 排序
            scan_results.sort(key=lambda x: x[0])

            if scan_results:
                headers = ['端口', '状态', '服务']
                rows = []
                for port, service in scan_results:
                    rows.append([str(port), '开放', service])
                    results.append({'port': port, 'state': 'open', 'service': service})

                print_table(headers, rows, color=Colors.GREEN)
                print_success(f"发现 {len(scan_results)} 个开放端口")
            else:
                print_warning("未发现开放端口")

        except Exception as e:
            print_error(f"端口扫描异常: {e}")

        return results

    # ==================== 5. 操作系统检测 ====================

    def os_detection(self):
        """
        操作系统检测 - 基于TTL值猜测操作系统
        """
        results = {}
        print_section("操作系统检测")

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        print_info(f"目标: {target_ip}")

        try:
            ttl = get_ttl(target_ip)

            if ttl is not None:
                os_guess = get_os_from_ttl(ttl)
                results['ttl'] = ttl
                results['os_guess'] = os_guess
                print_success(f"TTL值: {ttl}")
                print_success(f"操作系统猜测: {os_guess}")

                # 提供更详细的TTL范围说明
                print_info("TTL参考:")
                print_info("  Linux/Unix: 64 (范围 32-99)")
                print_info("  Windows:    128 (范围 100-199)")
                print_info("  Cisco/网络设备: 255 (范围 200-255)")
            else:
                print_warning("无法获取TTL值，可能目标不可达或防火墙阻止了ICMP")

                # 尝试通过其他方式检测
                print_info("尝试通过TCP探测进行OS检测...")
                if target_ip:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        sock.connect((target_ip, 80))
                        sock.close()
                        print_info("目标80端口开放，可能是Web服务器")
                    except Exception:
                        pass

        except Exception as e:
            print_error(f"操作系统检测异常: {e}")

        return results

    # ==================== 6. 服务版本检测 ====================

    def service_detection(self, ports=None):
        """
        服务版本检测 - 检测开放端口的服务版本
        :param ports: 端口列表，为None时使用common_ports()
        """
        results = []
        print_section("服务版本检测")

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        if ports is None:
            ports = common_ports()

        print_info(f"目标: {target_ip}")
        print_info("正在检测服务版本...")

        try:
            detected = []
            with ThreadPoolExecutor(max_workers=30) as executor:
                future_to_port = {}
                for port in ports:
                    future = executor.submit(self._detect_service_version, target_ip, port)
                    future_to_port[future] = port

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            detected.append(result)
                    except Exception:
                        pass

            detected.sort(key=lambda x: x['port'])

            if detected:
                headers = ['端口', '服务', '版本/指纹']
                rows = []
                for d in detected:
                    rows.append([str(d['port']), d['service'], d['version']])
                    results.append(d)
                print_table(headers, rows, color=Colors.CYAN)
                print_success(f"检测到 {len(detected)} 个服务")
            else:
                print_warning("未能检测到服务版本信息")

        except Exception as e:
            print_error(f"服务版本检测异常: {e}")

        return results

    def _detect_service_version(self, host, port, timeout=5):
        """检测单个服务的版本"""
        try:
            service = get_service_name(port)
            banner = banner_grab(host, port, timeout)

            if banner:
                return {
                    'port': port,
                    'service': service,
                    'version': banner[:150]
                }
            return None
        except Exception:
            return None

    # ==================== 7. Banner抓取 ====================

    def banner_grabbing(self, ports=None):
        """
        服务Banner抓取 - 抓取开放服务的Banner信息
        :param ports: 端口列表，为None时使用common_ports()
        """
        results = []
        print_section("Banner 抓取")

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        if ports is None:
            ports = common_ports()

        print_info(f"目标: {target_ip}")
        print_info("正在抓取服务Banner...")

        try:
            banners = []
            for port in ports:
                try:
                    banner = banner_grab(target_ip, port, timeout=5)
                    if banner and banner.strip():
                        service = get_service_name(port)
                        banners.append({
                            'port': port,
                            'service': service,
                            'banner': banner.strip()
                        })
                        print_success(f"端口 {port} ({service}): {banner.strip()[:100]}")
                except Exception:
                    continue

            if banners:
                results = banners
                print_success(f"成功抓取 {len(banners)} 个Banner")
            else:
                print_warning("未获取到Banner信息")

        except Exception as e:
            print_error(f"Banner抓取异常: {e}")

        return results

    # ==================== 8. IP地理位置查询 ====================

    def ip_geolocation(self):
        """
        IP地理位置查询 - 使用ip-api.com查询IP地理位置信息
        """
        results = {}
        print_section("IP 地理位置查询")

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        print_info(f"查询IP: {target_ip}")

        try:
            # 使用ip-api.com免费API
            url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            resp = requests.get(url, timeout=10, headers={'User-Agent': get_random_ua()})
            data = resp.json()

            if data.get('status') == 'success':
                results = data
                print_success(f"IP: {data.get('query', target_ip)}")
                print_info(f"国家: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
                print_info(f"地区: {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
                print_info(f"城市: {data.get('city', 'N/A')}")
                print_info(f"邮编: {data.get('zip', 'N/A')}")
                print_info(f"纬度: {data.get('lat', 'N/A')}")
                print_info(f"经度: {data.get('lon', 'N/A')}")
                print_info(f"时区: {data.get('timezone', 'N/A')}")
                print_info(f"ISP: {data.get('isp', 'N/A')}")
                print_info(f"组织: {data.get('org', 'N/A')}")
                print_info(f"ASN: {data.get('as', 'N/A')}")

                # 生成Google Maps链接
                if data.get('lat') and data.get('lon'):
                    maps_url = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
                    print_info(f"地图链接: {maps_url}")
            else:
                error_msg = data.get('message', '未知错误')
                print_error(f"查询失败: {error_msg}")
                # 尝试备用API
                print_info("尝试备用API...")
                try:
                    resp2 = requests.get(f"https://ipapi.co/{target_ip}/json/", timeout=10,
                                         headers={'User-Agent': get_random_ua()})
                    data2 = resp2.json()
                    if data2.get('ip'):
                        results = data2
                        print_success(f"IP: {data2.get('ip', target_ip)}")
                        print_info(f"国家: {data2.get('country_name', 'N/A')}")
                        print_info(f"城市: {data2.get('city', 'N/A')}")
                        print_info(f"ISP: {data2.get('org', 'N/A')}")
                except Exception:
                    print_error("备用API也失败")

        except requests.exceptions.Timeout:
            print_error("地理位置查询超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到地理位置API")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except json.JSONDecodeError:
            print_error("API返回数据格式错误")
        except Exception as e:
            print_error(f"IP地理位置查询异常: {e}")

        return results

    # ==================== 9. 反向DNS查询 ====================

    def reverse_dns(self):
        """
        反向DNS查询 - 查询IP对应的域名
        """
        results = {}
        print_section("反向DNS查询")

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        print_info(f"查询IP: {target_ip}")

        try:
            # 使用socket进行反向DNS查询
            hostname, aliases, ip_list = socket.gethostbyaddr(target_ip)
            results['hostname'] = hostname
            results['aliases'] = aliases or []
            results['ip_list'] = ip_list or []

            print_success(f"主机名: {hostname}")
            if aliases:
                print_info("别名:")
                for alias in aliases:
                    print_info(f"  - {alias}")
            if ip_list:
                print_info(f"IP列表: {', '.join(ip_list)}")

            # 尝试通过DNS PTR记录查询
            try:
                import dns.reversename
                reverse_name = dns.reversename.from_address(target_ip)
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                try:
                    ptr_answers = resolver.resolve(reverse_name, 'PTR')
                    ptr_records = [str(rdata) for rdata in ptr_answers]
                    results['ptr_records'] = ptr_records
                    print_info("PTR记录:")
                    for ptr in ptr_records:
                        print_info(f"  - {ptr}")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    print_info("无额外PTR记录")
                except dns.resolver.Timeout:
                    print_warning("DNS PTR查询超时")
                except dns.exception.DNSException:
                    print_info("DNS PTR查询失败")
            except ImportError:
                print_info("dns.reversename不可用，跳过PTR查询")
            except Exception as e:
                print_warning(f"PTR查询异常: {e}")

        except socket.herror:
            print_warning("无反向DNS记录")
        except socket.gaierror:
            print_error("IP地址格式无效")
        except Exception as e:
            print_error(f"反向DNS查询异常: {e}")

        return results

    # ==================== 10. DNS区域传输检测 ====================

    def dns_zone_transfer(self):
        """
        DNS区域传输检测 - 尝试对DNS服务器进行AXFR请求
        """
        results = {}
        print_section("DNS区域传输检测")

        if is_valid_ip(self.domain):
            print_error("DNS区域传输需要域名")
            return results

        print_info(f"目标域名: {self.domain}")
        print_warning("注意: 区域传输需要DNS服务器配置允许，通常会被拒绝")

        try:
            # 获取NS服务器
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            ns_answers = resolver.resolve(self.domain, 'NS')
            ns_servers = [str(rdata) for rdata in ns_answers]

            if ns_servers:
                results['ns_servers'] = ns_servers
                print_info(f"发现 {len(ns_servers)} 个NS服务器:")
                for ns in ns_servers:
                    print_info(f"  - {ns}")

                # 尝试对每个NS服务器进行区域传输
                zone_transfer_results = []
                for ns in ns_servers:
                    try:
                        print_info(f"尝试对 {ns} 进行区域传输...")
                        ns_ip = socket.gethostbyname(ns)

                        # 执行AXFR请求
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10, lifetime=15))

                        if zone:
                            records = []
                            for name, node in zone.nodes.items():
                                rdatasets = node.rdatasets
                                for rdataset in rdatasets:
                                    for rdata in rdataset:
                                        record_str = f"{name}. {rdataset.ttl} {rdataset.rdclass} {rdataset.rdtype} {rdata}"
                                        records.append(record_str)

                            zone_transfer_results.append({
                                'ns': ns,
                                'ns_ip': ns_ip,
                                'records_count': len(records),
                                'records': records[:50]  # 限制50条避免输出过多
                            })

                            print_success(f"区域传输成功! 从 {ns} ({ns_ip}) 获取到 {len(records)} 条记录")
                            for rec in records[:30]:
                                print_info(f"  {rec}")
                            if len(records) > 30:
                                print_info(f"  ... 还有 {len(records) - 30} 条记录")
                        else:
                            print_info(f"{ns}: 区域传输未返回数据")

                    except dns.query.TransferError as e:
                        code = getattr(e, 'rcode', 'unknown')
                        print_warning(f"{ns}: 区域传输被拒绝 (RCODE: {code})")
                        zone_transfer_results.append({
                            'ns': ns,
                            'status': 'refused',
                            'error': str(e)
                        })
                    except dns.exception.Timeout:
                        print_warning(f"{ns}: 区域传输超时")
                    except socket.gaierror:
                        print_error(f"{ns}: 无法解析NS服务器IP")
                    except Exception as e:
                        print_warning(f"{ns}: 区域传输失败: {e}")
                        zone_transfer_results.append({
                            'ns': ns,
                            'status': 'failed',
                            'error': str(e)
                        })

                results['zone_transfer_results'] = zone_transfer_results

                # 检查是否至少有一个成功
                success_count = sum(1 for r in zone_transfer_results if r.get('records_count', 0) > 0)
                if success_count > 0:
                    print_warning(f"警告: {success_count} 个DNS服务器允许区域传输，存在信息泄露风险!")
                else:
                    print_success("所有DNS服务器均拒绝区域传输，安全")
            else:
                print_warning("未找到NS服务器")

        except dns.resolver.NoAnswer:
            print_error("无法获取NS记录")
        except dns.resolver.NXDOMAIN:
            print_error(f"域名 {self.domain} 不存在")
        except dns.resolver.Timeout:
            print_warning("DNS查询超时")
        except dns.exception.DNSException as e:
            print_error(f"DNS解析失败: {e}")
        except Exception as e:
            print_error(f"DNS区域传输检测异常: {e}")

        return results

    # ==================== 11. 邮箱提取 ====================

    def email_harvester(self, pages=5):
        """
        从网页中提取邮箱地址
        :param pages: 爬取页面深度
        """
        results = set()
        print_section("邮箱提取")

        # 构建URL
        if is_valid_ip(self.domain):
            url = f"http://{self.domain}"
        else:
            url = f"http://{self.domain}"

        print_info(f"目标URL: {url}")
        print_info(f"爬取深度: {pages} 页")

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        visited = set()
        to_visit = [url]

        try:
            session = self._get_http_session()

            for i in range(min(pages, len(to_visit))):
                if not to_visit:
                    break

                page_url = to_visit.pop(0)
                if page_url in visited:
                    continue

                visited.add(page_url)
                print_info(f"爬取 [{i + 1}/{pages}]: {page_url}")

                try:
                    resp = session.get(page_url, timeout=10, allow_redirects=True)
                    content = resp.text

                    # 提取邮箱
                    found_emails = re.findall(email_pattern, content)
                    for email in found_emails:
                        email = email.lower().strip()
                        # 过滤常见的非邮箱模式
                        if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg', '.ico')):
                            if not email.startswith(('example@', 'test@', 'user@')):
                                results.add(email)

                    # 提取新链接
                    link_patterns = [
                        r'href=["\'](https?://[^"\']+)["\']',
                        r'href=["\'](/[^"\']+)["\']',
                    ]
                    for pattern in link_patterns:
                        links = re.findall(pattern, content)
                        for link in links:
                            if link.startswith('/'):
                                parsed = urlparse(page_url)
                                link = f"{parsed.scheme}://{parsed.netloc}{link}"
                            if self.domain in link and link not in visited and link not in to_visit:
                                to_visit.append(link)

                except requests.exceptions.RequestException as e:
                    print_warning(f"无法访问 {page_url}: {e}")

                # 尝试HTTPS
                if i == 0 and not results:
                    https_url = page_url.replace('http://', 'https://', 1)
                    if https_url not in visited:
                        try:
                            print_info(f"尝试HTTPS: {https_url}")
                            resp = session.get(https_url, timeout=10, allow_redirects=True)
                            content = resp.text
                            found_emails = re.findall(email_pattern, content)
                            for email in found_emails:
                                email = email.lower().strip()
                                if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg', '.ico')):
                                    results.add(email)
                        except requests.exceptions.RequestException:
                            pass

            if results:
                email_list = sorted(results)
                print_success(f"提取到 {len(email_list)} 个邮箱地址:")
                for email in email_list:
                    print_info(f"  - {email}")
            else:
                print_warning("未找到邮箱地址")

        except Exception as e:
            print_error(f"邮箱提取异常: {e}")

        return list(results)

    # ==================== 12. Web技术检测 ====================

    def web_tech_detect(self):
        """
        Web技术检测 - 通过HTTP头、HTML内容、Cookie等检测Web技术栈
        """
        results = {}
        print_section("Web技术检测")

        # 构建URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target
        elif is_valid_ip(self.domain):
            base_url = f"http://{self.domain}"
        else:
            base_url = f"http://{self.domain}"

        print_info(f"目标URL: {base_url}")

        try:
            session = self._get_http_session()
            technologies = []

            # 尝试HTTP
            try:
                resp = session.get(base_url, timeout=10, allow_redirects=True)
                final_url = resp.url
                headers = resp.headers
                html_content = resp.text[:50000]  # 取前50KB
                cookies = resp.cookies
                status_code = resp.status_code

                print_success(f"HTTP状态码: {status_code}")

                # 检测Server头
                server = headers.get('Server', '')
                if server:
                    technologies.append(('Web服务器', server))
                    print_info(f"Server: {server}")

                # 检测X-Powered-By
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    technologies.append(('框架', powered_by))
                    print_info(f"X-Powered-By: {powered_by}")

                # 检测多种技术标识
                tech_indicators = {
                    'ASP.NET': [('X-AspNet-Version', None), ('X-AspNetMvc-Version', None),
                                ('__VIEWSTATE', 'html'), ('ASP.NET', 'header')],
                    'PHP': [('X-Powered-By', 'PHP'), ('PHP', 'cookie')],
                    'Java': [('JSESSIONID', 'cookie'), ('JServ', 'header'),
                             ('X-Atlassian-Token', None), ('Java', 'header')],
                    'Nginx': [('nginx', 'header')],
                    'Apache': [('Apache', 'header')],
                    'IIS': [('IIS', 'header'), ('Microsoft-IIS', 'header')],
                    'Cloudflare': [('CF-RAY', 'header'), ('cloudflare', 'header')],
                    'WordPress': [('wp-content', 'html'), ('wp-includes', 'html'),
                                  ('WordPress', 'cookie')],
                    'Drupal': [('Drupal', 'header'), ('drupal', 'html')],
                    'Joomla': [('joomla', 'html'), ('Joomla', 'cookie')],
                    'Django': [('csrftoken', 'cookie'), ('django', 'header')],
                    'Flask': [('flask', 'cookie')],
                    'Ruby on Rails': [('rails', 'header'), ('_session_id', 'cookie')],
                    'Laravel': [('laravel_session', 'cookie'), ('XSRF-TOKEN', 'cookie')],
                    'Express': [('powered-by', 'Express'), ('express', 'header')],
                    'Tomcat': [('Tomcat', 'header')],
                    'JBoss': [('JBoss', 'header')],
                    'WebLogic': [('WebLogic', 'header')],
                    'Varnish': [('X-Varnish', 'header'), ('Via', 'Varnish')],
                    'Squid': [('Squid', 'header'), ('X-Squid', 'header')],
                    'HAProxy': [('HAProxy', 'header')],
                    'GitHub Pages': [('GitHub.com', 'header')],
                    'Netlify': [('Netlify', 'header')],
                    'Vercel': [('x-vercel', 'header')],
                    'Akamai': [('Akamai', 'header')],
                    'Fastly': [('Fastly', 'header')],
                    'CloudFront': [('x-amz-cf-id', 'header'), ('CloudFront', 'header')],
                    'Google Cloud': [('gws', 'header'), ('Google', 'header')],
                    'Bootstrap': [('bootstrap', 'html'), ('Bootstrap', 'html')],
                    'jQuery': [('jquery', 'html'), ('jQuery', 'html')],
                    'React': [('react', 'html'), ('_react', 'html')],
                    'Vue.js': [('vue', 'html'), ('Vue', 'html')],
                    'Angular': [('angular', 'html'), ('ng-', 'html')],
                    'Font Awesome': [('font-awesome', 'html'), ('fontawesome', 'html')],
                    'Google Analytics': [('google-analytics', 'html'), ('ga.js', 'html')],
                    'Open Graph': [('og:', 'html')],
                    'Twitter Cards': [('twitter:', 'html')],
                }

                detected = set()
                for tech, indicators in tech_indicators.items():
                    for indicator, source in indicators:
                        if source == 'header' or source is None:
                            # 检查header中的值
                            for header_key, header_val in headers.items():
                                search_key = indicator.lower()
                                if search_key in header_key.lower():
                                    detected.add(tech)
                                    break
                                if indicator.lower() in header_val.lower():
                                    detected.add(tech)
                                    break
                        elif source == 'html':
                            if indicator.lower() in html_content.lower():
                                detected.add(tech)
                        elif source == 'cookie':
                            for cookie in cookies:
                                if indicator.lower() in cookie.name.lower():
                                    detected.add(tech)
                                    break

                for tech in detected:
                    if tech not in [t[0] for t in technologies]:
                        technologies.append(('技术', tech))
                        print_info(f"检测到: {tech}")

                # 检测更多header信息
                interesting_headers = [
                    'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'Access-Control-Allow-Origin', 'X-Robots-Tag',
                    'Link', 'Set-Cookie', 'WWW-Authenticate',
                    'X-Debug-Token', 'X-Debug-Token-Link',
                    'X-Generator', 'X-SourceFiles', 'X-Drupal-Cache',
                    'X-Drupal-Dynamic-Cache', 'X-Varnish', 'Age',
                    'X-Cache', 'X-Served-By', 'X-Cache-Hits',
                    'X-Backend', 'X-Cache-Lookup',
                ]
                for h in interesting_headers:
                    if h in headers:
                        print_info(f"{h}: {headers[h]}")

                results['url'] = final_url
                results['status_code'] = status_code
                results['technologies'] = technologies
                results['headers'] = dict(headers)

            except requests.exceptions.ConnectionError:
                print_warning("HTTP连接失败，尝试HTTPS...")
                # 尝试HTTPS
                https_url = base_url.replace('http://', 'https://', 1)
                resp = session.get(https_url, timeout=10, allow_redirects=True)
                results['url'] = resp.url
                results['status_code'] = resp.status_code
                results['headers'] = dict(resp.headers)
                print_success(f"HTTPS连接成功，状态码: {resp.status_code}")

            if technologies:
                print_success(f"检测到 {len(technologies)} 项技术")
            else:
                print_warning("未检测到明确的技术栈信息")

        except requests.exceptions.Timeout:
            print_error("Web请求超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到目标Web服务器")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except Exception as e:
            print_error(f"Web技术检测异常: {e}")

        return results

    # ==================== 13. HTTP头分析 ====================

    def http_headers(self):
        """
        HTTP头分析 - 分析HTTP响应头的安全配置
        """
        results = {}
        print_section("HTTP头分析")

        # 构建URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target
        else:
            base_url = f"http://{self.domain}"

        print_info(f"目标URL: {base_url}")

        security_headers = {
            'Strict-Transport-Security': {
                'desc': 'HTTP严格传输安全(HSTS)',
                'importance': '高',
                'good': 'max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'desc': '内容安全策略(CSP)',
                'importance': '高',
                'good': '已配置'
            },
            'X-Frame-Options': {
                'desc': '点击劫持保护',
                'importance': '中',
                'good': 'DENY 或 SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'desc': 'MIME类型嗅探保护',
                'importance': '中',
                'good': 'nosniff'
            },
            'X-XSS-Protection': {
                'desc': 'XSS过滤',
                'importance': '中',
                'good': '1; mode=block'
            },
            'Referrer-Policy': {
                'desc': '引用策略',
                'importance': '低',
                'good': 'no-referrer 或 strict-origin'
            },
            'Permissions-Policy': {
                'desc': '权限策略',
                'importance': '低',
                'good': '已配置'
            },
            'Access-Control-Allow-Origin': {
                'desc': 'CORS跨域配置',
                'importance': '中',
                'good': '指定域名而非*'
            },
            'Public-Key-Pins': {
                'desc': 'HTTP公钥固定(HPKP)',
                'importance': '低',
                'good': '已配置'
            },
            'Set-Cookie': {
                'desc': 'Cookie安全属性',
                'importance': '高',
                'good': '包含Secure和HttpOnly标记'
            },
        }

        try:
            session = self._get_http_session()

            # 先尝试HTTP
            http_results = {}
            try:
                resp = session.get(base_url, timeout=10, allow_redirects=True)
                http_results = dict(resp.headers)
                results['final_url'] = resp.url
                results['status_code'] = resp.status_code
                print_info(f"最终URL: {resp.url}")
                print_info(f"状态码: {resp.status_code}")
            except requests.exceptions.RequestException:
                pass

            # 再尝试HTTPS
            https_results = {}
            https_url = base_url.replace('http://', 'https://', 1)
            try:
                resp = session.get(https_url, timeout=10, allow_redirects=True)
                https_results = dict(resp.headers)
                if not results.get('final_url'):
                    results['final_url'] = resp.url
                    results['status_code'] = resp.status_code
            except requests.exceptions.RequestException:
                pass

            # 合并结果
            all_headers = http_results.copy()
            all_headers.update(https_results)
            results['headers'] = all_headers

            # 分析安全头
            print_info("\n安全头分析:")
            findings = []
            for header, info in security_headers.items():
                value = all_headers.get(header, None)
                if value:
                    findings.append({
                        'header': header,
                        'value': value,
                        'present': True,
                        'description': info['desc'],
                        'importance': info['importance']
                    })
                    print_success(f"[{info['importance']}] {header}: {value[:100]}")
                else:
                    findings.append({
                        'header': header,
                        'value': None,
                        'present': False,
                        'description': info['desc'],
                        'importance': info['importance']
                    })
                    print_warning(f"[{info['importance']}] {header}: 未设置")

            results['security_headers'] = findings

            # 统计评分
            present_count = sum(1 for f in findings if f['present'])
            total_count = len(findings)
            score = int((present_count / total_count) * 100)
            results['security_score'] = score

            print_info(f"\n安全头评分: {score}/100 ({present_count}/{total_count})")
            if score >= 70:
                print_success("安全头配置良好")
            elif score >= 40:
                print_warning("安全头配置一般，建议改进")
            else:
                print_error("安全头配置较差，存在安全风险")

            # 检查Cookie安全属性
            if 'Set-Cookie' in all_headers:
                cookie_val = all_headers['Set-Cookie']
                cookie_issues = []
                if 'Secure' not in cookie_val:
                    cookie_issues.append('缺少Secure标记')
                if 'HttpOnly' not in cookie_val:
                    cookie_issues.append('缺少HttpOnly标记')
                if 'SameSite' not in cookie_val:
                    cookie_issues.append('缺少SameSite属性')
                if cookie_issues:
                    print_warning(f"Cookie安全问题: {', '.join(cookie_issues)}")
                else:
                    print_success("Cookie安全属性配置良好")

        except requests.exceptions.Timeout:
            print_error("HTTP请求超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到目标服务器")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except Exception as e:
            print_error(f"HTTP头分析异常: {e}")

        return results

    # ==================== 14. SSL证书信息 ====================

    def ssl_cert_info(self):
        """
        SSL证书信息 - 获取SSL/TLS证书的详细信息
        """
        results = {}
        print_section("SSL证书信息")

        if is_valid_ip(self.domain):
            target_host = self.domain
        else:
            target_host = self.domain

        # 常见SSL端口
        ssl_ports = [443, 8443, 465, 993, 995, 636, 989, 990, 2083, 2087, 2096]

        print_info(f"目标: {target_host}")
        print_info("正在获取SSL证书信息...")

        # 尝试标准端口
        checked_ports = []
        for port in ssl_ports:
            if port in checked_ports:
                continue
            checked_ports.append(port)

            try:
                print_info(f"尝试端口 {port}...")
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target_host, port))

                # 获取对等方证书
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        print_warning(f"端口 {port}: 未获取到证书")
                        continue

                    # 解析证书
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import hashes

                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())

                    cert_info = {}
                    cert_info['port'] = port
                    cert_info['subject'] = cert_obj.subject.rfc4514_string()
                    cert_info['issuer'] = cert_obj.issuer.rfc4514_string()
                    cert_info['serial_number'] = str(cert_obj.serial_number)

                    # 有效期
                    cert_info['not_valid_before'] = cert_obj.not_valid_before_utc.isoformat()
                    cert_info['not_valid_after'] = cert_obj.not_valid_after_utc.isoformat()

                    # 签名算法
                    cert_info['signature_algorithm'] = cert_obj.signature_algorithm_oid._name

                    # SAN
                    try:
                        from cryptography.x509.oid import ExtensionOID
                        san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        cert_info['san'] = [str(name) for name in san_ext.value]
                    except x509.ExtensionNotFound:
                        cert_info['san'] = []

                    # 公钥信息
                    pub_key = cert_obj.public_key()
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        cert_info['public_key_type'] = 'RSA'
                        cert_info['public_key_size'] = pub_key.key_size
                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        cert_info['public_key_type'] = 'EC'
                        cert_info['public_key_size'] = pub_key.key_size
                    elif isinstance(pub_key, dsa.DSAPublicKey):
                        cert_info['public_key_type'] = 'DSA'
                        cert_info['public_key_size'] = pub_key.key_size
                    else:
                        cert_info['public_key_type'] = type(pub_key).__name__

                    # 证书版本
                    cert_info['version'] = cert_obj.version.name

                    # 指纹
                    cert_info['fingerprint_sha256'] = cert_obj.fingerprint(hashes.SHA256()).hex()
                    cert_info['fingerprint_sha1'] = cert_obj.fingerprint(hashes.SHA1()).hex()

                    results[port] = cert_info
                    results['port'] = port

                    print_success(f"端口 {port}: 成功获取证书")
                    print_info(f"  主体: {cert_info['subject']}")
                    print_info(f"  颁发者: {cert_info['issuer']}")
                    print_info(f"  序列号: {cert_info['serial_number']}")
                    print_info(f"  生效时间: {cert_info['not_valid_before']}")
                    print_info(f"  过期时间: {cert_info['not_valid_after']}")
                    print_info(f"  签名算法: {cert_info['signature_algorithm']}")
                    print_info(f"  公钥: {cert_info.get('public_key_type', 'Unknown')} {cert_info.get('public_key_size', 'N/A')}位")
                    print_info(f"  证书版本: {cert_info['version']}")
                    print_info(f"  SHA256指纹: {cert_info['fingerprint_sha256'][:40]}...")

                    if cert_info['san']:
                        print_info(f"  SAN: {', '.join(cert_info['san'][:5])}")
                        if len(cert_info['san']) > 5:
                            print_info(f"    ... 还有 {len(cert_info['san']) - 5} 个")

                    # 检查证书是否过期
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    if cert_obj.not_valid_after_utc < now:
                        print_error("  证书已过期!")
                    elif (cert_obj.not_valid_after_utc - now).days < 30:
                        print_warning(f"  证书将在 {(cert_obj.not_valid_after_utc - now).days} 天后过期")
                    else:
                        print_success(f"  证书有效，剩余 {(cert_obj.not_valid_after_utc - now).days} 天")

                    # 如果找到了标准端口的证书，不再继续
                    if port in [443, 8443]:
                        break

            except ssl.SSLError as e:
                print_warning(f"端口 {port}: SSL错误: {e}")
            except socket.timeout:
                print_warning(f"端口 {port}: 连接超时")
            except socket.error as e:
                if port not in [443, 8443]:
                    pass  # 非标准端口静默跳过
                else:
                    print_warning(f"端口 {port}: 连接失败: {e}")
            except ImportError:
                print_error("需要安装cryptography库: pip install cryptography")
                break
            except Exception as e:
                if port in [443]:
                    print_error(f"端口 {port}: 获取证书失败: {e}")

        if not results:
            print_warning("未获取到SSL证书信息")
            print_info("提示: 可能需要安装cryptography库: pip install cryptography")

        return results

    # ==================== 15. robots.txt分析 ====================

    def robots_analyzer(self):
        """
        robots.txt分析 - 获取并分析robots.txt中的敏感路径
        """
        results = {}
        print_section("robots.txt分析")

        # 构建URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target.rstrip('/')
        else:
            base_url = f"http://{self.domain}"

        robots_url = f"{base_url}/robots.txt"
        print_info(f"目标URL: {robots_url}")

        try:
            session = self._get_http_session()
            resp = session.get(robots_url, timeout=10, allow_redirects=True)

            if resp.status_code == 200:
                content = resp.text
                results['content'] = content
                results['status_code'] = 200

                print_success("成功获取robots.txt")
                print_info(f"内容大小: {len(content)} 字节")

                # 解析
                disallowed_paths = []
                allowed_paths = []
                sitemaps = []
                user_agents = []
                crawl_delays = []
                comments = []

                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('#'):
                        comments.append(line)
                        continue

                    if line.lower().startswith('user-agent'):
                        ua = line.split(':', 1)[1].strip() if ':' in line else ''
                        user_agents.append(ua)
                    elif line.lower().startswith('disallow'):
                        path = line.split(':', 1)[1].strip() if ':' in line else ''
                        if path:
                            disallowed_paths.append(path)
                    elif line.lower().startswith('allow'):
                        path = line.split(':', 1)[1].strip() if ':' in line else ''
                        if path:
                            allowed_paths.append(path)
                    elif line.lower().startswith('sitemap'):
                        sm = line.split(':', 1)[1].strip() if ':' in line else ''
                        if sm:
                            sitemaps.append(sm)
                    elif line.lower().startswith('crawl-delay'):
                        delay = line.split(':', 1)[1].strip() if ':' in line else ''
                        if delay:
                            crawl_delays.append(delay)

                results['user_agents'] = user_agents
                results['disallowed'] = disallowed_paths
                results['allowed'] = allowed_paths
                results['sitemaps'] = sitemaps
                results['crawl_delays'] = crawl_delays

                if user_agents:
                    print_info(f"User-Agent条目: {len(user_agents)}")
                if disallowed_paths:
                    print_warning(f"禁止访问路径: {len(disallowed_paths)} 条")
                    for path in disallowed_paths:
                        print_info(f"  Disallow: {path}")

                    # 分析敏感路径
                    sensitive_patterns = {
                        '管理员后台': ['admin', 'manager', 'manage', 'dashboard', 'admincp',
                                      'administrator', 'admin.php', 'wp-admin'],
                        '配置文件': ['config', 'config.php', 'configuration', 'settings',
                                    'env', '.env', 'db_config'],
                        '数据库相关': ['database', 'db', 'sql', 'mysql', 'mongo', 'redis',
                                    'phpmyadmin', 'adminer', 'pma'],
                        '备份文件': ['backup', 'bak', 'dump', 'export', 'sql.gz', 'tar.gz',
                                    'backups', '.bak'],
                        '版本控制': ['.git', '.svn', '.hg', '.bzr', 'CVS'],
                        '日志文件': ['log', 'logs', 'error.log', 'access.log', 'debug.log'],
                        'API接口': ['api', 'api/', 'graphql', 'rest', 'soap', 'xmlrpc'],
                        '敏感文件': ['.htaccess', '.htpasswd', 'wp-config.php',
                                   'configuration.php', 'config.php.bak'],
                        '安装文件': ['install', 'setup', 'wizard', 'install.php', 'setup.php'],
                        '临时文件': ['tmp', 'temp', 'cache', 'sessions', 'uploads'],
                    }

                    print_warning("\n敏感路径分析:")
                    for category, patterns in sensitive_patterns.items():
                        found = []
                        for path in disallowed_paths:
                            for pattern in patterns:
                                if pattern in path.lower():
                                    found.append(path)
                                    break
                        if found:
                            print_warning(f"  [{category}]")
                            for f in found:
                                print_info(f"    潜在敏感路径: {f}")

                if sitemaps:
                    print_info("Sitemap:")
                    for sm in sitemaps:
                        print_info(f"  - {sm}")

                if crawl_delays:
                    print_info(f"Crawl-Delay: {', '.join(crawl_delays)}s")

                # 检查是否存在安全限制
                interesting_comments = [c for c in comments if any(
                    word in c.lower() for word in ['todo', 'fixme', 'hack', 'password',
                                                   'secret', 'private', 'hidden', 'note',
                                                   'TODO', 'FIXME', 'bug', 'warning'])]
                if interesting_comments:
                    print_warning("发现潜在敏感注释:")
                    for c in interesting_comments[:5]:
                        print_info(f"  {c}")

            elif resp.status_code == 404:
                results['status_code'] = 404
                print_info("robots.txt不存在 (404)")
            elif resp.status_code == 403:
                results['status_code'] = 403
                print_warning("robots.txt访问被禁止 (403)")
            elif resp.status_code == 301 or resp.status_code == 302:
                results['status_code'] = resp.status_code
                results['redirect_url'] = resp.headers.get('Location', '')
                print_info(f"robots.txt被重定向到: {results['redirect_url']}")

        except requests.exceptions.Timeout:
            print_error("请求超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到目标服务器")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except Exception as e:
            print_error(f"robots.txt分析异常: {e}")

        return results

    # ==================== 16. Wayback Machine URL查询 ====================

    def wayback_urls(self, limit=100):
        """
        Wayback Machine URL查询 - 查询Wayback Machine中的历史URL
        :param limit: 返回URL数量限制
        """
        results = []
        print_section("Wayback Machine URL查询")

        if is_valid_ip(self.domain):
            print_error("Wayback Machine查询需要域名")
            return results

        print_info(f"目标域名: {self.domain}")
        print_info(f"限制数量: {limit}")

        try:
            # 使用Wayback Machine CDX API
            url = "http://web.archive.org/cdx/search/cdx"
            params = {
                'url': f"{self.domain}/*",
                'output': 'json',
                'fl': 'original,timestamp,statuscode',
                'limit': limit,
                'collapse': 'urlkey',
            }

            resp = requests.get(url, params=params, timeout=30,
                                headers={'User-Agent': get_random_ua()})
            data = resp.json()

            if data and len(data) > 1:
                # 第一行是标题，跳过
                for row in data[1:]:
                    if len(row) >= 3:
                        url_str, timestamp, status = row[0], row[1], row[2]
                        results.append({
                            'url': url_str,
                            'timestamp': timestamp,
                            'status_code': status
                        })

                if results:
                    print_success(f"找到 {len(results)} 条历史记录")

                    # 按状态码分类
                    valid_urls = []
                    for r in results:
                        if r['status_code'] in ['200', '301', '302']:
                            valid_urls.append(r)

                    if valid_urls:
                        print_info(f"有效URL ({len(valid_urls)} 条):")
                        for r in valid_urls[:20]:
                            print_info(f"  [{r['status_code']}] {r['url']} ({r['timestamp']})")
                        if len(valid_urls) > 20:
                            print_info(f"  ... 还有 {len(valid_urls) - 20} 条")

                    # 分析敏感路径
                    sensitive_extensions = ['.sql', '.bak', '.old', '.swp', '.env',
                                            '.git', '.svn', '.tar.gz', '.zip', '.rar',
                                            '.php', '.asp', '.aspx', '.jsp']

                    sensitive_urls = [r for r in results if any(
                        r['url'].lower().endswith(ext) for ext in sensitive_extensions
                    )]
                    if sensitive_urls:
                        print_warning(f"发现潜在敏感文件 ({len(sensitive_urls)} 条):")
                        for r in sensitive_urls[:10]:
                            print_info(f"  {r['url']}")
                else:
                    print_warning("未找到历史记录")

            else:
                print_warning("未找到Wayback Machine记录")

        except requests.exceptions.Timeout:
            print_error("Wayback Machine查询超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到Wayback Machine API")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except json.JSONDecodeError:
            print_error("API返回数据格式错误")
        except Exception as e:
            print_error(f"Wayback Machine查询异常: {e}")

        return results

    # ==================== 17. CVE搜索 ====================

    def cve_search(self, keyword=None, limit=20):
        """
        CVE搜索 - 使用cve.circl.lu API搜索CVE漏洞
        :param keyword: 搜索关键词，为None时使用目标域名/IP
        :param limit: 返回结果数量限制
        """
        results = []
        print_section("CVE搜索")

        search_term = keyword or self.domain
        print_info(f"搜索关键词: {search_term}")
        print_info(f"结果限制: {limit}")

        try:
            # 使用CIRCL CVE API
            api_url = f"https://cve.circl.lu/api/cve/{search_term}"
            print_info(f"API: {api_url}")

            resp = requests.get(api_url, timeout=30,
                                headers={'User-Agent': get_random_ua()})

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    cve_list = data[:limit]
                elif isinstance(data, dict):
                    cve_list = [data] if data else []
                else:
                    cve_list = []

                if cve_list:
                    print_success(f"找到 {len(cve_list)} 个相关CVE")

                    for cve in cve_list:
                        cve_id = cve.get('id', 'Unknown')
                        summary = cve.get('summary', 'No description')
                        cvss = cve.get('cvss', 'N/A')
                        published = cve.get('Published', 'N/A')
                        access = cve.get('access', {})
                        vector = access.get('vector', 'N/A') if access else 'N/A'

                        cve_info = {
                            'id': cve_id,
                            'summary': summary[:200],
                            'cvss': cvss,
                            'published': published,
                            'vector': vector
                        }
                        results.append(cve_info)

                        severity = ""
                        if cvss != 'N/A' and cvss is not None:
                            try:
                                cvss_float = float(cvss)
                                if cvss_float >= 9.0:
                                    severity = Colors.RED + "[严重]" + Colors.RESET
                                elif cvss_float >= 7.0:
                                    severity = Colors.LIGHT_RED + "[高危]" + Colors.RESET
                                elif cvss_float >= 4.0:
                                    severity = Colors.YELLOW + "[中危]" + Colors.RESET
                                else:
                                    severity = Colors.GREEN + "[低危]" + Colors.RESET
                            except (ValueError, TypeError):
                                pass

                        print_info(f"")
                        print_info(f"{severity} {cve_id}")
                        print_info(f"  CVSS评分: {cvss}")
                        print_info(f"  发布时间: {published}")
                        print_info(f"  摘要: {summary[:200]}...")

                    # 统计风险等级
                    if results:
                        critical = sum(1 for r in results if r['cvss'] != 'N/A' and r['cvss'] is not None and float(r['cvss']) >= 9.0)
                        high = sum(1 for r in results if r['cvss'] != 'N/A' and r['cvss'] is not None and 7.0 <= float(r['cvss']) < 9.0)
                        medium = sum(1 for r in results if r['cvss'] != 'N/A' and r['cvss'] is not None and 4.0 <= float(r['cvss']) < 7.0)
                        low = sum(1 for r in results if r['cvss'] != 'N/A' and r['cvss'] is not None and float(r['cvss']) < 4.0)

                        print_info(f"\n风险统计:")
                        print_info(f"  严重: {critical}")
                        print_info(f"  高危: {high}")
                        print_info(f"  中危: {medium}")
                        print_info(f"  低危: {low}")

                else:
                    print_warning("未找到相关CVE记录")

            elif resp.status_code == 404:
                print_warning("未找到相关CVE记录")
            else:
                print_error(f"API请求失败: HTTP {resp.status_code}")

        except requests.exceptions.Timeout:
            print_error("CVE API查询超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到CVE API")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except json.JSONDecodeError:
            print_error("API返回数据格式错误")
        except Exception as e:
            print_error(f"CVE搜索异常: {e}")

        return results

    # ==================== 18. Shodan查询 ====================

    def shodan_lookup(self, api_key=None):
        """
        Shodan查询 - 查询Shodan中的目标信息
        :param api_key: Shodan API密钥，为None时尝试从环境变量获取
        """
        results = {}
        print_section("Shodan查询")

        if api_key is None:
            import os
            api_key = os.environ.get('SHODAN_API_KEY', '')

        if not api_key:
            print_warning("未提供Shodan API密钥")
            print_info("可以通过参数传递或在环境变量中设置 SHODAN_API_KEY")
            print_info("Shodan API密钥可在此获取: https://account.shodan.io")
            return results

        target_ip = self.ip
        if not target_ip:
            target_ip = get_ip_from_domain(self.domain)
            if not target_ip:
                print_error(f"无法解析目标: {self.domain}")
                return results

        print_info(f"目标IP: {target_ip}")
        print_info("正在查询Shodan...")

        try:
            # 使用Shodan API查询目标IP
            api_url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"

            resp = requests.get(api_url, timeout=30,
                                headers={'User-Agent': get_random_ua()})

            if resp.status_code == 200:
                data = resp.json()
                results = data

                print_success("Shodan查询成功!")

                # 基本信息
                print_info(f"IP: {data.get('ip_str', target_ip)}")
                print_info(f"国家: {data.get('country_name', 'N/A')}")
                print_info(f"城市: {data.get('city', 'N/A')}")
                print_info(f"组织: {data.get('org', 'N/A')}")
                print_info(f"ISP: {data.get('isp', 'N/A')}")
                print_info(f"ASN: {data.get('asn', 'N/A')}")
                print_info(f"操作系统: {data.get('os', 'N/A')}")

                # 开放端口
                ports = data.get('ports', [])
                if ports:
                    print_success(f"开放端口 ({len(ports)}): {', '.join(map(str, sorted(ports)))}")

                # 服务详情
                services = data.get('data', [])
                if services:
                    print_info(f"\n服务详情 ({len(services)} 条):")
                    for i, service in enumerate(services[:10]):
                        port = service.get('port', 'N/A')
                        transport = service.get('transport', '')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        banner_data = service.get('data', '')[:100]

                        print_info(f"\n  服务 [{i + 1}]:")
                        print_info(f"    端口: {port}/{transport}")
                        if product:
                            print_info(f"    产品: {product} {version}")
                        if banner_data:
                            print_info(f"    Banner: {banner_data.strip()}")

                        # 漏洞信息
                        vulns = service.get('vulns', [])
                        if vulns:
                            print_warning(f"    漏洞: {', '.join(list(vulns)[:5])}")

                    if len(services) > 10:
                        print_info(f"  ... 还有 {len(services) - 10} 条服务记录")

                # 主机名
                hostnames = data.get('hostnames', [])
                if hostnames:
                    print_info(f"主机名: {', '.join(hostnames[:5])}")

                # 漏洞信息
                all_vulns = data.get('vulns', {})
                if all_vulns:
                    print_warning(f"\n漏洞信息 ({len(all_vulns)} 个):")
                    for cve_id, vuln_info in list(all_vulns.items())[:10]:
                        cvss = vuln_info.get('cvss', 'N/A') if isinstance(vuln_info, dict) else 'N/A'
                        summary = vuln_info.get('summary', '')[:100] if isinstance(vuln_info, dict) else ''
                        print_warning(f"  {cve_id} (CVSS: {cvss})")
                        if summary:
                            print_info(f"    {summary}")

            elif resp.status_code == 401:
                print_error("Shodan API密钥无效")
            elif resp.status_code == 403:
                print_error("Shodan API配额不足或无权限")
            elif resp.status_code == 404:
                print_warning(f"Shodan中未找到 {target_ip} 的信息")
            else:
                print_error(f"Shodan API请求失败: HTTP {resp.status_code}")

        except requests.exceptions.Timeout:
            print_error("Shodan API查询超时")
        except requests.exceptions.ConnectionError:
            print_error("无法连接到Shodan API")
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP请求失败: {e}")
        except json.JSONDecodeError:
            print_error("Shodan API返回数据格式错误")
        except Exception as e:
            print_error(f"Shodan查询异常: {e}")

        return results