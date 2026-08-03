# -*- coding: utf-8 -*-
"""
通用工具模块 - 提供各种实用工具功能
"""

import random
import string
import ipaddress
import json
import time
import uuid
import re
import struct
from datetime import datetime, timezone
from core.colors import *
from core.utils import *


class Utilities:
    """通用工具类 - 提供各种实用工具方法"""

    # OUI数据库（常见厂商前缀）
    OUI_DATABASE = {
        '00:50:56': 'VMware',
        '00:0C:29': 'VMware',
        '00:05:69': 'VMware',
        '00:1C:42': 'Parallels',
        '00:15:5D': 'Hyper-V',
        '08:00:27': 'VirtualBox',
        '00:1A:11': 'Google',
        '00:1A:A0': 'Apple',
        '00:23:32': 'Apple',
        '00:26:08': 'Apple',
        '00:25:00': 'Apple',
        '00:50:43': 'Microsoft',
        '00:03:FF': 'Microsoft',
        '00:0D:3A': 'Microsoft',
        '00:1B:24': 'Dell',
        '00:14:22': 'Dell',
        '00:21:70': 'Dell',
        '00:1E:4F': 'HP',
        '00:1A:4B': 'HP',
        '00:21:5A': 'HP',
        '00:24:81': 'Lenovo',
        '00:1F:5B': 'Lenovo',
        '00:26:2D': 'Cisco',
        '00:1A:6C': 'Cisco',
        '00:1D:45': 'Cisco',
        '00:24:14': 'Cisco',
        '00:1E:13': 'Intel',
        '00:1B:21': 'Intel',
        '00:23:15': 'Intel',
        '00:1A:3F': 'Samsung',
        '00:23:D4': 'Samsung',
        '00:1E:D9': 'Samsung',
        '00:22:6B': 'Huawei',
        '00:25:9E': 'Huawei',
        '00:1A:2E': 'Huawei',
        '00:1F:64': 'Xiaomi',
        '00:0C:E7': 'Xiaomi',
        '00:25:96': 'TP-Link',
        '00:1A:3B': 'TP-Link',
        '00:14:BF': 'TP-Link',
        '00:0E:8E': 'Asus',
        '00:1B:FC': 'Asus',
        '00:24:8C': 'Asus',
        '00:1C:DF': 'Netgear',
        '00:0F:B5': 'Netgear',
        '00:23:69': 'Netgear',
        '04:0E:3C': 'Intel',
        '3C:5A:37': 'Intel',
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi',
        '00:0A:28': 'Raspberry Pi',
    }

    # 常见fuzz payload
    FUZZ_PAYLOADS = [
        # SQL注入
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "admin' --",
        "admin' #",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1,2,3,4 --",
        "' AND 1=1",
        "' AND 1=2",
        "'; DROP TABLE users --",
        "' OR 1=1--",
        "1' OR '1' = '1",
        "1' OR '1' = '2",
        # XSS
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</ScRiPt>",
        # 路径遍历
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "....//....//....//etc/passwd",
        # 命令注入
        "; ls -la",
        "| ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& ping -c 10 127.0.0.1 &",
        # 参数污染
        "key=1&key=2&key=3",
        # 整数溢出
        "2147483648",
        "-2147483649",
        "99999999999999999999",
        # 格式字符串
        "%x%x%x%x%x%x",
        "%s%s%s%s%s%s",
        "%n%n%n%n%n%n",
        # CRLF注入
        "%0d%0aSet-Cookie:%20test=1",
        "%0d%0aLocation:%20http://evil.com",
        # SSRF
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:22",
        "http://localhost:8080",
        "http://[::1]:80",
        "file:///etc/passwd",
        # 文件上传
        "shell.php",
        "shell.php5",
        "shell.phtml",
        "shell.php.jpg",
        "shell.asp;.jpg",
        # NoSQL注入
        "' || '1'=='1",
        "' && this.password.match(/.*/)",
        '{"$gt": ""}',
        '{"$ne": ""}',
        # XXE
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>",
        # 模板注入
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ]

    # 常见姓氏
    LAST_NAMES = [
        '王', '李', '张', '刘', '陈', '杨', '赵', '黄', '周', '吴',
        '徐', '孙', '胡', '朱', '高', '林', '何', '郭', '马', '罗',
        '梁', '宋', '郑', '谢', '韩', '唐', '冯', '于', '董', '萧',
        'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia',
        'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez',
    ]

    # 常见名字
    FIRST_NAMES = [
        '伟', '芳', '娜', '秀英', '敏', '静', '丽', '强', '磊', '军',
        '洋', '勇', '艳', '杰', '娟', '涛', '明', '超', '秀兰', '霞',
        'James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer',
        'Michael', 'Linda', 'David', 'Barbara', 'William', 'Elizabeth',
    ]

    # 城市列表
    CITIES = [
        '北京', '上海', '广州', '深圳', '杭州', '成都', '武汉', '西安',
        '南京', '重庆', '天津', '苏州', '长沙', '郑州', '青岛', '大连',
        'New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix',
        'Philadelphia', 'San Antonio', 'San Diego', 'Dallas', 'San Jose',
    ]

    # 国家/地区
    COUNTRIES = [
        '中国', '美国', '日本', '德国', '英国', '法国', '韩国', '加拿大',
        'Australia', 'Brazil', 'India', 'Russia', 'Italy', 'Spain',
    ]

    # 邮箱域名
    EMAIL_DOMAINS = [
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com',
        'icloud.com', 'protonmail.com', 'mail.com',
    ]

    # 电话号码前缀
    PHONE_PREFIXES = [
        '138', '139', '150', '151', '152', '157', '158', '159',
        '182', '183', '184', '187', '188', '130', '131', '132',
        '155', '156', '185', '186', '133', '153', '180', '181',
        '189', '170', '171', '212', '310', '415', '512', '617',
        '718', '818', '917', '202', '303', '404', '505', '606',
    ]

    def mac_address_generator(self, count=5, oui=None, separator=':'):
        """
        MAC地址生成器 - 生成随机或指定OUI的MAC地址
        """
        print_section('MAC地址生成器')
        results = []
        try:
            count = int(count)
            if count < 1:
                count = 1
            if count > 100:
                count = 100

            for i in range(count):
                if oui:
                    # 使用指定OUI
                    oui = oui.strip().upper()
                    # 清理OUI格式
                    oui = oui.replace(':', '').replace('-', '').replace('.', '')
                    if len(oui) == 6:
                        octets = [oui[j:j+2] for j in range(0, 6, 2)]
                    else:
                        print_warning(f"无效OUI格式: {oui}，使用随机生成")
                        octets = [f'{random.randint(0, 255):02X}' for _ in range(3)]
                else:
                    # 随机生成
                    octets = [f'{random.randint(0, 255):02X}' for _ in range(3)]

                # 生成后3个字节
                octets.extend([f'{random.randint(0, 255):02X}' for _ in range(3)])
                mac = separator.join(octets)

                # 尝试识别厂商
                oui_prefix = ':'.join(octets[:3])
                vendor = self.OUI_DATABASE.get(oui_prefix, '未知')

                results.append({'mac': mac, 'vendor': vendor})
                print_info(f"{mac}  [{Colors.GREEN}{vendor}{Colors.RESET}]")

            print_success(f"已生成 {len(results)} 个MAC地址")
            return results

        except Exception as e:
            print_error(f"MAC地址生成失败: {e}")
            return results

    def random_string_generator(self, length=16, use_digits=True, use_special=False, count=5):
        """
        随机字符串生成器 - 生成指定长度的随机字符串
        """
        print_section('随机字符串生成器')
        results = []
        try:
            length = int(length)
            if length < 1:
                length = 8
            if length > 1024:
                length = 1024

            count = int(count)
            if count < 1:
                count = 1
            if count > 100:
                count = 100

            chars = string.ascii_letters
            if use_digits:
                chars += string.digits
            if use_special:
                chars += string.punctuation

            for i in range(count):
                s = ''.join(random.choice(chars) for _ in range(length))

                # 确保包含至少一个每种字符类型
                if use_digits and not any(c.isdigit() for c in s):
                    s = s[:-1] + random.choice(string.digits)
                if use_special and not any(c in string.punctuation for c in s):
                    s = s[:-1] + random.choice(string.punctuation)

                results.append(s)
                complexity = '强' if use_digits and use_special and length >= 12 else '中' if use_digits else '弱'
                print_info(f"[{Colors.CYAN}{complexity}{Colors.RESET}] {s}")

            print_success(f"已生成 {len(results)} 个随机字符串 (长度: {length})")
            return results

        except Exception as e:
            print_error(f"随机字符串生成失败: {e}")
            return results

    def ip_calculator(self, network_address):
        """
        IP子网计算器 - 计算IP子网信息
        """
        print_section('IP子网计算器')
        result = {}
        try:
            network = ipaddress.ip_network(network_address, strict=False)

            result = {
                'network': str(network),
                'netmask': str(network.netmask),
                'wildcard': str(network.hostmask),
                'broadcast': str(network.broadcast_address),
                'network_address': str(network.network_address),
                'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else 0,
                'prefix_length': network.prefixlen,
                'is_private': network.is_private,
                'is_global': network.is_global,
                'ip_version': network.version,
            }

            print_info(f"网络地址:     {Colors.GREEN}{result['network']}{Colors.RESET}")
            print_info(f"子网掩码:     {Colors.GREEN}{result['netmask']}{Colors.RESET}")
            print_info(f"通配符掩码:   {Colors.GREEN}{result['wildcard']}{Colors.RESET}")
            print_info(f"广播地址:     {Colors.GREEN}{result['broadcast']}{Colors.RESET}")
            print_info(f"网络号:       {Colors.GREEN}{result['network_address']}{Colors.RESET}")
            print_info(f"可用主机数:   {Colors.GREEN}{result['num_hosts']}{Colors.RESET}")
            print_info(f"前缀长度:     {Colors.GREEN}/{result['prefix_length']}{Colors.RESET}")
            print_info(f"私有网络:     {Colors.GREEN}{'是' if result['is_private'] else '否'}{Colors.RESET}")
            print_info(f"公网网络:     {Colors.GREEN}{'是' if result['is_global'] else '否'}{Colors.RESET}")
            print_info(f"IP版本:       {Colors.GREEN}IPv{result['ip_version']}{Colors.RESET}")

            # 列出前几个可用主机
            if result['num_hosts'] > 0 and result['num_hosts'] <= 20:
                print_info("可用主机列表:")
                hosts = list(network.hosts())
                for h in hosts:
                    print(f"  {Colors.CYAN}{h}{Colors.RESET}")
            elif result['num_hosts'] > 20:
                hosts = list(network.hosts())
                print_info(f"可用主机范围: {hosts[0]} - {hosts[-1]}")

            print_success("子网计算完成")
            return result

        except ValueError as e:
            print_error(f"无效的网络地址: {e}")
            return result
        except Exception as e:
            print_error(f"IP子网计算失败: {e}")
            return result

    def port_list_generator(self, port_input='common'):
        """
        端口列表生成器 - 生成端口列表
        """
        print_section('端口列表生成器')
        ports = []
        try:
            if port_input.lower() == 'common':
                ports = common_ports()
                print_info("使用常见端口列表")
            elif port_input.lower() == 'web':
                ports = common_web_ports()
                print_info("使用常见Web端口列表")
            elif port_input.lower() == 'all':
                ports = list(range(1, 65536))
                print_info("使用全部端口 (1-65535)")
            elif port_input.lower() == 'top100':
                top100 = [
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    465, 993, 995, 1433, 1521, 2049, 2082, 2083, 2181, 2375,
                    3306, 3389, 3690, 4444, 4848, 5000, 5432, 5555, 5632, 5900,
                    5901, 5984, 5985, 5986, 6379, 7001, 7002, 8000, 8001, 8080,
                    8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090, 8443, 8888,
                    9000, 9001, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000,
                    10001, 11211, 27017, 27018, 50000, 50030, 50070, 20, 26, 69,
                    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 161, 162, 389, 514,
                    636, 873, 1080, 1194, 1352, 1526, 1723, 3128, 4333, 5000,
                    9090, 9443,
                ]
                ports = sorted(set(top100))
                print_info("使用Top 100端口列表")
            else:
                # 尝试作为端口范围解析
                ports = port_range_to_list(port_input)
                print_info(f"解析端口范围: {port_input}")

            # 验证端口
            valid_ports = [p for p in ports if is_valid_port(p)]

            # 分组显示
            print_info(f"共 {len(valid_ports)} 个端口:")
            service_groups = {}
            for p in valid_ports:
                svc = get_service_name(p)
                if svc not in service_groups:
                    service_groups[svc] = []
                service_groups[svc].append(p)

            for svc, plist in sorted(service_groups.items()):
                port_str = ', '.join(str(p) for p in plist)
                color = Colors.GREEN if svc != 'Unknown' else Colors.DIM
                print(f"  {color}{svc:15}{Colors.RESET} {port_str}")

            print_success(f"端口列表生成完成，共 {len(valid_ports)} 个有效端口")
            return valid_ports

        except Exception as e:
            print_error(f"端口列表生成失败: {e}")
            return ports

    def text_case_converter(self, text, case_type='lower'):
        """
        文本大小写转换器 - 转换文本大小写格式
        """
        print_section('文本大小写转换器')
        results = {}
        try:
            if not text:
                print_warning("输入文本为空")
                return results

            print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
            print_info(f"原始长度: {len(text)} 字符")

            converters = {
                'lower': ('小写', lambda t: t.lower()),
                'upper': ('大写', lambda t: t.upper()),
                'capitalize': ('首字母大写', lambda t: t.capitalize()),
                'title': ('单词首字母大写', lambda t: t.title()),
                'swapcase': ('大小写反转', lambda t: t.swapcase()),
                'camel': ('驼峰式', lambda t: ''.join(w.capitalize() if i > 0 else w.lower() for i, w in enumerate(re.split(r'[\s_\-]+', t)))),
                'snake': ('蛇形式', lambda t: re.sub(r'([A-Z])', r'_\1', t.replace('-', '_').replace(' ', '_')).lower().lstrip('_')),
                'kebab': ('烤串式', lambda t: re.sub(r'([A-Z])', r'-\1', t.replace('_', '-').replace(' ', '-')).lower().lstrip('-')),
                'pascal': ('帕斯卡式', lambda t: ''.join(w.capitalize() for w in re.split(r'[\s_\-]+', t))),
                'dot': ('点式', lambda t: re.sub(r'([A-Z])', r'.\1', t.replace('_', '.').replace(' ', '.')).lower().lstrip('.')),
            }

            if case_type == 'all':
                for key, (name, func) in converters.items():
                    try:
                        converted = func(text)
                        results[key] = converted
                        print(f"  {Colors.BLUE}{name:12}{Colors.RESET} {converted}")
                    except Exception:
                        pass
            elif case_type in converters:
                name, func = converters[case_type]
                converted = func(text)
                results[case_type] = converted
                print(f"  {Colors.BLUE}{name:12}{Colors.RESET} {converted}")
            else:
                print_warning(f"未知转换类型: {case_type}，可用类型: {', '.join(converters.keys())}")

            print_success("转换完成")
            return results

        except Exception as e:
            print_error(f"文本转换失败: {e}")
            return results

    def json_formatter(self, json_input, indent=2, sort_keys=False):
        """
        JSON格式化/美化 - 格式化JSON数据
        """
        print_section('JSON格式化/美化')
        result = {}
        try:
            indent = max(1, min(8, int(indent)))

            # 尝试解析输入
            parsed = None
            if isinstance(json_input, str):
                # 尝试直接解析
                try:
                    parsed = json.loads(json_input)
                except json.JSONDecodeError:
                    # 尝试从文件读取
                    try:
                        with open(json_input, 'r', encoding='utf-8') as f:
                            parsed = json.load(f)
                        print_info(f"从文件读取: {json_input}")
                    except (FileNotFoundError, IOError, json.JSONDecodeError):
                        print_error("无法解析JSON输入，请检查格式")
                        return result
            elif isinstance(json_input, (dict, list)):
                parsed = json_input
            else:
                print_error("不支持的输入类型")
                return result

            # 格式化输出
            formatted = json.dumps(parsed, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
            compact = json.dumps(parsed, separators=(',', ':'), ensure_ascii=False)

            result = {
                'parsed': parsed,
                'formatted': formatted,
                'compact': compact,
                'formatted_length': len(formatted),
                'compact_length': len(compact),
                'type': type(parsed).__name__,
                'keys': len(parsed) if isinstance(parsed, dict) else len(parsed) if isinstance(parsed, list) else 0,
            }

            print_info(f"数据类型: {Colors.GREEN}{result['type']}{Colors.RESET}")
            print_info(f"元素数量: {Colors.GREEN}{result['keys']}{Colors.RESET}")
            print_info(f"格式化大小: {Colors.GREEN}{result['formatted_length']} 字节{Colors.RESET}")
            print_info(f"压缩大小:   {Colors.GREEN}{result['compact_length']} 字节{Colors.RESET}")
            print_info(f"压缩率:     {Colors.GREEN}{(1 - result['compact_length'] / max(result['formatted_length'], 1)) * 100:.1f}%{Colors.RESET}")

            print_info("格式化结果:")
            for line in formatted.split('\n'):
                print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            print_success("JSON格式化完成")
            return result

        except Exception as e:
            print_error(f"JSON格式化失败: {e}")
            return result

    def timestamp_converter(self, timestamp=None, from_format='unix'):
        """
        时间戳转换器 - 在各种时间格式间转换
        """
        print_section('时间戳转换器')
        result = {}
        try:
            now = datetime.now()

            if timestamp is None:
                # 使用当前时间
                ts_unix = int(time.time())
                ts_ms = int(time.time() * 1000)
                print_info("使用当前时间")
            elif from_format == 'unix':
                ts_unix = int(timestamp)
                ts_ms = ts_unix * 1000
            elif from_format == 'unix_ms':
                ts_ms = int(timestamp)
                ts_unix = ts_ms // 1000
            elif from_format == 'iso':
                dt = datetime.fromisoformat(timestamp)
                ts_unix = int(dt.timestamp())
                ts_ms = int(dt.timestamp() * 1000)
            elif from_format == 'date':
                for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d', '%Y/%m/%d %H:%M:%S',
                            '%m/%d/%Y', '%m/%d/%Y %H:%M:%S', '%d-%m-%Y', '%d/%m/%Y']:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        ts_unix = int(dt.timestamp())
                        ts_ms = int(dt.timestamp() * 1000)
                        break
                    except ValueError:
                        continue
                else:
                    print_error(f"无法解析日期格式: {timestamp}")
                    return result
            else:
                print_warning(f"未知输入格式: {from_format}，使用Unix时间戳")
                ts_unix = int(time.time())
                ts_ms = int(time.time() * 1000)

            # 转换所有格式
            dt_utc = datetime.fromtimestamp(ts_unix, tz=timezone.utc)
            dt_local = datetime.fromtimestamp(ts_unix)

            result = {
                'unix_timestamp': ts_unix,
                'unix_milliseconds': ts_ms,
                'iso_utc': dt_utc.isoformat(),
                'iso_local': dt_local.isoformat(),
                'date_utc': dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'date_local': dt_local.strftime('%Y-%m-%d %H:%M:%S'),
                'date_rfc2822': dt_utc.strftime('%a, %d %b %Y %H:%M:%S +0000'),
                'date_common': dt_local.strftime('%Y-%m-%d %H:%M:%S'),
                'date_chinese': dt_local.strftime('%Y年%m月%d日 %H时%M分%S秒'),
                'year': dt_local.year,
                'month': dt_local.month,
                'day': dt_local.day,
                'hour': dt_local.hour,
                'minute': dt_local.minute,
                'second': dt_local.second,
                'weekday': dt_local.strftime('%A'),
                'weekday_cn': ['星期一', '星期二', '星期三', '星期四', '星期五', '星期六', '星期日'][dt_local.weekday()],
            }

            print_info(f"Unix时间戳:    {Colors.GREEN}{result['unix_timestamp']}{Colors.RESET}")
            print_info(f"Unix毫秒:      {Colors.GREEN}{result['unix_milliseconds']}{Colors.RESET}")
            print_info(f"UTC时间:       {Colors.GREEN}{result['date_utc']}{Colors.RESET}")
            print_info(f"本地时间:      {Colors.GREEN}{result['date_local']}{Colors.RESET}")
            print_info(f"RFC 2822:      {Colors.GREEN}{result['date_rfc2822']}{Colors.RESET}")
            print_info(f"中国格式:      {Colors.GREEN}{result['date_chinese']}{Colors.RESET}")
            print_info(f"星期:          {Colors.GREEN}{result['weekday_cn']} ({result['weekday']}){Colors.RESET}")

            print_success("时间戳转换完成")
            return result

        except Exception as e:
            print_error(f"时间戳转换失败: {e}")
            return result

    def user_agent_generator(self, count=5, browser=None, mobile=False):
        """
        User-Agent生成器 - 生成浏览器User-Agent
        """
        print_section('User-Agent生成器')
        results = []
        try:
            count = int(count)
            if count < 1:
                count = 1
            if count > 50:
                count = 50

            # 扩展的User-Agent数据库
            ua_database = {
                'chrome': [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ],
                'firefox': [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                ],
                'safari': [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                ],
                'edge': [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
                ],
                'mobile': [
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                    "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                ],
            }

            # 选择UA池
            if mobile:
                ua_pool = ua_database['mobile']
                print_info("模式: 移动端")
            elif browser and browser.lower() in ua_database:
                ua_pool = ua_database[browser.lower()]
                print_info(f"模式: {browser.capitalize()}")
            else:
                # 合并所有(除mobile)
                ua_pool = []
                for key, uas in ua_database.items():
                    if key != 'mobile':
                        ua_pool.extend(uas)
                print_info("模式: 全平台")

            # 随机选择
            for i in range(count):
                ua = random.choice(ua_pool)
                results.append(ua)

                # 提取平台和浏览器信息
                platform = 'Unknown'
                if 'Windows NT' in ua:
                    platform = 'Windows'
                elif 'Macintosh' in ua or 'Mac OS' in ua:
                    platform = 'macOS'
                elif 'Linux' in ua and 'Android' not in ua:
                    platform = 'Linux'
                elif 'Android' in ua:
                    platform = 'Android'
                elif 'iPhone' in ua:
                    platform = 'iOS'

                browser_name = 'Unknown'
                if 'Chrome' in ua and 'Edg' not in ua:
                    browser_name = 'Chrome'
                elif 'Firefox' in ua:
                    browser_name = 'Firefox'
                elif 'Safari' in ua and 'Chrome' not in ua:
                    browser_name = 'Safari'
                elif 'Edg' in ua:
                    browser_name = 'Edge'

                print(f"  [{Colors.GREEN}{platform:8}{Colors.RESET}] [{Colors.CYAN}{browser_name:7}{Colors.RESET}] {ua[:80]}...")

            print_success(f"已生成 {len(results)} 个User-Agent")
            return results

        except Exception as e:
            print_error(f"User-Agent生成失败: {e}")
            return results

    def uuid_generator(self, count=5, version=4, upper=False):
        """
        UUID生成器 - 生成各种版本的UUID
        """
        print_section('UUID生成器')
        results = []
        try:
            count = int(count)
            if count < 1:
                count = 1
            if count > 100:
                count = 100

            version = int(version)
            if version not in [1, 3, 4, 5]:
                print_warning(f"不支持的UUID版本: {version}，使用v4")
                version = 4

            version_names = {1: '基于时间', 3: '基于MD5命名空间', 4: '随机', 5: '基于SHA-1命名空间'}
            print_info(f"UUID版本: v{version} ({version_names.get(version, '未知')})")

            for i in range(count):
                if version == 1:
                    u = uuid.uuid1()
                elif version == 3:
                    namespace = uuid.NAMESPACE_DNS
                    name = f"example{i}.com"
                    u = uuid.uuid3(namespace, name)
                elif version == 4:
                    u = uuid.uuid4()
                elif version == 5:
                    namespace = uuid.NAMESPACE_DNS
                    name = f"example{i}.com"
                    u = uuid.uuid5(namespace, name)

                uuid_str = str(u)
                if upper:
                    uuid_str = uuid_str.upper()

                results.append(uuid_str)

                # 版本类型标识
                ver = u.version if hasattr(u, 'version') else version
                print(f"  [{Colors.GREEN}v{ver}{Colors.RESET}] {Colors.CYAN}{uuid_str}{Colors.RESET}")

            print_success(f"已生成 {len(results)} 个UUID")
            return results

        except Exception as e:
            print_error(f"UUID生成失败: {e}")
            return results

    def payload_fuzzer(self, payload_type='all', encode_mode=None):
        """
        Payload模糊测试器 - 生成各种模糊测试Payload
        """
        print_section('Payload模糊测试器')
        results = {}
        try:
            # 分类payload
            categories = {
                'sqli': ('SQL注入', [p for p in self.FUZZ_PAYLOADS if any(k in p.lower() for k in
                    ["'", "union", "select", "drop", "and", "or", "1=1", "1=2"])]),
                'xss': ('XSS跨站脚本', [p for p in self.FUZZ_PAYLOADS if any(k in p.lower() for k in
                    ["<script", "<img", "<svg", "<body", "onerror", "onload", "alert"])]),
                'path_traversal': ('路径遍历', [p for p in self.FUZZ_PAYLOADS if any(k in p.lower() for k in
                    ["../", "..\\", "passwd", "win.ini", "%2e"])]),
                'cmd_injection': ('命令注入', [p for p in self.FUZZ_PAYLOADS if any(k in p for k in
                    ["; ls", "| ls", "`ls", "$(", "cat /etc", "ping "])]),
                'ssrf': ('SSRF服务端请求伪造', [p for p in self.FUZZ_PAYLOADS if any(k in p for k in
                    ["127.0.0.1", "localhost", "file://", "[::1]"])]),
                'other': ('其他', [p for p in self.FUZZ_PAYLOADS if not any(
                    k in p.lower() for k in ["'", "union", "select", "drop", "<script", "<img",
                    "../", "..\\", "passwd", "win.ini", "; ls", "| ls", "`ls", "$(",
                    "127.0.0.1", "localhost", "file://"])]),
            }

            # 编码函数
            encoders = {
                'url': lambda s: re.sub(r'[^\w\s/]', lambda m: f'%{ord(m.group(0)):02X}', s).replace(' ', '%20'),
                'base64': lambda s: __import__('base64').b64encode(s.encode()).decode(),
                'hex': lambda s: s.encode().hex(),
                'unicode': lambda s: ''.join(f'\\u{ord(c):04X}' for c in s),
                'double_url': lambda s: re.sub(r'[^\w\s/]', lambda m: f'%25{ord(m.group(0)):02X}', s).replace(' ', '%2520'),
                'html_entity': lambda s: ''.join(f'&#{ord(c)};' if not c.isalnum() else c for c in s),
            }

            if payload_type == 'all':
                target_categories = categories
            elif payload_type in categories:
                target_categories = {payload_type: categories[payload_type]}
            else:
                print_warning(f"未知payload类型: {payload_type}，使用全部")
                target_categories = categories

            for cat_key, (cat_name, payloads) in target_categories.items():
                print_info(f"类别: {Colors.MAGENTA}{cat_name}{Colors.RESET} ({len(payloads)}个payload)")

                cat_results = []
                for payload in payloads:
                    encoded = payload

                    # 应用编码
                    if encode_mode and encode_mode in encoders:
                        try:
                            encoded = encoders[encode_mode](payload)
                        except Exception:
                            encoded = payload

                    cat_results.append({
                        'original': payload,
                        'encoded': encoded,
                        'length': len(encoded),
                    })

                    if encode_mode:
                        print(f"  {Colors.DIM}{payload[:50]:50}{Colors.RESET} → {Colors.CYAN}{encoded[:60]}{Colors.RESET}")
                    else:
                        print(f"  {Colors.CYAN}{payload}{Colors.RESET}")

                results[cat_key] = cat_results

            print_success(f"Payload生成完成，共 {sum(len(v) for v in results.values())} 个payload")
            return results

        except Exception as e:
            print_error(f"Payload生成失败: {e}")
            return results

    def regex_tester(self, pattern, test_strings=None):
        """
        正则表达式测试器 - 测试正则表达式匹配
        """
        print_section('正则表达式测试器')
        result = {}
        try:
            if not pattern:
                print_warning("未提供正则表达式")
                return result

            # 编译正则
            try:
                compiled = re.compile(pattern)
                print_info(f"模式:     {Colors.GREEN}{pattern}{Colors.RESET}")
                print_info(f"标志:     {Colors.GREEN}{' | '.join(
                    name for flag, name in [(re.IGNORECASE, 'IGNORECASE'), (re.MULTILINE, 'MULTILINE'),
                                            (re.DOTALL, 'DOTALL'), (re.UNICODE, 'UNICODE')]
                    if compiled.flags & flag
                ) or '无'}{Colors.RESET}")
            except re.error as e:
                print_error(f"正则表达式编译失败: {e}")
                return result

            # 默认测试字符串
            if test_strings is None:
                test_strings = [
                    "hello world 123",
                    "Hello World 456",
                    "test@example.com",
                    "192.168.1.1",
                    "https://www.example.com/path?q=1",
                    "2024-01-15 14:30:00",
                    "<html><body>Content</body></html>",
                    "user:password@host:8080",
                    "a1b2c3d4e5f6",
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                ]
            elif isinstance(test_strings, str):
                test_strings = [test_strings]

            print_info(f"测试字符串数: {len(test_strings)}")
            print()

            matches = []
            non_matches = []

            for i, test_str in enumerate(test_strings):
                try:
                    found = compiled.findall(test_str)
                    search_result = compiled.search(test_str)
                    match_result = compiled.match(test_str)

                    entry = {
                        'text': test_str,
                        'findall': found,
                        'search': search_result.group() if search_result else None,
                        'match': match_result.group() if match_result else None,
                        'groups': search_result.groups() if search_result and search_result.groups() else None,
                        'groupdict': search_result.groupdict() if search_result and search_result.groupdict() else None,
                    }

                    if found:
                        matches.append(entry)
                        print(f"  {Colors.GREEN}[✓]{Colors.RESET} {test_str[:60]}")
                        if entry['groups']:
                            print(f"       捕获组: {Colors.CYAN}{entry['groups']}{Colors.RESET}")
                        if entry['groupdict']:
                            print(f"       命名组: {Colors.CYAN}{entry['groupdict']}{Colors.RESET}")
                        if found:
                            print(f"       匹配:   {Colors.CYAN}{found[:3]}{'...' if len(found) > 3 else ''}{Colors.RESET}")
                    else:
                        non_matches.append(entry)
                        print(f"  {Colors.DIM}[✗] {test_str[:60]}{Colors.RESET}")

                except Exception as e:
                    print_warning(f"测试字符串 [{i}] 出错: {e}")

            result = {
                'pattern': pattern,
                'compiled': compiled,
                'matches': matches,
                'non_matches': non_matches,
                'total_tests': len(test_strings),
                'match_count': len(matches),
                'non_match_count': len(non_matches),
            }

            print()
            print_info(f"匹配:   {Colors.GREEN}{result['match_count']}{Colors.RESET}")
            print_info(f"不匹配: {Colors.RED}{result['non_match_count']}{Colors.RESET}")
            print_info(f"总计:   {result['total_tests']}")

            print_success("正则测试完成")
            return result

        except Exception as e:
            print_error(f"正则测试失败: {e}")
            return result

    def color_tester(self, test_text='Hello World'):
        """
        终端颜色测试器 - 测试终端颜色显示
        """
        print_section('终端颜色测试器')
        result = {}
        try:
            print_info(f"测试文本: \"{test_text}\"")
            print()

            # 基本颜色
            basic_colors = [
                ('RED', Colors.RED),
                ('GREEN', Colors.GREEN),
                ('YELLOW', Colors.YELLOW),
                ('BLUE', Colors.BLUE),
                ('MAGENTA', Colors.MAGENTA),
                ('CYAN', Colors.CYAN),
                ('WHITE', Colors.WHITE),
            ]

            print_info("基本颜色:")
            for name, color in basic_colors:
                print(f"  {color}{test_text:20}{Colors.RESET} {Colors.DIM}{name}{Colors.RESET}")

            print()

            # 亮色
            light_colors = [
                ('LIGHT_RED', Colors.LIGHT_RED),
                ('LIGHT_GREEN', Colors.LIGHT_GREEN),
                ('LIGHT_YELLOW', Colors.LIGHT_YELLOW),
                ('LIGHT_BLUE', Colors.LIGHT_BLUE),
                ('LIGHT_MAGENTA', Colors.LIGHT_MAGENTA),
                ('LIGHT_CYAN', Colors.LIGHT_CYAN),
            ]

            print_info("亮色:")
            for name, color in light_colors:
                print(f"  {color}{test_text:20}{Colors.RESET} {Colors.DIM}{name}{Colors.RESET}")

            print()

            # 暗色
            dark_colors = [
                ('DARK_RED', Colors.DARK_RED),
                ('DARK_GREEN', Colors.DARK_GREEN),
                ('DARK_YELLOW', Colors.DARK_YELLOW),
                ('DARK_BLUE', Colors.DARK_BLUE),
                ('DARK_MAGENTA', Colors.DARK_MAGENTA),
                ('DARK_CYAN', Colors.DARK_CYAN),
            ]

            print_info("暗色:")
            for name, color in dark_colors:
                print(f"  {color}{test_text:20}{Colors.RESET} {Colors.DIM}{name}{Colors.RESET}")

            print()

            # 特殊样式
            print_info("特殊样式:")
            print(f"  {Colors.BOLD}{test_text:20}{Colors.RESET} {Colors.DIM}BOLD{Colors.RESET}")
            print(f"  {Colors.DIM}{test_text:20}{Colors.RESET} {Colors.DIM}DIM{Colors.RESET}")
            print(f"  {Colors.UNDERLINE}{test_text:20}{Colors.RESET} {Colors.DIM}UNDERLINE{Colors.RESET}")
            print(f"  {Colors.BOLD}{Colors.RED}{test_text:20}{Colors.RESET} {Colors.DIM}BOLD+RED{Colors.RESET}")

            print()

            # 背景色
            print_info("背景色:")
            bg_colors = [
                ('BG_RED', Colors.BG_RED),
                ('BG_GREEN', Colors.BG_GREEN),
                ('BG_YELLOW', Colors.BG_YELLOW),
                ('BG_BLUE', Colors.BG_BLUE),
                ('BG_MAGENTA', Colors.BG_MAGENTA),
                ('BG_CYAN', Colors.BG_CYAN),
                ('BG_DARK_GRAY', Colors.BG_DARK_GRAY),
            ]
            for name, bg in bg_colors:
                print(f"  {bg}{Colors.BLACK if hasattr(Colors, 'BLACK') else Colors.WHITE}{test_text:20}{Colors.RESET} {Colors.DIM}{name}{Colors.RESET}")

            print()

            # 256色测试
            print_info("256色测试 (0-15):")
            row = ''
            for i in range(16):
                row += f'\033[48;5;{i}m  {i:02d}  \033[0m'
            print(f"  {row}")

            print()
            print_info("256色测试 (16-231):")
            for block in range(6):
                row = ''
                for i in range(36):
                    color = 16 + block * 36 + i
                    row += f'\033[48;5;{color}m \033[0m'
                print(f"  {row}")

            print()
            print_info("256色测试 (232-255 灰度):")
            row = ''
            for i in range(232, 256):
                row += f'\033[48;5;{i}m \033[0m'
            print(f"  {row}")

            # 彩虹效果
            print()
            print_info("彩虹效果:")
            rainbow_colors = [Colors.RED, Colors.ORANGE, Colors.YELLOW, Colors.GREEN,
                              Colors.CYAN, Colors.BLUE, Colors.MAGENTA]
            rainbow = ''
            for i, c in enumerate(rainbow_colors):
                rainbow += f'{c}{test_text[i % len(test_text)]}{Colors.RESET}'
            print(f"  {rainbow}")

            print()
            print_success("颜色测试完成")
            return result

        except Exception as e:
            print_error(f"颜色测试失败: {e}")
            return result

    def random_data_generator(self, data_type='all', count=5, locale='zh'):
        """
        随机数据生成器 - 生成随机个人信息数据
        """
        print_section('随机数据生成器')
        results = {}
        try:
            count = int(count)
            if count < 1:
                count = 1
            if count > 50:
                count = 50

            print_info(f"区域: {locale.upper()}")
            print_info(f"数量: {count}")

            def generate_name():
                """生成随机姓名"""
                if locale == 'zh':
                    last = random.choice(self.LAST_NAMES[:40])  # 中文姓氏在前
                    first = ''.join(random.choice(self.FIRST_NAMES[:20]) for _ in range(random.choice([1, 2])))
                    return last + first
                else:
                    return f"{random.choice(self.FIRST_NAMES[20:])} {random.choice(self.LAST_NAMES[20:])}"

            def generate_phone():
                """生成随机电话号码"""
                prefix = random.choice(self.PHONE_PREFIXES)
                suffix = ''.join(random.choice(string.digits) for _ in range(8))
                return prefix + suffix

            def generate_email(name=None):
                """生成随机邮箱"""
                if name is None:
                    name = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(6, 12)))
                else:
                    name = re.sub(r'[^a-zA-Z0-9]', '.', name).lower()
                domain = random.choice(self.EMAIL_DOMAINS)
                return f"{name}@{domain}"

            def generate_address():
                """生成随机地址"""
                if locale == 'zh':
                    city = random.choice(self.CITIES[:15])
                    street = f"{random.choice(['中山', '人民', '解放', '建设', '和平', '长安', '北京'])}路{random.randint(1, 999)}号"
                    return f"{city}{street}"
                else:
                    number = random.randint(100, 9999)
                    street = random.choice(['Main', 'Oak', 'Elm', 'Park', 'Lake', 'Hill', 'River'])
                    street_type = random.choice(['St', 'Ave', 'Blvd', 'Dr', 'Ln', 'Rd'])
                    city = random.choice(self.CITIES[15:])
                    return f"{number} {street} {street_type}, {city}"

            def generate_ssn():
                """生成随机身份证号/SSN"""
                if locale == 'zh':
                    # 18位身份证号
                    area = f"{random.randint(110000, 659000)}"
                    birth = f"{random.randint(1960, 2005)}{random.randint(1, 12):02d}{random.randint(1, 28):02d}"
                    seq = f"{random.randint(0, 999):03d}"
                    base = area + birth + seq
                    # 校验码
                    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
                    check_codes = '10X98765432'
                    total = sum(int(base[i]) * weights[i] for i in range(17))
                    return base + check_codes[total % 11]
                else:
                    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

            # 生成各类型数据
            if data_type in ('all', 'name'):
                names = [generate_name() for _ in range(count)]
                results['name'] = names
                print_info(f"姓名:")
                for n in names:
                    print(f"  {Colors.CYAN}{n}{Colors.RESET}")

            if data_type in ('all', 'phone'):
                phones = [generate_phone() for _ in range(count)]
                results['phone'] = phones
                print_info(f"电话:")
                for p in phones:
                    print(f"  {Colors.CYAN}{p}{Colors.RESET}")

            if data_type in ('all', 'email'):
                emails = [generate_email() for _ in range(count)]
                results['email'] = emails
                print_info(f"邮箱:")
                for e in emails:
                    print(f"  {Colors.CYAN}{e}{Colors.RESET}")

            if data_type in ('all', 'address'):
                addresses = [generate_address() for _ in range(count)]
                results['address'] = addresses
                print_info(f"地址:")
                for a in addresses:
                    print(f"  {Colors.CYAN}{a}{Colors.RESET}")

            if data_type in ('all', 'ssn'):
                ssns = [generate_ssn() for _ in range(count)]
                results['ssn'] = ssns
                print_info(f"身份证/SSN:")
                for s in ssns:
                    print(f"  {Colors.CYAN}{s}{Colors.RESET}")

            if data_type in ('all', 'full'):
                full_records = []
                for i in range(count):
                    n = generate_name()
                    record = {
                        'name': n,
                        'phone': generate_phone(),
                        'email': generate_email(n),
                        'address': generate_address(),
                        'ssn': generate_ssn(),
                    }
                    full_records.append(record)
                results['full'] = full_records
                print_info(f"完整记录:")
                for i, rec in enumerate(full_records):
                    print(f"  {Colors.GREEN}[{i+1}]{Colors.RESET}")
                    print(f"    姓名:    {Colors.CYAN}{rec['name']}{Colors.RESET}")
                    print(f"    电话:    {Colors.CYAN}{rec['phone']}{Colors.RESET}")
                    print(f"    邮箱:    {Colors.CYAN}{rec['email']}{Colors.RESET}")
                    print(f"    地址:    {Colors.CYAN}{rec['address']}{Colors.RESET}")
                    print(f"    证件号:  {Colors.CYAN}{rec['ssn']}{Colors.RESET}")

            print_success(f"随机数据生成完成，类型: {data_type}")
            return results

        except Exception as e:
            print_error(f"随机数据生成失败: {e}")
            return results

    def byte_converter(self, value, from_unit='B', to_unit=None):
        """
        字节单位转换器 - 在B, KB, MB, GB, TB, PB间转换
        """
        print_section('字节单位转换器')
        result = {}
        try:
            value = float(value)
            if value < 0:
                print_warning("负值输入，将使用绝对值")
                value = abs(value)

            # 单位定义 (字节数)
            units = {
                'B': 1,
                'KB': 1024,
                'MB': 1024 ** 2,
                'GB': 1024 ** 3,
                'TB': 1024 ** 4,
                'PB': 1024 ** 5,
                'EB': 1024 ** 6,
                'KiB': 1024,
                'MiB': 1024 ** 2,
                'GiB': 1024 ** 3,
                'TiB': 1024 ** 4,
                'PiB': 1024 ** 5,
                'EiB': 1024 ** 6,
                'b': 0.125,  # 1 bit = 0.125 bytes
                'Kb': 128,   # 1 kilobit = 128 bytes
                'Mb': 131072, # 1 megabit = 131072 bytes
                'Gb': 134217728, # 1 gigabit = 134217728 bytes
            }

            from_unit = from_unit.strip()
            if from_unit not in units:
                print_error(f"未知单位: {from_unit}")
                print_info(f"可用单位: {', '.join(units.keys())}")
                return result

            # 转换为字节
            bytes_value = value * units[from_unit]

            result = {
                'input_value': value,
                'input_unit': from_unit,
                'bytes': bytes_value,
            }

            print_info(f"输入: {Colors.GREEN}{value:,.2f} {from_unit}{Colors.RESET}")
            print_info(f"字节: {Colors.GREEN}{bytes_value:,.2f} B{Colors.RESET}")
            print()

            # 转换到所有单位
            if to_unit:
                # 只转换到指定单位
                if to_unit in units:
                    converted = bytes_value / units[to_unit]
                    result[to_unit] = converted
                    print_info(f"结果: {Colors.CYAN}{converted:,.4f} {to_unit}{Colors.RESET}")
                else:
                    print_warning(f"未知目标单位: {to_unit}")
            else:
                # 转换到所有常用单位
                display_units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'KiB', 'MiB', 'GiB', 'TiB']
                print_info("所有单位转换:")

                for unit in display_units:
                    if unit in units:
                        converted = bytes_value / units[unit]
                        result[unit] = converted
                        # 智能显示
                        if converted >= 1 or unit == 'B':
                            print(f"  {Colors.CYAN}{unit:5}{Colors.RESET} {converted:>15,.4f}")
                        else:
                            print(f"  {Colors.DIM}{unit:5}{Colors.RESET} {converted:>15,.4f}{Colors.RESET}")

            # 自动最佳单位
            best_unit = 'B'
            best_value = bytes_value
            for unit in ['PB', 'TB', 'GB', 'MB', 'KB', 'B']:
                if unit in units:
                    v = bytes_value / units[unit]
                    if v >= 1:
                        best_unit = unit
                        best_value = v
                        break

            result['best_unit'] = best_unit
            result['best_value'] = best_value
            result['best_display'] = f"{best_value:,.2f} {best_unit}"

            print()
            print_info(f"最佳显示: {Colors.GREEN}{result['best_display']}{Colors.RESET}")

            print_success("字节转换完成")
            return result

        except Exception as e:
            print_error(f"字节转换失败: {e}")
            return result