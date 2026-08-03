# -*- coding: utf-8 -*-
"""
HackerToolkit - 全能网络安全工具包主入口
Ultimate Security Toolkit - Main Entry Point
"""

import os
import sys
import time
import inspect
import importlib

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner, print_about, print_small_banner
from core.colors import *
from core.utils import *


def clear_screen():
    """清屏"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu_header(title):
    """打印菜单头部"""
    width = 70
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*width}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*width}{Colors.RESET}")


def print_sub_menu(items, cols=2):
    """打印子菜单项"""
    for i, (key, desc) in enumerate(items):
        print(f"  {Colors.GREEN}[{str(key).zfill(2)}]{Colors.RESET}  {Colors.WHITE}{desc}{Colors.RESET}")


def get_input(prompt, required=True):
    """获取用户输入"""
    try:
        value = input(f"{Colors.YELLOW}{prompt}{Colors.RESET}").strip()
        if required and not value:
            return None
        return value
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def get_int_input(prompt, min_val=1, max_val=None):
    """获取整数输入"""
    try:
        value = input(f"{Colors.YELLOW}{prompt}{Colors.RESET}").strip()
        num = int(value)
        if min_val is not None and num < min_val:
            print_error(f"输入不能小于 {min_val}")
            return None
        if max_val is not None and num > max_val:
            print_error(f"输入不能大于 {max_val}")
            return None
        return num
    except (ValueError, TypeError):
        print_error("请输入有效的数字")
        return None
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def wait_for_enter():
    """等待用户按回车"""
    try:
        input(f"\n{Colors.DIM}按 Enter 键继续...{Colors.RESET}")
    except (KeyboardInterrupt, EOFError):
        print()


def load_module(module_name):
    """动态加载模块"""
    try:
        module = importlib.import_module(f"modules.{module_name}")
        # 查找模块中的类
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and name != '__class__':
                return obj
        return None
    except Exception as e:
        print_error(f"加载模块 {module_name} 失败: {e}")
        return None


def run_tool(module_class, method_name, *args, **kwargs):
    """运行工具方法"""
    try:
        instance = module_class()
        method = getattr(instance, method_name, None)
        if method:
            return method(*args, **kwargs)
        else:
            print_error(f"方法 {method_name} 不存在")
            return None
    except Exception as e:
        print_error(f"执行失败: {e}")
        return None


# ==================== 模块接口 ====================

def info_gathering_menu():
    """信息收集模块菜单"""
    module_class = load_module("info_gathering")
    if not module_class:
        return

    menu_items = [
        ("01", "WHOIS 查询"),
        ("02", "DNS 枚举"),
        ("03", "子域名枚举"),
        ("04", "端口扫描"),
        ("05", "操作系统检测"),
        ("06", "服务版本检测"),
        ("07", "Banner 抓取"),
        ("08", "IP 地理位置查询"),
        ("09", "反向 DNS 查询"),
        ("10", "DNS 区域传输检测"),
        ("11", "邮箱地址提取"),
        ("12", "Web 技术检测"),
        ("13", "HTTP 头分析"),
        ("14", "SSL 证书信息"),
        ("15", "Robots.txt 分析"),
        ("16", "Wayback Machine 历史查询"),
        ("17", "CVE 搜索"),
        ("18", "Shodan 查询"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "whois_lookup", "2": "dns_enum", "3": "subdomain_enum",
        "4": "port_scan", "5": "os_detection", "6": "service_detection",
        "7": "banner_grabbing", "8": "ip_geolocation", "9": "reverse_dns",
        "10": "dns_zone_transfer", "11": "email_harvester",
        "12": "web_tech_detect", "13": "http_headers", "14": "ssl_cert_info",
        "15": "robots_analyzer", "16": "wayback_urls",
        "17": "cve_search", "18": "shodan_lookup",
    }

    while True:
        clear_screen()
        print_menu_header("  [01] 信息收集模块 - Information Gathering  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-18]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        instance = module_class()
        target = get_input("  请输入目标 (域名/IP/URL): ")

        if choice in ["17"]:
            keyword = get_input("  请输入搜索关键词或CVE编号: ")
            run_tool(module_class, method, keyword)
        elif choice in ["18"]:
            query = get_input("  请输入查询关键词: ")
            run_tool(module_class, method, query)
        elif choice in ["4", "6", "7"]:
            port_range = get_input("  请输入端口范围 (默认: 常见端口): ", required=False)
            if not port_range:
                port_range = "common"
            run_tool(module_class, method, target, port_range)
        elif choice in ["3"]:
            wordlist = get_input("  字典文件路径 (可选): ", required=False)
            run_tool(module_class, method, target, wordlist or None)
        else:
            run_tool(module_class, method, target)

        wait_for_enter()


def web_vuln_scan_menu():
    """Web漏洞扫描模块菜单"""
    module_class = load_module("web_vuln_scanner")
    if not module_class:
        return

    menu_items = [
        ("01", "SQL 注入检测"),
        ("02", "XSS 跨站脚本检测"),
        ("03", "LFI 本地文件包含检测"),
        ("04", "RFI 远程文件包含检测"),
        ("05", "命令注入检测"),
        ("06", "CSRF 漏洞检测"),
        ("07", "SSRF 服务端请求伪造检测"),
        ("08", "开放重定向检测"),
        ("09", "XXE 注入检测"),
        ("10", "路径遍历检测"),
        ("11", "文件上传漏洞检测"),
        ("12", "点击劫持检测"),
        ("13", "SSTI 模板注入检测"),
        ("14", "CORS 配置错误检测"),
        ("15", "目录列表检测"),
        ("16", "HTTP 方法枚举"),
        ("17", "WAF 检测"),
        ("18", "全量扫描（所有漏洞）"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "check_sql_injection", "2": "check_xss", "3": "check_lfi",
        "4": "check_rfi", "5": "check_command_injection", "6": "check_csrf",
        "7": "check_ssrf", "8": "check_open_redirect", "9": "check_xxe",
        "10": "check_path_traversal", "11": "check_file_upload",
        "12": "check_clickjacking", "13": "check_ssti",
        "14": "check_cors", "15": "check_directory_listing",
        "16": "check_http_methods", "17": "check_waf", "18": "scan_all",
    }

    while True:
        clear_screen()
        print_menu_header("  [02] Web漏洞扫描模块 - Vulnerability Scanner  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-18]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        url = get_input("  请输入目标URL (如: http://example.com): ")
        url = normalize_url(url)

        if choice == "18":
            instance = module_class(url)
            instance.scan_all()
        else:
            run_tool(module_class, method, url)

        wait_for_enter()


def exploitation_menu():
    """漏洞利用模块菜单"""
    module_class = load_module("exploitation")
    if not module_class:
        return

    menu_items = [
        ("01", "反弹 Shell 生成器"),
        ("02", "绑定 Shell 生成器"),
        ("03", "PHP WebShell 生成"),
        ("04", "ASP/ASPX WebShell 生成"),
        ("05", "Python Payload 生成"),
        ("06", "MSF Payload 生成向导"),
        ("07", "默认凭据检查器"),
        ("08", "WordPress 漏洞扫描"),
        ("09", "Joomla 漏洞扫描"),
        ("10", "Shellshock 漏洞检测"),
        ("11", "Struts2 漏洞检测"),
        ("12", "WebLogic 漏洞检测"),
        ("13", "Payload 编码器"),
        ("14", "下载执行 Payload 生成"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "reverse_shell_generator", "2": "bind_shell_generator",
        "3": "php_webshell", "4": "asp_webshell",
        "5": "python_payloads", "6": "msf_payload_generator",
        "7": "default_credential_checker", "8": "wordpress_exploit_scanner",
        "9": "joomla_exploit_scanner", "10": "shellshock_checker",
        "11": "struts2_checker", "12": "weblogic_checker",
        "13": "payload_encoder", "14": "download_exec_payloads",
    }

    while True:
        clear_screen()
        print_menu_header("  [03] 漏洞利用模块 - Exploitation  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-14]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        instance = module_class()
        if choice in ["1", "2"]:
            ip = get_input("  请输入IP地址: ")
            port = get_int_input("  请输入端口: ", 1, 65535)
            run_tool(module_class, method, ip, port)
        elif choice in ["3", "4"]:
            pwd = get_input("  请输入密码 (默认: pass): ", required=False)
            run_tool(module_class, method, pwd or "pass")
        elif choice in ["7"]:
            target = get_input("  请输入目标IP/域名: ")
            service = get_input("  请输入服务类型 (可选): ", required=False)
            run_tool(module_class, method, target, service or None)
        elif choice in ["8", "9", "10", "11", "12"]:
            url = get_input("  请输入目标URL: ")
            run_tool(module_class, method, url)
        elif choice in ["13"]:
            payload = get_input("  请输入要编码的Payload: ")
            encoding = get_input("  编码类型 (base64/url/hex/unicode/octal): ")
            run_tool(module_class, method, payload, encoding)
        elif choice in ["14"]:
            url = get_input("  请输入下载URL: ")
            run_tool(module_class, method, url)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def network_tools_menu():
    """网络工具模块菜单"""
    module_class = load_module("network_tools")
    if not module_class:
        return

    menu_items = [
        ("01", "Ping 扫描 - 探测网段活跃主机"),
        ("02", "ARP 扫描 - 局域网设备发现"),
        ("03", "路由追踪"),
        ("04", "DNS 批量解析"),
        ("05", "MAC 地址厂商查询"),
        ("06", "简易 HTTP 文件服务器"),
        ("07", "简易 Netcat 监听器"),
        ("08", "代理检测"),
        ("09", "IP 子网计算器"),
        ("10", "端口转发器"),
        ("11", "网络扫描器"),
        ("12", "批量 DNS 解析"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "ping_sweep", "2": "arp_scan", "3": "traceroute",
        "4": "dns_resolver", "5": "mac_address_lookup",
        "6": "http_server", "7": "netcat_listener",
        "8": "proxy_checker", "9": "ip_calculator",
        "10": "port_forwarder", "11": "network_scanner",
        "12": "dns_mass_resolver",
    }

    while True:
        clear_screen()
        print_menu_header("  [04] 网络工具模块 - Network Tools  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-12]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1", "11"]:
            subnet = get_input("  请输入网段 (如: 192.168.1.0/24): ")
            run_tool(module_class, method, subnet)
        elif choice in ["2"]:
            iface = get_input("  请输入网卡IP (可选): ", required=False)
            run_tool(module_class, method, iface or None)
        elif choice in ["3"]:
            target = get_input("  请输入目标IP/域名: ")
            run_tool(module_class, method, target)
        elif choice in ["4", "12"]:
            domains = get_input("  请输入域名列表 (逗号分隔): ")
            domain_list = [d.strip() for d in domains.split(",") if d.strip()]
            run_tool(module_class, method, domain_list)
        elif choice in ["5"]:
            mac = get_input("  请输入MAC地址: ")
            run_tool(module_class, method, mac)
        elif choice in ["6"]:
            port = get_int_input("  请输入端口 (默认: 8000): ", 1, 65535) or 8000
            directory = get_input("  请输入共享目录路径 (可选): ", required=False)
            run_tool(module_class, method, port, directory or None)
        elif choice in ["7"]:
            port = get_int_input("  请输入监听端口: ", 1, 65535)
            run_tool(module_class, method, port)
        elif choice in ["8"]:
            proxy = get_input("  请输入代理地址 (如: http://127.0.0.1:8080): ")
            test_url = get_input("  请输入测试URL (可选): ", required=False)
            run_tool(module_class, method, proxy, test_url or None)
        elif choice in ["9"]:
            cidr = get_input("  请输入CIDR (如: 192.168.1.0/24): ")
            run_tool(module_class, method, cidr)
        elif choice in ["10"]:
            lport = get_int_input("  本地监听端口: ", 1, 65535)
            rhost = get_input("  远程目标IP: ")
            rport = get_int_input("  远程目标端口: ", 1, 65535)
            run_tool(module_class, method, lport, rhost, rport)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def web_tools_menu():
    """Web工具模块菜单"""
    module_class = load_module("web_tools")
    if not module_class:
        return

    menu_items = [
        ("01", "目录/文件爆破"),
        ("02", "后台管理页面查找"),
        ("03", "CMS 检测"),
        ("04", "备份文件查找"),
        ("05", "网页爬虫"),
        ("06", "链接提取"),
        ("07", "表单分析"),
        ("08", "HTML 注释提取"),
        ("09", "HTTP 方法测试"),
        ("10", "SSL 证书检查"),
        ("11", "WAF 检测"),
        ("12", "参数发现"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "directory_buster", "2": "admin_finder",
        "3": "cms_detector", "4": "backup_file_finder",
        "5": "web_crawler", "6": "link_extractor",
        "7": "form_analyzer", "8": "comment_extractor",
        "9": "http_method_tester", "10": "ssl_checker",
        "11": "waf_detector", "12": "parameter_discovery",
    }

    while True:
        clear_screen()
        print_menu_header("  [05] Web工具模块 - Web Tools  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-12]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        url = get_input("  请输入目标URL: ")
        url = normalize_url(url)

        if choice in ["1"]:
            ext = get_input("  扩展名 (如: php,asp, 逗号分隔, 可选): ", required=False)
            run_tool(module_class, method, url, ext or None)
        elif choice in ["5"]:
            depth = get_int_input("  爬取深度 (默认: 2): ", 1, 10) or 2
            run_tool(module_class, method, url, depth)
        else:
            run_tool(module_class, method, url)

        wait_for_enter()


def password_attacks_menu():
    """密码攻击模块菜单"""
    module_class = load_module("password_attacks")
    if not module_class:
        return

    menu_items = [
        ("01", "密码强度检测"),
        ("02", "密码字典生成器"),
        ("03", "HTTP Basic 认证爆破"),
        ("04", "HTTP 表单认证爆破"),
        ("05", "哈希字典破解"),
        ("06", "ZIP 密码破解"),
        ("07", "默认密码查询"),
        ("08", "常用密码生成器"),
        ("09", "WiFi 密码提取 (Windows)"),
        ("10", "密码分析器"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "password_strength_checker", "2": "wordlist_generator",
        "3": "brute_force_http_basic", "4": "brute_force_http_form",
        "5": "hash_cracker_dictionary", "6": "zip_password_cracker",
        "7": "default_password_checker", "8": "common_password_generator",
        "9": "wifi_password_decrypt", "10": "password_analyzer",
    }

    while True:
        clear_screen()
        print_menu_header("  [06] 密码攻击模块 - Password Attacks  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-10]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1"]:
            pwd = get_input("  请输入要检测的密码: ")
            run_tool(module_class, method, pwd)
        elif choice in ["2"]:
            base_words = get_input("  请输入基础词 (逗号分隔): ")
            words = [w.strip() for w in base_words.split(",") if w.strip()]
            run_tool(module_class, method, words)
        elif choice in ["3"]:
            url = get_input("  请输入目标URL: ")
            user = get_input("  用户名: ")
            passlist = get_input("  密码列表 (逗号分隔): ")
            run_tool(module_class, method, url, user, [p.strip() for p in passlist.split(",") if p.strip()])
        elif choice in ["4"]:
            url = get_input("  请输入目标URL: ")
            user_field = get_input("  用户名字段 (默认: username): ", required=False) or "username"
            pass_field = get_input("  密码字段 (默认: password): ", required=False) or "password"
            user = get_input("  用户名: ")
            passlist = get_input("  密码列表 (逗号分隔): ")
            run_tool(module_class, method, url, user_field, pass_field, user, [p.strip() for p in passlist.split(",") if p.strip()])
        elif choice in ["5"]:
            hash_val = get_input("  请输入哈希值: ")
            hash_type = get_input("  哈希类型 (md5/sha1/sha256, 默认: md5): ", required=False) or "md5"
            wordlist = get_input("  字典文件路径 (可选): ", required=False)
            run_tool(module_class, method, hash_val, hash_type, wordlist or None)
        elif choice in ["6"]:
            zip_path = get_input("  ZIP文件路径: ")
            passlist = get_input("  密码列表 (逗号分隔, 可选): ", required=False)
            run_tool(module_class, method, zip_path, [p.strip() for p in passlist.split(",") if p.strip()] if passlist else None)
        elif choice in ["7"]:
            service = get_input("  请输入服务/设备名称 (可选): ", required=False)
            run_tool(module_class, method, service or None)
        elif choice in ["8"]:
            keyword = get_input("  请输入关键词: ")
            run_tool(module_class, method, keyword)
        elif choice in ["9"]:
            run_tool(module_class, method)
        elif choice in ["10"]:
            passwords = get_input("  请输入密码列表 (逗号分隔): ")
            run_tool(module_class, method, [p.strip() for p in passwords.split(",") if p.strip()])
        else:
            run_tool(module_class, method)

        wait_for_enter()


def crypto_tools_menu():
    """加密/编码工具模块菜单"""
    module_class = load_module("crypto_tools")
    if not module_class:
        return

    menu_items = [
        ("01", "哈希生成器"),
        ("02", "Base64 编码/解码"),
        ("03", "Base32 编码/解码"),
        ("04", "URL 编码/解码"),
        ("05", "Hex 编码/解码"),
        ("06", "凯撒密码"),
        ("07", "ROT13/ROT47"),
        ("08", "XOR 加密/解密"),
        ("09", "维吉尼亚密码"),
        ("10", "进制转换器"),
        ("11", "JWT 解码器"),
        ("12", "摩斯电码"),
        ("13", "Atbash 密码"),
        ("14", "字符频率分析"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "hash_generator", "2": "base64_encode_decode",
        "3": "base32_encode_decode", "4": "url_encode_decode",
        "5": "hex_encode_decode", "6": "caesar_cipher",
        "7": "rot13_cipher", "8": "xor_cipher",
        "9": "vigenere_cipher", "10": "binary_converter",
        "11": "jwt_decoder", "12": "morse_code",
        "13": "atbash_cipher", "14": "char_frequency",
    }

    while True:
        clear_screen()
        print_menu_header("  [07] 加密/编码工具 - Crypto Tools  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-14]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1"]:
            text = get_input("  请输入要哈希的文本: ")
            run_tool(module_class, method, text)
        elif choice in ["2", "3", "4", "5"]:
            text = get_input("  请输入文本: ")
            action = get_input("  操作 (encode/decode, 默认: encode): ", required=False) or "encode"
            run_tool(module_class, method, text, action)
        elif choice in ["6"]:
            text = get_input("  请输入文本: ")
            shift = get_int_input("  移位值 (1-25, 0=暴力破解): ", 0, 25) or 0
            run_tool(module_class, method, text, shift)
        elif choice in ["7"]:
            text = get_input("  请输入文本: ")
            mode = get_input("  模式 (rot13/rot47, 默认: rot13): ", required=False) or "rot13"
            run_tool(module_class, method, text, mode)
        elif choice in ["8"]:
            text = get_input("  请输入文本: ")
            key = get_input("  密钥: ")
            run_tool(module_class, method, text, key)
        elif choice in ["9"]:
            text = get_input("  请输入文本: ")
            key = get_input("  密钥: ")
            action = get_input("  操作 (encrypt/decrypt): ")
            run_tool(module_class, method, text, key, action)
        elif choice in ["10"]:
            value = get_input("  请输入数值: ")
            run_tool(module_class, method, value)
        elif choice in ["11"]:
            token = get_input("  请输入JWT Token: ")
            run_tool(module_class, method, token)
        elif choice in ["12"]:
            text = get_input("  请输入文本: ")
            action = get_input("  操作 (encode/decode): ")
            run_tool(module_class, method, text, action)
        elif choice in ["13"]:
            text = get_input("  请输入文本: ")
            run_tool(module_class, method, text)
        elif choice in ["14"]:
            text = get_input("  请输入文本: ")
            run_tool(module_class, method, text)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def osint_menu():
    """OSINT模块菜单"""
    module_class = load_module("osint_tools")
    if not module_class:
        return

    menu_items = [
        ("01", "邮箱 OSINT"),
        ("02", "用户名搜索"),
        ("03", "电话号码查询"),
        ("04", "IP 追踪"),
        ("05", "域名信誉检查"),
        ("06", "Google Dork 生成器"),
        ("07", "Pastebin 搜索"),
        ("08", "Have I Been Pwned 检查"),
        ("09", "DNS Dumpster 查询"),
        ("10", "社交媒体档案查找"),
        ("11", "邮箱信誉检查"),
        ("12", "泄露信息目录查询"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "email_osint", "2": "username_search", "3": "phone_lookup",
        "4": "ip_tracker", "5": "domain_reputation",
        "6": "google_dork_generator", "7": "pastebin_search",
        "8": "haveibeenpwned_check", "9": "dns_dumpster",
        "10": "social_media_profile", "11": "email_reputation",
        "12": "breach_directory",
    }

    while True:
        clear_screen()
        print_menu_header("  [08] OSINT 模块 - Open Source Intelligence  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-12]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1", "10", "11"]:
            email = get_input("  请输入邮箱地址: ")
            run_tool(module_class, method, email)
        elif choice in ["2"]:
            username = get_input("  请输入用户名: ")
            run_tool(module_class, method, username)
        elif choice in ["3"]:
            phone = get_input("  请输入电话号码: ")
            run_tool(module_class, method, phone)
        elif choice in ["4"]:
            ip = get_input("  请输入IP地址: ")
            run_tool(module_class, method, ip)
        elif choice in ["5", "6", "7", "9"]:
            domain = get_input("  请输入域名: ")
            run_tool(module_class, method, domain)
        elif choice in ["8"]:
            email = get_input("  请输入邮箱或用户名: ")
            run_tool(module_class, method, email)
        elif choice in ["12"]:
            query = get_input("  请输入搜索关键词: ")
            run_tool(module_class, method, query)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def forensic_menu():
    """取证分析模块菜单"""
    module_class = load_module("forensic_tools")
    if not module_class:
        return

    menu_items = [
        ("01", "文件元数据提取"),
        ("02", "隐写检测"),
        ("03", "文件签名分析"),
        ("04", "字符串提取"),
        ("05", "Hex 转储查看器"),
        ("06", "文件类型检测"),
        ("07", "EXIF 数据读取"),
        ("08", "文件雕刻"),
        ("09", "哈希比较"),
        ("10", "熵分析"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "file_metadata_extractor", "2": "stego_detector",
        "3": "file_signature_analyzer", "4": "string_extractor",
        "5": "hex_dump", "6": "file_type_detector",
        "7": "exif_reader", "8": "file_carver",
        "9": "hash_compare", "10": "entropy_analyzer",
    }

    while True:
        clear_screen()
        print_menu_header("  [09] 取证分析模块 - Forensics  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-10]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1", "2", "3", "4", "5", "6", "7", "10"]:
            filepath = get_input("  请输入文件路径: ")
            if os.path.exists(filepath):
                run_tool(module_class, method, filepath)
            else:
                print_error("文件不存在")
        elif choice in ["8"]:
            data_file = get_input("  请输入数据文件路径: ")
            sig = get_input("  请输入文件签名 (如: \x89PNG): ", required=False)
            run_tool(module_class, method, data_file, sig or None)
        elif choice in ["9"]:
            file1 = get_input("  文件1路径: ")
            file2 = get_input("  文件2路径: ")
            alg = get_input("  哈希算法 (md5/sha1/sha256, 默认: md5): ", required=False) or "md5"
            run_tool(module_class, method, file1, file2, alg)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def searchsploit_menu():
    """SearchSploit漏洞库模块菜单"""
    module_class = load_module("searchsploit")
    if not module_class:
        return

    menu_items = [
        ("01", "按关键词搜索漏洞"),
        ("02", "按 CVE 编号搜索"),
        ("03", "列出漏洞分类"),
        ("04", "获取漏洞详情"),
        ("05", "浏览漏洞库"),
        ("06", "按平台搜索"),
        ("07", "按类型搜索"),
        ("08", "漏洞统计信息"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "search_exploit", "2": "search_by_cve",
        "3": "list_categories", "4": "get_exploit_details",
        "5": "exploit_db_browser", "6": "search_by_platform",
        "7": "search_by_type", "8": "exploit_stats",
    }

    while True:
        clear_screen()
        print_menu_header("  [10] SearchSploit 漏洞库 - Exploit Database  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-08]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1"]:
            keyword = get_input("  请输入搜索关键词: ")
            run_tool(module_class, method, keyword)
        elif choice in ["2"]:
            cve = get_input("  请输入CVE编号 (如: CVE-2024-xxx): ")
            run_tool(module_class, method, cve)
        elif choice in ["3"]:
            filter_str = get_input("  筛选关键词 (可选): ", required=False)
            run_tool(module_class, method, filter_str or None)
        elif choice in ["4"]:
            edb_id = get_input("  请输入EDB-ID或CVE编号: ")
            run_tool(module_class, method, edb_id)
        elif choice in ["5"]:
            run_tool(module_class, method)
        elif choice in ["6"]:
            platform = get_input("  请输入平台 (如: windows, linux, webapps): ")
            run_tool(module_class, method, platform)
        elif choice in ["7"]:
            vuln_type = get_input("  请输入漏洞类型 (如: remote, dos, webapps): ")
            run_tool(module_class, method, vuln_type)
        elif choice in ["8"]:
            run_tool(module_class, method)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def utilities_menu():
    """实用工具模块菜单"""
    module_class = load_module("utilities")
    if not module_class:
        return

    menu_items = [
        ("01", "MAC 地址生成器"),
        ("02", "随机字符串生成器"),
        ("03", "IP 子网计算器"),
        ("04", "端口列表生成器"),
        ("05", "文本大小写转换器"),
        ("06", "JSON 格式化工具"),
        ("07", "时间戳转换器"),
        ("08", "User-Agent 生成器"),
        ("09", "UUID 生成器"),
        ("10", "Payload 模糊测试器"),
        ("11", "正则表达式测试器"),
        ("12", "终端颜色测试器"),
        ("13", "随机数据生成器"),
        ("14", "字节单位转换器"),
        ("00", "返回主菜单"),
    ]

    methods_map = {
        "1": "mac_address_generator", "2": "random_string_generator",
        "3": "ip_calculator", "4": "port_list_generator",
        "5": "text_case_converter", "6": "json_formatter",
        "7": "timestamp_converter", "8": "user_agent_generator",
        "9": "uuid_generator", "10": "payload_fuzzer",
        "11": "regex_tester", "12": "color_tester",
        "13": "random_data_generator", "14": "byte_converter",
    }

    while True:
        clear_screen()
        print_menu_header("  [11] 实用工具模块 - Utilities  ")
        print_sub_menu(menu_items)
        print(f"\n  {Colors.DIM}{'─'*70}{Colors.RESET}")
        choice = get_input("  请选择功能 [00-14]: ")

        if choice == "00" or choice is None:
            break

        method = methods_map.get(choice)
        if not method:
            print_error("无效选择")
            wait_for_enter()
            continue

        if choice in ["1"]:
            oui = get_input("  请输入OUI前缀 (可选): ", required=False)
            run_tool(module_class, method, oui or None)
        elif choice in ["2"]:
            length = get_int_input("  长度 (默认: 16): ", 1, 256) or 16
            use_digits = get_input("  包含数字? (y/n, 默认: y): ", required=False) or "y"
            use_special = get_input("  包含特殊字符? (y/n, 默认: n): ", required=False) or "n"
            run_tool(module_class, method, length, use_digits.lower() == 'y', use_special.lower() == 'y')
        elif choice in ["3"]:
            cidr = get_input("  请输入CIDR (如: 192.168.1.0/24): ")
            run_tool(module_class, method, cidr)
        elif choice in ["4"]:
            mode = get_input("  模式 (common/web/all/top100, 默认: common): ", required=False) or "common"
            run_tool(module_class, method, mode)
        elif choice in ["5"]:
            text = get_input("  请输入文本: ")
            case = get_input("  转换类型 (upper/lower/camel/snake/kebab/pascal): ")
            run_tool(module_class, method, text, case)
        elif choice in ["6"]:
            json_str = get_input("  请输入JSON字符串 (或文件路径): ")
            run_tool(module_class, method, json_str)
        elif choice in ["7"]:
            ts = get_input("  请输入时间戳/日期: ")
            run_tool(module_class, method, ts)
        elif choice in ["8"]:
            browser = get_input("  浏览器类型 (chrome/firefox/safari/edge, 可选): ", required=False)
            run_tool(module_class, method, browser or None)
        elif choice in ["9"]:
            ver = get_int_input("  UUID版本 (1/3/4/5, 默认: 4): ", 1, 5) or 4
            run_tool(module_class, method, ver)
        elif choice in ["10"]:
            fuzz_type = get_input("  模糊测试类型 (sqli/xss/lfi/rfi/command_injection/ssrf): ")
            run_tool(module_class, method, fuzz_type)
        elif choice in ["11"]:
            pattern = get_input("  正则表达式: ")
            test_str = get_input("  测试字符串: ")
            run_tool(module_class, method, pattern, test_str)
        elif choice in ["12"]:
            run_tool(module_class, method)
        elif choice in ["13"]:
            region = get_input("  区域 (cn/en, 默认: cn): ", required=False) or "cn"
            count = get_int_input("  生成数量 (默认: 5): ", 1, 100) or 5
            run_tool(module_class, method, region, count)
        elif choice in ["14"]:
            value = get_input("  请输入数值 (如: 1024): ")
            unit = get_input("  单位 (B/KB/MB/GB/TB, 默认: MB): ", required=False) or "MB"
            run_tool(module_class, method, float(value), unit)
        else:
            run_tool(module_class, method)

        wait_for_enter()


def quick_scan_menu():
    """快速扫描菜单 - 常用功能快捷入口"""
    clear_screen()
    print_menu_header("  快速扫描 - Quick Scan  ")

    target = get_input("  请输入目标 (IP/域名/URL): ")
    if not target:
        return

    print_section("快速扫描报告")
    print_info(f"目标: {target}")

    # 1. 解析IP
    ip = get_ip_from_domain(target) if not is_valid_ip(target) else target
    if ip:
        print_success(f"解析IP: {ip}")
    else:
        ip = target

    # 2. 快速端口扫描
    print_info("正在快速端口扫描...")
    open_ports = []
    for port in [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017]:
        if check_port(ip, port, timeout=1):
            open_ports.append((port, get_service_name(port)))
            print_success(f"  端口 {port}/{get_service_name(port)} 开放")

    if not open_ports:
        print_warning("  未发现开放端口")

    # 3. TTL检测
    ttl = get_ttl(ip)
    if ttl:
        os_guess = get_os_from_ttl(ttl)
        print_success(f"TTL: {ttl} - 推测OS: {os_guess}")

    # 4. HTTP头检测
    if is_valid_url(target) or target.startswith(('http://', 'https://')):
        url = normalize_url(target)
        IG = load_module("info_gathering")
        if IG:
            info_gathering = IG(target=url)
            info_gathering.http_headers()

    # 5. 保存结果
    save_results(f"quick_scan_{get_timestamp()}.txt",
                 f"目标: {target}\nIP: {ip}\n开放端口: {open_ports}\nTTL: {ttl}")

    wait_for_enter()


def main():
    """主函数"""
    while True:
        clear_screen()
        print_banner()

        main_menu = [
            ("01", "信息收集模块", "信息收集"),
            ("02", "Web漏洞扫描模块", "漏洞扫描"),
            ("03", "漏洞利用模块", "漏洞利用"),
            ("04", "网络工具模块", "网络工具"),
            ("05", "Web工具模块", "Web工具"),
            ("06", "密码攻击模块", "密码攻击"),
            ("07", "加密/编码工具", "加密工具"),
            ("08", "OSINT 模块", "信息搜集"),
            ("09", "取证分析模块", "取证分析"),
            ("10", "SearchSploit 漏洞库", "漏洞搜索"),
            ("11", "实用工具模块", "实用工具"),
            ("12", "快速扫描", "快捷扫描"),
            ("13", "关于 / 帮助", "帮助"),
            ("00", "退出程序", "退出"),
        ]

        print(f"  {Colors.CYAN}{Colors.BOLD}{'主菜单 - Main Menu':^60}{Colors.RESET}")
        print(f"  {Colors.CYAN}{'─'*60}{Colors.RESET}")

        for key, desc, tag in main_menu:
            color = Colors.GREEN if key not in ["00", "12", "13"] else Colors.YELLOW
            tag_color = Colors.DIM
            print(f"    {color}[{key}]{Colors.RESET}  {Colors.WHITE}{desc:<25}{Colors.RESET} {tag_color}{tag}{Colors.RESET}")

        print(f"\n  {Colors.CYAN}{'─'*60}{Colors.RESET}")
        print(f"  {Colors.GRAY}共 11 个模块, 120+ 安全工具{Colors.RESET}")

        choice = get_input("  请选择 [00-13]: ")

        if choice == "00" or choice is None:
            print(f"\n  {Colors.GREEN}感谢使用 HackerToolkit！再见！{Colors.RESET}")
            sys.exit(0)
        elif choice == "01":
            info_gathering_menu()
        elif choice == "02":
            web_vuln_scan_menu()
        elif choice == "03":
            exploitation_menu()
        elif choice == "04":
            network_tools_menu()
        elif choice == "05":
            web_tools_menu()
        elif choice == "06":
            password_attacks_menu()
        elif choice == "07":
            crypto_tools_menu()
        elif choice == "08":
            osint_menu()
        elif choice == "09":
            forensic_menu()
        elif choice == "10":
            searchsploit_menu()
        elif choice == "11":
            utilities_menu()
        elif choice == "12":
            quick_scan_menu()
        elif choice == "13":
            clear_screen()
            print_about()
            wait_for_enter()
        else:
            print_error("无效选择，请重新输入")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.YELLOW}用户中断程序{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print_error(f"程序异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)