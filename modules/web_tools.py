# -*- coding: utf-8 -*-
"""
Web工具模块 - Web信息收集与安全检测
"""

import requests
import ssl
import socket
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.colors import *
from core.utils import *


class WebTools:
    """Web工具类 - 提供各种Web信息收集与安全检测功能"""

    # 常见目录/文件列表
    COMMON_DIRECTORIES = [
        "admin", "administrator", "login", "wp-admin", "admin.php",
        "manager", "manage", "backend", "dashboard", "panel",
        "cms", "system", "admincp", "adminarea", "webadmin",
        "config", "backup", "db", "database", "sql",
        "phpmyadmin", "phpMyAdmin", "pma", "mysql", "phpPgAdmin",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "api", "api/v1", "api/v2", "v1", "v2",
        "upload", "uploads", "download", "downloads",
        "images", "img", "css", "js", "static", "assets",
        "test", "tests", "debug", "dev", "development",
        "tmp", "temp", "logs", "log", "error_log",
        "install", "setup", "wizard", "upgrade", "update",
        "readme.html", "readme.txt", "license.txt",
        "xmlrpc.php", "wp-includes", "wp-content",
        "index.php", "index.html", "index.htm",
        "default.aspx", "default.php", "default.html",
        "web.config", "info.php", "phpinfo.php", "test.php",
        "server-status", "server-info",
    ]

    # 后台管理路径
    ADMIN_PATHS = [
        "admin", "administrator", "login", "wp-admin", "admin.php",
        "admin/login", "admin/index", "admin/dashboard",
        "adminpanel", "panel", "cpanel", "cp",
        "manager", "manage", "management", "backend",
        "admin/login.php", "admin/index.php", "admin/index.html",
        "administrator/index.php", "administrator/login.php",
        "login.php", "login.html", "login.aspx",
        "signin", "sign-in", "auth", "authenticate",
        "user/login", "user/admin", "users/admin",
        "webadmin", "sysadmin", "adminarea",
        "admincp", "admincp/index.php", "acp",
        "admin/account", "admin/control", "admin/console",
        "bb-admin", "community/admin", "forum/admin",
        "moderator", "mod", "staff", "staff/admin",
        "phpmyadmin", "phpMyAdmin", "pma",
        "admin/backup", "backup/admin",
        "admin/config", "config/admin",
        "admin/db", "dbadmin", "database",
    ]

    # CMS特征
    CMS_SIGNATURES = {
        "WordPress": [
            ("/wp-admin/", "WordPress"),
            ("/wp-content/", "WordPress"),
            ("/wp-includes/", "WordPress"),
            ("/wp-json/", "WordPress"),
            ("/xmlrpc.php", "WordPress"),
            ("/wp-login.php", "WordPress"),
            ("/wp-admin/admin-ajax.php", "WordPress"),
            ("/readme.html", "WordPress"),
            ("/license.txt", "WordPress"),
            ("wp-content/themes", "WordPress"),
            ("wp-content/plugins", "WordPress"),
            ("generator\" content=\"WordPress", "WordPress"),
        ],
        "Joomla": [
            ("/administrator/", "Joomla"),
            ("/components/", "Joomla"),
            ("/modules/", "Joomla"),
            ("/templates/", "Joomla"),
            ("/media/", "Joomla"),
            ("/includes/", "Joomla"),
            ("/language/", "Joomla"),
            ("/cache/", "Joomla"),
            ("/tmp/", "Joomla"),
            ("/logs/", "Joomla"),
            ("/plugins/", "Joomla"),
            ("/index.php?option=", "Joomla"),
            ("/robots.txt", "Joomla"),
            ("generator\" content=\"Joomla", "Joomla"),
            ("com_content", "Joomla"),
            ("com_user", "Joomla"),
            ("com_search", "Joomla"),
            ("com_contact", "Joomla"),
        ],
        "Drupal": [
            ("/sites/", "Drupal"),
            ("/sites/all/", "Drupal"),
            ("/sites/default/", "Drupal"),
            ("/sites/default/files/", "Drupal"),
            ("/sites/default/settings.php", "Drupal"),
            ("/misc/", "Drupal"),
            ("/modules/", "Drupal"),
            ("/profiles/", "Drupal"),
            ("/includes/", "Drupal"),
            ("/themes/", "Drupal"),
            ("/scripts/", "Drupal"),
            ("/update.php", "Drupal"),
            ("/install.php", "Drupal"),
            ("/xmlrpc.php", "Drupal"),
            ("/CHANGELOG.txt", "Drupal"),
            ("Drupal", "Drupal"),
            ("generator\" content=\"Drupal", "Drupal"),
            ("SESS.+Drupal", "Drupal"),
        ],
        "Magento": [
            ("/skin/", "Magento"),
            ("/js/", "Magento"),
            ("/media/", "Magento"),
            ("/app/", "Magento"),
            ("/var/", "Magento"),
            ("/lib/", "Magento"),
            ("/errors/", "Magento"),
            ("/downloader/", "Magento"),
            ("/admin/", "Magento"),
            ("/index.php/admin/", "Magento"),
            ("/cron.php", "Magento"),
            ("/install.php", "Magento"),
            ("/api/", "Magento"),
            ("/api/soap/", "Magento"),
            ("/api/rest/", "Magento"),
            ("Magento", "Magento"),
            ("Varien_Form", "Magento"),
            ("BLANK_IMG", "Magento"),
        ],
        "Discuz": [
            ("/forum.php", "Discuz"),
            ("/forum-", "Discuz"),
            ("/thread-", "Discuz"),
            ("/misc.php", "Discuz"),
            ("/member.php", "Discuz"),
            ("/viewthread.php", "Discuz"),
            ("/admin.php", "Discuz"),
            ("/source/", "Discuz"),
            ("/template/", "Discuz"),
            ("/data/", "Discuz"),
            ("/uc_server/", "Discuz"),
            ("/uc_client/", "Discuz"),
            ("/api/", "Discuz"),
            ("/config/", "Discuz"),
            ("/static/", "Discuz"),
            ("Discuz!", "Discuz"),
            ("Comsenz", "Discuz"),
            ("powered by discuz", "Discuz"),
        ],
        "DedeCMS": [
            ("/dede/", "DedeCMS"),
            ("/include/", "DedeCMS"),
            ("/plus/", "DedeCMS"),
            ("/data/", "DedeCMS"),
            ("/member/", "DedeCMS"),
            ("/templets/", "DedeCMS"),
            ("/tags.php", "DedeCMS"),
            ("/book/", "DedeCMS"),
            ("/group/", "DedeCMS"),
            ("/ask/", "DedeCMS"),
            ("/special/", "DedeCMS"),
            ("DedeCMS", "DedeCMS"),
            ("DedeCms", "DedeCMS"),
            ("powered by dedecms", "DedeCMS"),
        ],
        "PHPWind": [
            ("/wind/", "PHPWind"),
            ("/res/", "PHPWind"),
            ("/attachment/", "PHPWind"),
            ("/html/", "PHPWind"),
            ("/themes/", "PHPWind"),
            ("/admin.php", "PHPWind"),
            ("/windid/", "PHPWind"),
            ("PHPWind", "PHPWind"),
            ("powered by phpwind", "PHPWind"),
        ],
        "ThinkPHP": [
            ("/index.php/Home/", "ThinkPHP"),
            ("/index.php/Admin/", "ThinkPHP"),
            ("/index.php/Index/", "ThinkPHP"),
            ("/Application/", "ThinkPHP"),
            ("/Runtime/", "ThinkPHP"),
            ("/Public/", "ThinkPHP"),
            ("/ThinkPHP/", "ThinkPHP"),
            ("ThinkPHP", "ThinkPHP"),
            ("/index.php?s=", "ThinkPHP"),
        ],
        "Shopify": [
            ("/admin/", "Shopify"),
            ("/cart", "Shopify"),
            ("/checkouts/", "Shopify"),
            ("/collections/", "Shopify"),
            ("/products/", "Shopify"),
            ("/pages/", "Shopify"),
            ("/blogs/", "Shopify"),
            ("myshopify.com", "Shopify"),
            ("cdn.shopify.com", "Shopify"),
            ("shopify", "Shopify"),
        ],
        "Laravel": [
            ("/artisan", "Laravel"),
            ("/storage/", "Laravel"),
            ("/vendor/", "Laravel"),
            ("/bootstrap/", "Laravel"),
            ("/resources/", "Laravel"),
            ("/routes/", "Laravel"),
            ("/app/", "Laravel"),
            ("/config/", "Laravel"),
            ("/database/", "Laravel"),
            ("/public/", "Laravel"),
            ("Laravel", "Laravel"),
            ("X-Powered-By: Laravel", "Laravel"),
        ],
        "SiteServer": [
            ("/siteserver/", "SiteServer"),
            ("SiteServer", "SiteServer"),
        ],
    }

    # 备份文件扩展名
    BACKUP_EXTENSIONS = [
        ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".temp",
        ".swp", ".swo", ".swn", ".~", ".~bk", ".~backup",
        ".sql", ".dump", ".db", ".sqlite", ".sqlite3",
        ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".gz",
        ".txt", ".log", ".txt.bak", ".inc", ".save",
        ".php.bak", ".php.old", ".php~", ".php.1",
        ".asp.bak", ".asp.old", ".aspx.bak",
        ".jsp.bak", ".jsp.old",
        ".conf", ".config", ".cfg", ".ini",
        ".json", ".xml", ".yaml", ".yml",
    ]

    # 备份文件常见名称
    BACKUP_FILES = [
        "config", "db", "database", "backup", "www", "web",
        "site", "root", "home", "data", "sql", "dump",
        "wp-config", "wp-content", "settings", "setting",
        "conn", "connection", "global", "main",
        "index", "default", "admin", "login",
        ".env", ".git", ".svn", ".htaccess",
    ]

    # WAF特征
    WAF_SIGNATURES = {
        "Cloudflare": [
            "cloudflare", "__cfduid", "cf-ray", "cf-cache-status",
            "cloudflare-nginx", "server: cloudflare",
        ],
        "ModSecurity": [
            "mod_security", "modsecurity", "not acceptable",
            "406 not acceptable", "mod_security/",
        ],
        "AWS WAF": [
            "awswaf", "aws-waf", "x-amzn-requestid",
            "x-amz-cf-id", "x-amz-cf-pop",
        ],
        "Akamai": [
            "akamai", "akamaighost", "x-akamai-",
            "x-akamai-transformed", "akamai/",
        ],
        "F5 BIG-IP ASM": [
            "big-ip", "bigip", "f5", "x-wa-info",
            "x-asm-request-id", "x-asm-",
        ],
        "Sucuri": [
            "sucuri", "x-sucuri-", "sucuri/cloudproxy",
            "x-sucuri-cache", "x-sucuri-id",
        ],
        "Barracuda": [
            "barracuda", "barra", "x-barrasession",
            "x-barracuda-",
        ],
        "Imperva": [
            "imperva", "incapsula", "x-iinfo",
            "x-cdn", "incapsula/",
        ],
        "腾讯云WAF": [
            "tencent", "txwaf", "waf.tencent",
            "x-waf-request-id",
        ],
        "阿里云WAF": [
            "aliyun", "aliyundun", "x-waf-",
            "waf.aliyun", "x-aliyundun-",
        ],
        "安全狗": [
            "safedog", "safedog/", "x-safedog-",
            "waf.safedog",
        ],
        "360主机卫士": [
            "360waf", "360-web-guard", "x-360-",
        ],
        "D盾": [
            "d-dun", "d盾", "dkey",
        ],
        "WebKnight": [
            "webknight", "web knight", "x-webknight",
        ],
        "Wordfence": [
            "wordfence", "x-wordfence-",
        ],
        "Comodo WAF": [
            "comodo", "cwaf", "x-cwaf-",
        ],
        "Varnish": [
            "varnish", "x-varnish", "via: 1.1 varnish",
        ],
        "Naxsi": [
            "naxsi", "x-naxsi-", "naxsi/",
        ],
        "Profense": [
            "profense", "pl_", "x-profense-",
        ],
        "DotDefender": [
            "dotdefender", "x-dotdefender-",
        ],
    }

    # HTTP方法测试列表
    HTTP_METHODS = [
        "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE",
        "TRACE", "CONNECT", "PATCH", "MOVE", "COPY",
        "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK",
        "SEARCH", "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY",
        "POLL", "REPORT", "LINK", "UNLINK", "MERGE",
        "BASELINE-CONTROL", "CHECKIN", "CHECKOUT", "MKWORKSPACE",
        "UPDATE", "LABEL", "VERSION-CONTROL",
    ]

    # 常见参数
    COMMON_PARAMETERS = [
        "id", "page", "page_id", "cat", "cat_id", "cate", "category",
        "article_id", "news_id", "product_id", "item_id", "item",
        "user", "user_id", "uid", "username", "uname", "name",
        "pass", "password", "pwd", "passwd",
        "search", "q", "query", "keyword", "keys", "words",
        "file", "filename", "fname", "path", "dir", "folder",
        "url", "link", "redirect", "return", "next", "goto",
        "action", "act", "do", "op", "oper", "cmd", "command",
        "type", "mode", "method", "func", "function",
        "option", "option_id", "opt", "value",
        "msg", "message", "text", "content", "title",
        "lang", "language", "locale", "region",
        "theme", "template", "style", "skin",
        "format", "output", "view", "display",
        "sort", "order", "orderby", "limit", "offset",
        "page_size", "count", "num", "number",
        "email", "mail", "send", "to",
        "debug", "test", "info", "status",
        "token", "session", "sid", "csrf",
        "callback", "jsonp", "ajax",
        "api_key", "apikey", "key", "secret",
        "signature", "sig", "hash",
        "timestamp", "time", "date",
        "version", "ver", "v",
        "host", "hostname", "server", "domain",
        "port", "protocol", "scheme",
        "source", "src", "ref", "referer", "referrer",
        "target", "dest", "destination", "site",
        "upload", "image", "img", "avatar", "photo",
        "attachment", "file_id", "media",
        "r", "callback", "jsoncallback", "jsonp_callback",
        "data", "json", "xml", "format",
        "scope", "grant_type", "response_type",
        "client_id", "client_secret", "redirect_uri",
        "code", "state", "access_token", "refresh_token",
        "admin", "administrator", "root",
        "config", "configure", "setup",
        "install", "uninstall", "delete", "remove",
        "create", "update", "edit", "modify", "save",
        "add", "new", "copy", "clone", "import", "export",
        "enable", "disable", "active", "deactive",
        "ban", "unban", "block", "unblock",
        "approve", "reject", "publish", "unpublish",
        "hide", "show", "visible", "invisible",
        "mobile", "phone", "tel", "phone_number",
        "address", "location", "country", "city", "province",
        "zip", "zipcode", "postal", "postal_code",
        "first_name", "last_name", "full_name", "nickname",
    ]

    def __init__(self, timeout=10, verify_ssl=False, proxies=None):
        """
        初始化WebTools

        Args:
            timeout: 请求超时时间（秒）
            verify_ssl: 是否验证SSL证书
            proxies: 代理设置
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxies:
            self.session.proxies.update(proxies)

    def _request(self, url, method='GET', **kwargs):
        """发送HTTP请求的通用方法"""
        headers = kwargs.pop('headers', {})
        if 'User-Agent' not in headers:
            headers['User-Agent'] = get_random_ua()
        try:
            return self.session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                **kwargs
            )
        except requests.exceptions.SSLError:
            # SSL错误时尝试不验证
            try:
                return self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    **kwargs
                )
            except Exception as e:
                return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None

    def directory_buster(self, url, wordlist=None, threads=10, extensions=None):
        """
        目录/文件爆破

        Args:
            url: 目标URL
            wordlist: 自定义字典（默认使用内置字典）
            threads: 并发线程数
            extensions: 文件扩展名列表（如 ['php', 'asp', 'html']）

        Returns:
            list: 找到的目录/文件列表
        """
        print_section("目录/文件爆破")

        target = normalize_url(url)
        domain = get_domain_from_url(target)
        print_info(f"目标: {target}")
        print_info(f"域名: {domain}")

        wordlist = wordlist or self.COMMON_DIRECTORIES
        ext_list = extensions or ['php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'txt']

        results = []
        found = []

        # 对每个路径，尝试原始和带扩展名的版本
        paths_to_check = []
        for path in wordlist:
            # 如果路径已有扩展名，直接添加
            if '.' in path:
                paths_to_check.append(path)
            else:
                paths_to_check.append(path)
                # 尝试常见扩展名
                for ext in ext_list:
                    paths_to_check.append(f"{path}.{ext}")

        total = len(paths_to_check)
        print_info(f"正在检查 {total} 个路径（使用 {threads} 线程）...")

        def check_path(path):
            full_url = f"{target}/{path}"
            try:
                resp = self._request(full_url)
                if resp is None:
                    return None
                status = resp.status_code
                if status in [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]:
                    size = len(resp.content)
                    return (path, full_url, status, size)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, p): p for p in paths_to_check}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    path, full_url, status, size = result
                    found.append(result)
                    if status in [200, 201, 202, 204]:
                        print_success(f"发现: {full_url} [{status}] ({size} bytes)")
                    elif status in [301, 302, 303, 307, 308]:
                        print_warning(f"重定向: {full_url} [{status}]")
                    elif status in [401, 403]:
                        print_warning(f"受限: {full_url} [{status}]")
                    results.append(result)

        print_info(f"扫描完成，共发现 {len(found)} 个结果")

        # 按状态码排序显示结果
        if found:
            print_success("发现的结果:")
            status_order = {200: 0, 201: 1, 202: 2, 204: 3, 301: 4, 302: 5, 401: 6, 403: 7}
            found.sort(key=lambda x: (status_order.get(x[2], 99), x[0]))
            for path, full_url, status, size in found:
                print(f"  {Colors.CYAN}{full_url:<70}{Colors.RESET} "
                      f"{Colors.GREEN if status < 400 else Colors.YELLOW}[{status}]{Colors.RESET} "
                      f"{Colors.DIM}({size} bytes){Colors.RESET}")

        return results

    def admin_finder(self, url, paths=None, threads=10):
        """
        后台管理页面查找

        Args:
            url: 目标URL
            paths: 自定义后台路径列表
            threads: 并发线程数

        Returns:
            list: 找到的后台页面列表
        """
        print_section("后台管理页面查找")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        paths = paths or self.ADMIN_PATHS
        results = []

        print_info(f"正在检查 {len(paths)} 个常见后台路径（使用 {threads} 线程）...")

        def check_admin(path):
            full_url = f"{target}/{path}"
            try:
                resp = self._request(full_url)
                if resp is None:
                    return None
                status = resp.status_code
                if status in [200, 201, 202, 301, 302, 303, 307, 308]:
                    content_len = len(resp.content)
                    return (path, full_url, status, content_len)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_admin, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, full_url, status, content_len = result
                    results.append(result)
                    if status in [200, 201, 202]:
                        print_success(f"发现后台: {full_url} [{status}] ({content_len} bytes)")
                    else:
                        print_warning(f"可能的后台: {full_url} [{status}]")

        if not results:
            print_warning("未发现已知的后台管理页面")
        else:
            print_success(f"扫描完成，共发现 {len(results)} 个可能的后台路径")

        return results

    def cms_detector(self, url):
        """
        CMS检测

        Args:
            url: 目标URL

        Returns:
            dict: 检测到的CMS信息
        """
        print_section("CMS检测")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        detected_cms = {}
        all_signatures = []

        # 收集所有特征用于检测
        for cms_name, signatures in self.CMS_SIGNATURES.items():
            for sig_path, _ in signatures:
                all_signatures.append((cms_name, sig_path))

        # 第一步：检查URL路径特征
        print_info("正在检测CMS特征...")
        for cms_name, signatures in self.CMS_SIGNATURES.items():
            detected_cms[cms_name] = {"matched": 0, "total": len(signatures), "indicators": []}

        try:
            # 获取首页内容
            resp = self._request(target)
            if resp is None:
                print_error("无法访问目标URL")
                return {}

            body = resp.text
            headers = dict(resp.headers)
            print_info(f"HTTP状态码: {resp.status_code}")
            print_info(f"服务器: {headers.get('Server', 'Unknown')}")
            print_info(f"Content-Type: {headers.get('Content-Type', 'Unknown')}")

            # 检查响应头特征
            for cms_name, signatures in self.CMS_SIGNATURES.items():
                for sig_path, _ in signatures:
                    sig_lower = sig_path.lower()
                    # 检查响应体
                    if sig_lower in body.lower():
                        detected_cms[cms_name]["matched"] += 1
                        detected_cms[cms_name]["indicators"].append(sig_path)
                    # 检查响应头
                    for header_name, header_value in headers.items():
                        header_line = f"{header_name}: {header_value}"
                        if sig_lower in header_line.lower():
                            detected_cms[cms_name]["matched"] += 1
                            detected_cms[cms_name]["indicators"].append(f"Header: {header_line}")

            # 第二步：检查常见路径
            cms_paths = {}
            for cms_name, signatures in self.CMS_SIGNATURES.items():
                for sig_path, _ in signatures:
                    if sig_path.startswith('/'):
                        if cms_name not in cms_paths:
                            cms_paths[cms_name] = []
                        cms_paths[cms_name].append(sig_path)

            # 对每个CMS的路径进行抽样检查
            for cms_name, paths in cms_paths.items():
                check_paths = paths[:5]  # 每个CMS最多检查5个路径
                for path in check_paths:
                    try:
                        check_url = f"{target}{path}"
                        path_resp = self._request(check_url)
                        if path_resp and path_resp.status_code in [200, 301, 302]:
                            detected_cms[cms_name]["matched"] += 1
                            detected_cms[cms_name]["indicators"].append(f"Path found: {path} [{path_resp.status_code}]")
                    except Exception:
                        pass

            # 第三步：输出结果
            print_info("\n检测结果:")
            found_any = False
            for cms_name, info in sorted(detected_cms.items()):
                matched = info["matched"]
                total = info["total"]
                if matched > 0:
                    found_any = True
                    confidence = min(matched / max(total, 1) * 100, 100)
                    if confidence >= 50:
                        print_success(f"{Colors.BOLD}{cms_name}{Colors.RESET}: "
                                      f"{Colors.GREEN}置信度 {confidence:.0f}%{Colors.RESET} "
                                      f"(匹配 {matched}/{total} 项)")
                    elif confidence >= 20:
                        print_warning(f"{Colors.BOLD}{cms_name}{Colors.RESET}: "
                                      f"置信度 {confidence:.0f}% "
                                      f"(匹配 {matched}/{total} 项)")
                    else:
                        print_info(f"{cms_name}: 置信度 {confidence:.0f}% "
                                   f"(匹配 {matched}/{total} 项)")

            if not found_any:
                print_warning("未检测到已知CMS")

            # 清理并返回结果
            result = {
                cms: {
                    "confidence": min(info["matched"] / max(info["total"], 1) * 100, 100),
                    "matched": info["matched"],
                    "total": info["total"],
                    "indicators": info["indicators"][:10],
                }
                for cms, info in detected_cms.items()
                if info["matched"] > 0
            }

            return result

        except Exception as e:
            print_error(f"CMS检测失败: {e}")
            return {}

    def backup_file_finder(self, url, threads=10):
        """
        备份文件查找

        Args:
            url: 目标URL
            threads: 并发线程数

        Returns:
            list: 发现的备份文件列表
        """
        print_section("备份文件查找")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        # 构建备份文件路径列表
        paths_to_check = []

        # 基于备份文件名+扩展名组合
        for name in self.BACKUP_FILES:
            for ext in self.BACKUP_EXTENSIONS:
                paths_to_check.append(f"{name}{ext}")

        # 常见备份文件路径模式
        paths_to_check.extend([
            "backup.zip", "backup.tar.gz", "backup.tar", "backup.rar",
            "backup.sql", "backup.db", "backup.txt",
            "db.zip", "db.tar.gz", "db.sql", "db.rar",
            "database.zip", "database.tar.gz", "database.sql",
            "www.zip", "www.tar.gz", "www.rar",
            "site.zip", "site.tar.gz", "site.rar",
            "web.zip", "web.tar.gz", "web.rar",
            "root.zip", "root.tar.gz",
            "config.zip", "config.tar.gz",
            "wp-config.php.bak", "wp-config.php.old",
            "wp-config.php~", "wp-config.php_",
            "config.php.bak", "config.php.old",
            "conn.php.bak", "conn.asp.bak",
            "index.php.bak", "index.html.bak",
            "default.aspx.bak",
            ".env.bak", ".env.old", ".env.save",
            ".git/config", ".git/HEAD",
            ".svn/entries", ".svn/wc.db",
        ])

        results = []
        print_info(f"正在检查 {len(paths_to_check)} 个备份文件路径（使用 {threads} 线程）...")

        def check_backup(path):
            full_url = f"{target}/{path}"
            try:
                resp = self._request(full_url)
                if resp is None:
                    return None
                status = resp.status_code
                if status in [200, 201, 202]:
                    content_type = resp.headers.get('Content-Type', '')
                    content_len = len(resp.content)
                    # 排除HTML页面，纯备份文件通常不是text/html
                    if 'text/html' not in content_type or content_len < 100:
                        return (path, full_url, content_len, content_type)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_backup, p): p for p in paths_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, full_url, content_len, content_type = result
                    results.append(result)
                    print_success(f"发现备份文件: {full_url}")
                    print_info(f"  大小: {content_len} bytes | 类型: {content_type}")

        if not results:
            print_warning("未发现备份文件")
        else:
            print_success(f"扫描完成，共发现 {len(results)} 个备份文件")

        return results

    def web_crawler(self, url, max_depth=2, max_pages=50):
        """
        网页爬虫 - 提取页面链接

        Args:
            url: 起始URL
            max_depth: 最大爬取深度
            max_pages: 最大爬取页面数

        Returns:
            list: 爬取到的所有链接
        """
        print_section("网页爬虫")

        target = normalize_url(url)
        domain = get_domain_from_url(target)
        print_info(f"目标: {target}")
        print_info(f"域名: {domain}")
        print_info(f"最大深度: {max_depth}, 最大页面数: {max_pages}")

        visited = set()
        links_found = set()
        to_visit = [(target, 0)]
        page_count = 0

        while to_visit and page_count < max_pages:
            current_url, depth = to_visit.pop(0)

            if current_url in visited or depth > max_depth:
                continue

            visited.add(current_url)
            page_count += 1

            print_info(f"[{page_count}/{max_pages}] 爬取: {current_url} (深度: {depth})")

            try:
                resp = self._request(current_url)
                if resp is None:
                    continue

                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                    continue

                body = resp.text

                # 提取所有链接
                link_pattern = re.compile(r'href=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+|\.\.?/[^\s\'">]+)[\'">]', re.I)
                matches = link_pattern.findall(body)

                for link in matches:
                    # 规范化链接
                    full_url = urljoin(current_url, link)
                    full_url = full_url.split('#')[0].split('?')[0]  # 去掉锚点和查询参数
                    full_url = full_url.rstrip('/')

                    if not full_url.startswith(('http://', 'https://')):
                        continue

                    links_found.add(full_url)

                    # 如果链接属于同一域名且未访问，加入待爬取队列
                    link_domain = get_domain_from_url(full_url)
                    if link_domain == domain and full_url not in visited:
                        to_visit.append((full_url, depth + 1))

                print_success(f"  解析到 {len(matches)} 个链接")

            except Exception as e:
                print_error(f"  爬取失败: {e}")
                continue

        print_info(f"\n爬取完成!")
        print_info(f"访问页面: {len(visited)}")
        print_info(f"发现链接: {len(links_found)}")

        # 分类显示链接
        internal_links = [l for l in links_found if get_domain_from_url(l) == domain]
        external_links = [l for l in links_found if get_domain_from_url(l) != domain]

        print_info(f"内部链接: {len(internal_links)}")
        print_info(f"外部链接: {len(external_links)}")

        if internal_links:
            print_info("\n内部链接示例:")
            for link in sorted(internal_links)[:20]:
                print(f"  {Colors.CYAN}{link}{Colors.RESET}")

        return list(links_found)

    def link_extractor(self, url):
        """
        链接提取 - 从单个页面提取所有链接

        Args:
            url: 目标URL

        Returns:
            dict: 分类后的链接
        """
        print_section("链接提取")

        target = normalize_url(url)
        domain = get_domain_from_url(target)
        print_info(f"目标: {target}")

        try:
            resp = self._request(target)
            if resp is None:
                print_error("无法访问目标URL")
                return {}

            body = resp.text
            base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

            # 提取不同类型链接
            # 1. <a href="...">
            a_links = set()
            a_pattern = re.compile(r'<a[^>]+href=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+|\.\.?/[^\s\'">]+)[\'">]', re.I)
            for match in a_pattern.findall(body):
                full_url = urljoin(target, match)
                full_url = full_url.split('#')[0]
                if full_url.startswith(('http://', 'https://')):
                    a_links.add(full_url)

            # 2. <form action="...">
            form_links = set()
            form_pattern = re.compile(r'<form[^>]+action=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+|\.\.?/[^\s\'">]+)[\'">]', re.I)
            for match in form_pattern.findall(body):
                full_url = urljoin(target, match)
                if full_url.startswith(('http://', 'https://')):
                    form_links.add(full_url)

            # 3. <script src="...">
            script_links = set()
            script_pattern = re.compile(r'<script[^>]+src=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+)[\'">]', re.I)
            for match in script_pattern.findall(body):
                full_url = urljoin(target, match)
                if full_url.startswith(('http://', 'https://')):
                    script_links.add(full_url)

            # 4. <link href="...">
            link_links = set()
            link_pattern = re.compile(r'<link[^>]+href=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+)[\'">]', re.I)
            for match in link_pattern.findall(body):
                full_url = urljoin(target, match)
                if full_url.startswith(('http://', 'https://')):
                    link_links.add(full_url)

            # 5. <img src="...">
            img_links = set()
            img_pattern = re.compile(r'<img[^>]+src=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+)[\'">]', re.I)
            for match in img_pattern.findall(body):
                full_url = urljoin(target, match)
                if full_url.startswith(('http://', 'https://')):
                    img_links.add(full_url)

            # 6. <iframe src="...">
            iframe_links = set()
            iframe_pattern = re.compile(r'<iframe[^>]+src=[\'"]?(https?://[^\s\'">]+|/[^\s\'">]+)[\'">]', re.I)
            for match in iframe_pattern.findall(body):
                full_url = urljoin(target, match)
                if full_url.startswith(('http://', 'https://')):
                    iframe_links.add(full_url)

            # 合并所有链接
            all_links = a_links | form_links | script_links | link_links | img_links | iframe_links

            # 分类：内部/外部
            internal = [l for l in all_links if get_domain_from_url(l) == domain]
            external = [l for l in all_links if get_domain_from_url(l) != domain]

            # 去重并按类型展示
            print_success(f"提取完成!")
            print_info(f"  <a> 链接: {len(a_links)}")
            print_info(f"  <form> 链接: {len(form_links)}")
            print_info(f"  <script> 链接: {len(script_links)}")
            print_info(f"  <link> 链接: {len(link_links)}")
            print_info(f"  <img> 链接: {len(img_links)}")
            print_info(f"  <iframe> 链接: {len(iframe_links)}")
            print_info(f"  总链接数: {len(all_links)}")
            print_info(f"  内部链接: {len(internal)}")
            print_info(f"  外部链接: {len(external)}")

            if internal:
                print_info("\n内部链接:")
                for link in sorted(internal)[:15]:
                    print(f"  {Colors.CYAN}{link}{Colors.RESET}")

            if external:
                print_info("\n外部链接:")
                for link in sorted(external)[:15]:
                    print(f"  {Colors.DIM}{link}{Colors.RESET}")

            return {
                "all_links": list(all_links),
                "a_links": list(a_links),
                "form_links": list(form_links),
                "script_links": list(script_links),
                "link_links": list(link_links),
                "img_links": list(img_links),
                "iframe_links": list(iframe_links),
                "internal": internal,
                "external": external,
            }

        except Exception as e:
            print_error(f"链接提取失败: {e}")
            return {}

    def form_analyzer(self, url):
        """
        表单分析

        Args:
            url: 目标URL

        Returns:
            list: 表单信息列表
        """
        print_section("表单分析")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        try:
            resp = self._request(target)
            if resp is None:
                print_error("无法访问目标URL")
                return []

            body = resp.text
            forms = []

            # 提取所有表单
            form_pattern = re.compile(
                r'<form([^>]*)>(.*?)</form>',
                re.I | re.S | re.DOTALL
            )

            form_matches = form_pattern.findall(body)

            if not form_matches:
                print_warning("未发现表单")
                return []

            print_success(f"发现 {len(form_matches)} 个表单")

            for i, (form_attrs, form_content) in enumerate(form_matches, 1):
                form_info = {
                    "id": i,
                    "action": "",
                    "method": "GET",
                    "enctype": "",
                    "inputs": [],
                    "textareas": [],
                    "selects": [],
                    "buttons": [],
                }

                # 解析表单属性
                action_match = re.search(r'action=[\'"]?([^\s\'">]+)[\'">]?', form_attrs, re.I)
                if action_match:
                    form_info["action"] = urljoin(target, action_match.group(1))

                method_match = re.search(r'method=[\'"]?([^\s\'">]+)[\'">]?', form_attrs, re.I)
                if method_match:
                    form_info["method"] = method_match.group(1).upper()

                enctype_match = re.search(r'enctype=[\'"]?([^\s\'">]+)[\'">]?', form_attrs, re.I)
                if enctype_match:
                    form_info["enctype"] = enctype_match.group(1)

                # 提取输入字段
                input_pattern = re.compile(r'<input([^>]*)>', re.I)
                for input_match in input_pattern.findall(form_content):
                    input_info = self._parse_input_tag(input_match)
                    form_info["inputs"].append(input_info)

                # 提取textarea
                textarea_pattern = re.compile(r'<textarea([^>]*)>(.*?)</textarea>', re.I | re.S)
                for ta_match in textarea_pattern.findall(form_content):
                    ta_attrs = ta_match[0]
                    ta_name = re.search(r'name=[\'"]?([^\s\'">]+)', ta_attrs, re.I)
                    form_info["textareas"].append({
                        "name": ta_name.group(1) if ta_name else "unknown",
                        "raw": f"<textarea{ta_attrs}>...</textarea>",
                    })

                # 提取select
                select_pattern = re.compile(r'<select([^>]*)>(.*?)</select>', re.I | re.S)
                for sel_match in select_pattern.findall(form_content):
                    sel_attrs = sel_match[0]
                    sel_name = re.search(r'name=[\'"]?([^\s\'">]+)', sel_attrs, re.I)
                    form_info["selects"].append({
                        "name": sel_name.group(1) if sel_name else "unknown",
                        "raw": f"<select{sel_attrs}>...</select>",
                    })

                # 提取按钮
                button_pattern = re.compile(r'<button([^>]*)>(.*?)</button>', re.I | re.S)
                for btn_match in button_pattern.findall(form_content):
                    btn_attrs = btn_match[0]
                    btn_type = re.search(r'type=[\'"]?([^\s\'">]+)', btn_attrs, re.I)
                    form_info["buttons"].append({
                        "type": btn_type.group(1) if btn_type else "submit",
                        "raw": f"<button{btn_attrs}>...</button>",
                    })

                forms.append(form_info)

                # 显示表单信息
                print_info(f"\n表单 #{i}:")
                print_info(f"  Action: {form_info['action'] or '(当前页面)'}")
                print_info(f"  Method: {form_info['method']}")
                if form_info['enctype']:
                    print_info(f"  Enctype: {form_info['enctype']}")

                # 标记敏感字段
                sensitive_types = {'password', 'email', 'hidden'}
                file_types = {'file'}

                for input_info in form_info["inputs"]:
                    input_type = input_info.get("type", "text")
                    input_name = input_info.get("name", "unknown")
                    icon = Colors.GREEN if input_type in sensitive_types else \
                           Colors.YELLOW if input_type in file_types else \
                           Colors.CYAN
                    print(f"    {icon}[{input_type}]{Colors.RESET} name={input_name}")

                for ta in form_info["textareas"]:
                    print(f"    {Colors.MAGENTA}[textarea]{Colors.RESET} name={ta['name']}")

                for sel in form_info["selects"]:
                    print(f"    {Colors.MAGENTA}[select]{Colors.RESET} name={sel['name']}")

                for btn in form_info["buttons"]:
                    print(f"    {Colors.DIM}[button]{Colors.RESET} type={btn['type']}")

            return forms

        except Exception as e:
            print_error(f"表单分析失败: {e}")
            return []

    def _parse_input_tag(self, tag_content):
        """解析单个input标签属性"""
        input_info = {"type": "text", "name": "", "value": "", "maxlength": ""}

        type_match = re.search(r'type=[\'"]?([^\s\'">]+)', tag_content, re.I)
        if type_match:
            input_info["type"] = type_match.group(1).lower()

        name_match = re.search(r'name=[\'"]?([^\s\'">]+)', tag_content, re.I)
        if name_match:
            input_info["name"] = name_match.group(1)

        value_match = re.search(r'value=[\'"]?([^\s\'">]+)', tag_content, re.I)
        if value_match:
            input_info["value"] = value_match.group(1)

        maxlength_match = re.search(r'maxlength=[\'"]?(\d+)[\'"]?', tag_content, re.I)
        if maxlength_match:
            input_info["maxlength"] = maxlength_match.group(1)

        return input_info

    def comment_extractor(self, url):
        """
        HTML注释提取

        Args:
            url: 目标URL

        Returns:
            list: 提取到的注释列表
        """
        print_section("HTML注释提取")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        try:
            resp = self._request(target)
            if resp is None:
                print_error("无法访问目标URL")
                return []

            body = resp.text

            # 提取HTML注释 <!-- ... -->
            html_comment_pattern = re.compile(r'<!--(.*?)-->', re.I | re.S | re.DOTALL)
            html_comments = html_comment_pattern.findall(body)

            # 提取条件注释 <!--[if ...]> ... <![endif]-->
            cond_comment_pattern = re.compile(r'<!--\[if[^>]*>(.*?)<!\[endif\]-->', re.I | re.S | re.DOTALL)
            cond_comments = cond_comment_pattern.findall(body)

            # 提取JavaScript注释 // 和 /* */
            js_comment_pattern = re.compile(r'/\*(.*?)\*/', re.I | re.S | re.DOTALL)
            js_comments = js_comment_pattern.findall(body)

            # 提取TODO/FIXME/XXX注释
            todo_pattern = re.compile(r'(?:TODO|FIXME|XXX|HACK|BUG|NOTE|OPTIMIZE)[:\s]*(.*?)(?:\n|$)', re.I)
            todo_comments = todo_pattern.findall(body)

            # 合并结果
            all_comments = []

            # 处理HTML注释
            for comment in html_comments:
                stripped = comment.strip()
                if stripped and not stripped.startswith('['):
                    all_comments.append({
                        "type": "HTML",
                        "content": stripped,
                    })

            # 处理条件注释
            for comment in cond_comments:
                stripped = comment.strip()
                if stripped:
                    all_comments.append({
                        "type": "Conditional HTML",
                        "content": stripped[:200],
                    })

            # 处理JS注释
            for comment in js_comments:
                stripped = comment.strip()
                if stripped and len(stripped) > 3:  # 过滤掉空注释
                    all_comments.append({
                        "type": "JavaScript",
                        "content": stripped[:200],
                    })

            # 处理TODO等
            for comment in todo_comments:
                stripped = comment.strip()
                if stripped:
                    all_comments.append({
                        "type": "TODO/FIXME",
                        "content": stripped[:200],
                    })

            # 输出结果
            print_info(f"HTML注释: {len(html_comments)}")
            print_info(f"条件注释: {len(cond_comments)}")
            print_info(f"JavaScript注释: {len(js_comments)}")
            print_info(f"TODO/FIXME标记: {len(todo_comments)}")
            print_info(f"有效注释总数: {len(all_comments)}")

            if all_comments:
                print_info("\n提取到的注释:")
                for i, comment in enumerate(all_comments, 1):
                    comment_type = comment["type"]
                    content = comment["content"]
                    type_color = Colors.GREEN if comment_type == "TODO/FIXME" else \
                                 Colors.YELLOW if comment_type == "HTML" else \
                                 Colors.CYAN

                    print(f"\n  {type_color}[{comment_type}]{Colors.RESET}")
                    # 对敏感内容高亮
                    sensitive_keywords = ['password', 'pass', 'user', 'admin', 'token', 'secret',
                                          'key', 'api', 'todo', 'fixme', 'hack', 'bug', '漏洞',
                                          '密码', '账号', '管理员', '后台']
                    highlighted = content
                    for kw in sensitive_keywords:
                        if kw.lower() in content.lower():
                            highlighted = re.sub(
                                f'({re.escape(kw)})',
                                f'{Colors.BOLD}{Colors.RED}\\1{Colors.RESET}',
                                highlighted,
                                flags=re.I
                            )
                    print(f"    {highlighted}")

            return all_comments

        except Exception as e:
            print_error(f"注释提取失败: {e}")
            return []

    def http_method_tester(self, url, methods=None):
        """
        HTTP方法测试

        Args:
            url: 目标URL
            methods: 要测试的HTTP方法列表

        Returns:
            list: 测试结果
        """
        print_section("HTTP方法测试")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        methods = methods or self.HTTP_METHODS
        results = []

        print_info(f"正在测试 {len(methods)} 个HTTP方法...")

        # 先尝试OPTIONS方法
        print_info("\n尝试 OPTIONS 方法获取允许的方法列表...")
        try:
            options_resp = self._request(target, method='OPTIONS')
            if options_resp:
                allow_header = options_resp.headers.get('Allow', '') or \
                               options_resp.headers.get('Public', '')
                if allow_header:
                    allowed_methods = [m.strip() for m in allow_header.split(',')]
                    print_success(f"服务器允许的方法: {', '.join(allowed_methods)}")
                else:
                    print_warning("OPTIONS响应未返回Allow头")
                    print_info(f"状态码: {options_resp.status_code}")
        except Exception as e:
            print_warning(f"OPTIONS请求失败: {e}")

        print_info("\n逐方法测试...")

        def test_method(method):
            try:
                resp = self._request(target, method=method)
                if resp is None:
                    return {"method": method, "status": 0, "status_text": "Connection Failed", "length": 0}
                status = resp.status_code
                length = len(resp.content)
                return {
                    "method": method,
                    "status": status,
                    "status_text": self._get_status_text(status),
                    "length": length,
                }
            except Exception as e:
                return {"method": method, "status": 0, "status_text": str(e), "length": 0}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_method, m): m for m in methods}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)

        # 按状态码排序
        results.sort(key=lambda x: (x["status"] == 0, x["status"]))

        # 输出结果
        print_info("\n测试结果:")
        headers = ["方法", "状态码", "说明", "响应大小"]
        table_rows = []
        for r in results:
            method = r["method"]
            status = r["status"]
            status_text = r["status_text"]
            length = r["length"]

            if status == 0:
                status_display = f"{Colors.RED}{status}{Colors.RESET}"
                method_display = f"{Colors.DIM}{method}{Colors.RESET}"
            elif status in [200, 201, 202, 204]:
                status_display = f"{Colors.GREEN}{status}{Colors.RESET}"
                method_display = f"{Colors.BOLD}{method}{Colors.RESET}"
            elif status in [301, 302, 303, 307, 308]:
                status_display = f"{Colors.YELLOW}{status}{Colors.RESET}"
                method_display = f"{Colors.YELLOW}{method}{Colors.RESET}"
            elif status in [401, 403, 405, 406]:
                status_display = f"{Colors.CYAN}{status}{Colors.RESET}"
                method_display = f"{Colors.CYAN}{method}{Colors.RESET}"
            else:
                status_display = f"{Colors.WHITE}{status}{Colors.RESET}"
                method_display = f"{Colors.WHITE}{method}{Colors.RESET}"

            print(f"  {method_display:<12} {status_display:<10} {status_text:<20} {length} bytes")
            table_rows.append([method, str(status), status_text, f"{length} bytes"])

        # 安全警告
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "MOVE", "COPY", "MKCOL"]
        enabled_dangerous = [r["method"] for r in results if r["method"] in dangerous_methods and r["status"] in [200, 201, 202, 204, 301, 302, 307]]

        if enabled_dangerous:
            print_warning(f"\n发现危险方法: {', '.join(enabled_dangerous)}")
            for method in enabled_dangerous:
                if method == "PUT":
                    print_warning("  PUT - 可能允许上传文件，存在远程代码执行风险")
                elif method == "DELETE":
                    print_warning("  DELETE - 可能允许删除文件")
                elif method == "TRACE":
                    print_warning("  TRACE - 可能存在跨站脚本攻击风险(XST)")
                elif method == "CONNECT":
                    print_warning("  CONNECT - 可能被用作代理隧道")
                elif method in ["MOVE", "COPY"]:
                    print_warning(f"  {method} - 可能允许操作服务器文件")
                elif method == "MKCOL":
                    print_warning("  MKCOL - 可能允许创建目录")

        return results

    def _get_status_text(self, status_code):
        """获取HTTP状态码说明"""
        status_texts = {
            200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
            301: "Moved", 302: "Found", 303: "See Other", 307: "Temp Redirect",
            308: "Perm Redirect",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
            500: "Server Error", 501: "Not Implemented", 502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_texts.get(status_code, "Unknown")

    def ssl_checker(self, url):
        """
        SSL证书检查

        Args:
            url: 目标URL

        Returns:
            dict: SSL证书信息
        """
        print_section("SSL证书检查")

        target = normalize_url(url)
        # 确保使用HTTPS
        if not target.startswith('https://'):
            target = target.replace('http://', 'https://', 1)
            if not target.startswith('https://'):
                target = 'https://' + target

        print_info(f"目标: {target}")

        domain = get_domain_from_url(target)
        port = 443

        # 检查URL是否包含端口
        parsed = urlparse(target)
        if ':' in parsed.netloc:
            host_part = parsed.netloc.split(':')
            domain = host_part[0]
            try:
                port = int(host_part[1])
            except (ValueError, IndexError):
                port = 443

        print_info(f"域名: {domain}, 端口: {port}")

        try:
            # 创建SSL连接
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((domain, port), timeout=self.timeout)
            ssl_sock = context.wrap_socket(sock, server_hostname=domain)
            cert = ssl_sock.getpeercert()
            ssl_sock.close()

            if not cert:
                print_error("无法获取SSL证书信息")
                return {}

            # 提取证书信息
            cert_info = {}

            # 主题
            subject = dict(x[0] for x in cert.get('subject', []))
            cert_info["subject"] = subject
            print_success("证书主题:")
            for key, value in subject.items():
                print_info(f"  {key}: {value}")

            # 颁发者
            issuer = dict(x[0] for x in cert.get('issuer', []))
            cert_info["issuer"] = issuer
            print_info("\n颁发者:")
            for key, value in issuer.items():
                print_info(f"  {key}: {value}")

            # 有效期
            not_before = cert.get('notBefore', 'N/A')
            not_after = cert.get('notAfter', 'N/A')
            cert_info["not_before"] = not_before
            cert_info["not_after"] = not_after

            print_info("\n有效期:")
            print_info(f"  开始: {not_before}")
            print_info(f"  结束: {not_after}")

            # 计算剩余天数
            try:
                from datetime import datetime
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                remaining_days = (expiry_date - datetime.now()).days
                cert_info["remaining_days"] = remaining_days

                if remaining_days < 0:
                    print_error(f"  证书已过期 {abs(remaining_days)} 天!")
                elif remaining_days < 30:
                    print_warning(f"  证书将在 {remaining_days} 天后过期，请及时续期")
                else:
                    print_success(f"  证书有效，剩余 {remaining_days} 天")
            except Exception:
                pass

            # 主题备用名称 (SAN)
            san_list = []
            for ext in cert.get('subjectAltName', []):
                san_list.append(ext[1])
            cert_info["subject_alt_names"] = san_list

            if san_list:
                print_info(f"\n主题备用名称 (SAN): {len(san_list)} 个")
                for san in san_list[:10]:
                    print_info(f"  - {san}")

            # 序列号
            serial = cert.get('serialNumber', 'N/A')
            cert_info["serial_number"] = serial
            print_info(f"\n序列号: {serial}")

            # SSL版本
            version = ssl_sock.version()
            cert_info["ssl_version"] = version
            print_info(f"SSL/TLS版本: {version}")

            # 密码套件
            cipher = ssl_sock.cipher()
            if cipher:
                cert_info["cipher"] = {
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2],
                }
                print_info(f"密码套件: {cipher[0]}")
                print_info(f"协议版本: {cipher[1]}")
                print_info(f"加密强度: {cipher[2]} bits")

            print_success("\nSSL证书检查完成")
            return cert_info

        except socket.timeout:
            print_error(f"连接超时: {domain}:{port}")
            return {}
        except socket.gaierror:
            print_error(f"域名解析失败: {domain}")
            return {}
        except ssl.SSLError as e:
            print_error(f"SSL错误: {e}")
            return {}
        except ConnectionRefusedError:
            print_error(f"连接被拒绝: {domain}:{port}")
            return {}
        except Exception as e:
            print_error(f"SSL检查失败: {e}")
            return {}

    def waf_detector(self, url):
        """
        WAF检测

        Args:
            url: 目标URL

        Returns:
            dict: WAF检测结果
        """
        print_section("WAF检测")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        result = {
            "detected": False,
            "waf_name": None,
            "confidence": 0,
            "indicators": [],
            "all_matches": {},
        }

        try:
            # 第一步：发送正常请求获取基准响应
            print_info("步骤1: 发送正常请求获取基准...")
            normal_resp = self._request(target)
            if normal_resp is None:
                print_error("无法访问目标URL")
                return result

            normal_status = normal_resp.status_code
            normal_headers = dict(normal_resp.headers)
            normal_body_len = len(normal_resp.content)
            normal_body = normal_resp.text

            print_info(f"  正常响应: 状态码={normal_status}, 大小={normal_body_len} bytes")

            # 第二步：发送恶意请求触发WAF
            print_info("步骤2: 发送恶意请求探测WAF...")

            malicious_payloads = [
                {"type": "SQL注入", "url": f"{target}?id=1' OR '1'='1"},
                {"type": "SQL注入2", "url": f"{target}?id=1 UNION SELECT 1,2,3--"},
                {"type": "XSS", "url": f"{target}?q=<script>alert(1)</script>"},
                {"type": "路径遍历", "url": f"{target}?file=../../../etc/passwd"},
                {"type": "代码执行", "url": f"{target}?cmd=cat+/etc/passwd"},
            ]

            malicious_responses = []
            for payload in malicious_payloads:
                try:
                    resp = self._request(payload["url"])
                    if resp:
                        malicious_responses.append({
                            "type": payload["type"],
                            "status": resp.status_code,
                            "headers": dict(resp.headers),
                            "body_len": len(resp.content),
                            "body": resp.text,
                        })
                except Exception:
                    pass

            # 第三步：分析响应差异
            print_info("步骤3: 分析响应特征...")

            # 检查响应头中的WAF特征
            all_headers = {}
            all_headers.update(normal_headers)
            for mr in malicious_responses:
                all_headers.update(mr["headers"])

            for header_name, header_value in all_headers.items():
                header_line = f"{header_name}: {header_value}"
                header_line_lower = header_line.lower()

                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in header_line_lower:
                            if waf_name not in result["all_matches"]:
                                result["all_matches"][waf_name] = []
                            result["all_matches"][waf_name].append(f"Header: {header_line}")

            # 检查响应体中的WAF特征
            for mr in malicious_responses:
                body_lower = mr["body"].lower()
                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in body_lower:
                            if waf_name not in result["all_matches"]:
                                result["all_matches"][waf_name] = []
                            result["all_matches"][waf_name].append(f"Body: {sig} (in {mr['type']} response)")

            # 检查恶意请求是否被拦截（状态码差异或内容差异）
            for mr in malicious_responses:
                if mr["status"] in [403, 406, 419, 429, 500, 501, 503]:
                    body_lower = mr["body"].lower()
                    waf_indicators = [
                        "blocked", "block", "denied", "deny", "rejected", "forbidden",
                        "waf", "security", "firewall", "attack", "malicious",
                        "suspicious", "mod_security", "modsecurity",
                        "illegal", "injection", "detected", "预警", "拦截",
                        "安全", "防火墙", "攻击", "恶意",
                    ]
                    for indicator in waf_indicators:
                        if indicator in body_lower:
                            result["all_matches"]["Unknown WAF"] = result["all_matches"].get("Unknown WAF", [])
                            result["all_matches"]["Unknown WAF"].append(
                                f"Blocked: {mr['type']} -> {mr['status']} (contains '{indicator}')"
                            )
                            break

            # 检查恶意请求与正常请求的内容长度差异
            for mr in malicious_responses:
                if mr["body_len"] != normal_body_len and mr["status"] != normal_status:
                    if "Unknown WAF" not in result["all_matches"]:
                        result["all_matches"]["Unknown WAF"] = []
                    result["all_matches"]["Unknown WAF"].append(
                        f"Behavior: {mr['type']} -> status={mr['status']} (normal={normal_status}), "
                        f"len={mr['body_len']} (normal={normal_body_len})"
                    )

            # 检查cookie中的WAF特征
            for mr in malicious_responses:
                for cookie_name, cookie_value in mr["headers"].get("Set-Cookie", "").split(";") if "Set-Cookie" in mr["headers"] else []:
                    cookie_line = f"{cookie_name}={cookie_value}"
                    for waf_name, signatures in self.WAF_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in cookie_line.lower():
                                if waf_name not in result["all_matches"]:
                                    result["all_matches"][waf_name] = []
                                result["all_matches"][waf_name].append(f"Cookie: {cookie_line}")

            # 第四步：输出结果
            print_info("\n步骤4: WAF检测结果:")

            if result["all_matches"]:
                # 找出匹配最多的WAF
                best_waf = max(result["all_matches"].items(), key=lambda x: len(x[1]))
                result["waf_name"] = best_waf[0]
                result["indicators"] = best_waf[1]
                result["confidence"] = min(len(best_waf[1]) * 20, 95)
                result["detected"] = True

                print_success(f"检测到WAF: {Colors.BOLD}{result['waf_name']}{Colors.RESET} "
                              f"(置信度: {result['confidence']}%)")
                print_info(f"匹配特征数: {len(result['indicators'])}")

                for indicator in result["indicators"][:5]:
                    print_info(f"  - {indicator}")

                # 显示所有检测到的WAF
                if len(result["all_matches"]) > 1:
                    print_info("\n其他可能的WAF:")
                    for waf_name, indicators in sorted(result["all_matches"].items(), key=lambda x: -len(x[1])):
                        if waf_name != result["waf_name"]:
                            print_info(f"  {waf_name}: {len(indicators)} 个特征")
            else:
                print_info("未检测到WAF特征")
                # 检查是否可能没有WAF
                has_block = any(
                    mr["status"] in [403, 406, 429, 503]
                    for mr in malicious_responses
                )
                if has_block:
                    print_warning("部分恶意请求被拦截，但未识别出具体WAF类型")
                else:
                    print_success("目标似乎没有WAF保护")

            return result

        except Exception as e:
            print_error(f"WAF检测失败: {e}")
            return result

    def parameter_discovery(self, url, params=None, threads=10):
        """
        参数发现 - 探测常见GET/POST参数

        Args:
            url: 目标URL
            params: 自定义参数列表
            threads: 并发线程数

        Returns:
            list: 发现的参数列表
        """
        print_section("参数发现")

        target = normalize_url(url)
        print_info(f"目标: {target}")

        params = params or self.COMMON_PARAMETERS
        results = []

        print_info(f"正在测试 {len(params)} 个常见参数（使用 {threads} 线程）...")

        def test_param(param):
            try:
                # 测试GET参数
                test_url = f"{target}?{param}=1"
                get_resp = self._request(test_url)
                if get_resp is None:
                    return None

                # 与不带参数的请求对比
                base_resp = self._request(target)
                if base_resp is None:
                    return None

                # 判断参数是否有效：响应内容不同 或 状态码不同
                get_body_len = len(get_resp.content)
                base_body_len = len(base_resp.content)

                if get_resp.status_code != base_resp.status_code:
                    # 状态码不同，说明参数被处理
                    return {
                        "param": param,
                        "method": "GET",
                        "status": get_resp.status_code,
                        "base_status": base_resp.status_code,
                        "length_diff": get_body_len - base_body_len,
                        "reason": "状态码变化",
                    }

                if abs(get_body_len - base_body_len) > 50:
                    # 内容长度变化超过50字节，说明参数有效
                    return {
                        "param": param,
                        "method": "GET",
                        "status": get_resp.status_code,
                        "base_status": base_resp.status_code,
                        "length_diff": get_body_len - base_body_len,
                        "reason": "内容长度变化",
                    }

                # 检查响应内容是否包含参数名（反射）
                if param.lower() in get_resp.text.lower()[:5000]:
                    return {
                        "param": param,
                        "method": "GET",
                        "status": get_resp.status_code,
                        "base_status": base_resp.status_code,
                        "length_diff": get_body_len - base_body_len,
                        "reason": "参数值反射",
                    }

            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_param, p): p for p in params}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    results.append(result)
                    param = result["param"]
                    method = result["method"]
                    status = result["status"]
                    reason = result["reason"]
                    length_diff = result["length_diff"]
                    length_str = f"+{length_diff}" if length_diff > 0 else str(length_diff)

                    if reason == "状态码变化":
                        print_warning(f"发现参数: {param} ({method}) [{status}] - {reason}")
                    else:
                        print_success(f"发现参数: {param} ({method}) [{status}] - {reason} (长度{length_str})")

        if not results:
            print_warning("未发现有效参数")
        else:
            print_success(f"\n扫描完成，共发现 {len(results)} 个有效参数")
            # 按状态码分类输出
            print_info("\n有效参数列表:")
            for r in sorted(results, key=lambda x: x["param"]):
                length_str = f"+{r['length_diff']}" if r['length_diff'] > 0 else str(r['length_diff'])
                print(f"  {Colors.CYAN}?{r['param']}=1{Colors.RESET} "
                      f"[{r['status']}] {r['reason']} (长度{length_str})")

        return results

    def run_all(self, url, threads=10):
        """
        运行所有Web工具

        Args:
            url: 目标URL
            threads: 并发线程数

        Returns:
            dict: 所有工具的结果汇总
        """
        print_section("Web工具 - 全面扫描")

        target = normalize_url(url)
        print_info(f"目标: {target}")
        print_info(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print_info("将依次执行以下检测:")
        tools = [
            "CMS检测", "WAF检测", "SSL证书检查", "HTTP方法测试",
            "后台管理页面查找", "目录/文件爆破", "备份文件查找",
            "参数发现", "网页爬虫", "链接提取", "表单分析", "注释提取",
        ]
        for i, tool in enumerate(tools, 1):
            print_info(f"  {i}. {tool}")

        all_results = {}

        # 执行所有检测
        all_results["cms"] = self.cms_detector(target)
        all_results["waf"] = self.waf_detector(target)
        all_results["ssl"] = self.ssl_checker(target)
        all_results["http_methods"] = self.http_method_tester(target)
        all_results["admin"] = self.admin_finder(target, threads=threads)
        all_results["directories"] = self.directory_buster(target, threads=threads)
        all_results["backups"] = self.backup_file_finder(target, threads=threads)
        all_results["params"] = self.parameter_discovery(target, threads=threads)
        all_results["crawled_links"] = self.web_crawler(target, max_depth=1, max_pages=20)
        all_results["links"] = self.link_extractor(target)
        all_results["forms"] = self.form_analyzer(target)
        all_results["comments"] = self.comment_extractor(target)

        # 汇总
        print_section("全面扫描完成")
        summary = {
            "url": target,
            "end_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "cms_detected": bool(all_results.get("cms")),
            "waf_detected": all_results.get("waf", {}).get("detected", False),
            "admin_pages_found": len(all_results.get("admin", [])),
            "directories_found": len(all_results.get("directories", [])),
            "backup_files_found": len(all_results.get("backups", [])),
            "parameters_found": len(all_results.get("params", [])),
            "forms_found": len(all_results.get("forms", [])),
            "comments_found": len(all_results.get("comments", [])),
            "links_found": len(all_results.get("links", {}).get("all_links", [])),
        }

        print_info("扫描摘要:")
        for key, value in summary.items():
            print_info(f"  {key}: {value}")

        return all_results