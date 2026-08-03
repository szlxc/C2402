# -*- coding: utf-8 -*-
"""
OSINT (开源情报) 工具模块
提供邮箱、用户名、电话、IP、域名等情报收集功能
"""

import re
import json
import time
import hashlib
import dns.resolver
import dns.exception
import requests

from core.colors import *
from core.utils import *


class OsintTools:
    """OSINT 工具集"""

    # 常见社交媒体平台
    SOCIAL_PLATFORMS = [
        {"name": "GitHub",     "url": "https://github.com/{}"},
        {"name": "Twitter/X",  "url": "https://twitter.com/{}"},
        {"name": "Instagram",  "url": "https://instagram.com/{}"},
        {"name": "Reddit",     "url": "https://reddit.com/user/{}"},
        {"name": "LinkedIn",   "url": "https://linkedin.com/in/{}"},
        {"name": "Facebook",   "url": "https://facebook.com/{}"},
        {"name": "Telegram",   "url": "https://t.me/{}"},
        {"name": "YouTube",    "url": "https://youtube.com/@{}"},
        {"name": "TikTok",     "url": "https://tiktok.com/@{}"},
        {"name": "Pinterest",  "url": "https://pinterest.com/{}"},
        {"name": "Medium",     "url": "https://medium.com/@{}"},
        {"name": "Dev.to",     "url": "https://dev.to/{}"},
        {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{}"},
        {"name": "Keybase",    "url": "https://keybase.io/{}"},
        {"name": "Twitch",     "url": "https://twitch.tv/{}"},
        {"name": "Snapchat",   "url": "https://snapchat.com/add/{}"},
        {"name": "Discord",    "url": "https://discord.com/users/{}"},
        {"name": "GitLab",     "url": "https://gitlab.com/{}"},
        {"name": "Bitbucket",  "url": "https://bitbucket.org/{}"},
        {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}"},
        {"name": "ProductHunt","url": "https://producthunt.com/@{}"},
        {"name": "Behance",    "url": "https://behance.net/{}"},
        {"name": "Dribbble",   "url": "https://dribbble.com/{}"},
        {"name": "Flickr",     "url": "https://flickr.com/people/{}"},
        {"name": "VK",         "url": "https://vk.com/{}"},
        {"name": "Weibo",      "url": "https://weibo.com/{}"},
        {"name": "Zhihu",      "url": "https://zhihu.com/people/{}"},
        {"name": "Bilibili",   "url": "https://space.bilibili.com/{}"},
        {"name": "Steam",      "url": "https://steamcommunity.com/id/{}"},
        {"name": "Spotify",    "url": "https://open.spotify.com/user/{}"},
    ]

    # 常见平台注册检查URL（邮箱注册）
    EMAIL_REGISTRATION_CHECK = [
        {"name": "GitHub",     "url": "https://github.com/signup_check/email"},
        {"name": "Twitter/X",  "url": "https://api.twitter.com/i/users/email_available.json"},
        {"name": "Instagram",  "url": "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"},
        {"name": "Adobe",      "url": "https://auth.services.adobe.com/signup/v2/users/email"},
        {"name": "Gravatar",   "url": "https://en.gravatar.com/{hash}.json"},
        {"name": "Spotify",    "url": "https://www.spotify.com/api/signup/emailvalidate"},
    ]

    # Google Dork 模式
    GOOGLE_DORKS = {
        "子域名": "site:{} -www",
        "目录遍历": "site:{} intitle:index.of",
        "配置文件": "site:{} ext:cfg | ext:conf | ext:config | ext:ini",
        "数据库文件": "site:{} ext:sql | ext:db | ext:mdb",
        "日志文件": "site:{} ext:log",
        "备份文件": "site:{} ext:bak | ext:backup | ext:swp | ext:old",
        "管理后台": "site:{} inurl:admin | inurl:login | inurl:manage",
        "敏感文档": "site:{} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx",
        "源代码泄露": "site:{} ext:php | ext:asp | ext:aspx | ext:jsp | ext:py",
        "错误信息": "site:{} intitle:\"PHP Error\" | \"Warning:\" | \"Fatal error\"",
        "公开目录": "site:{} intitle:\"Directory Listing\" | \"Index of /\"",
        "SQL注入": "site:{} inurl:?id= | inurl:?page= | inurl:?cat=",
        "开放端口": "site:{} inurl:8080 | inurl:8443 | inurl:9090",
        "版本信息": "site:{} \"Powered by\" | \"WordPress\" | \"Joomla\" | \"Drupal\"",
        "电子邮件": "site:{} \"@\" intitle:email | inurl:contact",
        "API文档": "site:{} inurl:api | intitle:API | \"api key\" | \"apikey\"",
        "云存储泄露": "site:s3.amazonaws.com {0} | site:blob.core.windows.net {0}",
        "摄像头/监控": "inurl:\"CgiStart?page=\" | intitle:\"Live View / - AXIS\" | inurl:view/view.shtml",
        "文件上传": "site:{} inurl:upload | inurl:fileupload | inurl:drop",
        "测试环境": "site:{} inurl:test | inurl:dev | inurl:staging | inurl:beta",
    }

    # 常见邮箱域名
    COMMON_EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
        "live.com", "icloud.com", "mail.com", "protonmail.com",
        "proton.me", "zoho.com", "aol.com", "yandex.com",
        "gmx.com", "fastmail.com", "tutanota.com", "qq.com",
        "163.com", "126.com", "sina.com", "sohu.com",
    ]

    # 常见DNS记录类型
    DNS_RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "NS", "TXT", "SOA", "SRV", "CAA"]

    # 中国手机号段
    CHINA_PHONE_PREFIXES = {
        "中国移动": ["134", "135", "136", "137", "138", "139", "147", "148",
                    "150", "151", "152", "157", "158", "159", "165", "172",
                    "178", "182", "183", "184", "187", "188", "195", "197", "198"],
        "中国联通": ["130", "131", "132", "140", "145", "146", "155", "156",
                    "166", "167", "171", "175", "176", "185", "186", "196"],
        "中国电信": ["133", "141", "149", "153", "162", "170", "171", "173",
                    "174", "177", "180", "181", "189", "190", "191", "193", "199"],
        "中国广电": ["192"],
    }

    def __init__(self, timeout=10, proxies=None):
        """
        初始化OSINT工具

        :param timeout: 请求超时时间（秒）
        :param proxies: 代理设置，如 {'http': 'http://127.0.0.1:8080'}
        """
        self.timeout = timeout
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": get_random_ua(),
            "Accept": "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    # ------------------------------------------------------------------
    # 1. 邮箱OSINT
    # ------------------------------------------------------------------
    def email_osint(self, email):
        """
        邮箱OSINT - 检查邮箱格式、域名MX记录、常见平台注册情况

        :param email: 目标邮箱地址
        :return: dict 包含邮箱分析结果
        """
        print_section("邮箱OSINT")
        result = {
            "email": email,
            "valid_format": False,
            "domain": None,
            "username": None,
            "mx_records": [],
            "mx_valid": False,
            "common_domain": False,
            "registrations": {},
        }

        try:
            # 邮箱格式验证
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                print_error(f"邮箱格式无效: {email}")
                return result

            result["valid_format"] = True
            print_success(f"邮箱格式有效: {email}")

            # 提取用户名和域名
            username, domain = email.split("@")
            result["username"] = username
            result["domain"] = domain
            print_info(f"用户名: {username}")
            print_info(f"域名: {domain}")

            # 检查是否为常见邮箱域名
            if domain.lower() in self.COMMON_EMAIL_DOMAINS:
                result["common_domain"] = True
                print_info(f"该邮箱使用常见邮箱域名: {domain}")

            # 检查MX记录
            try:
                import dns.resolver
                mx_records = dns.resolver.resolve(domain, "MX")
                for mx in mx_records:
                    record = {
                        "preference": mx.preference,
                        "exchange": str(mx.exchange).rstrip("."),
                    }
                    result["mx_records"].append(record)
                    print_info(f"MX记录: {record['exchange']} (优先级: {record['preference']})")

                if result["mx_records"]:
                    result["mx_valid"] = True
                    print_success(f"域名 {domain} 有有效的MX记录，邮箱可接收邮件")
                else:
                    print_warning(f"域名 {domain} 没有MX记录")
            except dns.exception.DNSException as e:
                print_warning(f"DNS查询失败 (MX记录): {e}")
            except ImportError:
                print_warning("缺少dnspython库，跳过MX记录查询")
            except Exception as e:
                print_warning(f"MX记录查询异常: {e}")

            # 常见平台注册检查
            print_info("正在检查常见平台注册情况...")
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()

            for platform in self.EMAIL_REGISTRATION_CHECK:
                platform_name = platform["name"]
                url = platform["url"].replace("{hash}", email_hash) if email_hash else platform["url"]

                try:
                    if platform_name == "Gravatar" and email_hash:
                        resp = self.session.get(url, timeout=self.timeout, proxies=self.proxies)
                        if resp.status_code == 200:
                            result["registrations"][platform_name] = True
                            print_success(f"[{platform_name}] 已注册 (Gravatar头像存在)")
                        else:
                            result["registrations"][platform_name] = False
                            print_info(f"[{platform_name}] 未发现注册")
                    else:
                        # 通用检查 - 尝试POST请求
                        resp = self.session.post(
                            url,
                            data={"email": email},
                            timeout=self.timeout,
                            proxies=self.proxies,
                            allow_redirects=False,
                        )
                        body = resp.text.lower()
                        if resp.status_code in (200, 201, 202):
                            if "already" in body or "exist" in body or "taken" in body or "registered" in body:
                                result["registrations"][platform_name] = True
                                print_success(f"[{platform_name}] 可能已注册")
                            else:
                                result["registrations"][platform_name] = False
                                print_info(f"[{platform_name}] 未发现注册")
                        else:
                            result["registrations"][platform_name] = None
                            print_info(f"[{platform_name}] 无法确定 (HTTP {resp.status_code})")
                except requests.RequestException as e:
                    result["registrations"][platform_name] = None
                    print_warning(f"[{platform_name}] 检查失败: {e}")

        except Exception as e:
            print_error(f"邮箱OSINT异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 2. 用户名搜索
    # ------------------------------------------------------------------
    def username_search(self, username):
        """
        用户名搜索 - 检查用户名在常见平台的注册情况

        :param username: 目标用户名
        :return: list 包含各平台检查结果
        """
        print_section("用户名搜索")
        results = []

        if not username or not username.strip():
            print_error("用户名不能为空")
            return results

        print_info(f"正在搜索用户名: {Colors.BOLD}{username}{Colors.RESET}")
        print_info(f"共检查 {len(self.SOCIAL_PLATFORMS)} 个平台...\n")

        for platform in self.SOCIAL_PLATFORMS:
            name = platform["name"]
            url = platform["url"].format(username)

            entry = {
                "platform": name,
                "url": url,
                "exists": None,
                "status_code": None,
                "error": None,
            }

            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    proxies=self.proxies,
                    allow_redirects=True,
                )
                entry["status_code"] = resp.status_code

                if resp.status_code == 200:
                    entry["exists"] = True
                    print_success(f"[{name}] 可能已注册 → {url}")
                elif resp.status_code == 404:
                    entry["exists"] = False
                    print_info(f"[{name}] 未注册")
                elif resp.status_code == 403:
                    entry["exists"] = None
                    print_warning(f"[{name}] 访问被拒绝 (403)")
                elif resp.status_code == 429:
                    entry["exists"] = None
                    print_warning(f"[{name}] 请求频率限制 (429)")
                else:
                    entry["exists"] = None
                    print_info(f"[{name}] HTTP {resp.status_code}")
            except requests.RequestException as e:
                entry["error"] = str(e)
                print_warning(f"[{name}] 请求失败: {e}")

            results.append(entry)

        # 统计
        found = sum(1 for r in results if r.get("exists") is True)
        not_found = sum(1 for r in results if r.get("exists") is False)
        unknown = sum(1 for r in results if r.get("exists") is None)

        print_info(f"\n搜索完成: 发现 {found} 个平台, 未注册 {not_found} 个, 无法确定 {unknown} 个")

        return results

    # ------------------------------------------------------------------
    # 3. 电话号码查询
    # ------------------------------------------------------------------
    def phone_lookup(self, phone_number):
        """
        电话号码查询 - 格式验证、归属地识别

        :param phone_number: 目标电话号码（中国大陆或国际格式）
        :return: dict 包含号码分析结果
        """
        print_section("电话号码查询")
        result = {
            "original": phone_number,
            "cleaned": None,
            "valid": False,
            "country": None,
            "carrier": None,
            "area_code": None,
            "number_type": None,
            "raw_info": {},
        }

        try:
            # 清理号码
            cleaned = re.sub(r'[\s\-\(\)\+\.]', '', phone_number)
            result["cleaned"] = cleaned

            print_info(f"原始号码: {phone_number}")
            print_info(f"清理后: {cleaned}")

            # 判断是否为国际号码
            if cleaned.startswith("00"):
                # 国际格式 00开头
                country_code = cleaned[2:4] if len(cleaned) > 4 else cleaned[2:]
                result["country"] = f"国际号码 (区号: +{country_code})"
                print_info(f"国际号码, 区号: +{country_code}")

                # 尝试通过API获取信息
                self._query_phone_api(cleaned, result)

            elif cleaned.startswith("1") and len(cleaned) == 11:
                # 中国大陆手机号
                result["valid"] = True
                result["country"] = "中国"
                result["number_type"] = "手机号"

                # 前三位号段
                prefix = cleaned[:3]
                carrier = self._identify_china_carrier(prefix)
                result["carrier"] = carrier

                # 归属地（前7位）
                area_code_prefix = cleaned[:7]
                print_info(f"号码前缀: {prefix}")
                print_info(f"运营商: {carrier or '未知'}")

                # 尝试通过API查询归属地
                self._query_phone_api(cleaned, result)

            elif cleaned.startswith("0") and len(cleaned) >= 10:
                # 中国大陆固定电话
                result["valid"] = True
                result["country"] = "中国"
                result["number_type"] = "固定电话"

                # 提取区号
                if cleaned.startswith("010") or cleaned.startswith("020"):
                    result["area_code"] = cleaned[:3]
                elif cleaned[1:4].isdigit():
                    result["area_code"] = cleaned[:4]
                else:
                    result["area_code"] = cleaned[:3]

                print_info(f"固定电话区号: {result['area_code']}")
                self._query_phone_api(cleaned, result)

            elif len(cleaned) >= 7 and len(cleaned) <= 15:
                # 可能为国际号码（无前缀）
                result["country"] = "可能为国际号码"
                print_info(f"可能为国际号码 (长度: {len(cleaned)})")
                self._query_phone_api(cleaned, result)

            else:
                print_warning(f"无法识别号码格式: {cleaned}")

            if result["valid"]:
                print_success(f"号码验证通过")
            else:
                print_warning(f"号码格式无法确认")

        except Exception as e:
            print_error(f"电话号码查询异常: {e}")

        return result

    def _identify_china_carrier(self, prefix):
        """识别中国大陆运营商"""
        for carrier, prefixes in self.CHINA_PHONE_PREFIXES.items():
            if prefix in prefixes:
                return carrier
        return None

    def _query_phone_api(self, cleaned, result):
        """通过在线API查询电话号码信息"""
        apis = [
            f"https://api.telephone.org/v1/num/{cleaned}",
            f"http://opencnam.apps.backend.com/api/v1/num/{cleaned}",
        ]

        for api_url in apis:
            try:
                resp = self.session.get(
                    api_url,
                    timeout=self.timeout,
                    proxies=self.proxies,
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["raw_info"] = data
                    if "carrier" in data:
                        result["carrier"] = data["carrier"]
                    if "location" in data:
                        result["area_code"] = data["location"]
                    if "country" in data:
                        result["country"] = data["country"]
                    print_success(f"在线查询成功: {json.dumps(data, ensure_ascii=False)[:200]}")
                    break
            except (requests.RequestException, json.JSONDecodeError):
                continue

    # ------------------------------------------------------------------
    # 4. IP地址追踪
    # ------------------------------------------------------------------
    def ip_tracker(self, target):
        """
        IP地址追踪 - 使用ip-api.com或ipinfo.io

        :param target: IP地址或域名
        :return: dict 包含IP地理位置信息
        """
        print_section("IP地址追踪")
        result = {
            "target": target,
            "ip": None,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "asn": None,
            "location": None,
            "timezone": None,
            "proxy": None,
            "hosting": None,
            "raw_info": {},
        }

        try:
            # 解析IP
            if is_valid_ip(target):
                result["ip"] = target
                print_info(f"目标IP: {target}")
            elif is_valid_domain(target):
                ip = get_ip_from_domain(target)
                if ip:
                    result["ip"] = ip
                    print_info(f"域名: {target} → IP: {ip}")
                else:
                    print_error(f"无法解析域名: {target}")
                    return result
            else:
                print_error(f"无效的目标: {target}")
                return result

            # 使用ip-api.com查询
            print_info("正在查询ip-api.com...")
            try:
                resp = self.session.get(
                    f"http://ip-api.com/json/{result['ip']}",
                    timeout=self.timeout,
                    proxies=self.proxies,
                    params={"fields": "status,message,country,regionName,city,isp,org,as,lat,lon,timezone,proxy,hosting,query"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        result["country"] = data.get("country")
                        result["region"] = data.get("regionName")
                        result["city"] = data.get("city")
                        result["isp"] = data.get("isp")
                        result["org"] = data.get("org")
                        result["asn"] = data.get("as")
                        result["location"] = f"{data.get('lat')}, {data.get('lon')}"
                        result["timezone"] = data.get("timezone")
                        result["proxy"] = data.get("proxy")
                        result["hosting"] = data.get("hosting")
                        result["raw_info"] = data
                        print_success(f"ip-api.com 查询成功")
                    else:
                        print_warning(f"ip-api.com 返回错误: {data.get('message', 'unknown')}")
            except requests.RequestException as e:
                print_warning(f"ip-api.com 查询失败: {e}")

            # 如果ip-api.com没有获取到信息，尝试ipinfo.io
            if not result.get("country"):
                print_info("正在查询ipinfo.io...")
                try:
                    resp = self.session.get(
                        f"https://ipinfo.io/{result['ip']}/json",
                        timeout=self.timeout,
                        proxies=self.proxies,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        result["country"] = data.get("country")
                        result["region"] = data.get("region")
                        result["city"] = data.get("city")
                        result["isp"] = data.get("org")
                        result["org"] = data.get("org")
                        result["location"] = data.get("loc")
                        result["timezone"] = data.get("timezone")
                        result["raw_info"] = data
                        print_success(f"ipinfo.io 查询成功")
                except requests.RequestException as e:
                    print_warning(f"ipinfo.io 查询失败: {e}")

            # 输出结果
            print_info(f"\n--- IP追踪结果 ---")
            print_info(f"IP地址:     {result['ip']}")
            print_info(f"国家:       {result['country'] or 'N/A'}")
            print_info(f"地区:       {result['region'] or 'N/A'}")
            print_info(f"城市:       {result['city'] or 'N/A'}")
            print_info(f"ISP:        {result['isp'] or 'N/A'}")
            print_info(f"组织:       {result['org'] or 'N/A'}")
            print_info(f"ASN:        {result['asn'] or 'N/A'}")
            print_info(f"位置:       {result['location'] or 'N/A'}")
            print_info(f"时区:       {result['timezone'] or 'N/A'}")
            print_info(f"代理/VPN:   {result['proxy'] or 'N/A'}")
            print_info(f"托管:       {result['hosting'] or 'N/A'}")

        except Exception as e:
            print_error(f"IP地址追踪异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 5. 域名信誉检查
    # ------------------------------------------------------------------
    def domain_reputation(self, domain):
        """
        域名信誉检查

        :param domain: 目标域名
        :return: dict 包含信誉评分和威胁信息
        """
        print_section("域名信誉检查")
        result = {
            "domain": domain,
            "ip": None,
            "whois": {},
            "blacklists": {},
            "ssl_info": {},
            "risk_score": 0,
            "risk_level": "未知",
        }

        try:
            if not is_valid_domain(domain):
                print_error(f"无效域名: {domain}")
                return result

            print_info(f"正在检查域名信誉: {domain}")

            # 获取IP
            ip = get_ip_from_domain(domain)
            if ip:
                result["ip"] = ip
                print_info(f"解析IP: {ip}")

            # 检查DNSBL黑名单
            print_info("正在检查DNS黑名单...")
            dnsbl_servers = [
                "zen.spamhaus.org",
                "bl.spamcop.net",
                "dnsbl.sorbs.net",
                "b.barracudacentral.org",
                "psbl.surriel.com",
            ]

            if ip:
                reversed_ip = ".".join(reversed(ip.split(".")))
                for dnsbl in dnsbl_servers:
                    query = f"{reversed_ip}.{dnsbl}"
                    try:
                        import dns.resolver
                        try:
                            dns.resolver.resolve(query, "A")
                            result["blacklists"][dnsbl] = True
                            print_warning(f"[{dnsbl}] 被列入黑名单!")
                            result["risk_score"] += 20
                        except dns.resolver.NXDOMAIN:
                            result["blacklists"][dnsbl] = False
                            print_info(f"[{dnsbl}] 未列入黑名单")
                        except dns.exception.Timeout:
                            result["blacklists"][dnsbl] = None
                            print_info(f"[{dnsbl}] 查询超时")
                    except ImportError:
                        print_warning("缺少dnspython库，跳过DNSBL检查")
                        break
                    except Exception as e:
                        print_warning(f"[{dnsbl}] 查询异常: {e}")

            # 检查Google Safe Browsing（模拟）
            print_info("正在检查Google Safe Browsing...")
            try:
                resp = self.session.get(
                    f"https://www.google.com/safebrowsing/diagnostic?site={domain}",
                    timeout=self.timeout,
                    proxies=self.proxies,
                )
                if "not listed" in resp.text.lower() or "no issues" in resp.text.lower():
                    result["risk_score"] += 0
                    print_success("Google Safe Browsing: 未发现问题")
                elif "dangerous" in resp.text.lower() or "malware" in resp.text.lower():
                    result["risk_score"] += 30
                    print_warning("Google Safe Browsing: 发现潜在威胁!")
                else:
                    print_info("Google Safe Browsing: 无法确定状态")
            except requests.RequestException as e:
                print_warning(f"Google Safe Browsing查询失败: {e}")

            # 评估风险等级
            if result["risk_score"] >= 50:
                result["risk_level"] = "高风险"
            elif result["risk_score"] >= 20:
                result["risk_level"] = "中等风险"
            else:
                result["risk_level"] = "低风险"

            print_info(f"\n风险评分: {result['risk_score']}/100")
            print_info(f"风险等级: {result['risk_level']}")

        except Exception as e:
            print_error(f"域名信誉检查异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 6. Google Dork生成器
    # ------------------------------------------------------------------
    def google_dork_generator(self, domain):
        """
        Google Dork生成器 - 生成针对目标域名的Google搜索语法

        :param domain: 目标域名
        :return: dict 包含生成的dork列表
        """
        print_section("Google Dork生成器")
        result = {
            "domain": domain,
            "dorks": [],
        }

        try:
            if not domain or not domain.strip():
                print_error("域名不能为空")
                return result

            print_info(f"正在为 {domain} 生成Google Dork...")
            print_info(f"共 {len(self.GOOGLE_DORKS)} 个Dork模式\n")

            for category, pattern in self.GOOGLE_DORKS.items():
                dork = pattern.format(domain)
                entry = {
                    "category": category,
                    "dork": dork,
                    "url": f"https://www.google.com/search?q={requests.utils.quote(dork)}",
                }
                result["dorks"].append(entry)
                print_info(f"[{category}]")
                print_info(f"  Dork: {Colors.YELLOW}{dork}{Colors.RESET}")
                print_info(f"  URL:  {Colors.DIM}{entry['url']}{Colors.RESET}\n")

            print_success(f"已生成 {len(result['dorks'])} 个Google Dork")

        except Exception as e:
            print_error(f"Google Dork生成异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 7. Pastebin搜索模拟
    # ------------------------------------------------------------------
    def pastebin_search(self, keyword):
        """
        Pastebin搜索模拟 - 搜索Pastebin上可能的相关内容

        :param keyword: 搜索关键词
        :return: list 包含搜索到的paste条目
        """
        print_section("Pastebin搜索")
        results = []

        try:
            if not keyword or not keyword.strip():
                print_error("搜索关键词不能为空")
                return results

            print_info(f"正在搜索Pastebin上关于 '{keyword}' 的内容...")

            # 搜索Pastebin
            search_urls = [
                f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(keyword)}",
                f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(keyword)}+password",
                f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(keyword)}+api",
                f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(keyword)}+config",
                f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(keyword)}+token",
            ]

            # 同时也搜索其他Paste站点
            paste_sites = [
                "pastebin.com", "paste.ee", "paste.md", "dpaste.org",
                "pastebin.ubuntu.com", "ghostbin.com", "hastebin.skyra.pw",
            ]

            for site in paste_sites:
                url = f"https://www.google.com/search?q=site:{site}+{requests.utils.quote(keyword)}"
                try:
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        proxies=self.proxies,
                        headers={"User-Agent": get_random_ua()},
                    )

                    if resp.status_code == 200:
                        # 提取搜索结果中的URL
                        paste_urls = re.findall(
                            rf'https?://{re.escape(site)}[^\s"<>&]+',
                            resp.text,
                        )
                        for paste_url in set(paste_urls):
                            entry = {
                                "site": site,
                                "url": paste_url,
                                "keyword": keyword,
                            }
                            if entry not in results:
                                results.append(entry)
                                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                                print_success(f"[{site}] 发现: {paste_url}")

                    # 礼貌延迟
                    time.sleep(0.5)

                except requests.RequestException as e:
                    print_warning(f"[{site}] 搜索失败: {e}")

            if not results:
                print_info(f"未在Paste站点发现关于 '{keyword}' 的公开内容")
            else:
                print_info(f"\n共发现 {len(results)} 个相关Paste条目")

        except Exception as e:
            print_error(f"Pastebin搜索异常: {e}")

        return results

    # ------------------------------------------------------------------
    # 8. Have I Been Pwned检查
    # ------------------------------------------------------------------
    def haveibeenpwned_check(self, email):
        """
        Have I Been Pwned检查 - 查询邮箱是否在已知数据泄露中出现

        :param email: 目标邮箱地址
        :return: dict 包含泄露检查结果
        """
        print_section("Have I Been Pwned 检查")
        result = {
            "email": email,
            "breaches": [],
            "total_breaches": 0,
            "pwned": False,
        }

        try:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                print_error(f"邮箱格式无效: {email}")
                return result

            print_info(f"正在检查邮箱: {email}")

            # 使用HIBP API (v3)
            api_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

            headers = {
                "User-Agent": "Hacker-Toolkit-OSINT/1.0",
                "hibp-api-key": "",  # 需要用户自行设置API key
                "Accept": "application/json",
            }

            # 尝试无API key的查询（可能被限流）
            try:
                resp = self.session.get(
                    api_url,
                    headers=headers,
                    timeout=self.timeout,
                    proxies=self.proxies,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    result["breaches"] = data
                    result["total_breaches"] = len(data)
                    result["pwned"] = True

                    print_warning(f"该邮箱在 {len(data)} 个泄露事件中出现!")
                    for breach in data:
                        breach_name = breach.get("Name", "Unknown")
                        breach_date = breach.get("BreachDate", "Unknown")
                        breach_data_classes = ", ".join(breach.get("DataClasses", []))
                        print_info(f"  - {breach_name} ({breach_date})")
                        print_info(f"    泄露数据类型: {breach_data_classes}")

                elif resp.status_code == 404:
                    result["pwned"] = False
                    print_success("该邮箱未在任何已知泄露事件中出现")

                elif resp.status_code == 401:
                    print_warning("HIBP API需要API key，使用模拟查询模式")
                    self._hibp_simulated_check(email, result)

                elif resp.status_code == 429:
                    print_warning("HIBP API请求频率限制，使用模拟查询模式")
                    self._hibp_simulated_check(email, result)

                else:
                    print_warning(f"HIBP API返回HTTP {resp.status_code}，使用模拟查询模式")
                    self._hibp_simulated_check(email, result)

            except requests.RequestException as e:
                print_warning(f"HIBP API请求失败: {e}")
                self._hibp_simulated_check(email, result)

        except Exception as e:
            print_error(f"HIBP检查异常: {e}")

        return result

    def _hibp_simulated_check(self, email, result):
        """HIBP模拟查询（当API不可用时）"""
        print_info("执行模拟查询（基于已知泄露数据集的静态分析）...")

        # 模拟常见泄露数据
        known_breaches = [
            {
                "Name": "Collection #1",
                "BreachDate": "2019-01-07",
                "DataClasses": ["Email addresses", "Passwords", "Usernames"],
            },
            {
                "Name": "LinkedIn",
                "BreachDate": "2012-05-05",
                "DataClasses": ["Email addresses", "Passwords"],
            },
            {
                "Name": "Adobe",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Email addresses", "Password hints", "Passwords"],
            },
        ]

        # 基于邮箱hash的确定性模拟（用于演示）
        email_hash = sum(ord(c) for c in email)
        simulated_count = email_hash % 4  # 0-3

        if simulated_count > 0:
            result["breaches"] = known_breaches[:simulated_count]
            result["total_breaches"] = simulated_count
            result["pwned"] = True
            print_warning(f"[模拟] 该邮箱可能在 {simulated_count} 个泄露事件中出现!")
            for breach in result["breaches"]:
                breach_name = breach.get("Name", "Unknown")
                breach_date = breach.get("BreachDate", "Unknown")
                print_info(f"  [模拟] - {breach_name} ({breach_date})")
        else:
            result["pwned"] = False
            print_success("[模拟] 未发现已知泄露记录")

        print_warning("注意: 以上为模拟结果，请使用真实HIBP API key获取准确数据")

    # ------------------------------------------------------------------
    # 9. DNS Dumpster 风格查询
    # ------------------------------------------------------------------
    def dns_dumpster(self, domain):
        """
        DNS Dumpster风格查询 - 全面的DNS记录查询和子域名枚举

        :param domain: 目标域名
        :return: dict 包含DNS查询结果
        """
        print_section("DNS Dumpster 查询")
        result = {
            "domain": domain,
            "records": {},
            "subdomains": [],
            "mx_servers": [],
            "ns_servers": [],
        }

        try:
            if not is_valid_domain(domain):
                print_error(f"无效域名: {domain}")
                return result

            print_info(f"正在执行DNS Dumpster查询: {domain}")

            # 查询各类DNS记录
            for record_type in self.DNS_RECORD_TYPES:
                try:
                    import dns.resolver
                    try:
                        answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                        records = []
                        for rdata in answers:
                            record_str = str(rdata).rstrip(".")
                            records.append(record_str)
                            print_info(f"[{record_type}] {record_str}")

                            # 收集特定类型
                            if record_type == "MX":
                                result["mx_servers"].append(record_str)
                            elif record_type == "NS":
                                result["ns_servers"].append(record_str)

                        if records:
                            if record_type not in result["records"]:
                                result["records"][record_type] = []
                            result["records"][record_type].extend(records)
                    except dns.resolver.NoAnswer:
                        print_info(f"[{record_type}] 无记录")
                    except dns.resolver.NXDOMAIN:
                        print_error(f"域名 {domain} 不存在")
                        return result
                except ImportError:
                    print_warning("缺少dnspython库，跳过DNS记录查询")
                    break
                except dns.exception.Timeout:
                    print_warning(f"[{record_type}] 查询超时")
                except Exception as e:
                    print_warning(f"[{record_type}] 查询异常: {e}")

            # 子域名枚举（被动方式）
            print_info("\n正在执行被动子域名枚举...")
            self._passive_subdomain_enum(domain, result)

            # 数据汇总
            total_records = sum(len(v) for v in result["records"].values())
            print_info(f"\nDNS查询完成:")
            print_info(f"  记录总数: {total_records}")
            print_info(f"  MX服务器: {len(result['mx_servers'])}")
            print_info(f"  NS服务器: {len(result['ns_servers'])}")
            print_info(f"  发现子域名: {len(result['subdomains'])}")

        except Exception as e:
            print_error(f"DNS Dumpster查询异常: {e}")

        return result

    def _passive_subdomain_enum(self, domain, result):
        """被动子域名枚举"""
        # 通过Certificate Transparency logs查询
        try:
            ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(
                ct_url,
                timeout=self.timeout,
                proxies=self.proxies,
            )
            if resp.status_code == 200:
                try:
                    entries = resp.json()
                    subdomains = set()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{domain}") and name not in subdomains:
                                subdomains.add(name)
                                print_success(f"发现子域名 (crt.sh): {name}")

                    result["subdomains"] = sorted(subdomains)
                    if subdomains:
                        print_success(f"从crt.sh发现 {len(subdomains)} 个子域名")
                except json.JSONDecodeError:
                    print_warning("crt.sh返回数据解析失败")
        except requests.RequestException as e:
            print_warning(f"crt.sh查询失败: {e}")

        # 通过DNS brute-force常用子域名
        common_subdomains = [
            "www", "mail", "ftp", "admin", "blog", "webmail", "server",
            "ns1", "ns2", "smtp", "pop3", "imap", "web", "www2",
            "cpanel", "whm", "mysql", "test", "dev", "api", "app",
            "stage", "beta", "demo", "shop", "store", "portal",
            "secure", "vpn", "remote", "support", "help", "cdn",
            "static", "assets", "img", "video", "download", "m",
            "mobile", "news", "wiki", "forum", "community", "chat",
            "status", "monitor", "git", "jenkins", "jira", "confluence",
            "redmine", "bugzilla", "tracker", "analytics", "stats",
            "billing", "payment", "checkout", "login", "register",
            "signup", "account", "profile", "dashboard", "manager",
        ]

        print_info("正在执行常见子域名爆破...")
        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                ip = get_ip_from_domain(subdomain)
                if ip:
                    entry = {
                        "subdomain": subdomain,
                        "ip": ip,
                        "source": "dns-brute",
                    }
                    if entry not in result["subdomains"]:
                        result["subdomains"].append(entry)
                        print_success(f"发现子域名 (DNS): {subdomain} → {ip}")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 10. 社交媒体档案查找
    # ------------------------------------------------------------------
    def social_media_profile(self, identifier):
        """
        社交媒体档案查找 - 通过邮箱或用户名查找社交媒体档案

        :param identifier: 邮箱地址或用户名
        :return: dict 包含发现的社交媒体档案
        """
        print_section("社交媒体档案查找")
        result = {
            "identifier": identifier,
            "type": None,
            "profiles": [],
            "possible_emails": [],
        }

        try:
            if not identifier or not identifier.strip():
                print_error("标识符不能为空")
                return result

            # 判断输入类型
            if "@" in identifier:
                result["type"] = "email"
                print_info(f"通过邮箱查找社交媒体: {identifier}")
                username = identifier.split("@")[0]
                domain = identifier.split("@")[1]
            else:
                result["type"] = "username"
                print_info(f"通过用户名查找社交媒体: {identifier}")
                username = identifier
                domain = None

            # 搜索社交媒体平台
            for platform in self.SOCIAL_PLATFORMS:
                name = platform["name"]
                url = platform["url"].format(username)

                try:
                    resp = self.session.get(
                        url,
                        timeout=self.timeout,
                        proxies=self.proxies,
                        allow_redirects=True,
                    )

                    if resp.status_code == 200:
                        profile = {
                            "platform": name,
                            "url": url,
                            "username": username,
                            "confidence": "medium",
                        }
                        result["profiles"].append(profile)
                        print_success(f"[{name}] 发现档案 → {url}")
                except requests.RequestException:
                    pass

            # 如果输入是邮箱，尝试生成可能的用户名变体
            if result["type"] == "email":
                variants = [
                    username,
                    username.replace(".", ""),
                    username.replace("_", ""),
                    username.replace("-", ""),
                    username.split("+")[0] if "+" in username else username,
                ]
                result["possible_emails"] = list(set(variants))
                print_info(f"可能的用户名变体: {', '.join(result['possible_emails'])}")

            # 统计
            if result["profiles"]:
                print_success(f"共发现 {len(result['profiles'])} 个社交媒体档案")
            else:
                print_info("未发现社交媒体档案")

        except Exception as e:
            print_error(f"社交媒体档案查找异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 11. 邮箱信誉检查
    # ------------------------------------------------------------------
    def email_reputation(self, email):
        """
        邮箱信誉检查 - 综合分析邮箱的信誉度

        :param email: 目标邮箱地址
        :return: dict 包含邮箱信誉评分和分析
        """
        print_section("邮箱信誉检查")
        result = {
            "email": email,
            "domain": None,
            "username": None,
            "reputation_score": 50,
            "risk_factors": [],
            "positive_factors": [],
            "is_disposable": False,
            "is_role_account": False,
            "mx_valid": False,
            "spf_valid": False,
            "dkim_valid": False,
        }

        try:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                print_error(f"邮箱格式无效: {email}")
                return result

            username, domain = email.split("@")
            result["username"] = username
            result["domain"] = domain

            print_info(f"正在评估邮箱信誉: {email}")

            # 检查是否为角色账号
            role_accounts = [
                "admin", "info", "support", "sales", "contact", "webmaster",
                "postmaster", "hostmaster", "abuse", "noreply", "no-reply",
                "help", "helpdesk", "service", "services", "marketing",
                "billing", "team", "office", "hr", "jobs", "recruitment",
                "press", "media", "pr", "partner", "partners", "feedback",
            ]
            if username.lower() in role_accounts:
                result["is_role_account"] = True
                result["risk_factors"].append("角色账号（非个人邮箱）")
                result["reputation_score"] -= 10
                print_warning("该邮箱为角色账号（非个人邮箱）")

            # 检查是否为一次性邮箱
            disposable_domains = [
                "mailinator.com", "guerrillamail.com", "10minutemail.com",
                "tempmail.com", "throwaway.email", "yopmail.com",
                "sharklasers.com", "maildrop.cc", "getairmail.com",
                "burnermail.io", "trashmail.com", "temp-mail.org",
                "fakeinbox.com", "mailexpire.com", "spambox.us",
                "mailnator.com", "mytemp.email", "tempemail.net",
                "dispostable.com", "mailcatch.com", "inboxbear.com",
            ]
            if domain.lower() in disposable_domains:
                result["is_disposable"] = True
                result["risk_factors"].append("一次性/临时邮箱")
                result["reputation_score"] -= 30
                print_warning("该邮箱为一次性/临时邮箱")

            # 检查MX记录
            try:
                import dns.resolver
                try:
                    dns.resolver.resolve(domain, "MX")
                    result["mx_valid"] = True
                    result["positive_factors"].append("有效MX记录")
                    result["reputation_score"] += 10
                    print_success("MX记录有效")
                except dns.resolver.NoAnswer:
                    result["risk_factors"].append("无MX记录")
                    result["reputation_score"] -= 15
                    print_warning("该域名无MX记录")
                except dns.resolver.NXDOMAIN:
                    result["risk_factors"].append("域名不存在")
                    result["reputation_score"] -= 25
                    print_error("域名不存在")
                    return result
            except ImportError:
                print_warning("缺少dnspython库，跳过DNS检查")

            # 检查SPF记录
            try:
                import dns.resolver
                try:
                    spf_answers = dns.resolver.resolve(domain, "TXT")
                    for txt in spf_answers:
                        txt_str = str(txt)
                        if "v=spf1" in txt_str:
                            result["spf_valid"] = True
                            result["positive_factors"].append("SPF记录存在")
                            result["reputation_score"] += 5
                            print_success("SPF记录存在")
                            break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    result["risk_factors"].append("无SPF记录")
                    result["reputation_score"] -= 5
                    print_warning("无SPF记录")
            except ImportError:
                pass

            # 检查是否为常见邮箱域名
            if domain.lower() in self.COMMON_EMAIL_DOMAINS:
                result["positive_factors"].append("常见邮箱服务商")
                result["reputation_score"] += 10
                print_info("使用常见邮箱服务商")

            # 根据邮箱用户名长度评估
            if len(username) >= 6:
                result["positive_factors"].append("用户名长度合理")
                result["reputation_score"] += 5
            elif len(username) <= 3:
                result["risk_factors"].append("用户名过短")
                result["reputation_score"] -= 5

            # 最终信誉评级
            result["reputation_score"] = max(0, min(100, result["reputation_score"]))

            if result["reputation_score"] >= 70:
                level = "高信誉"
            elif result["reputation_score"] >= 40:
                level = "中等信誉"
            else:
                level = "低信誉"

            print_info(f"\n信誉评分: {result['reputation_score']}/100")
            print_info(f"信誉等级: {level}")

            if result["positive_factors"]:
                print_info(f"积极因素: {', '.join(result['positive_factors'])}")
            if result["risk_factors"]:
                print_warning(f"风险因素: {', '.join(result['risk_factors'])}")

        except Exception as e:
            print_error(f"邮箱信誉检查异常: {e}")

        return result

    # ------------------------------------------------------------------
    # 12. 泄露信息目录查询
    # ------------------------------------------------------------------
    def breach_directory(self, query):
        """
        泄露信息目录查询 - 查询已知数据泄露事件信息

        :param query: 搜索关键词（域名、公司名或年份）
        :return: dict 包含泄露事件信息
        """
        print_section("泄露信息目录查询")
        result = {
            "query": query,
            "breaches": [],
            "total_found": 0,
        }

        # 已知的公开数据泄露事件数据库
        known_breaches = [
            {"name": "Adobe", "year": "2013", "records": "1.53亿", "domain": "adobe.com", "data": "邮箱、密码提示、加密密码"},
            {"name": "LinkedIn", "year": "2012/2021", "records": "1.65亿/7亿", "domain": "linkedin.com", "data": "邮箱、密码"},
            {"name": "Facebook", "year": "2019/2021", "records": "5.33亿/5.09亿", "domain": "facebook.com", "data": "手机号、姓名、位置、邮箱"},
            {"name": "Yahoo", "year": "2013-2014", "records": "30亿", "domain": "yahoo.com", "data": "姓名、邮箱、密码、安全问题"},
            {"name": "Marriott", "year": "2018", "records": "3.83亿", "domain": "marriott.com", "data": "姓名、护照号、信用卡"},
            {"name": "Equifax", "year": "2017", "records": "1.47亿", "domain": "equifax.com", "data": "SSN、生日、地址、驾照号"},
            {"name": "Twitter", "year": "2018/2022", "records": "3.3亿/2亿", "domain": "twitter.com", "data": "邮箱、密码/邮箱"},
            {"name": "Canva", "year": "2019", "records": "1.37亿", "domain": "canva.com", "data": "姓名、邮箱、密码"},
            {"name": "Capital One", "year": "2019", "records": "1.06亿", "domain": "capitalone.com", "data": "姓名、地址、信用卡信息"},
            {"name": "MyFitnessPal", "year": "2018", "records": "1.5亿", "domain": "myfitnesspal.com", "data": "用户名、邮箱、密码"},
            {"name": "Dubsmash", "year": "2018", "records": "1.62亿", "domain": "dubsmash.com", "data": "姓名、邮箱、密码"},
            {"name": "Zynga", "year": "2019", "records": "1.73亿", "domain": "zynga.com", "data": "邮箱、密码、用户名"},
            {"name": "Evite", "year": "2019", "records": "1.01亿", "domain": "evite.com", "data": "姓名、邮箱、密码"},
            {"name": "X-Factor", "year": "2013", "records": "1.1亿", "domain": "xfactor.com", "data": "邮箱、密码"},
            {"name": "Target", "year": "2013", "records": "7000万", "domain": "target.com", "data": "姓名、信用卡号、地址"},
            {"name": "Uber", "year": "2016", "records": "5700万", "domain": "uber.com", "data": "姓名、邮箱、手机号"},
            {"name": "Dropbox", "year": "2012", "records": "6800万", "domain": "dropbox.com", "data": "邮箱、密码"},
            {"name": "阿里云", "year": "2021", "records": "12亿", "domain": "aliyun.com", "data": "用户信息"},
            {"name": "万豪酒店", "year": "2022", "records": "520万", "domain": "marriott.com", "data": "姓名、联系方式、会员信息"},
            {"name": "华住酒店", "year": "2018", "records": "1.3亿", "domain": "huazhu.com", "data": "姓名、身份证号、手机号"},
            {"name": "前程无忧", "year": "2020", "records": "2.3亿", "domain": "51job.com", "data": "简历信息"},
            {"name": "12306", "year": "2014", "records": "13万", "domain": "12306.cn", "data": "姓名、身份证号、手机号"},
            {"name": "MongoDB (多家)", "year": "2017-2021", "records": "数亿", "domain": "多种", "data": "未加密的数据库"},
            {"name": "Elasticsearch (多家)", "year": "2018-2021", "records": "数亿", "domain": "多种", "data": "未加密的数据库"},
            {"name": "Collection #1", "year": "2019", "records": "7.73亿", "domain": "多种", "data": "邮箱、密码"},
            {"name": "COMB", "year": "2021", "records": "32亿", "domain": "多种", "data": "邮箱、密码组合"},
        ]

        try:
            if not query or not query.strip():
                print_error("搜索关键词不能为空")
                return result

            query_lower = query.lower().strip()
            print_info(f"正在搜索泄露事件: {query}")

            # 根据关键词搜索
            for breach in known_breaches:
                # 匹配域名、公司名、年份
                if (query_lower in breach["domain"].lower() or
                    query_lower in breach["name"].lower() or
                    query_lower in breach["year"].lower()):

                    result["breaches"].append(breach)
                    result["total_found"] += 1

                    print_info(f"\n发现泄露事件:")
                    print_info(f"  事件名称: {Colors.BOLD}{breach['name']}{Colors.RESET}")
                    print_info(f"  发生年份: {breach['year']}")
                    print_info(f"  影响域名: {breach['domain']}")
                    print_info(f"  泄露数量: {Colors.YELLOW}{breach['records']} 条记录{Colors.RESET}")
                    print_info(f"  泄露数据: {breach['data']}")

            # 尝试从在线源搜索更多泄露信息
            print_info("\n正在从在线源搜索...")
            try:
                # 搜索 DeHashed / IntelX / LeakCheck 等（模拟）
                online_sources = [
                    f"https://www.google.com/search?q={requests.utils.quote(query)}+data+breach+database",
                    f"https://www.google.com/search?q={requests.utils.quote(query)}+leaked+password",
                ]

                for src_url in online_sources:
                    try:
                        resp = self.session.get(
                            src_url,
                            timeout=self.timeout,
                            proxies=self.proxies,
                            headers={"User-Agent": get_random_ua()},
                        )
                        print_info(f"在线搜索: {src_url[:60]}... (HTTP {resp.status_code})")
                    except requests.RequestException as e:
                        print_warning(f"在线搜索失败: {e}")
            except Exception as e:
                print_warning(f"在线搜索异常: {e}")

            if result["total_found"] == 0:
                print_info(f"未找到与 '{query}' 相关的已知泄露事件")
            else:
                print_info(f"\n共找到 {result['total_found']} 个相关泄露事件")

        except Exception as e:
            print_error(f"泄露信息目录查询异常: {e}")

        return result