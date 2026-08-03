# -*- coding: utf-8 -*-
"""
密码学/编码工具模块 - 渗透测试工具包
"""

import hashlib
import base64
import json
import string
from urllib.parse import quote, unquote
from core.colors import *
from core.utils import *


class CryptoTools:
    """密码学/编码工具箱"""

    @staticmethod
    def hash_generator(text, algorithms=None):
        """哈希生成 (MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160, Blake2b, Blake2s, SHA3)"""
        print_section("哈希生成器")

        if not text:
            print_error("请输入要哈希的文本")
            return None

        if algorithms is None:
            algorithms = [
                'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                'ripemd160', 'blake2b', 'blake2s', 'sha3_256', 'sha3_512'
            ]

        data = text.encode('utf-8')
        results = {}

        try:
            for algo in algorithms:
                algo_lower = algo.lower().replace('-', '_')
                try:
                    if algo_lower == 'ripemd160':
                        h = hashlib.new('ripemd160', data)
                    elif algo_lower == 'blake2b':
                        h = hashlib.blake2b(data)
                    elif algo_lower == 'blake2s':
                        h = hashlib.blake2s(data)
                    elif algo_lower in ('sha3_256', 'sha3_512'):
                        h = hashlib.new(algo_lower, data)
                    else:
                        h = hashlib.new(algo_lower, data)
                    digest = h.hexdigest()
                    results[algo] = digest
                    print_info(f"{algo.upper():12s}: {Colors.GREEN}{digest}{Colors.RESET}")
                except ValueError:
                    print_warning(f"算法不可用: {algo}")

            print_success(f"共生成 {len(results)} 个哈希值")
            return results

        except Exception as e:
            print_error(f"哈希生成失败: {e}")
            return None

    @staticmethod
    def base64_encode_decode(operation, data):
        """Base64编码解码"""
        print_section("Base64 编码/解码")

        if not data:
            print_error("请输入要处理的数据")
            return None

        try:
            if operation == 'encode':
                if isinstance(data, str):
                    data = data.encode('utf-8')
                result = base64.b64encode(data).decode('utf-8')
                print_info(f"原始数据: {Colors.CYAN}{data.decode('utf-8') if isinstance(data, bytes) else data}{Colors.RESET}")
                print_success(f"Base64编码: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            elif operation == 'decode':
                try:
                    decoded = base64.b64decode(data)
                    result = decoded.decode('utf-8')
                    print_info(f"Base64数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_success(f"Base64解码: {Colors.GREEN}{result}{Colors.RESET}")
                    return result
                except Exception:
                    # 尝试处理可能不是UTF-8的数据
                    decoded = base64.b64decode(data)
                    result = decoded.hex()
                    print_info(f"Base64数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_success(f"Base64解码(Hex): {Colors.GREEN}{result}{Colors.RESET}")
                    return result

            else:
                print_error("操作类型错误，请使用 'encode' 或 'decode'")
                return None

        except Exception as e:
            print_error(f"Base64处理失败: {e}")
            return None

    @staticmethod
    def base32_encode_decode(operation, data):
        """Base32编码解码"""
        print_section("Base32 编码/解码")

        if not data:
            print_error("请输入要处理的数据")
            return None

        try:
            if operation == 'encode':
                if isinstance(data, str):
                    data = data.encode('utf-8')
                result = base64.b32encode(data).decode('utf-8')
                print_info(f"原始数据: {Colors.CYAN}{data.decode('utf-8') if isinstance(data, bytes) else data}{Colors.RESET}")
                print_success(f"Base32编码: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            elif operation == 'decode':
                decoded = base64.b32decode(data)
                result = decoded.decode('utf-8')
                print_info(f"Base32数据: {Colors.CYAN}{data}{Colors.RESET}")
                print_success(f"Base32解码: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            else:
                print_error("操作类型错误，请使用 'encode' 或 'decode'")
                return None

        except Exception as e:
            print_error(f"Base32处理失败: {e}")
            return None

    @staticmethod
    def url_encode_decode(operation, data):
        """URL编码解码"""
        print_section("URL 编码/解码")

        if not data:
            print_error("请输入要处理的数据")
            return None

        try:
            if operation == 'encode':
                result = quote(data, safe='')
                print_info(f"原始数据: {Colors.CYAN}{data}{Colors.RESET}")
                print_success(f"URL编码: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            elif operation == 'decode':
                result = unquote(data)
                print_info(f"URL数据: {Colors.CYAN}{data}{Colors.RESET}")
                print_success(f"URL解码: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            else:
                print_error("操作类型错误，请使用 'encode' 或 'decode'")
                return None

        except Exception as e:
            print_error(f"URL处理失败: {e}")
            return None

    @staticmethod
    def hex_encode_decode(operation, data):
        """Hex编码解码"""
        print_section("Hex 编码/解码")

        if not data:
            print_error("请输入要处理的数据")
            return None

        try:
            if operation == 'encode':
                if isinstance(data, str):
                    data = data.encode('utf-8')
                result = data.hex()
                print_info(f"原始数据: {Colors.CYAN}{data.decode('utf-8') if isinstance(data, bytes) else data}{Colors.RESET}")
                print_success(f"Hex编码: {Colors.GREEN}{result}{Colors.RESET}")

                # 显示带空格的可读格式
                spaced = ' '.join(f'{b:02x}' for b in data)
                print_info(f"Hex(空格分隔): {Colors.GREEN}{spaced}{Colors.RESET}")
                return result

            elif operation == 'decode':
                clean = data.replace(' ', '').replace('0x', '').replace('0X', '')
                try:
                    decoded = bytes.fromhex(clean)
                    result = decoded.decode('utf-8')
                    print_info(f"Hex数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_success(f"Hex解码(UTF-8): {Colors.GREEN}{result}{Colors.RESET}")
                    return result
                except UnicodeDecodeError:
                    # 非UTF-8数据，显示为原始字节
                    decoded = bytes.fromhex(clean)
                    result = decoded.hex()
                    print_info(f"Hex数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_success(f"Hex解码(原始字节): {Colors.GREEN}{decoded}{Colors.RESET}")
                    return decoded

            else:
                print_error("操作类型错误，请使用 'encode' 或 'decode'")
                return None

        except Exception as e:
            print_error(f"Hex处理失败: {e}")
            return None

    @staticmethod
    def caesar_cipher(text, shift=3, mode='encrypt', brute=False):
        """凯撒密码加密/解密/暴力破解"""
        print_section("凯撒密码")

        if not text:
            print_error("请输入要处理的文本")
            return None

        try:
            if brute:
                print_info(f"对文本进行凯撒暴力破解: {Colors.CYAN}{text}{Colors.RESET}")
                results = []
                for s in range(1, 26):
                    decrypted = []
                    for ch in text:
                        if ch.isupper():
                            decrypted.append(chr((ord(ch) - ord('A') - s) % 26 + ord('A')))
                        elif ch.islower():
                            decrypted.append(chr((ord(ch) - ord('a') - s) % 26 + ord('a')))
                        else:
                            decrypted.append(ch)
                    result = ''.join(decrypted)
                    results.append((s, result))
                    print_info(f"移位 {s:2d}: {Colors.GREEN}{result}{Colors.RESET}")
                print_success(f"暴力破解完成，共尝试 {len(results)} 种移位")
                return results

            else:
                shift = shift % 26
                if mode == 'decrypt':
                    shift = -shift

                result = []
                for ch in text:
                    if ch.isupper():
                        result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
                    elif ch.islower():
                        result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
                    else:
                        result.append(ch)

                result_str = ''.join(result)
                mode_name = "加密" if mode == 'encrypt' else "解密"
                print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
                print_info(f"移位: {abs(shift) if mode == 'decrypt' else shift}")
                print_success(f"凯撒{mode_name}: {Colors.GREEN}{result_str}{Colors.RESET}")
                return result_str

        except Exception as e:
            print_error(f"凯撒密码处理失败: {e}")
            return None

    @staticmethod
    def rot13_cipher(text, mode='rot13'):
        """ROT13/ROT47"""
        print_section("ROT13/ROT47 密码")

        if not text:
            print_error("请输入要处理的文本")
            return None

        try:
            if mode == 'rot13':
                result = text.translate(str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                ))
                print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
                print_success(f"ROT13: {Colors.GREEN}{result}{Colors.RESET}")

            elif mode == 'rot47':
                result = []
                for ch in text:
                    code = ord(ch)
                    if 33 <= code <= 126:
                        result.append(chr(33 + ((code - 33 + 47) % 94)))
                    else:
                        result.append(ch)
                result = ''.join(result)
                print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
                print_success(f"ROT47: {Colors.GREEN}{result}{Colors.RESET}")

            else:
                print_error("模式错误，请使用 'rot13' 或 'rot47'")
                return None

            return result

        except Exception as e:
            print_error(f"ROT处理失败: {e}")
            return None

    @staticmethod
    def xor_cipher(data, key=None, mode='encrypt', brute=False):
        """XOR加密/解密/密钥爆破"""
        print_section("XOR 密码")

        if not data:
            print_error("请输入要处理的数据")
            return None

        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data

            if brute:
                print_info(f"对数据进行单字节XOR爆破: {Colors.CYAN}{data}{Colors.RESET}")
                results = []
                for k in range(256):
                    decrypted = bytes(b ^ k for b in data_bytes)
                    try:
                        text = decrypted.decode('utf-8')
                        if all(c in string.printable for c in text):
                            results.append((k, text))
                            print_info(f"密钥 0x{k:02x} ({chr(k) if 32 <= k <= 126 else '?'}): {Colors.GREEN}{text}{Colors.RESET}")
                    except (UnicodeDecodeError, ValueError):
                        pass

                if not results:
                    print_warning("未找到可读的XOR解密结果（可能不是文本数据）")
                else:
                    print_success(f"密钥爆破完成，找到 {len(results)} 个可读结果")
                return results

            else:
                if key is None:
                    key = 0x42  # 默认密钥

                if isinstance(key, str):
                    key_bytes = key.encode('utf-8')
                    # 多字节XOR
                    result = bytes(data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes)))
                elif isinstance(key, int):
                    # 单字节XOR
                    result = bytes(b ^ key for b in data_bytes)
                else:
                    print_error("密钥类型错误，请使用整数或字符串")
                    return None

                try:
                    result_str = result.decode('utf-8')
                    print_info(f"原始数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_info(f"密钥: {Colors.YELLOW}{key}{Colors.RESET}")
                    print_success(f"XOR结果: {Colors.GREEN}{result_str}{Colors.RESET}")
                except UnicodeDecodeError:
                    result_str = result.hex()
                    print_info(f"原始数据: {Colors.CYAN}{data}{Colors.RESET}")
                    print_info(f"密钥: {Colors.YELLOW}{key}{Colors.RESET}")
                    print_success(f"XOR结果(Hex): {Colors.GREEN}{result_str}{Colors.RESET}")

                return result

        except Exception as e:
            print_error(f"XOR处理失败: {e}")
            return None

    @staticmethod
    def vigenere_cipher(text, key, mode='encrypt'):
        """维吉尼亚密码加密/解密"""
        print_section("维吉尼亚密码")

        if not text:
            print_error("请输入要处理的文本")
            return None

        if not key:
            print_error("请输入密钥")
            return None

        try:
            # 清理密钥，只保留字母并转为大写
            key = ''.join(c for c in key.upper() if c.isalpha())
            if not key:
                print_error("密钥必须包含至少一个字母")
                return None

            key_len = len(key)
            key_shifts = [ord(k) - ord('A') for k in key]

            if mode == 'decrypt':
                key_shifts = [-s for s in key_shifts]

            result = []
            key_idx = 0
            for ch in text:
                if ch.isupper():
                    shift = (ord(ch) - ord('A') + key_shifts[key_idx % key_len]) % 26
                    result.append(chr(shift + ord('A')))
                    key_idx += 1
                elif ch.islower():
                    shift = (ord(ch) - ord('a') + key_shifts[key_idx % key_len]) % 26
                    result.append(chr(shift + ord('a')))
                    key_idx += 1
                else:
                    result.append(ch)

            result_str = ''.join(result)
            mode_name = "加密" if mode == 'encrypt' else "解密"
            print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
            print_info(f"密钥: {Colors.YELLOW}{key}{Colors.RESET}")
            print_success(f"维吉尼亚{mode_name}: {Colors.GREEN}{result_str}{Colors.RESET}")
            return result_str

        except Exception as e:
            print_error(f"维吉尼亚密码处理失败: {e}")
            return None

    @staticmethod
    def binary_converter(value, from_base='auto'):
        """进制转换 (bin/oct/dec/hex)"""
        print_section("进制转换器")

        if not value:
            print_error("请输入要转换的值")
            return None

        try:
            value = value.strip().lower()

            # 自动检测输入进制
            if from_base == 'auto':
                if value.startswith('0b'):
                    from_base = 'bin'
                elif value.startswith('0x') or value.startswith('0X'):
                    from_base = 'hex'
                elif value.startswith('0o') or value.startswith('0O'):
                    from_base = 'oct'
                elif all(c in '01' for c in value):
                    from_base = 'bin'
                elif all(c in '01234567' for c in value):
                    from_base = 'oct'
                elif all(c in '0123456789abcdef' for c in value):
                    from_base = 'hex'
                else:
                    from_base = 'dec'

            # 转换为十进制
            if from_base == 'bin':
                clean = value.replace('0b', '')
                dec_val = int(clean, 2)
            elif from_base == 'oct':
                clean = value.replace('0o', '').replace('0O', '')
                dec_val = int(clean, 8)
            elif from_base == 'hex':
                clean = value.replace('0x', '').replace('0X', '')
                dec_val = int(clean, 16)
            elif from_base == 'dec':
                dec_val = int(value)
            else:
                print_error("不支持的进制类型")
                return None

            results = {
                'dec': str(dec_val),
                'bin': bin(dec_val),
                'oct': oct(dec_val),
                'hex': hex(dec_val),
            }

            print_info(f"输入: {Colors.CYAN}{value}{Colors.RESET} (检测进制: {from_base})")
            print_info(f"十进制 (DEC): {Colors.GREEN}{results['dec']}{Colors.RESET}")
            print_info(f"二进制 (BIN): {Colors.GREEN}{results['bin']}{Colors.RESET}")
            print_info(f"八进制 (OCT): {Colors.GREEN}{results['oct']}{Colors.RESET}")
            print_info(f"十六进制 (HEX): {Colors.GREEN}{results['hex']}{Colors.RESET}")

            # 额外显示ASCII字符（如果值是有效的ASCII范围）
            if 32 <= dec_val <= 126:
                print_info(f"ASCII字符: {Colors.GREEN}{chr(dec_val)}{Colors.RESET}")

            print_success("进制转换完成")
            return results

        except ValueError:
            print_error(f"无法解析输入值: {value}")
            return None
        except Exception as e:
            print_error(f"进制转换失败: {e}")
            return None

    @staticmethod
    def jwt_decoder(token):
        """JWT解码"""
        print_section("JWT 解码器")

        if not token:
            print_error("请输入JWT Token")
            return None

        try:
            parts = token.split('.')
            if len(parts) != 3:
                print_error("无效的JWT格式，JWT应包含3个部分（用点分隔）")
                return None

            # 解码Header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4) if len(parts[0]) % 4 else parts[0]
            try:
                header_json = base64.urlsafe_b64decode(header_padded)
                header = json.loads(header_json)
                print_info("Header:")
                print(f"{Colors.GREEN}{json.dumps(header, indent=2, ensure_ascii=False)}{Colors.RESET}")
            except Exception:
                print_warning("Header解码失败")

            # 解码Payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4) if len(parts[1]) % 4 else parts[1]
            try:
                payload_json = base64.urlsafe_b64decode(payload_padded)
                payload = json.loads(payload_json)
                print_info("Payload:")
                print(f"{Colors.GREEN}{json.dumps(payload, indent=2, ensure_ascii=False)}{Colors.RESET}")

                # 显示过期时间等信息
                if 'exp' in payload:
                    from datetime import datetime
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    print_info(f"过期时间: {Colors.YELLOW}{exp_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
                if 'iat' in payload:
                    from datetime import datetime
                    iat_time = datetime.fromtimestamp(payload['iat'])
                    print_info(f"签发时间: {Colors.YELLOW}{iat_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
            except Exception:
                print_warning("Payload解码失败")
                payload = None

            # 显示签名（不修改）
            print_info(f"签名: {Colors.YELLOW}{parts[2]}{Colors.RESET}")

            result = {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
            print_success("JWT解码完成")
            return result

        except Exception as e:
            print_error(f"JWT解码失败: {e}")
            return None

    @staticmethod
    def morse_code(operation, text):
        """摩斯电码编码解码"""
        print_section("摩斯电码")

        if not text:
            print_error("请输入要处理的文本")
            return None

        # 摩斯电码表
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..',
            '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.',
            '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
            '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
            '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
            '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
            '$': '...-..-', '@': '.--.-.', ' ': '/'
        }

        # 反向映射表
        reverse_morse = {v: k for k, v in morse_dict.items()}

        try:
            if operation == 'encode':
                text = text.upper()
                result_parts = []
                for ch in text:
                    if ch in morse_dict:
                        result_parts.append(morse_dict[ch])
                    else:
                        print_warning(f"跳过无法编码的字符: {ch}")

                result = ' '.join(result_parts)
                print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
                print_success(f"摩斯电码: {Colors.GREEN}{result}{Colors.RESET}")

                # 显示可读格式
                readable = result.replace('.', '•').replace('-', '—')
                print_info(f"可读格式: {Colors.GREEN}{readable}{Colors.RESET}")
                return result

            elif operation == 'decode':
                # 标准化空格
                words = text.strip().split(' / ')
                result_parts = []

                for word in words:
                    symbols = word.split()
                    for sym in symbols:
                        if sym in reverse_morse:
                            result_parts.append(reverse_morse[sym])
                        else:
                            print_warning(f"跳过无法识别的摩斯码: {sym}")
                    result_parts.append(' ')

                result = ''.join(result_parts).strip()
                print_info(f"摩斯电码: {Colors.CYAN}{text}{Colors.RESET}")
                print_success(f"解码文本: {Colors.GREEN}{result}{Colors.RESET}")
                return result

            else:
                print_error("操作类型错误，请使用 'encode' 或 'decode'")
                return None

        except Exception as e:
            print_error(f"摩斯电码处理失败: {e}")
            return None

    @staticmethod
    def atbash_cipher(text):
        """Atbash密码"""
        print_section("Atbash 密码")

        if not text:
            print_error("请输入要处理的文本")
            return None

        try:
            result = []
            for ch in text:
                if ch.isupper():
                    result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
                elif ch.islower():
                    result.append(chr(ord('z') - (ord(ch) - ord('a'))))
                else:
                    result.append(ch)

            result_str = ''.join(result)
            print_info(f"原始文本: {Colors.CYAN}{text}{Colors.RESET}")
            print_success(f"Atbash: {Colors.GREEN}{result_str}{Colors.RESET}")

            # 显示映射表
            print_info("字母映射:")
            upper_map = {chr(ord('A') + i): chr(ord('Z') - i) for i in range(26)}
            mapping_line = ' '.join(f"{k}→{v}" for k, v in list(upper_map.items())[:13])
            mapping_line2 = ' '.join(f"{k}→{v}" for k, v in list(upper_map.items())[13:])
            print(f"  {Colors.CYAN}{mapping_line}{Colors.RESET}")
            print(f"  {Colors.CYAN}{mapping_line2}{Colors.RESET}")

            return result_str

        except Exception as e:
            print_error(f"Atbash处理失败: {e}")
            return None

    @staticmethod
    def char_frequency(text):
        """字符频率分析"""
        print_section("字符频率分析")

        if not text:
            print_error("请输入要分析的文本")
            return None

        try:
            total = len(text)
            if total == 0:
                print_warning("文本为空")
                return None

            # 统计字符频率
            freq = {}
            for ch in text:
                freq[ch] = freq.get(ch, 0) + 1

            # 按频率排序
            sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

            print_info(f"文本长度: {Colors.YELLOW}{total}{Colors.RESET} 字符")
            print_info(f"唯一字符: {Colors.YELLOW}{len(freq)}{Colors.RESET} 个")
            print_info("")

            # 统计各类字符
            uppercase = sum(1 for ch in text if ch.isupper())
            lowercase = sum(1 for ch in text if ch.islower())
            digits = sum(1 for ch in text if ch.isdigit())
            spaces = text.count(' ')
            punctuation = sum(1 for ch in text if ch in string.punctuation)
            other = total - uppercase - lowercase - digits - spaces - punctuation

            print_info("字符分类统计:")
            print_info(f"  大写字母: {Colors.GREEN}{uppercase}{Colors.RESET} ({uppercase/total*100:.1f}%)")
            print_info(f"  小写字母: {Colors.GREEN}{lowercase}{Colors.RESET} ({lowercase/total*100:.1f}%)")
            print_info(f"  数字:     {Colors.GREEN}{digits}{Colors.RESET} ({digits/total*100:.1f}%)")
            print_info(f"  空格:     {Colors.GREEN}{spaces}{Colors.RESET} ({spaces/total*100:.1f}%)")
            print_info(f"  标点:     {Colors.GREEN}{punctuation}{Colors.RESET} ({punctuation/total*100:.1f}%)")
            print_info(f"  其他:     {Colors.GREEN}{other}{Colors.RESET} ({other/total*100:.1f}%)")
            print_info("")

            # 显示频率表（前20个）
            print_info("字符频率表 (Top 20):")
            headers = ['字符', '频率', '百分比', '柱状图']
            rows = []
            for ch, count in sorted_freq[:20]:
                display_ch = ch if ch != ' ' else '␣'
                if ch == '\n':
                    display_ch = '\\n'
                elif ch == '\t':
                    display_ch = '\\t'
                elif ch == '\r':
                    display_ch = '\\r'
                pct = count / total * 100
                bar = '█' * int(count / total * 50) + '░' * (50 - int(count / total * 50))
                rows.append([f"'{display_ch}'", str(count), f"{pct:.2f}%", bar])

            print_table(headers, rows)

            if len(sorted_freq) > 20:
                print_info(f"... 及其他 {len(sorted_freq) - 20} 个字符")

            # 英文频率对比（如果是英文文本）
            eng_freq = {
                'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
                'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
                'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
                'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
            }

            letter_freq = {ch.upper(): count / total * 100 for ch, count in freq.items() if ch.isalpha()}
            if letter_freq:
                print_info("")
                print_info("字母频率与英文标准频率对比:")
                headers2 = ['字母', '实际频率', '英文标准', '差异']
                rows2 = []
                for ch, std_pct in sorted(eng_freq.items(), key=lambda x: x[1], reverse=True):
                    actual = letter_freq.get(ch, 0)
                    diff = actual - std_pct
                    rows2.append([ch, f"{actual:.2f}%", f"{std_pct:.2f}%", f"{diff:+.2f}%"])
                print_table(headers2, rows2, color=Colors.GREEN)

            result = {
                'total': total,
                'unique': len(freq),
                'frequencies': sorted_freq,
                'categories': {
                    'uppercase': uppercase,
                    'lowercase': lowercase,
                    'digits': digits,
                    'spaces': spaces,
                    'punctuation': punctuation,
                    'other': other,
                }
            }
            print_success("字符频率分析完成")
            return result

        except Exception as e:
            print_error(f"字符频率分析失败: {e}")
            return None