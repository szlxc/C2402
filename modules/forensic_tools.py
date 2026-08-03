# -*- coding: utf-8 -*-
"""
取证分析工具模块
"""

import os
import sys
import struct
import hashlib
import math
import json
from datetime import datetime
from core.colors import *
from core.utils import *


class ForensicTools:
    """取证分析工具集"""

    # 常见文件签名（魔数）
    FILE_SIGNATURES = {
        # 图片
        'FFD8FF': {'ext': '.jpg', 'desc': 'JPEG图像'},
        'FFD8FFE0': {'ext': '.jpg', 'desc': 'JPEG图像 (JFIF)'},
        'FFD8FFE1': {'ext': '.jpg', 'desc': 'JPEG图像 (Exif)'},
        '89504E47': {'ext': '.png', 'desc': 'PNG图像'},
        '47494638': {'ext': '.gif', 'desc': 'GIF图像'},
        '424D': {'ext': '.bmp', 'desc': 'BMP位图'},
        '49492A00': {'ext': '.tif', 'desc': 'TIFF图像 (小端)'},
        '4D4D002A': {'ext': '.tif', 'desc': 'TIFF图像 (大端)'},
        '52494646': {'ext': '.webp', 'desc': 'WebP图像'},
        '00000100': {'ext': '.ico', 'desc': 'ICO图标'},

        # 文档
        '25504446': {'ext': '.pdf', 'desc': 'PDF文档'},
        'D0CF11E0': {'ext': '.doc', 'desc': 'OLE2复合文档 (doc/xls/ppt)'},
        '504B0304': {'ext': '.zip', 'desc': 'ZIP压缩包 / Office文档 (docx/xlsx/pptx)'},
        '504B0506': {'ext': '.zip', 'desc': 'ZIP空档案'},
        '504B0708': {'ext': '.zip', 'desc': 'ZIP分卷档案'},
        '7B5C7274': {'ext': '.rtf', 'desc': 'RTF富文本格式'},

        # 压缩包
        '1F8B': {'ext': '.gz', 'desc': 'GZIP压缩'},
        '1F8B08': {'ext': '.gz', 'desc': 'GZIP压缩'},
        '1F9D': {'ext': '.z', 'desc': 'Z压缩 (LZW)'},
        '1FA0': {'ext': '.z', 'desc': 'Z压缩 (LZH)'},
        '425A68': {'ext': '.bz2', 'desc': 'BZIP2压缩'},
        '52617221': {'ext': '.rar', 'desc': 'RAR压缩包'},
        '526172211A07': {'ext': '.rar', 'desc': 'RAR压缩包 (v1.5+)'},
        'FD377A58': {'ext': '.xz', 'desc': 'XZ压缩'},
        '377ABCAF271C': {'ext': '.7z', 'desc': '7z压缩包'},
        '4C5A4950': {'ext': '.lz', 'desc': 'LZIP压缩'},

        # 可执行文件
        '4D5A': {'ext': '.exe', 'desc': 'PE可执行文件 (DOS头)'},
        '7F454C46': {'ext': '.elf', 'desc': 'ELF可执行文件'},
        'CAFEBABE': {'ext': '.class', 'desc': 'Java字节码'},
        'CFA1': {'ext': '.class', 'desc': 'Java字节码 (替代标记)'},
        'FEEDFACE': {'ext': '.bin', 'desc': 'Mach-O (32位)'},
        'FEEDFACF': {'ext': '.bin', 'desc': 'Mach-O (64位)'},
        'CEFAEDFE': {'ext': '.bin', 'desc': 'Mach-O (小端)'},
        'CFFAEDFE': {'ext': '.bin', 'desc': 'Mach-O (大端)'},

        # 多媒体
        '494433': {'ext': '.mp3', 'desc': 'MP3音频 (ID3v2标签)'},
        'FFF3': {'ext': '.mp3', 'desc': 'MP3音频 (MPEG帧)'},
        'FFF2': {'ext': '.mp3', 'desc': 'MP3音频 (MPEG帧)'},
        'FFF1': {'ext': '.mp3', 'desc': 'MP3音频 (MPEG帧)'},
        '664C6143': {'ext': '.flac', 'desc': 'FLAC音频'},
        '4F676753': {'ext': '.ogg', 'desc': 'OGG音频'},
        '000001BA': {'ext': '.mpg', 'desc': 'MPEG视频'},
        '000001B3': {'ext': '.mpg', 'desc': 'MPEG视频'},
        '1A45DFA3': {'ext': '.mkv', 'desc': 'Matroska视频 (mkv/webm)'},
        '66747970': {'ext': '.mp4', 'desc': 'MP4视频 (MP4容器)'},
        '0000002066747970': {'ext': '.mp4', 'desc': 'MP4视频 (fMP4)'},
        '52494646': {'ext': '.avi', 'desc': 'AVI视频'},
        '3026B2758E66CF11': {'ext': '.asf', 'desc': 'ASF/WMV视频'},
        '000001BA': {'desc': 'VOB视频文件', 'ext': '.vob'},

        # 其他
        '89504E470D0A1A0A': {'ext': '.png', 'desc': 'PNG图像 (完整头)'},
        '38425053': {'ext': '.psd', 'desc': 'Photoshop文档'},
        '25215053': {'ext': '.eps', 'desc': 'EPS PostScript'},
        '1B5B': {'ext': '.txt', 'desc': 'ANSI转义序列'},
        'EFBBBF': {'ext': '.txt', 'desc': 'UTF-8 BOM文本'},
        'FFFE': {'ext': '.txt', 'desc': 'UTF-16 LE文本'},
        'FEFF': {'ext': '.txt', 'desc': 'UTF-16 BE文本'},
        '0000FFFF': {'ext': '.bin', 'desc': 'Intel HEX'},
        '2D6C6832': {'ext': '.bin', 'desc': 'ELF链接脚本'},
        '2142444E': {'ext': '.pcap', 'desc': 'Wireshark/tcpdump pcap'},
        '0A0D0D0A': {'ext': '.pcap', 'desc': 'pcapng格式'},
        'D4C3B2A1': {'ext': '.pcap', 'desc': 'pcap (小端)'},
        'A1B2C3D4': {'ext': '.pcap', 'desc': 'pcap (大端)'},
        '3C3F786D': {'ext': '.xml', 'desc': 'XML文档'},
        '3C68746D': {'ext': '.html', 'desc': 'HTML文档'},
        '3C21444F': {'ext': '.html', 'desc': 'HTML5文档'},
        '53697874': {'ext': '.s19', 'desc': 'S-Record'},
        '4C4F4C': {'ext': '.bin', 'desc': 'LOL音频'},
    }

    # 常见文件尾标记
    FILE_FOOTERS = {
        'FFD9': '.jpg',       # JPEG结束
        '49454E44': '.png',    # PNG IEND块
        '3B': '.gif',          # GIF结束
        '00000000': '.mp4',    # MP4结束 (常见)
        '49454E44AE426082': '.png',  # PNG完整尾
    }

    def __init__(self):
        """初始化取证工具"""
        pass

    # ──────────────────────────────────────────────
    # 1. 文件元数据提取
    # ──────────────────────────────────────────────

    def file_metadata_extractor(self, filepath):
        """
        提取文件元数据

        参数:
            filepath: 文件路径

        返回:
            dict: 元数据字典
        """
        print_section(f"文件元数据提取: {os.path.basename(filepath)}")

        result = {'filepath': filepath, 'exists': False}

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            result['exists'] = True
            stat = os.stat(filepath)

            # 基本信息
            metadata = {
                '文件名': os.path.basename(filepath),
                '文件路径': os.path.abspath(filepath),
                '文件大小': self._format_size(stat.st_size),
                '字节数': stat.st_size,
                '创建时间': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                '修改时间': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                '访问时间': datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                '权限': oct(stat.st_mode)[-3:],
                'inode': stat.st_ino,
                '设备': stat.st_dev,
                '硬链接数': stat.st_nlink,
                '用户ID': stat.st_uid,
                '组ID': stat.st_gid,
            }

            # 如果是文件符号链接
            if os.path.islink(filepath):
                metadata['符号链接'] = os.readlink(filepath)

            # 检测文件类型
            sig = self._read_hex(filepath, 16)
            file_type = self._identify_signature(sig)
            if file_type:
                metadata['检测类型'] = file_type

            result['metadata'] = metadata

            # 打印结果
            for key, value in metadata.items():
                print_info(f"{Colors.CYAN}{key}:{Colors.RESET} {value}")

            print_success("文件元数据提取完成")
            return result

        except PermissionError:
            error_msg = f"权限不足: {filepath}"
            print_error(error_msg)
            result['error'] = error_msg
            return result
        except Exception as e:
            error_msg = f"提取元数据时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    # ──────────────────────────────────────────────
    # 2. 隐写检测工具
    # ──────────────────────────────────────────────

    def stego_detector(self, filepath):
        """
        隐写检测 - 基础检测

        检测内容包括:
        - 文件大小异常（尾随数据）
        - 文件签名字段异常
        - 可执行文件节区异常
        - 文本/注释区域异常
        - 高位熵值异常区域

        参数:
            filepath: 文件路径

        返回:
            dict: 检测结果
        """
        print_section(f"隐写检测: {os.path.basename(filepath)}")

        result = {'filepath': filepath, 'anomalies': [], 'suspicious': False}

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            data = self._read_file_raw(filepath)
            if data is None:
                return result

            file_size = len(data)
            print_info(f"文件大小: {self._format_size(file_size)}")

            # 1. 检查文件末尾是否有附加数据
            footer_anomaly = self._check_trailing_data(data, filepath)
            if footer_anomaly:
                result['anomalies'].append(footer_anomaly)
                result['suspicious'] = True

            # 2. 检查文件签名是否匹配扩展名
            sig_anomaly = self._check_signature_mismatch(data, filepath)
            if sig_anomaly:
                result['anomalies'].append(sig_anomaly)
                result['suspicious'] = True

            # 3. 检查文件内容中的异常高熵区域
            entropy_anomaly = self._check_entropy_anomaly(data)
            if entropy_anomaly:
                result['anomalies'].append(entropy_anomaly)
                result['suspicious'] = True

            # 4. 检查文件中的嵌入数据模式
            embedded = self._check_embedded_data(data)
            if embedded:
                result['anomalies'].append(embedded)
                result['suspicious'] = True

            if not result['suspicious']:
                print_success("未发现明显的隐写痕迹")
                result['summary'] = '未发现异常'
            else:
                print_warning(f"发现 {len(result['anomalies'])} 个可疑异常")
                result['summary'] = f'发现 {len(result["anomalies"])} 个异常'

            return result

        except Exception as e:
            error_msg = f"隐写检测时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _check_trailing_data(self, data, filepath):
        """检查文件末尾附加数据"""
        ext = os.path.splitext(filepath)[1].lower()

        # 已知文件格式的预期结束位置检测
        # 对PNG文件：检查IEND块后的数据
        if ext == '.png':
            iend_pos = data.rfind(b'IEND')
            if iend_pos >= 0:
                trailing = len(data) - (iend_pos + 12)  # IEND块大小
                if trailing > 0:
                    msg = f"PNG文件末尾包含 {self._format_size(trailing)} 额外数据"
                    print_warning(msg)
                    return msg

        # 对JPEG文件：检查FFD9标记后的数据
        if ext in ('.jpg', '.jpeg'):
            pos = 0
            last_marker = -1
            while True:
                pos = data.find(b'\xFF\xD9', pos)
                if pos == -1:
                    break
                last_marker = pos
                pos += 2
            if last_marker >= 0:
                trailing = len(data) - (last_marker + 2)
                if trailing > 0:
                    msg = f"JPEG文件末尾包含 {self._format_size(trailing)} 额外数据 (可能隐藏了数据)"
                    print_warning(msg)
                    return msg

        # 对GIF文件：检查结束标记后的数据
        if ext == '.gif':
            if data[-1:] == b'\x3B':  # GIF结束标记
                pass  # 正常结束
            else:
                gif_end = data.rfind(b'\x00\x3B')
                if gif_end >= 0:
                    trailing = len(data) - (gif_end + 2)
                    if trailing > 0:
                        msg = f"GIF文件末尾包含 {self._format_size(trailing)} 额外数据"
                        print_warning(msg)
                        return msg

        # 通用检查：对ZIP文件检查
        if ext == '.zip' or data[:2] == b'PK':
            eocd_pos = data.rfind(b'PK\x05\x06')
            if eocd_pos >= 0:
                # 检查EOCD注释
                comment_len = struct.unpack('<H', data[eocd_pos + 20:eocd_pos + 22])[0]
                expected_end = eocd_pos + 22 + comment_len
                if len(data) > expected_end:
                    trailing = len(data) - expected_end
                    msg = f"ZIP文件末尾包含 {self._format_size(trailing)} 额外数据"
                    print_warning(msg)
                    return msg

        return None

    def _check_signature_mismatch(self, data, filepath):
        """检查文件签名是否匹配扩展名"""
        ext = os.path.splitext(filepath)[1].lower()
        if not ext or len(data) < 4:
            return None

        sig = data[:4].hex().upper()
        # 尝试匹配不同长度的签名
        for magic, info in self.FILE_SIGNATURES.items():
            if sig.startswith(magic) or magic.startswith(sig):
                expected_ext = info['ext']
                if ext != expected_ext and ext != '':
                    msg = (f"文件签名不匹配: 扩展名为 {ext}，"
                           f"但签名 {sig[:8]} 指示为 {expected_ext} ({info['desc']})")
                    print_warning(msg)
                    return msg
                break

        return None

    def _check_entropy_anomaly(self, data, block_size=256):
        """检查文件中的异常高熵区域"""
        anomalies = []
        if len(data) < block_size:
            return None

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) < 16:
                continue
            entropy = self._calculate_entropy(block)
            if entropy > 7.5:  # 高熵值暗示加密或压缩数据
                offset = self._format_offset(i)
                anomalies.append(f"偏移 {offset}: 熵值 {entropy:.2f} (异常高)")

        if anomalies:
            msg = f"发现 {len(anomalies)} 个高熵区域 (可能包含加密/压缩数据)"
            # 只显示前3个
            for a in anomalies[:3]:
                print_warning(a)
            if len(anomalies) > 3:
                print_info(f"...以及其他 {len(anomalies) - 3} 个区域")
            return msg

        return None

    def _check_embedded_data(self, data):
        """检查文件中的嵌入数据模式"""
        findings = []

        # 查找ZIP文件头嵌入
        zip_count = 0
        pos = 0
        while True:
            pos = data.find(b'PK\x03\x04', pos)
            if pos == -1:
                break
            if pos > 0:  # 不在文件开头
                zip_count += 1
            pos += 4

        if zip_count > 0:
            findings.append(f"发现 {zip_count} 个嵌入的ZIP文件头")

        # 查找PNG文件头嵌入
        png_count = 0
        pos = 0
        while True:
            pos = data.find(b'\x89PNG\r\n\x1a\n', pos)
            if pos == -1:
                break
            if pos > 0:
                png_count += 1
            pos += 8

        if png_count > 0:
            findings.append(f"发现 {png_count} 个嵌入的PNG文件头")

        # 查找JPEG文件头嵌入
        jpg_count = 0
        pos = 0
        while True:
            pos = data.find(b'\xFF\xD8\xFF', pos)
            if pos == -1:
                break
            if pos > 0:
                jpg_count += 1
            pos += 3

        if jpg_count > 0:
            findings.append(f"发现 {jpg_count} 个嵌入的JPEG文件头")

        if findings:
            msg = '; '.join(findings)
            print_warning(msg)
            return msg

        return None

    # ──────────────────────────────────────────────
    # 3. 文件签名分析
    # ──────────────────────────────────────────────

    def file_signature_analyzer(self, filepath, offset=0, length=64):
        """
        文件签名分析 (魔数分析)

        参数:
            filepath: 文件路径
            offset: 起始偏移 (默认0)
            length: 读取长度 (默认64字节)

        返回:
            dict: 签名分析结果
        """
        print_section(f"文件签名分析: {os.path.basename(filepath)}")

        result = {'filepath': filepath, 'signatures': []}

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            data = self._read_file_raw(filepath)
            if data is None:
                return result

            file_size = len(data)
            print_info(f"文件大小: {self._format_size(file_size)}")

            # 分析文件中所有匹配的签名
            analyzed_offsets = set()

            # 从多个偏移量检查签名
            check_offsets = [0]
            if file_size > 4:
                check_offsets.append(file_size - 4)  # 文件末尾
            if file_size > 1024:
                check_offsets.extend([file_size // 4, file_size // 2, file_size * 3 // 4])

            for off in sorted(set(check_offsets)):
                if off < 0 or off >= file_size:
                    continue
                read_len = min(16, file_size - off)
                hex_sig = data[off:off + read_len].hex().upper()

                sig_info = self._identify_signature(hex_sig)
                if sig_info:
                    if off not in analyzed_offsets:
                        analyzed_offsets.add(off)
                        sig_entry = {
                            'offset': off,
                            'offset_hex': f"0x{off:X}",
                            'hex': hex_sig[:32],
                            'identified': sig_info,
                        }
                        result['signatures'].append(sig_entry)

            # 分析文件前64字节
            hexdump = self._format_hex_block(data[:min(64, file_size)])
            print_info(f"文件头 (前64字节):")
            print(f"{Colors.DIM}{hexdump}{Colors.RESET}")

            # 分析文件头签名
            header_sig = data[:min(16, file_size)].hex().upper()
            identified = self._identify_signature(header_sig)

            if identified:
                print_success(f"检测到签名: {identified}")
                result['identified_type'] = identified
            else:
                print_info("签名未识别")
                result['identified_type'] = 'Unknown'

            # 打印所有发现的签名
            if result['signatures']:
                print_info("发现的签名:")
                for sig in result['signatures']:
                    print_info(f"  偏移 {sig['offset_hex']}: {sig['hex']} → {sig['identified']}")

            # 检查文件末尾签名
            if file_size > 4:
                footer_sig = data[-4:].hex().upper()
                footer_identified = self._identify_signature(footer_sig)
                result['footer_signature'] = footer_sig
                if footer_identified:
                    print_info(f"文件尾签名: {footer_sig} → {footer_identified}")
                    result['footer_identified'] = footer_identified

            print_success("文件签名分析完成")
            return result

        except Exception as e:
            error_msg = f"签名分析时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _identify_signature(self, hex_sig):
        """根据十六进制签名识别文件类型"""
        if not hex_sig:
            return None

        hex_sig = hex_sig.upper()
        # 从最长匹配到最短匹配
        sorted_magic = sorted(self.FILE_SIGNATURES.keys(), key=len, reverse=True)
        for magic in sorted_magic:
            if hex_sig.startswith(magic):
                info = self.FILE_SIGNATURES[magic]
                return f"{info['desc']} ({info['ext']})"
        return None

    # ──────────────────────────────────────────────
    # 4. 字符串提取
    # ──────────────────────────────────────────────

    def string_extractor(self, filepath, min_length=4, encoding='utf-8', max_results=200):
        """
        从二进制文件中提取可读字符串

        参数:
            filepath: 文件路径
            min_length: 最小字符串长度 (默认4)
            encoding: 编码 (默认utf-8)
            max_results: 最大返回结果数 (默认200, 0表示不限制)

        返回:
            dict: 提取结果 {strings, ascii_strings, utf16_strings}
        """
        print_section(f"字符串提取: {os.path.basename(filepath)}")

        result = {
            'filepath': filepath,
            'min_length': min_length,
            'ascii_strings': [],
            'utf16_strings': [],
            'total': 0,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            data = self._read_file_raw(filepath)
            if data is None:
                return result

            file_size = len(data)
            print_info(f"文件大小: {self._format_size(file_size)}")
            print_info(f"最小字符串长度: {min_length}")
            print_info(f"编码: {encoding}")

            # 提取ASCII/UTF-8字符串
            ascii_strings = self._extract_ascii_strings(data, min_length)
            # 提取UTF-16字符串
            utf16_strings = self._extract_utf16_strings(data, min_length)

            # 限制结果数量
            if max_results > 0:
                if len(ascii_strings) > max_results:
                    print_info(f"ASCII字符串过多，仅显示前 {max_results} 个 (共 {len(ascii_strings)} 个)")
                    ascii_strings = ascii_strings[:max_results]
                if len(utf16_strings) > max_results:
                    utf16_strings = utf16_strings[:max_results]

            result['ascii_strings'] = ascii_strings
            result['utf16_strings'] = utf16_strings
            result['total'] = len(ascii_strings) + len(utf16_strings)

            # 打印ASCII字符串
            if ascii_strings:
                print_info(f"ASCII/UTF-8 字符串 ({len(ascii_strings)} 个):")
                for offset, string in ascii_strings[:50]:  # 最多显示50个
                    print(f"  {Colors.DIM}{self._format_offset(offset)}{Colors.RESET}  {Colors.GREEN}{string}{Colors.RESET}")
                if len(ascii_strings) > 50:
                    print_info(f"  ... 还有 {len(ascii_strings) - 50} 个字符串")
            else:
                print_info("未找到ASCII字符串")

            # 打印UTF-16字符串
            if utf16_strings:
                print_info(f"UTF-16 字符串 ({len(utf16_strings)} 个):")
                for offset, string in utf16_strings[:20]:
                    print(f"  {Colors.DIM}{self._format_offset(offset)}{Colors.RESET}  {Colors.CYAN}{string}{Colors.RESET}")
                if len(utf16_strings) > 20:
                    print_info(f"  ... 还有 {len(utf16_strings) - 20} 个字符串")
            else:
                print_info("未找到UTF-16字符串")

            print_success(f"字符串提取完成，共 {result['total']} 个")
            return result

        except Exception as e:
            error_msg = f"字符串提取时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _extract_ascii_strings(self, data, min_length=4):
        """提取ASCII字符串"""
        strings = []
        current = []
        current_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # 可打印ASCII
                if not current:
                    current_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append((current_offset, ''.join(current)))
                current = []

        # 处理末尾
        if len(current) >= min_length:
            strings.append((current_offset, ''.join(current)))

        return strings

    def _extract_utf16_strings(self, data, min_length=4):
        """提取UTF-16字符串 (小端)"""
        strings = []
        current = []
        current_offset = 0

        # 确保数据长度为偶数
        if len(data) % 2 != 0:
            data = data[:-1]

        for i in range(0, len(data) - 1, 2):
            char_code = struct.unpack('<H', data[i:i + 2])[0]
            if 32 <= char_code <= 126 or char_code in (0x0D, 0x0A, 0x09):
                if not current:
                    current_offset = i
                current.append(chr(char_code))
            else:
                if len(current) >= min_length:
                    strings.append((current_offset, ''.join(current)))
                current = []

        if len(current) >= min_length:
            strings.append((current_offset, ''.join(current)))

        return strings

    # ──────────────────────────────────────────────
    # 5. Hex转储查看器
    # ──────────────────────────────────────────────

    def hex_dump(self, filepath, offset=0, length=512, show_ascii=True, group_size=2):
        """
        Hex转储查看器

        参数:
            filepath: 文件路径
            offset: 起始偏移
            length: 读取长度 (默认512字节)
            show_ascii: 是否显示ASCII侧 (默认True)
            group_size: 字节分组大小 (默认2)

        返回:
            dict: 转储结果
        """
        print_section(f"Hex转储: {os.path.basename(filepath)}")

        result = {
            'filepath': filepath,
            'offset': offset,
            'length': length,
            'lines': [],
            'total_size': 0,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            file_size = os.path.getsize(filepath)
            result['total_size'] = file_size

            if offset >= file_size:
                print_error(f"偏移 {offset} 超出文件大小 {file_size}")
                return result

            # 调整读取长度
            read_len = min(length, file_size - offset)
            data = self._read_file_raw(filepath, offset, read_len)
            if data is None:
                return result

            print_info(f"文件大小: {self._format_size(file_size)}")
            print_info(f"显示范围: 0x{offset:X} - 0x{offset + read_len:X} ({read_len} 字节)")

            # 生成转储
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                # 偏移地址
                addr = offset + i
                addr_str = f"{Colors.BOLD}{Colors.CYAN}{self._format_offset(addr)}{Colors.RESET}"

                # 十六进制部分
                hex_parts = []
                for j in range(0, len(chunk), group_size):
                    group = chunk[j:j + group_size]
                    hex_parts.append(group.hex().upper())
                hex_str = ' '.join(hex_parts)
                hex_str = hex_str.ljust(16 * 3 - 1)  # 对齐

                # ASCII部分
                if show_ascii:
                    ascii_str = ''
                    for byte in chunk:
                        if 32 <= byte <= 126:
                            ascii_str += chr(byte)
                        else:
                            ascii_str += '.'
                    line = f"{addr_str}  {hex_str}  {Colors.DIM}|{ascii_str}|{Colors.RESET}"
                else:
                    line = f"{addr_str}  {hex_str}"

                print(line)
                lines.append({
                    'address': addr,
                    'hex': chunk.hex().upper(),
                    'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk),
                })

            result['lines'] = lines
            print_success(f"Hex转储完成，共 {len(lines)} 行")
            return result

        except Exception as e:
            error_msg = f"Hex转储时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    # ──────────────────────────────────────────────
    # 6. 文件类型检测
    # ──────────────────────────────────────────────

    def file_type_detector(self, filepath):
        """
        文件类型检测 (基于签名和内容分析)

        参数:
            filepath: 文件路径

        返回:
            dict: 类型检测结果
        """
        print_section(f"文件类型检测: {os.path.basename(filepath)}")

        result = {
            'filepath': filepath,
            'extension': os.path.splitext(filepath)[1].lower(),
            'detected_types': [],
            'mime_type': None,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            if os.path.isdir(filepath):
                print_info(f"这是一个目录: {filepath}")
                result['is_directory'] = True
                return result

            data = self._read_file_raw(filepath, 0, 64)
            if data is None:
                return result

            file_size = os.path.getsize(filepath)
            result['file_size'] = file_size
            ext = result['extension']

            print_info(f"扩展名: {ext if ext else '(无扩展名)'}")
            print_info(f"文件大小: {self._format_size(file_size)}")

            # 1. 基于签名检测
            hex_sig = data.hex().upper()
            signature_type = self._identify_signature(hex_sig)
            if signature_type:
                result['detected_types'].append(('签名', signature_type))
                print_success(f"基于签名: {signature_type}")

            # 2. 基于内容分析
            content_type = self._analyze_content_type(data, file_size)
            if content_type and content_type != signature_type:
                result['detected_types'].append(('内容', content_type))
                print_info(f"基于内容: {content_type}")

            # 3. 基于统计特征
            stat_type = self._analyze_statistical_type(data)
            if stat_type:
                result['detected_types'].append(('统计', stat_type))
                print_info(f"基于统计: {stat_type}")

            # 4. 文本/二进制检测
            is_text = self._is_text_file(data)
            result['is_text'] = is_text
            if is_text:
                encoding = self._detect_text_encoding(data)
                result['text_encoding'] = encoding
                print_info(f"文本文件: 编码 {encoding}")
            else:
                print_info(f"二进制文件")

            # 确定最终类型
            if result['detected_types']:
                result['mime_type'] = result['detected_types'][0][1]
                print_info(f"最终判定: {result['mime_type']}")

            print_success("文件类型检测完成")
            return result

        except Exception as e:
            error_msg = f"文件类型检测时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _analyze_content_type(self, data, file_size):
        """基于内容分析文件类型"""
        if len(data) < 4:
            return None

        # 检查是否为PE文件
        if data[:2] == b'MZ':
            return "PE可执行文件 (.exe/.dll)"

        # 检查是否为ELF文件
        if data[:4] == b'\x7fELF':
            ei_class = data[4] if len(data) > 4 else 0
            if ei_class == 1:
                return "ELF 32-bit可执行文件"
            elif ei_class == 2:
                return "ELF 64-bit可执行文件"

        # 检查是否为Mach-O
        if data[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe'):
            return "Mach-O 32-bit (Intel)"
        if data[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
            return "Mach-O 64-bit (Intel)"

        # 检查是否为Shell脚本
        if data[:2] == b'#!':
            end = data.find(b'\n')
            if end > 0:
                interpreter = data[2:end].decode('utf-8', errors='ignore')
                return f"脚本文件: {interpreter}"

        return None

    def _analyze_statistical_type(self, data):
        """基于统计特征分析文件类型"""
        if len(data) < 64:
            return None

        # 计算熵值
        entropy = self._calculate_entropy(data)

        # 计算可打印字符比例
        printable = sum(1 for b in data if 32 <= b <= 126)
        printable_ratio = printable / len(data)

        # 检查空字节比例
        null_bytes = sum(1 for b in data if b == 0)
        null_ratio = null_bytes / len(data)

        # 统计特征判定
        if printable_ratio > 0.95 and entropy < 5.0:
            return "纯文本文件"
        elif printable_ratio > 0.8 and entropy < 6.0:
            return "源码/标记文本文件"
        elif null_ratio > 0.3 and entropy > 6.0:
            return "二进制数据文件"
        elif entropy > 7.5:
            return "加密/压缩数据"
        elif null_ratio > 0.1:
            return "结构化二进制文件"

        return None

    def _is_text_file(self, data):
        """检测是否为文本文件"""
        if len(data) == 0:
            return True

        # 检查BOM
        if data[:3] in (b'\xEF\xBB\xBF', b'\xFF\xFE', b'\xFE\xFF'):
            return True

        # 检查空字节（文本文件通常没有空字节）
        null_count = sum(1 for b in data[:min(1024, len(data))] if b == 0)
        if null_count > 2:
            return False

        # 检查可打印字符比例
        printable = sum(1 for b in data[:min(1024, len(data))] if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / min(1024, len(data)) > 0.8

    def _detect_text_encoding(self, data):
        """检测文本编码"""
        if data[:3] == b'\xEF\xBB\xBF':
            return 'UTF-8 with BOM'
        if data[:2] == b'\xFF\xFE':
            return 'UTF-16 LE'
        if data[:2] == b'\xFE\xFF':
            return 'UTF-16 BE'

        # 尝试检测UTF-8
        try:
            data[:min(1024, len(data))].decode('utf-8')
            return 'UTF-8 (无BOM)'
        except (UnicodeDecodeError, UnicodeError):
            pass

        # 尝试检测Latin-1
        try:
            data[:min(1024, len(data))].decode('latin-1')
            return 'Latin-1 / ISO-8859-1'
        except (UnicodeDecodeError, UnicodeError):
            pass

        return 'Unknown (二进制)'

    # ──────────────────────────────────────────────
    # 7. EXIF数据读取
    # ──────────────────────────────────────────────

    def exif_reader(self, filepath):
        """
        读取EXIF数据 (使用PIL/Pillow，如果不可用则使用struct手动解析)

        参数:
            filepath: 文件路径

        返回:
            dict: EXIF数据
        """
        print_section(f"EXIF数据读取: {os.path.basename(filepath)}")

        result = {'filepath': filepath, 'exif_data': {}}

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            # 尝试使用PIL/Pillow
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS

                img = Image.open(filepath)
                exif_raw = img._getexif()

                if exif_raw:
                    print_info("使用PIL/Pillow读取EXIF数据")
                    for tag_id, value in exif_raw.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        # 处理字节串
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except Exception:
                                value = repr(value)
                        result['exif_data'][tag_name] = value
                else:
                    print_info("未找到EXIF数据")
                    result['exif_data'] = None

            except ImportError:
                print_info("PIL/Pillow不可用，使用struct手动解析EXIF")
                self._parse_exif_manual(filepath, result)
            except Exception as pil_err:
                print_warning(f"PIL解析失败: {pil_err}")
                print_info("尝试手动解析EXIF")
                self._parse_exif_manual(filepath, result)

            # 打印EXIF数据
            if result['exif_data']:
                # 按类别分组打印
                gps_data = {}
                other_data = {}
                for key, value in result['exif_data'].items():
                    if 'GPS' in str(key) or 'gps' in str(key).lower():
                        gps_data[key] = value
                    else:
                        other_data[key] = value

                if other_data:
                    print_info("EXIF信息:")
                    for key, value in sorted(other_data.items()):
                        if value is not None:
                            print(f"  {Colors.CYAN}{key}:{Colors.RESET} {value}")

                if gps_data:
                    print_info("GPS信息:")
                    for key, value in sorted(gps_data.items()):
                        print(f"  {Colors.YELLOW}{key}:{Colors.RESET} {value}")

                print_success(f"EXIF数据读取完成，共 {len(result['exif_data'])} 个字段")
            else:
                print_info("此文件不包含EXIF数据")

            return result

        except Exception as e:
            error_msg = f"读取EXIF时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _parse_exif_manual(self, filepath, result):
        """手动解析JPEG文件中的EXIF数据"""
        try:
            data = self._read_file_raw(filepath)
            if data is None:
                return

            if data[:2] != b'\xFF\xD8':
                print_info("不是JPEG文件，无法解析EXIF")
                return

            # 查找APP1 (EXIF) 标记
            pos = 2
            while pos < len(data) - 2:
                if data[pos] == 0xFF and data[pos + 1] in (0xE1, 0xE0):
                    marker_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
                    if data[pos + 1] == 0xE1 and data[pos + 4:pos + 8] == b'Exif':
                        exif_data = data[pos + 4:pos + 4 + marker_len]
                        # 验证TIFF头
                        if exif_data[6:8] in (b'II', b'MM'):
                            is_little = exif_data[6:8] == b'II'
                            tiff_offset = struct.unpack('<I' if is_little else '>I',
                                                         exif_data[10:14])[0]
                            # 解析IFD0
                            if tiff_offset + 2 <= len(exif_data):
                                ifd_count = struct.unpack('<H' if is_little else '>H',
                                                           exif_data[tiff_offset:tiff_offset + 2])[0]
                                # 读取IFD条目
                                for i in range(ifd_count):
                                    entry_offset = tiff_offset + 2 + i * 12
                                    if entry_offset + 12 > len(exif_data):
                                        break
                                    entry = exif_data[entry_offset:entry_offset + 12]
                                    tag = struct.unpack('<H' if is_little else '>H', entry[:2])[0]
                                    data_format = entry[2]
                                    num_components = struct.unpack('<I' if is_little else '>I',
                                                                    entry[4:8])[0]
                                    value_offset = entry[8:12]

                                    # 常见EXIF标签
                                    exif_tags = {
                                        0x010F: '制造商',
                                        0x0110: '相机型号',
                                        0x0112: '方向',
                                        0x011A: 'X分辨率',
                                        0x011B: 'Y分辨率',
                                        0x0128: '分辨率单位',
                                        0x0131: '软件',
                                        0x0132: '修改日期',
                                        0x010E: '图像描述',
                                        0x010B: '艺术家',
                                        0x0211: 'YCbCr系数',
                                        0x0213: 'YCbCr定位',
                                        0x8769: 'Exif偏移',
                                        0x8825: 'GPS信息偏移',
                                        0x829A: '曝光时间',
                                        0x829D: '光圈值',
                                        0x8822: '曝光程序',
                                        0x8827: 'ISO感光度',
                                        0x9003: '拍摄日期',
                                        0x9004: '数字化日期',
                                        0x9101: '分量配置',
                                        0x9201: '快门速度',
                                        0x9202: '光圈',
                                        0x9203: '亮度',
                                        0x9204: '曝光补偿',
                                        0x9205: '最大光圈',
                                        0x9206: '测光模式',
                                        0x9207: '闪光灯',
                                        0x9208: '焦距',
                                        0x9209: '闪光强度',
                                        0x920A: '闪光距离',
                                        0x927C: '制造商备注',
                                        0x9286: '用户注释',
                                        0xA001: '色彩空间',
                                        0xA002: '图像宽度',
                                        0xA003: '图像高度',
                                        0xA005: 'Interoperability偏移',
                                        0xA20E: '焦距(35mm)',
                                        0xA20F: '镜头型号',
                                        0xA210: '镜头规格',
                                        0xA217: '场景类型',
                                        0xA300: '拍摄设备类型',
                                        0xA401: '自定义渲染',
                                        0xA402: '曝光模式',
                                        0xA403: '白平衡',
                                        0xA404: '数字变焦',
                                        0xA405: '等效焦距',
                                        0xA406: '场景模式',
                                        0xA407: '主体距离',
                                        0xA408: '对比度',
                                        0xA409: '饱和度',
                                        0xA40A: '锐度',
                                        0xA40C: '主体距离范围',
                                    }

                                    if tag in exif_tags:
                                        tag_name = exif_tags[tag]
                                        # 简化解析
                                        try:
                                            if data_format == 2:  # ASCII
                                                val = value_offset.rstrip(b'\x00').decode('utf-8', errors='ignore')
                                            elif data_format in (3, 4):  # SHORT, LONG
                                                if is_little:
                                                    val = struct.unpack('<H' if data_format == 3 else '<I',
                                                                        value_offset[:2 if data_format == 3 else 4])[0]
                                                else:
                                                    val = struct.unpack('>H' if data_format == 3 else '>I',
                                                                        value_offset[:2 if data_format == 3 else 4])[0]
                                            else:
                                                val = value_offset.hex()
                                            result['exif_data'][tag_name] = val
                                        except Exception:
                                            pass

                    break
                pos += 2 if marker_len == 0 else 2 + marker_len

            if not result['exif_data']:
                print_info("未找到EXIF数据")

        except Exception as e:
            print_warning(f"手动解析EXIF失败: {e}")

    # ──────────────────────────────────────────────
    # 8. 文件雕刻
    # ──────────────────────────────────────────────

    def file_carver(self, filepath, output_dir=None, signatures=None):
        """
        文件雕刻 - 基于文件签名从二进制文件中恢复文件

        参数:
            filepath: 源文件路径
            output_dir: 输出目录 (默认: 当前目录/carved)
            signatures: 要搜索的签名列表 (默认: 所有)

        返回:
            dict: 雕刻结果
        """
        print_section(f"文件雕刻: {os.path.basename(filepath)}")

        result = {
            'source': filepath,
            'carved_files': [],
            'total_carved': 0,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            data = self._read_file_raw(filepath)
            if data is None:
                return result

            file_size = len(data)
            print_info(f"源文件大小: {self._format_size(file_size)}")

            # 设置输出目录
            if output_dir is None:
                output_dir = os.path.join(os.path.dirname(os.path.abspath(filepath)), 'carved')
            os.makedirs(output_dir, exist_ok=True)
            print_info(f"输出目录: {output_dir}")

            # 选择要搜索的签名
            if signatures:
                target_sigs = {k: v for k, v in self.FILE_SIGNATURES.items() if k in signatures}
            else:
                target_sigs = self.FILE_SIGNATURES

            # 搜索签名
            found_positions = []
            for magic_bytes, info in target_sigs.items():
                magic_raw = bytes.fromhex(magic_bytes)
                pos = 0
                while pos < len(data):
                    pos = data.find(magic_raw, pos)
                    if pos == -1:
                        break
                    found_positions.append((pos, magic_bytes, info))
                    pos += 1

            # 按偏移排序
            found_positions.sort(key=lambda x: x[0])

            print_info(f"找到 {len(found_positions)} 个潜在文件头")

            # 雕刻文件
            carved_count = 0
            for i, (pos, magic, info) in enumerate(found_positions):
                # 确定文件结束位置
                if i + 1 < len(found_positions):
                    end_pos = found_positions[i + 1][0]
                else:
                    end_pos = file_size

                # 跳过太小的文件
                if end_pos - pos < 4:
                    continue

                # 跳过源文件本身（如果从头部开始匹配）
                if pos == 0 and end_pos == file_size:
                    continue

                # 生成文件名
                ext = info['ext']
                carved_name = f"carved_{pos:08X}_{info['desc'].split()[0]}{ext}"
                carved_path = os.path.join(output_dir, carved_name)

                # 写入文件
                try:
                    with open(carved_path, 'wb') as f:
                        f.write(data[pos:end_pos])
                    carved_size = end_pos - pos
                    carved_count += 1
                    carved_entry = {
                        'file': carved_name,
                        'offset': pos,
                        'offset_hex': f"0x{pos:X}",
                        'size': carved_size,
                        'size_formatted': self._format_size(carved_size),
                        'type': info['desc'],
                    }
                    result['carved_files'].append(carved_entry)
                    print_success(f"雕刻: {carved_name} ({self._format_size(carved_size)}) @ 0x{pos:X}")

                except Exception as write_err:
                    print_error(f"写入文件失败 {carved_name}: {write_err}")

            result['total_carved'] = carved_count
            if carved_count > 0:
                print_success(f"雕刻完成，共恢复 {carved_count} 个文件")
            else:
                print_info("未找到可雕刻的文件")

            return result

        except Exception as e:
            error_msg = f"文件雕刻时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    # ──────────────────────────────────────────────
    # 9. 哈希比较
    # ──────────────────────────────────────────────

    def hash_compare(self, filepath, compare_path=None, known_hash=None, algorithm='sha256'):
        """
        哈希比较

        参数:
            filepath: 文件路径
            compare_path: 要比较的文件路径 (可选)
            known_hash: 已知哈希值 (可选)
            algorithm: 哈希算法 (md5, sha1, sha256, sha512)

        返回:
            dict: 哈希比较结果
        """
        print_section(f"哈希比较: {os.path.basename(filepath)}")

        result = {
            'filepath': filepath,
            'algorithm': algorithm,
            'hash': None,
            'comparison': None,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            if not os.path.isfile(filepath):
                print_error(f"不是文件: {filepath}")
                return result

            # 计算哈希
            file_hash = self._compute_hash(filepath, algorithm)
            if file_hash is None:
                print_error(f"计算哈希失败")
                return result

            result['hash'] = file_hash
            print_info(f"文件: {os.path.basename(filepath)}")
            print_info(f"算法: {algorithm.upper()}")
            print_info(f"哈希值: {Colors.GREEN}{file_hash}{Colors.RESET}")

            # 比较文件
            if compare_path:
                if not os.path.exists(compare_path):
                    print_error(f"比较文件不存在: {compare_path}")
                else:
                    compare_hash = self._compute_hash(compare_path, algorithm)
                    if compare_hash:
                        result['comparison'] = {
                            'compare_file': compare_path,
                            'compare_hash': compare_hash,
                            'match': file_hash == compare_hash,
                        }
                        if file_hash == compare_hash:
                            print_success(f"两个文件哈希值一致 ✓")
                            print_info(f"  比较文件: {os.path.basename(compare_path)}")
                        else:
                            print_warning(f"两个文件哈希值不一致 ✗")
                            print_info(f"  比较文件: {os.path.basename(compare_path)}")
                            print_info(f"  比较哈希: {Colors.YELLOW}{compare_hash}{Colors.RESET}")
                    else:
                        print_error(f"计算比较文件哈希失败")

            # 比较已知哈希
            if known_hash:
                known_hash = known_hash.lower().strip()
                match = file_hash == known_hash
                result['comparison'] = {
                    'known_hash': known_hash,
                    'match': match,
                }
                if match:
                    print_success(f"哈希值匹配已知值 ✓")
                else:
                    print_warning(f"哈希值不匹配已知值 ✗")
                    print_info(f"  期望值: {Colors.YELLOW}{known_hash}{Colors.RESET}")

            print_success("哈希比较完成")
            return result

        except Exception as e:
            error_msg = f"哈希比较时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _compute_hash(self, filepath, algorithm='sha256', buffer_size=65536):
        """计算文件哈希"""
        try:
            if algorithm == 'md5':
                h = hashlib.md5()
            elif algorithm == 'sha1':
                h = hashlib.sha1()
            elif algorithm == 'sha256':
                h = hashlib.sha256()
            elif algorithm == 'sha512':
                h = hashlib.sha512()
            else:
                print_error(f"不支持的哈希算法: {algorithm}")
                return None

            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(buffer_size)
                    if not chunk:
                        break
                    h.update(chunk)

            return h.hexdigest()

        except Exception as e:
            print_error(f"计算哈希失败: {e}")
            return None

    # ──────────────────────────────────────────────
    # 10. 熵分析
    # ──────────────────────────────────────────────

    def entropy_analyzer(self, filepath, block_size=256, show_blocks=True, max_blocks=100):
        """
        熵分析 - 计算文件的香农熵

        参数:
            filepath: 文件路径
            block_size: 块大小 (默认256字节)
            show_blocks: 是否显示每个块的熵值 (默认True)
            max_blocks: 最大显示块数 (默认100)

        返回:
            dict: 熵分析结果
        """
        print_section(f"熵分析: {os.path.basename(filepath)}")

        result = {
            'filepath': filepath,
            'block_size': block_size,
            'blocks': [],
            'overall_entropy': 0.0,
            'min_entropy': float('inf'),
            'max_entropy': 0.0,
            'classification': None,
        }

        try:
            if not os.path.exists(filepath):
                print_error(f"文件不存在: {filepath}")
                return result

            data = self._read_file_raw(filepath)
            if data is None:
                return result

            file_size = len(data)
            print_info(f"文件大小: {self._format_size(file_size)}")
            print_info(f"块大小: {block_size} 字节")
            print_info(f"总块数: {math.ceil(file_size / block_size)}")

            # 计算每个块的熵值
            block_entropies = []
            for i in range(0, file_size, block_size):
                block = data[i:i + block_size]
                if len(block) < 4:  # 跳过太小的块
                    continue
                entropy = self._calculate_entropy(block)
                block_entropies.append(entropy)

                if entropy < result['min_entropy']:
                    result['min_entropy'] = entropy
                if entropy > result['max_entropy']:
                    result['max_entropy'] = entropy

            if not block_entropies:
                print_error("没有足够的数据进行熵分析")
                return result

            # 计算总体熵
            result['overall_entropy'] = self._calculate_entropy(data)
            result['blocks'] = block_entropies

            # 分类文件
            result['classification'] = self._classify_by_entropy(
                result['overall_entropy'],
                result['min_entropy'],
                result['max_entropy'],
                block_entropies,
            )

            # 打印摘要
            print_info(f"总体熵值: {Colors.BOLD}{result['overall_entropy']:.4f}{Colors.RESET}")
            print_info(f"最小块熵: {result['min_entropy']:.4f}")
            print_info(f"最大块熵: {result['max_entropy']:.4f}")
            print_info(f"分类: {Colors.CYAN}{result['classification']}{Colors.RESET}")

            # 熵值说明
            if result['overall_entropy'] < 4.0:
                print_info("特征: 低熵 - 高度结构化/重复数据")
            elif result['overall_entropy'] < 6.0:
                print_info("特征: 中熵 - 混合内容/文本数据")
            elif result['overall_entropy'] < 7.5:
                print_info("特征: 高熵 - 压缩/多媒体数据")
            else:
                print_info("特征: 极高熵 - 加密/随机数据")

            # 显示块熵值
            if show_blocks and block_entropies:
                display_blocks = min(len(block_entropies), max_blocks)
                if len(block_entropies) > max_blocks:
                    print_info(f"熵值分布 (前 {max_blocks} 个块):")
                else:
                    print_info("熵值分布:")

                # 创建ASCII熵图
                for i in range(display_blocks):
                    e = block_entropies[i]
                    bar_len = int(e * 4)  # 最大8*4=32
                    bar = '█' * min(bar_len, 32) + '░' * max(0, 32 - bar_len)

                    # 颜色编码
                    if e < 4.0:
                        color = Colors.GREEN
                    elif e < 6.0:
                        color = Colors.YELLOW
                    elif e < 7.5:
                        color = Colors.ORANGE
                    else:
                        color = Colors.RED

                    offset = i * block_size
                    print(f"  {self._format_offset(offset)} |{color}{bar}{Colors.RESET}| {e:.2f}")

            # 显示异常高熵区域
            high_entropy_blocks = [(i, e) for i, e in enumerate(block_entropies) if e > 7.5]
            if high_entropy_blocks:
                print_warning(f"发现 {len(high_entropy_blocks)} 个异常高熵块 (> 7.5):")
                for idx, e in high_entropy_blocks[:5]:
                    offset = idx * block_size
                    print_warning(f"  偏移 {self._format_offset(offset)}: 熵值 {e:.2f}")
                if len(high_entropy_blocks) > 5:
                    print_info(f"  ... 以及 {len(high_entropy_blocks) - 5} 个其他块")

            print_success("熵分析完成")
            return result

        except Exception as e:
            error_msg = f"熵分析时出错: {e}"
            print_error(error_msg)
            result['error'] = str(e)
            return result

    def _calculate_entropy(self, data):
        """计算数据的香农熵"""
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        # 频率统计
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # 计算熵
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy

    def _classify_by_entropy(self, overall, min_e, max_e, blocks):
        """根据熵值分类文件"""
        if overall < 3.0:
            return "高度结构化数据 (源码/配置/文本)"
        elif overall < 4.5:
            return "文本/结构化数据"
        elif overall < 5.5:
            return "混合内容"
        elif overall < 7.0:
            return "多媒体/压缩数据"
        elif overall < 7.8:
            return "高熵数据 (强压缩/加密)"
        else:
            return "极高熵数据 (加密/随机)"

    # ──────────────────────────────────────────────
    # 辅助方法
    # ──────────────────────────────────────────────

    def _read_file_raw(self, filepath, offset=0, length=None):
        """读取文件的原始字节"""
        try:
            with open(filepath, 'rb') as f:
                f.seek(offset)
                if length is not None:
                    return f.read(length)
                return f.read()
        except PermissionError:
            print_error(f"权限不足: {filepath}")
            return None
        except FileNotFoundError:
            print_error(f"文件不存在: {filepath}")
            return None
        except Exception as e:
            print_error(f"读取文件失败: {e}")
            return None

    def _read_hex(self, filepath, length=16, offset=0):
        """读取文件并返回十六进制字符串"""
        data = self._read_file_raw(filepath, offset, length)
        if data:
            return data.hex().upper()
        return ''

    def _format_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def _format_offset(self, offset):
        """格式化偏移地址"""
        return f"0x{offset:08X}"

    def _format_hex_block(self, data):
        """格式化十六进制数据块为可读字符串"""
        if not data:
            return ''

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            hex_str = hex_str.ljust(47)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"0x{i:04X}  {hex_str}  |{ascii_str}|")

        return '\n'.join(lines)