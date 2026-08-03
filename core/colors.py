# -*- coding: utf-8 -*-
"""
颜色输出模块 - 跨平台支持
"""

import os
import sys

# 检测是否支持颜色
if os.name == 'nt':  # Windows
    try:
        import colorama
        colorama.init()
        _USE_COLOR = True
    except ImportError:
        _USE_COLOR = False
else:
    _USE_COLOR = True


class Colors:
    """ANSI颜色代码"""
    if _USE_COLOR:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        UNDERLINE = '\033[4m'
        BLINK = '\033[5m'
        RESET = '\033[0m'
        LIGHT_RED = '\033[91m'
        LIGHT_GREEN = '\033[92m'
        LIGHT_YELLOW = '\033[93m'
        LIGHT_BLUE = '\033[94m'
        LIGHT_MAGENTA = '\033[95m'
        LIGHT_CYAN = '\033[96m'
        ORANGE = '\033[38;5;214m'
        PURPLE = '\033[38;5;129m'
        GRAY = '\033[90m'
        DARK_RED = '\033[31m'
        DARK_GREEN = '\033[32m'
        DARK_YELLOW = '\033[33m'
        DARK_BLUE = '\033[34m'
        DARK_MAGENTA = '\033[35m'
        DARK_CYAN = '\033[36m'
        BG_RED = '\033[41m'
        BG_GREEN = '\033[42m'
        BG_YELLOW = '\033[43m'
        BG_BLUE = '\033[44m'
        BG_MAGENTA = '\033[45m'
        BG_CYAN = '\033[46m'
        BG_DARK_GRAY = '\033[100m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
        BOLD = DIM = UNDERLINE = BLINK = RESET = ''
        LIGHT_RED = LIGHT_GREEN = LIGHT_YELLOW = LIGHT_BLUE = ''
        LIGHT_MAGENTA = LIGHT_CYAN = ORANGE = PURPLE = GRAY = ''
        DARK_RED = DARK_GREEN = DARK_YELLOW = DARK_BLUE = ''
        DARK_MAGENTA = DARK_CYAN = ''
        BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = ''
        BG_MAGENTA = BG_CYAN = BG_DARK_GRAY = ''


def colorize(text, color, bold=False):
    """给文本添加颜色"""
    if bold:
        return f"{Colors.BOLD}{color}{text}{Colors.RESET}"
    return f"{color}{text}{Colors.RESET}"


def print_info(msg):
    """打印信息消息"""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def print_success(msg):
    """打印成功消息"""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def print_warning(msg):
    """打印警告消息"""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_error(msg):
    """打印错误消息"""
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def print_banner(msg):
    """打印横幅"""
    print(f"{Colors.CYAN}{Colors.BOLD}{msg}{Colors.RESET}")


def print_section(title):
    """打印分区标题"""
    width = 60
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}{'='*width}{Colors.RESET}")
    print(f"{Colors.MAGENTA}{Colors.BOLD}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.MAGENTA}{Colors.BOLD}{'='*width}{Colors.RESET}\n")


def print_table(headers, rows, color=Colors.CYAN):
    """打印表格"""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # 打印表头
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(f"{color}{Colors.BOLD}{header_line}{Colors.RESET}")
    print(f"{color}{'-' * len(header_line)}{Colors.RESET}")

    # 打印数据行
    for row in rows:
        line = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        print(f"{color}{line}{Colors.RESET}")