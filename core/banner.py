# -*- coding: utf-8 -*-
"""
ASCII 横幅和关于信息
"""

from core.colors import Colors, colorize


BANNER = f"""
{Colors.RED}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   {Colors.LIGHT_CYAN}██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗{Colors.RED}   ║
    ║   {Colors.LIGHT_CYAN}██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗{Colors.RED}   ║
    ║   {Colors.LIGHT_CYAN}███████║███████║██║     █████╔╝ █████╗  ██████╔╝{Colors.RED}   ║
    ║   {Colors.LIGHT_CYAN}██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗{Colors.RED}   ║
    ║   {Colors.LIGHT_CYAN}██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║{Colors.RED}   ║
    ║   {Colors.LIGHT_CYAN}╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{Colors.RED}   ║
    ║                                                          ║
    ║              {Colors.YELLOW}Ultimate Security Toolkit{Colors.RED}                 ║
    ║           {Colors.GRAY}Penetration Testing Framework v3.0{Colors.RED}            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
{Colors.RESET}"""


SMALL_BANNER = f"""
{Colors.RED}{Colors.BOLD}╔═══ HackerToolkit ═══╗
║ {Colors.CYAN}Ultimate Security Toolkit{Colors.RED} ║
╚═══════════════════════╝{Colors.RESET}
"""


ABOUT = f"""
{Colors.CYAN}{Colors.BOLD}HackerToolkit - 全能网络安全工具包{Colors.RESET}
{Colors.GRAY}{'='*50}{Colors.RESET}

{Colors.YELLOW}描述:{Colors.RESET}   一个集信息收集、漏洞扫描、漏洞利用、密码攻击、
             网络分析、取证分析、OSINT 于一体的多功能安全工具包

{Colors.YELLOW}版本:{Colors.RESET}    3.0.0
{Colors.YELLOW}作者:{Colors.RESET}    Security Research Team
{Colors.YELLOW}平台:{Colors.RESET}    Windows / Linux / macOS

{Colors.YELLOW}模块列表:{Colors.RESET}
  {Colors.GREEN}[01]{Colors.RESET} 信息收集模块      - 15+ 工具 (端口扫描、DNS枚举、子域名等)
  {Colors.GREEN}[02]{Colors.RESET} Web漏洞扫描模块    - 15+ 工具 (SQL注入、XSS、LFI等)
  {Colors.GREEN}[03]{Colors.RESET} 漏洞利用模块       - 10+ 工具 (反弹Shell、Payload生成等)
  {Colors.GREEN}[04]{Colors.RESET} 网络工具模块       - 10+ 工具 (嗅探、ARP、扫描等)
  {Colors.GREEN}[05]{Colors.RESET} Web工具模块        - 10+ 工具 (目录爆破、爬虫、SSL等)
  {Colors.GREEN}[06]{Colors.RESET} 密码攻击模块       - 8+ 工具 (爆破、哈希破解等)
  {Colors.GREEN}[07]{Colors.RESET} 加密/编码工具      - 8+ 工具 (哈希、编码、密码等)
  {Colors.GREEN}[08]{Colors.RESET} OSINT模块          - 8+ 工具 (邮箱、用户名、电话等)
  {Colors.GREEN}[09]{Colors.RESET} 取证分析模块       - 6+ 工具 (元数据、隐写、文件分析)
  {Colors.GREEN}[10]{Colors.RESET} SearchSploit模块    - 5+ 工具 (漏洞库搜索)
  {Colors.GREEN}[11]{Colors.RESET} 实用工具模块       - 10+ 工具 (编码、转换、生成器)

{Colors.YELLOW}免责声明:{Colors.RESET}
  本工具仅用于授权的安全测试和教育目的。
  使用者应遵守当地法律法规，作者不承担任何法律责任。

{Colors.GRAY}{'='*50}{Colors.RESET}
"""


def print_banner():
    """打印主横幅"""
    print(BANNER)


def print_small_banner():
    """打印小横幅"""
    print(SMALL_BANNER)


def print_about():
    """打印关于信息"""
    print(ABOUT)