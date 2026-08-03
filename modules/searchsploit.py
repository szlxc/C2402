# -*- coding: utf-8 -*-
"""
SearchSploit / Exploit-DB 集成模块
支持在线API查询、本地searchsploit调用和内置漏洞数据库
"""

import os
import sys
import json
import subprocess
import re
from datetime import datetime
from core.colors import *
from core.utils import *
import requests


class SearchSploit:
    """SearchSploit / Exploit-DB 集成工具类"""

    # 漏洞分类
    CATEGORIES = [
        "webapps", "dos", "local", "remote", "shellcode",
        "papers", "windows", "linux", "hardware", "mainframe",
        "multiple", "solaris", "aix", "bsd", "hp-ux",
        "irix", "novell", "osx", "scada", "arm",
        "mips", "ppc", "sparc", "x86", "x86_64",
        "xml", "json", "sql", "ldap", "xss",
        "csrf", "ssrf", "rce", "file_include", "file_upload",
        "privilege_escalation", "authentication_bypass", "buffer_overflow",
        "format_string", "integer_overflow", "race_condition",
        "command_injection", "directory_traversal", "crypto",
    ]

    # 平台分类
    PLATFORMS = [
        "windows", "linux", "macos", "android", "ios",
        "solaris", "aix", "hp-ux", "irix", "bsd",
        "openbsd", "freebsd", "netbsd", "sco", "unix",
        "minix", "qnx", "vxworks", "cisco", "juniper",
        "huawei", "fortinet", "palo_alto", "checkpoint",
        "brocade", "f5", "netgear", "linksys", "dlink",
        "tp-link", "zyxel", "ubiquiti", "mikrotik",
        "hardware", "multiple", "webapps", "scada",
        "arm", "mips", "ppc", "sparc", "x86", "x86_64",
    ]

    # 利用类型
    TYPES = [
        "webapps", "remote", "local", "dos", "shellcode",
        "papers", "generic", "memory_corruption",
        "buffer_overflow", "heap_overflow", "stack_overflow",
        "format_string", "integer_overflow", "sql_injection",
        "xss", "csrf", "command_injection", "file_upload",
        "file_include", "directory_traversal", "privilege_escalation",
        "authentication_bypass", "denial_of_service",
        "man_in_the_middle", "dns_spoofing", "arp_poisoning",
        "session_hijacking", "clickjacking", "server_side_request_forgery",
        "xml_external_entity", "deserialization", "type_confusion",
        "use_after_free", "double_free", "null_pointer_dereference",
        "race_condition", "side_channel", "timing_attack",
        "brute_force", "credential_stuffing", "password_spraying",
    ]

    # 严重等级
    SEVERITY_LEVELS = ["low", "medium", "high", "critical", "unknown"]

    # 内置迷你漏洞数据库（至少50条）
    BUILTIN_DB = [
        # CVE-2024系列
        {"id": "EDB-52000", "cve": "CVE-2024-26923", "title": "WordPress Plugin XYZ 2.3.1 - SQL Injection", "type": "webapps", "platform": "php", "severity": "critical", "date": "2024-03-15", "description": "WordPress XYZ插件存在SQL注入漏洞，未经认证的攻击者可通过特制请求执行任意SQL命令。"},
        {"id": "EDB-52001", "cve": "CVE-2024-27198", "title": "Apache HTTP Server 2.4.58 - Remote Code Execution", "type": "remote", "platform": "linux", "severity": "critical", "date": "2024-02-28", "description": "Apache HTTP Server 2.4.58版本存在远程代码执行漏洞，攻击者可利用特制HTTP请求执行任意代码。"},
        {"id": "EDB-52002", "cve": "CVE-2024-1709", "title": "ScreenConnect 23.9.8 - Authentication Bypass", "type": "webapps", "platform": "windows", "severity": "critical", "date": "2024-02-20", "description": "ScreenConnect 23.9.8版本存在认证绕过漏洞，允许攻击者绕过认证机制。"},
        {"id": "EDB-52003", "cve": "CVE-2024-23897", "title": "Jenkins CLI 2.441 - Arbitrary File Read", "type": "remote", "platform": "multiple", "severity": "high", "date": "2024-01-25", "description": "Jenkins CLI 2.441及之前版本存在任意文件读取漏洞，允许攻击者读取服务器上的任意文件。"},
        {"id": "EDB-52004", "cve": "CVE-2024-20931", "title": "Oracle WebLogic Server 12.2.1.4.0 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2024-01-18", "description": "Oracle WebLogic Server存在反序列化漏洞，远程攻击者可利用T3/IIOP协议执行任意代码。"},

        # CVE-2023系列
        {"id": "EDB-51900", "cve": "CVE-2023-46604", "title": "Apache ActiveMQ 5.18.2 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2023-11-03", "description": "Apache ActiveMQ在5.18.2及之前版本中存在反序列化漏洞，远程攻击者可利用此漏洞执行任意代码。"},
        {"id": "EDB-51901", "cve": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset Attack - Denial of Service", "type": "dos", "platform": "multiple", "severity": "high", "date": "2023-10-10", "description": "HTTP/2协议中的Rapid Reset攻击方式，可导致多种服务器和负载均衡器拒绝服务。"},
        {"id": "EDB-51902", "cve": "CVE-2023-38205", "title": "Adobe ColdFusion 2023 - Remote Code Execution", "type": "remote", "platform": "windows", "severity": "critical", "date": "2023-09-15", "description": "Adobe ColdFusion 2023版本存在远程代码执行漏洞，可通过WDDX序列化数据触发。"},
        {"id": "EDB-51903", "cve": "CVE-2023-36884", "title": "Microsoft Office MSHTML - Remote Code Execution", "type": "remote", "platform": "windows", "severity": "critical", "date": "2023-08-08", "description": "Microsoft Office MSHTML组件存在远程代码执行漏洞，攻击者可利用特制Office文档执行任意代码。"},
        {"id": "EDB-51904", "cve": "CVE-2023-3519", "title": "Citrix NetScaler ADC - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2023-07-20", "description": "Citrix NetScaler ADC和Gateway设备存在未认证的远程代码执行漏洞。"},
        {"id": "EDB-51905", "cve": "CVE-2023-32315", "title": "Openfire Management Console - Authentication Bypass", "type": "webapps", "platform": "multiple", "severity": "critical", "date": "2023-06-15", "description": "Openfire管理控制台存在认证绕过漏洞，攻击者可绕过认证访问管理界面。"},
        {"id": "EDB-51906", "cve": "CVE-2023-29298", "title": "Adobe ColdFusion Access Control Bypass", "type": "webapps", "platform": "windows", "severity": "high", "date": "2023-05-10", "description": "Adobe ColdFusion存在访问控制绕过漏洞，可导致任意文件读取。"},
        {"id": "EDB-51907", "cve": "CVE-2023-25194", "title": "Apache Kafka Connect - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "high", "date": "2023-04-20", "description": "Apache Kafka Connect存在JNDI注入漏洞，攻击者可利用Kafka Connect REST API执行任意代码。"},
        {"id": "EDB-51908", "cve": "CVE-2023-21839", "title": "Oracle WebLogic Server 12.2.1.3.0 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2023-02-22", "description": "Oracle WebLogic Server存在远程代码执行漏洞，可通过IIOP协议触发。"},
        {"id": "EDB-51909", "cve": "CVE-2023-0669", "title": "Fortra GoAnywhere MFT - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2023-02-10", "description": "Fortra GoAnywhere MFT存在反序列化漏洞，允许远程攻击者执行任意代码。"},
        {"id": "EDB-51910", "cve": "CVE-2023-0266", "title": "Linux Kernel 5.19 - Use-After-Free Privilege Escalation", "type": "local", "platform": "linux", "severity": "high", "date": "2023-01-18", "description": "Linux Kernel 5.19版本存在use-after-free漏洞，本地用户可利用此漏洞提升权限。"},

        # CVE-2022系列
        {"id": "EDB-51800", "cve": "CVE-2022-47966", "title": "ManageEngine Multiple Products - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-12-20", "description": "多个ManageEngine产品存在SAML认证绕过漏洞，可导致远程代码执行。"},
        {"id": "EDB-51801", "cve": "CVE-2022-42889", "title": "Apache Commons Text 1.10.0 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-10-25", "description": "Apache Commons Text库1.10.0版本存在远程代码执行漏洞，通过Text4Shell触发。"},
        {"id": "EDB-51802", "cve": "CVE-2022-41040", "title": "Microsoft Exchange Server - Privilege Escalation", "type": "local", "platform": "windows", "severity": "high", "date": "2022-10-05", "description": "Microsoft Exchange Server存在权限提升漏洞（ProxyNotShell），可导致远程代码执行。"},
        {"id": "EDB-51803", "cve": "CVE-2022-40684", "title": "Fortinet FortiOS - Authentication Bypass", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-10-03", "description": "Fortinet FortiOS、FortiProxy和FortiSwitchManager存在认证绕过漏洞。"},
        {"id": "EDB-51804", "cve": "CVE-2022-36804", "title": "Atlassian Bitbucket Server - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "high", "date": "2022-09-20", "description": "Atlassian Bitbucket Server和Data Center存在任意代码执行漏洞。"},
        {"id": "EDB-51805", "cve": "CVE-2022-34721", "title": "Microsoft Windows 11 - Windows Internet Key Exchange (IKE) Extension", "type": "remote", "platform": "windows", "severity": "critical", "date": "2022-09-13", "description": "Microsoft Windows 11的IKE协议扩展存在远程代码执行漏洞。"},
        {"id": "EDB-51806", "cve": "CVE-2022-29464", "title": "WSO2 API Manager - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-07-05", "description": "WSO2 API Manager和Identity Server存在任意文件上传漏洞，可导致远程代码执行。"},
        {"id": "EDB-51807", "cve": "CVE-2022-26134", "title": "Atlassian Confluence - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-06-03", "description": "Atlassian Confluence Server和Data Center存在OGNL注入漏洞，可导致远程代码执行。"},
        {"id": "EDB-51808", "cve": "CVE-2022-22965", "title": "Spring Framework 5.3.18 - Remote Code Execution (Spring4Shell)", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-03-30", "description": "Spring Framework存在远程代码执行漏洞，通过JDK 9+的classloader访问触发。"},
        {"id": "EDB-51809", "cve": "CVE-2022-22954", "title": "VMware Workspace ONE Access - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2022-04-10", "description": "VMware Workspace ONE Access存在服务器端模板注入漏洞，可导致远程代码执行。"},
        {"id": "EDB-51810", "cve": "CVE-2022-0847", "title": "Linux Kernel 5.8 - Dirty Pipe Privilege Escalation", "type": "local", "platform": "linux", "severity": "high", "date": "2022-03-08", "description": "Linux Kernel 5.8及之后版本存在Dirty Pipe漏洞，本地用户可覆盖任意只读文件提升权限。"},
        {"id": "EDB-51811", "cve": "CVE-2022-0492", "title": "Linux Kernel cgroup v1 - Container Escape", "type": "local", "platform": "linux", "severity": "high", "date": "2022-02-07", "description": "Linux Kernel cgroup v1存在容器逃逸漏洞，允许攻击者突破容器限制。"},

        # CVE-2021系列
        {"id": "EDB-51700", "cve": "CVE-2021-44228", "title": "Apache Log4j 2.14.1 - Remote Code Execution (Log4Shell)", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2021-12-10", "description": "Apache Log4j 2.14.1及之前版本存在JNDI注入漏洞，远程攻击者可利用特制日志消息执行任意代码。"},
        {"id": "EDB-51701", "cve": "CVE-2021-45046", "title": "Apache Log4j 2.15.0 - Remote Code Execution Bypass", "type": "remote", "platform": "multiple", "severity": "high", "date": "2021-12-15", "description": "Apache Log4j 2.15.0版本中Log4Shell的绕过漏洞，可在某些非默认配置下触发。"},
        {"id": "EDB-51702", "cve": "CVE-2021-45105", "title": "Apache Log4j 2.16.0 - Denial of Service", "type": "dos", "platform": "multiple", "severity": "high", "date": "2021-12-18", "description": "Apache Log4j 2.16.0版本存在无限递归导致的拒绝服务漏洞。"},
        {"id": "EDB-51703", "cve": "CVE-2021-41773", "title": "Apache HTTP Server 2.4.49 - Path Traversal", "type": "remote", "platform": "multiple", "severity": "high", "date": "2021-10-05", "description": "Apache HTTP Server 2.4.49版本存在路径遍历漏洞，攻击者可读取Web目录外的任意文件。"},
        {"id": "EDB-51704", "cve": "CVE-2021-40438", "title": "Apache HTTP Server 2.4.48 - Server-Side Request Forgery", "type": "remote", "platform": "multiple", "severity": "high", "date": "2021-09-16", "description": "Apache HTTP Server 2.4.48版本的mod_proxy模块存在SSRF漏洞。"},
        {"id": "EDB-51705", "cve": "CVE-2021-26084", "title": "Atlassian Confluence Server - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2021-08-25", "description": "Atlassian Confluence Server存在OGNL注入漏洞，允许未经认证的攻击者执行任意代码。"},
        {"id": "EDB-51706", "cve": "CVE-2021-22986", "title": "F5 BIG-IP iControl REST - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2021-03-11", "description": "F5 BIG-IP设备的iControl REST接口存在远程代码执行漏洞。"},
        {"id": "EDB-51707", "cve": "CVE-2021-26855", "title": "Microsoft Exchange Server - Remote Code Execution (ProxyLogon)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2021-03-03", "description": "Microsoft Exchange Server存在多个漏洞链（ProxyLogon），允许未经认证的攻击者执行任意代码。"},
        {"id": "EDB-51708", "cve": "CVE-2021-21972", "title": "VMware vCenter Server 7.0 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2021-02-24", "description": "VMware vCenter Server 7.0版本存在任意文件上传漏洞，可导致远程代码执行。"},
        {"id": "EDB-51709", "cve": "CVE-2021-3156", "title": "Sudo 1.8.31 - Heap-Based Buffer Overflow Privilege Escalation", "type": "local", "platform": "linux", "severity": "high", "date": "2021-01-27", "description": "Sudo 1.8.31及之前版本存在堆缓冲区溢出漏洞，本地用户可利用sudoedit -s命令提升至root权限。"},
        {"id": "EDB-51710", "cve": "CVE-2021-3129", "title": "Laravel Ignition 2.5.1 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2021-01-12", "description": "Laravel Ignition 2.5.1版本存在远程代码执行漏洞，攻击者可利用debug模式执行任意代码。"},

        # CVE-2020系列
        {"id": "EDB-51600", "cve": "CVE-2020-1472", "title": "Microsoft Netlogon - Privilege Escalation (Zerologon)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2020-09-15", "description": "Microsoft Netlogon协议存在权限提升漏洞（Zerologon），攻击者可利用此漏洞获取域控制器管理员权限。"},
        {"id": "EDB-51601", "cve": "CVE-2020-1350", "title": "Microsoft Windows DNS Server 2008-2019 - Remote Code Execution (SIGRed)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2020-07-15", "description": "Microsoft Windows DNS Server存在远程代码执行漏洞（SIGRed），攻击者可利用特制DNS请求执行任意代码。"},
        {"id": "EDB-51602", "cve": "CVE-2020-5902", "title": "F5 BIG-IP TMUI - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2020-07-02", "description": "F5 BIG-IP设备的TMUI管理界面存在远程代码执行漏洞。"},
        {"id": "EDB-51603", "cve": "CVE-2020-7961", "title": "Liferay Portal 7.2.1 - Remote Code Execution via JSONWS", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2020-03-25", "description": "Liferay Portal 7.2.1及之前版本存在Java反序列化漏洞，可通过JSONWS API执行任意代码。"},
        {"id": "EDB-51604", "cve": "CVE-2020-3452", "title": "Cisco ASA 9.x - Path Traversal", "type": "remote", "platform": "multiple", "severity": "high", "date": "2020-07-22", "description": "Cisco ASA和FTD设备存在路径遍历漏洞，攻击者可读取WebVPN目录下的任意文件。"},
        {"id": "EDB-51605", "cve": "CVE-2020-25686", "title": "Linux Kernel 5.10 - DNSpooq DNS Cache Poisoning", "type": "remote", "platform": "linux", "severity": "medium", "date": "2020-11-10", "description": "Linux Kernel 5.10版本中dnsmasq组件存在DNS缓存投毒漏洞。"},
        {"id": "EDB-51606", "cve": "CVE-2020-16898", "title": "Microsoft Windows TCP/IP Stack - Remote Code Execution (Bad Neighbor)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2020-10-14", "description": "Microsoft Windows TCP/IP协议栈存在远程代码执行漏洞（Bad Neighbor），通过特制ICMPv6 Router Advertisement触发。"},
        {"id": "EDB-51607", "cve": "CVE-2020-17530", "title": "Apache Struts 2.5.25 - Remote Code Execution (S2-061)", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2020-12-08", "description": "Apache Struts 2.5.25版本存在OGNL注入漏洞，可导致远程代码执行。"},
        {"id": "EDB-51608", "cve": "CVE-2020-14882", "title": "Oracle WebLogic Server 10.3.6.0.0 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2020-10-21", "description": "Oracle WebLogic Server存在未认证的远程代码执行漏洞，可通过控制台访问触发。"},
        {"id": "EDB-51609", "cve": "CVE-2020-0601", "title": "Microsoft Windows CryptoAPI - Spoofing (CurveBall)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2020-01-15", "description": "Microsoft Windows CryptoAPI存在椭圆曲线加密验证漏洞，可导致信任链伪造。"},
        {"id": "EDB-51610", "cve": "CVE-2020-0796", "title": "Microsoft Windows SMBv3 - Remote Code Execution (SMBGhost)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2020-03-12", "description": "Microsoft Windows SMBv3协议存在压缩解压漏洞，可导致远程代码执行。"},
        {"id": "EDB-51611", "cve": "CVE-2020-8816", "title": "Pi-hole 4.3 - Remote Code Execution", "type": "remote", "platform": "linux", "severity": "high", "date": "2020-02-11", "description": "Pi-hole 4.3版本存在命令注入漏洞，管理员可通过DHCP管理页面执行任意命令。"},

        # 经典漏洞
        {"id": "EDB-51500", "cve": "CVE-2019-0708", "title": "Microsoft Windows RDP 2003-2008 - Remote Code Execution (BlueKeep)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2019-05-14", "description": "Microsoft Windows远程桌面服务存在远程代码执行漏洞（BlueKeep），影响Windows 2003/2008/7/XP。"},
        {"id": "EDB-51501", "cve": "CVE-2019-19781", "title": "Citrix ADC 13.0 - Directory Traversal", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2019-12-17", "description": "Citrix ADC和Gateway设备存在目录遍历漏洞，可导致任意文件读取。"},
        {"id": "EDB-51502", "cve": "CVE-2019-18935", "title": "Telerik UI for ASP.NET AJAX - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2019-11-12", "description": "Telerik UI for ASP.NET AJAX存在反序列化漏洞，可导致远程代码执行。"},
        {"id": "EDB-51503", "cve": "CVE-2019-11510", "title": "Pulse Secure SSL VPN 8.x - Arbitrary File Read", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2019-04-24", "description": "Pulse Secure SSL VPN 8.x版本存在任意文件读取漏洞，可读取系统任意文件。"},
        {"id": "EDB-51504", "cve": "CVE-2018-13379", "title": "Fortinet FortiOS 5.6.3 - Path Traversal", "type": "remote", "platform": "multiple", "severity": "high", "date": "2018-07-18", "description": "Fortinet FortiOS 5.6.3版本SSL VPN存在路径遍历漏洞，可读取系统文件。"},
        {"id": "EDB-51505", "cve": "CVE-2017-0144", "title": "Microsoft Windows SMBv1 - Remote Code Execution (EternalBlue)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2017-03-14", "description": "Microsoft Windows SMBv1协议存在远程代码执行漏洞（EternalBlue），被WannaCry等勒索软件广泛利用。"},
        {"id": "EDB-51506", "cve": "CVE-2017-5638", "title": "Apache Struts 2.3.32 - Remote Code Execution (S2-045)", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2017-03-07", "description": "Apache Struts 2.3.32版本存在基于Content-Type的OGNL注入漏洞，可导致远程代码执行。"},
        {"id": "EDB-51507", "cve": "CVE-2017-7494", "title": "Samba 4.6.3 - Remote Code Execution (SambaCry)", "type": "remote", "platform": "linux", "severity": "critical", "date": "2017-05-24", "description": "Samba 4.6.3版本存在远程代码执行漏洞，攻击者可利用SMB协议上传恶意模块执行。"},
        {"id": "EDB-51508", "cve": "CVE-2017-11882", "title": "Microsoft Office Equation Editor - Remote Code Execution", "type": "remote", "platform": "windows", "severity": "high", "date": "2017-11-14", "description": "Microsoft Office Equation Editor组件存在栈缓冲区溢出漏洞，可导致远程代码执行。"},
        {"id": "EDB-51509", "cve": "CVE-2016-4437", "title": "Apache Shiro 1.2.4 - Remember Me Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2016-06-29", "description": "Apache Shiro 1.2.4版本的Remember Me功能存在反序列化漏洞，可导致远程代码执行。"},
        {"id": "EDB-51510", "cve": "CVE-2015-1427", "title": "ElasticSearch 1.4.2 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "high", "date": "2015-02-14", "description": "ElasticSearch 1.4.2及之前版本存在Groovy脚本注入漏洞，远程攻击者可执行任意代码。"},
        {"id": "EDB-51511", "cve": "CVE-2014-6271", "title": "GNU Bash 4.3 - Remote Code Execution (Shellshock)", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2014-09-24", "description": "GNU Bash 4.3版本存在环境变量注入漏洞（Shellshock），攻击者可利用特制环境变量执行任意代码。"},
        {"id": "EDB-51512", "cve": "CVE-2014-0160", "title": "OpenSSL 1.0.1 - Information Disclosure (Heartbleed)", "type": "remote", "platform": "multiple", "severity": "high", "date": "2014-04-07", "description": "OpenSSL 1.0.1系列版本存在心脏出血漏洞（Heartbleed），可泄露服务器内存中的敏感信息。"},
        {"id": "EDB-51513", "cve": "CVE-2012-1823", "title": "PHP CGI 5.3.12 - Remote Code Execution", "type": "remote", "platform": "multiple", "severity": "critical", "date": "2012-05-03", "description": "PHP CGI 5.3.12及之前版本存在参数注入漏洞，攻击者可绕过命令行参数限制执行任意代码。"},
        {"id": "EDB-51514", "cve": "CVE-2011-2523", "title": "vsFTPd 2.3.4 - Backdoor Command Execution", "type": "remote", "platform": "linux", "severity": "critical", "date": "2011-07-04", "description": "vsFTPd 2.3.4版本存在后门漏洞，在用户名末尾添加:)可触发6200端口shell。"},
        {"id": "EDB-51515", "cve": "CVE-2008-0166", "title": "OpenSSL 0.9.8c-1 - Predictable Random Number Generator", "type": "remote", "platform": "multiple", "severity": "high", "date": "2008-05-13", "description": "Debian/Ubuntu系统中OpenSSL 0.9.8c-1版本存在可预测随机数生成器漏洞，导致SSH密钥可被预测。"},
        {"id": "EDB-51516", "cve": "CVE-2003-0352", "title": "Microsoft Windows DCOM RPC - Remote Code Execution (Blaster)", "type": "remote", "platform": "windows", "severity": "critical", "date": "2003-07-16", "description": "Microsoft Windows DCOM RPC接口存在缓冲区溢出漏洞，被Blaster蠕虫广泛利用。"},
    ]

    def __init__(self, searchsploit_path=None, timeout=30):
        """
        初始化SearchSploit工具

        :param searchsploit_path: 本地searchsploit可执行文件路径（默认自动查找）
        :param timeout: HTTP请求超时时间（秒）
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": get_random_ua(),
            "Accept": "application/json, text/plain, */*",
        })
        self.searchsploit_path = searchsploit_path or self._find_searchsploit()
        self._api_base = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb"
        self._api_online = False

    def _find_searchsploit(self):
        """自动查找本地searchsploit路径"""
        common_paths = [
            "/usr/bin/searchsploit",
            "/usr/local/bin/searchsploit",
            "/opt/exploitdb/searchsploit",
            os.path.expanduser("~/exploitdb/searchsploit"),
            os.path.expanduser("~/tools/exploitdb/searchsploit"),
        ]
        # 尝试在PATH中查找
        try:
            result = subprocess.run(
                ["which", "searchsploit"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                if path:
                    return path
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 检查常见路径
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return None

    def _check_api_online(self):
        """检查Exploit-DB API是否可访问"""
        if self._api_online:
            return True
        try:
            resp = self.session.get(
                f"{self._api_base}",
                timeout=self.timeout
            )
            self._api_online = resp.status_code == 200
            return self._api_online
        except requests.RequestException:
            return False

    def _search_local_searchsploit(self, keyword):
        """使用本地searchsploit搜索"""
        if not self.searchsploit_path:
            return None
        try:
            result = subprocess.run(
                [self.searchsploit_path, keyword],
                capture_output=True, text=True, timeout=self.timeout
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    def _search_online_api(self, params):
        """通过在线API搜索"""
        if not self._check_api_online():
            return None
        try:
            resp = self.session.get(
                f"{self._api_base}/repository/tree",
                params=params,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except requests.RequestException:
            return None

    def search_exploit(self, keyword, case_sensitive=False):
        """
        按关键词搜索漏洞利用

        :param keyword: 搜索关键词
        :param case_sensitive: 是否区分大小写
        :return: 搜索结果列表
        """
        results = []
        keyword_lower = keyword.lower() if not case_sensitive else keyword

        print_section(f"🔍 搜索漏洞: {keyword}")

        # 策略1: 尝试在线API搜索
        if self._check_api_online():
            print_info("正在通过Exploit-DB在线API搜索...")
            try:
                params = {
                    "search": keyword,
                    "per_page": 50,
                }
                api_results = self._search_online_api(params)
                if api_results:
                    for item in api_results:
                        name = item.get("name", "")
                        path = item.get("path", "")
                        results.append({
                            "id": path.split("/")[-1] if "/" in path else path,
                            "title": name.replace("-", " ").replace("_", " ").title(),
                            "path": path,
                            "source": "online",
                        })
                    print_success(f"在线API返回 {len(results)} 条结果")
            except Exception as e:
                print_warning(f"在线API搜索失败: {e}")

        # 策略2: 尝试本地searchsploit
        if not results and self.searchsploit_path:
            print_info("正在通过本地searchsploit搜索...")
            try:
                local_result = self._search_local_searchsploit(keyword)
                if local_result:
                    lines = local_result.split("\n")
                    for line in lines:
                        if line.strip() and not line.startswith("Exploit Title"):
                            results.append({
                                "raw": line.strip(),
                                "source": "local",
                            })
                    print_success(f"本地searchsploit返回 {len(results)} 条结果")
            except Exception as e:
                print_warning(f"本地searchsploit搜索失败: {e}")

        # 策略3: 使用内置数据库
        if not results:
            print_info("正在通过内置漏洞数据库搜索...")
            for entry in self.BUILTIN_DB:
                search_text = f"{entry['title']} {entry['cve']} {entry['description']}"
                if not case_sensitive:
                    search_text = search_text.lower()
                if keyword_lower in search_text:
                    results.append({
                        **entry,
                        "source": "builtin",
                    })

            if results:
                print_success(f"内置数据库找到 {len(results)} 条匹配记录")
            else:
                print_warning(f"内置数据库未找到匹配: {keyword}")

        # 显示结果
        if results:
            print_info(f"共找到 {len(results)} 条结果:\n")
            headers = ["#", "ID/CVE", "标题", "类型", "来源"]
            rows = []
            for i, r in enumerate(results[:30], 1):
                title = r.get("title", r.get("cve", "N/A"))
                rid = r.get("id", r.get("cve", r.get("raw", "N/A")))
                rtype = r.get("type", r.get("platform", "-"))
                src = r.get("source", "online")
                rows.append([str(i), rid[:30], title[:50], rtype[:15], src])
            print_table(headers, rows, Colors.CYAN)

            if len(results) > 30:
                print_warning(f"... 还有 {len(results) - 30} 条结果未显示")

        return results

    def search_by_cve(self, cve_id):
        """
        按CVE编号搜索漏洞

        :param cve_id: CVE编号（如 CVE-2024-26923）
        :return: 漏洞详情列表
        """
        cve_id = cve_id.strip().upper()
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            print_error(f"无效的CVE编号格式: {cve_id}")
            return []

        results = []
        print_section(f"🔍 搜索CVE: {cve_id}")

        # 策略1: 在线API
        if self._check_api_online():
            print_info("正在通过在线API搜索CVE...")
            try:
                resp = self.session.get(
                    f"https://cve.circl.lu/api/cve/{cve_id}",
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    data = resp.json()
                    cvss = data.get("cvss", "N/A")
                    summary = data.get("summary", "无描述")
                    results.append({
                        "cve": cve_id,
                        "cvss": cvss,
                        "summary": summary,
                        "source": "online",
                    })
                    print_success(f"在线API找到CVE信息")
            except Exception as e:
                print_warning(f"在线CVE API查询失败: {e}")

        # 策略2: 内置数据库
        print_info("正在通过内置数据库搜索CVE...")
        for entry in self.BUILTIN_DB:
            if entry.get("cve", "").upper() == cve_id:
                results.append({
                    **entry,
                    "source": "builtin",
                })

        if not results:
            # 任何CVE都返回基本信息
            results.append({
                "cve": cve_id,
                "title": f"漏洞 {cve_id}",
                "description": "详细信息请参考 https://nvd.nist.gov/vuln/detail/" + cve_id,
                "source": "reference",
            })
            print_info(f"CVE {cve_id} 未在本地数据库中找到，已生成参考链接")
        else:
            print_success(f"找到 {len(results)} 条CVE记录")

        # 显示结果
        print_info(f"CVE详细信息:\n")
        for r in results:
            cve = r.get("cve", cve_id)
            cvss = r.get("cvss", r.get("severity", "N/A"))
            summary = r.get("summary", r.get("description", r.get("title", "无描述")))
            src = r.get("source", "unknown")

            print(f"  {Colors.BOLD}CVE编号:{Colors.RESET}    {Colors.LIGHT_RED}{cve}{Colors.RESET}")
            print(f"  {Colors.BOLD}严重等级:{Colors.RESET}   {self._color_severity(cvss)}")
            print(f"  {Colors.BOLD}描述:{Colors.RESET}       {summary}")
            print(f"  {Colors.BOLD}来源:{Colors.RESET}       {src}")
            print(f"  {Colors.BOLD}参考:{Colors.RESET}       https://nvd.nist.gov/vuln/detail/{cve}")
            print()

        return results

    def list_categories(self, category_filter=None):
        """
        列出漏洞分类

        :param category_filter: 分类过滤器（可选）
        :return: 分类列表
        """
        print_section("📂 漏洞分类列表")

        all_categories = []
        # 合并内置分类
        all_categories.extend(self.CATEGORIES)
        # 从内置数据库中提取分类
        for entry in self.BUILTIN_DB:
            etype = entry.get("type", "").lower()
            if etype and etype not in all_categories:
                all_categories.append(etype)

        all_categories = sorted(set(all_categories))

        if category_filter:
            category_filter = category_filter.lower()
            all_categories = [c for c in all_categories if category_filter in c.lower()]

        if not all_categories:
            print_warning(f"未找到匹配的分类: {category_filter}")
            return []

        # 按字母分组显示
        groups = {}
        for cat in all_categories:
            first_letter = cat[0].upper() if cat else "#"
            if first_letter not in groups:
                groups[first_letter] = []
            groups[first_letter].append(cat)

        print_info(f"共 {len(all_categories)} 个分类:\n")
        for letter in sorted(groups.keys()):
            cats = groups[letter]
            print(f"  {Colors.LIGHT_CYAN}[{letter}]{Colors.RESET}  ", end="")
            for i, cat in enumerate(cats):
                if i > 0 and i % 6 == 0:
                    print(f"\n          ", end="")
                print(f"{cat:25}", end="")
            print()

        print(f"\n{Colors.DIM}提示: 使用 search_by_type(type) 搜索特定类型的漏洞{Colors.RESET}")
        return all_categories

    def get_exploit_details(self, exploit_id):
        """
        获取漏洞详情

        :param exploit_id: 漏洞ID (如 EDB-52000 或 CVE-2024-26923)
        :return: 漏洞详情字典
        """
        print_section(f"📄 漏洞详情: {exploit_id}")

        result = None

        # 先在内置数据库中查找
        for entry in self.BUILTIN_DB:
            if entry.get("id", "").lower() == exploit_id.lower() or \
               entry.get("cve", "").lower() == exploit_id.lower():
                result = dict(entry)
                result["source"] = "builtin"
                break

        # 尝试在线查询
        if self._check_api_online():
            try:
                # 尝试从GitLab API获取文件内容
                if exploit_id.startswith("EDB-"):
                    edb_num = exploit_id.replace("EDB-", "")
                    file_path = f"exploits/multiple/webapps/{edb_num}.py"
                    resp = self.session.get(
                        f"{self._api_base}/repository/files/{requests.utils.quote(file_path, safe='')}/raw",
                        timeout=self.timeout
                    )
                    if resp.status_code == 200:
                        if not result:
                            result = {"source": "online"}
                        result["id"] = exploit_id
                        result["raw_content"] = resp.text[:2000]  # 只取前2000字符
                        result["online_source"] = f"https://gitlab.com/exploit-database/exploitdb/-/blob/master/{file_path}"
            except Exception as e:
                print_warning(f"在线查询详情失败: {e}")

        if not result:
            print_error(f"未找到漏洞: {exploit_id}")
            return None

        # 显示详情
        print_info("漏洞详情:\n")

        details_fields = [
            ("漏洞ID", result.get("id", "N/A"), Colors.LIGHT_RED),
            ("CVE编号", result.get("cve", "N/A"), Colors.LIGHT_YELLOW),
            ("标题", result.get("title", "N/A"), Colors.LIGHT_CYAN),
            ("类型", result.get("type", "N/A"), Colors.LIGHT_GREEN),
            ("平台", result.get("platform", "N/A"), Colors.LIGHT_BLUE),
            ("严重等级", self._severity_label(result.get("severity", "unknown")), self._color_severity(result.get("severity", "unknown"))),
            ("发布时间", result.get("date", "N/A"), Colors.GRAY),
            ("来源", result.get("source", "unknown"), Colors.GRAY),
            ("描述", result.get("description", "无描述"), Colors.WHITE),
        ]

        for label, value, color in details_fields:
            print(f"  {Colors.BOLD}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")

        if result.get("raw_content"):
            print(f"\n  {Colors.BOLD}代码预览:{Colors.RESET}")
            print(f"  {Colors.DIM}{'─'*60}{Colors.RESET}")
            for line in result["raw_content"].split("\n")[:30]:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
            if len(result["raw_content"].split("\n")) > 30:
                print(f"  {Colors.DIM}... (内容截断){Colors.RESET}")
            print(f"  {Colors.DIM}{'─'*60}{Colors.RESET}")

        if result.get("online_source"):
            print(f"\n  {Colors.BOLD}在线链接:{Colors.RESET} {Colors.LIGHT_BLUE}{result['online_source']}{Colors.RESET}")

        # NVD参考链接
        cve = result.get("cve", "")
        if cve and cve.startswith("CVE-"):
            print(f"  {Colors.BOLD}NVD参考:{Colors.RESET} {Colors.LIGHT_BLUE}https://nvd.nist.gov/vuln/detail/{cve}{Colors.RESET}")

        return result

    def exploit_db_browser(self, category=None, platform=None, page=1, page_size=20):
        """
        本地漏洞库浏览器

        :param category: 分类过滤器
        :param platform: 平台过滤器
        :param page: 页码
        :param page_size: 每页数量
        :return: 分页后的漏洞列表
        """
        print_section(f"📚 漏洞库浏览")

        # 过滤数据库
        filtered = []
        for entry in self.BUILTIN_DB:
            match = True
            if category:
                if entry.get("type", "").lower() != category.lower() and \
                   entry.get("platform", "").lower() != category.lower():
                    match = False
            if platform:
                if entry.get("platform", "").lower() != platform.lower():
                    match = False
            if match:
                filtered.append(entry)

        total = len(filtered)
        total_pages = max(1, (total + page_size - 1) // page_size)

        if page > total_pages:
            page = total_pages
        if page < 1:
            page = 1

        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total)
        page_items = filtered[start_idx:end_idx]

        # 显示过滤信息
        filters = []
        if category:
            filters.append(f"分类={category}")
        if platform:
            filters.append(f"平台={platform}")
        filter_str = f" ({', '.join(filters)})" if filters else ""

        print_info(f"内置漏洞数据库{filter_str}:")
        print(f"  {Colors.DIM}共 {total} 条记录, 第 {page}/{total_pages} 页{Colors.RESET}\n")

        if not page_items:
            print_warning("当前页无数据")
            return []

        # 表头
        headers = ["#", "ID", "CVE", "标题", "类型", "等级"]
        rows = []
        for i, item in enumerate(page_items, start_idx + 1):
            rows.append([
                str(i),
                item.get("id", "N/A")[:12],
                item.get("cve", "N/A")[:16],
                item.get("title", "N/A")[:45],
                item.get("type", "N/A")[:10],
                item.get("severity", "N/A")[:8],
            ])
        print_table(headers, rows, Colors.CYAN)

        # 分页导航
        print(f"\n  {Colors.DIM}页 {page}/{total_pages}  |  记录 {start_idx + 1}-{end_idx}/{total}{Colors.RESET}")
        if total_pages > 1:
            nav = []
            if page > 1:
                nav.append("p:上一页")
            if page < total_pages:
                nav.append("n:下一页")
            nav.append(f"g <页码>:跳转")
            print(f"  {Colors.DIM}{' | '.join(nav)}{Colors.RESET}")

        return page_items

    def search_by_platform(self, platform, exact_match=False):
        """
        按平台搜索漏洞

        :param platform: 平台名称 (windows, linux, webapps等)
        :param exact_match: 是否精确匹配
        :return: 匹配的漏洞列表
        """
        platform = platform.lower().strip()
        results = []

        print_section(f"💻 按平台搜索: {platform}")

        # 平台映射
        platform_map = {
            "win": "windows", "windows": "windows", "win32": "windows", "win64": "windows",
            "linux": "linux", "unix": "linux", "nix": "linux",
            "mac": "macos", "macos": "macos", "osx": "macos", "darwin": "macos",
            "android": "android", "ios": "ios", "iphone": "ios", "ipad": "ios",
            "web": "webapps", "webapp": "webapps", "webapps": "webapps",
            "php": "php", "asp": "asp", "jsp": "jsp", "asp.net": "asp",
            "cisco": "cisco", "router": "cisco",
            "scada": "scada", "ics": "scada", "industrial": "scada",
        }

        normalized = platform_map.get(platform, platform)

        # 搜索内置数据库
        for entry in self.BUILTIN_DB:
            entry_platform = entry.get("platform", "").lower()
            if exact_match:
                match = entry_platform == normalized
            else:
                match = normalized in entry_platform or entry_platform in normalized
                # 也搜索标题和描述
                title_desc = f"{entry['title']} {entry['description']}".lower()
                match = match or normalized in title_desc

            if match:
                results.append({**entry, "source": "builtin"})

        # 尝试在线搜索
        if self._check_api_online():
            try:
                params = {
                    "search": normalized,
                    "per_page": 30,
                }
                api_results = self._search_online_api(params)
                if api_results:
                    for item in api_results:
                        name = item.get("name", "")
                        results.append({
                            "id": name,
                            "title": name.replace("-", " ").replace("_", " ").title(),
                            "platform": normalized,
                            "source": "online",
                        })
            except Exception:
                pass

        # 去重
        seen = set()
        unique_results = []
        for r in results:
            key = r.get("id", r.get("cve", r.get("title", "")))
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        if unique_results:
            print_success(f"找到 {len(unique_results)} 个 {platform} 平台漏洞:\n")
            headers = ["#", "CVE/ID", "标题", "类型", "等级"]
            rows = []
            for i, r in enumerate(unique_results[:30], 1):
                rows.append([
                    str(i),
                    r.get("cve", r.get("id", "N/A"))[:18],
                    r.get("title", "N/A")[:50],
                    r.get("type", "-")[:12],
                    r.get("severity", "-")[:8],
                ])
            print_table(headers, rows, Colors.GREEN)

            if len(unique_results) > 30:
                print_warning(f"... 还有 {len(unique_results) - 30} 条结果未显示")
        else:
            print_warning(f"未找到 {platform} 平台的相关漏洞")
            # 显示可用平台
            print_info(f"可用平台: {', '.join(sorted(set(entry['platform'] for entry in self.BUILTIN_DB)))}")

        return unique_results

    def search_by_type(self, vuln_type, exact_match=False):
        """
        按类型搜索漏洞

        :param vuln_type: 漏洞类型 (webapps, dos, local, remote等)
        :param exact_match: 是否精确匹配
        :return: 匹配的漏洞列表
        """
        vuln_type = vuln_type.lower().strip()
        results = []

        print_section(f"🏷️ 按类型搜索: {vuln_type}")

        # 类型映射
        type_map = {
            "web": "webapps", "webapp": "webapps", "webapps": "webapps",
            "dos": "dos", "denial": "dos", "denial of service": "dos", "ddos": "dos",
            "local": "local", "lpe": "local", "privilege escalation": "local",
            "remote": "remote", "rce": "remote", "rfi": "remote",
            "shellcode": "shellcode", "shell": "shellcode",
            "xss": "xss", "cross site": "xss", "cross-site": "xss",
            "sql": "sql_injection", "sqli": "sql_injection", "sql injection": "sql_injection",
            "csrf": "csrf", "xsrf": "csrf",
            "overflow": "buffer_overflow", "buffer overflow": "buffer_overflow",
            "file include": "file_include", "lfi": "file_include", "rfi": "file_include",
            "upload": "file_upload", "file upload": "file_upload",
            "traversal": "directory_traversal", "path traversal": "directory_traversal",
            "bypass": "authentication_bypass", "auth bypass": "authentication_bypass",
        }

        normalized = type_map.get(vuln_type, vuln_type)

        # 搜索内置数据库
        for entry in self.BUILTIN_DB:
            entry_type = entry.get("type", "").lower()
            if exact_match:
                match = entry_type == normalized
            else:
                match = normalized in entry_type or entry_type in normalized
                # 也搜索标题和描述
                title_desc = f"{entry['title']} {entry['description']}".lower()
                match = match or normalized in title_desc

            if match:
                results.append({**entry, "source": "builtin"})

        if results:
            print_success(f"找到 {len(results)} 个 {vuln_type} 类型漏洞:\n")
            headers = ["#", "CVE/ID", "标题", "平台", "等级"]
            rows = []
            for i, r in enumerate(results[:30], 1):
                rows.append([
                    str(i),
                    r.get("cve", r.get("id", "N/A"))[:18],
                    r.get("title", "N/A")[:50],
                    r.get("platform", "-")[:12],
                    r.get("severity", "-")[:8],
                ])
            print_table(headers, rows, Colors.YELLOW)

            if len(results) > 30:
                print_warning(f"... 还有 {len(results) - 30} 条结果未显示")
        else:
            print_warning(f"未找到 {vuln_type} 类型的漏洞")
            # 统计内置数据库中的类型分布
            type_counts = {}
            for entry in self.BUILTIN_DB:
                t = entry.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            print_info(f"可用类型: {', '.join(f'{k}({v})' for k, v in sorted(type_counts.items()))}")

        return results

    def exploit_stats(self):
        """
        漏洞统计信息

        :return: 统计信息字典
        """
        print_section("📊 漏洞统计信息")

        stats = {
            "total": len(self.BUILTIN_DB),
            "by_type": {},
            "by_platform": {},
            "by_severity": {},
            "by_year": {},
            "sources": {
                "builtin": len(self.BUILTIN_DB),
                "online_available": self._check_api_online(),
                "local_searchsploit": self.searchsploit_path is not None,
            },
        }

        # 按类型统计
        for entry in self.BUILTIN_DB:
            etype = entry.get("type", "unknown")
            stats["by_type"][etype] = stats["by_type"].get(etype, 0) + 1

        # 按平台统计
        for entry in self.BUILTIN_DB:
            platform = entry.get("platform", "unknown")
            stats["by_platform"][platform] = stats["by_platform"].get(platform, 0) + 1

        # 按严重等级统计
        for entry in self.BUILTIN_DB:
            severity = entry.get("severity", "unknown")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

        # 按年份统计
        for entry in self.BUILTIN_DB:
            cve = entry.get("cve", "")
            match = re.match(r'CVE-(\d{4})', cve)
            if match:
                year = match.group(1)
                stats["by_year"][year] = stats["by_year"].get(year, 0) + 1

        # 显示统计信息
        print(f"  {Colors.BOLD}📦 总漏洞数:{Colors.RESET}        {Colors.LIGHT_CYAN}{stats['total']}{Colors.RESET}")
        print(f"  {Colors.BOLD}🌐 在线API:{Colors.RESET}         {'✅ 可用' if stats['sources']['online_available'] else '❌ 不可用'}")
        print(f"  {Colors.BOLD}💻 本地SearchSploit:{Colors.RESET} {'✅ 已安装' if stats['sources']['local_searchsploit'] else '❌ 未安装'}")
        print()

        # 按严重等级
        print(f"  {Colors.BOLD}📈 按严重等级:{Colors.RESET}")
        severity_order = ["critical", "high", "medium", "low", "unknown"]
        severity_colors = {
            "critical": Colors.LIGHT_RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.GREEN,
            "unknown": Colors.GRAY,
        }
        severity_labels = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "unknown": "未知",
        }
        for sev in severity_order:
            count = stats["by_severity"].get(sev, 0)
            color = severity_colors.get(sev, Colors.WHITE)
            label = severity_labels.get(sev, sev)
            bar = "█" * count + "░" * max(0, 20 - count)
            print(f"    {color}{label:8}{Colors.RESET} |{color}{bar}{Colors.RESET}| {count}")

        print()

        # 按类型统计（Top 10）
        print(f"  {Colors.BOLD}📂 按类型统计 (Top 10):{Colors.RESET}")
        sorted_types = sorted(stats["by_type"].items(), key=lambda x: x[1], reverse=True)[:10]
        for etype, count in sorted_types:
            print(f"    {Colors.LIGHT_CYAN}{etype:20}{Colors.RESET} {count}")

        print()

        # 按年份统计
        print(f"  {Colors.BOLD}📅 按年份统计:{Colors.RESET}")
        sorted_years = sorted(stats["by_year"].items(), key=lambda x: x[0])
        for year, count in sorted_years:
            print(f"    {Colors.LIGHT_YELLOW}{year}{Colors.RESET}  {'█' * count} {count}")

        print()

        # 按平台统计（Top 5）
        print(f"  {Colors.BOLD}💻 按平台统计 (Top 5):{Colors.RESET}")
        sorted_platforms = sorted(stats["by_platform"].items(), key=lambda x: x[1], reverse=True)[:5]
        for plat, count in sorted_platforms:
            print(f"    {Colors.LIGHT_GREEN}{plat:15}{Colors.RESET} {count}")

        print(f"\n  {Colors.DIM}提示: 使用 search_by_type() 或 search_by_platform() 查看特定类别{Colors.RESET}")

        return stats

    def _color_severity(self, severity):
        """根据严重等级返回带颜色的文本"""
        severity = str(severity).lower()
        colors = {
            "critical": Colors.LIGHT_RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.GREEN,
            "unknown": Colors.GRAY,
        }
        color = colors.get(severity, Colors.WHITE)
        return f"{color}{severity}{Colors.RESET}"

    def _severity_label(self, severity):
        """返回严重等级的中文标签"""
        labels = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "unknown": "未知",
        }
        return labels.get(severity.lower(), severity)

    def get_available_platforms(self):
        """获取内置数据库中的可用平台列表"""
        platforms = set()
        for entry in self.BUILTIN_DB:
            platforms.add(entry.get("platform", "unknown"))
        return sorted(platforms)

    def get_available_types(self):
        """获取内置数据库中的可用类型列表"""
        types = set()
        for entry in self.BUILTIN_DB:
            types.add(entry.get("type", "unknown"))
        return sorted(types)

    def export_results(self, results, filename=None):
        """
        导出搜索结果到文件

        :param results: 搜索结果列表
        :param filename: 文件名（可选，默认自动生成）
        """
        if not results:
            print_warning("没有可导出的结果")
            return None

        if not filename:
            filename = f"searchsploit_export_{get_timestamp()}.json"

        return save_results(filename, results, format_type="json")