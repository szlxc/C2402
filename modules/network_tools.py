# -*- coding: utf-8 -*-
"""
网络工具模块 - NetworkTools
包含Ping扫描、ARP扫描、路由追踪、DNS解析、MAC查询等网络工具
"""

import os
import sys
import socket
import struct
import subprocess
import threading
import ipaddress
import re
import time
import json
import http.server
import socketserver
import select
import warnings
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime

from core.colors import *
from core.utils import *


class NetworkTools:
    """网络工具类"""

    # OUI数据库（常用厂商MAC前缀）
    OUI_DATABASE = {
        # Cisco Systems
        '00:00:0C': 'Cisco Systems', '00:01:42': 'Cisco Systems',
        '00:01:43': 'Cisco Systems', '00:01:96': 'Cisco Systems',
        '00:01:97': 'Cisco Systems', '00:01:63': 'Cisco Systems',
        '00:02:4A': 'Cisco Systems', '00:02:7D': 'Cisco Systems',
        '00:02:FC': 'Cisco Systems', '00:03:6B': 'Cisco Systems',
        '00:04:9A': 'Cisco Systems', '00:05:5D': 'Cisco Systems',
        '00:05:9A': 'Cisco Systems', '00:05:73': 'Cisco Systems',
        '00:06:3D': 'Cisco Systems', '00:06:5B': 'Cisco Systems',
        '00:06:7C': 'Cisco Systems', '00:06:C1': 'Cisco Systems',
        '00:07:0E': 'Cisco Systems', '00:07:7D': 'Cisco Systems',
        '00:09:7B': 'Cisco Systems', '00:0D:BC': 'Cisco Systems',
        '00:11:92': 'Cisco Systems', '00:12:7F': 'Cisco Systems',
        '00:13:10': 'Cisco Systems', '00:13:19': 'Cisco Systems',
        '00:13:5F': 'Cisco Systems', '00:13:80': 'Cisco Systems',
        '00:14:1C': 'Cisco Systems', '00:14:6B': 'Cisco Systems',
        '00:14:A9': 'Cisco Systems', '00:14:F1': 'Cisco Systems',
        '00:14:F2': 'Cisco Systems', '00:15:2C': 'Cisco Systems',
        '00:15:62': 'Cisco Systems', '00:15:63': 'Cisco Systems',
        '00:15:FA': 'Cisco Systems', '00:16:46': 'Cisco Systems',
        '00:16:9D': 'Cisco Systems', '00:16:C8': 'Cisco Systems',
        '00:17:0E': 'Cisco Systems', '00:17:94': 'Cisco Systems',
        '00:17:DF': 'Cisco Systems', '00:17:E0': 'Cisco Systems',
        '00:18:0A': 'Cisco Systems', '00:18:18': 'Cisco Systems',
        '00:18:39': 'Cisco Systems', '00:18:73': 'Cisco Systems',
        '00:18:BA': 'Cisco Systems', '00:19:06': 'Cisco Systems',
        '00:19:30': 'Cisco Systems', '00:19:55': 'Cisco Systems',
        '00:19:AA': 'Cisco Systems', '00:19:E7': 'Cisco Systems',
        '00:1A:2F': 'Cisco Systems', '00:1A:6C': 'Cisco Systems',
        '00:1A:A1': 'Cisco Systems', '00:1A:A2': 'Cisco Systems',
        '00:1A:E7': 'Cisco Systems', '00:1B:0C': 'Cisco Systems',
        '00:1B:0D': 'Cisco Systems', '00:1B:19': 'Cisco Systems',
        '00:1B:54': 'Cisco Systems', '00:1B:8E': 'Cisco Systems',
        '00:1B:D4': 'Cisco Systems', '00:1C:0E': 'Cisco Systems',
        '00:1C:0F': 'Cisco Systems', '00:1C:10': 'Cisco Systems',
        '00:1C:57': 'Cisco Systems', '00:1C:B0': 'Cisco Systems',
        '00:1C:F6': 'Cisco Systems', '00:1C:F9': 'Cisco Systems',
        '00:1D:45': 'Cisco Systems', '00:1D:46': 'Cisco Systems',
        '00:1D:7E': 'Cisco Systems', '00:1D:A1': 'Cisco Systems',
        '00:1D:E5': 'Cisco Systems', '00:1E:13': 'Cisco Systems',
        '00:1E:49': 'Cisco Systems', '00:1E:79': 'Cisco Systems',
        '00:1E:BD': 'Cisco Systems', '00:1E:F7': 'Cisco Systems',
        '00:1F:26': 'Cisco Systems', '00:1F:6C': 'Cisco Systems',
        '00:1F:CA': 'Cisco Systems',
        # Microsoft
        '00:50:73': 'Microsoft', '00:50:F2': 'Microsoft',
        '00:60:08': 'Microsoft', '00:60:97': 'Microsoft',
        '00:03:FF': 'Microsoft', '00:04:23': 'Microsoft',
        '00:0B:DB': 'Microsoft', '00:0D:3A': 'Microsoft',
        '00:0F:8F': 'Microsoft', '00:10:83': 'Microsoft',
        '00:11:D8': 'Microsoft', '00:12:5A': 'Microsoft',
        '00:13:74': 'Microsoft', '00:14:5F': 'Microsoft',
        '00:15:5D': 'Microsoft', '00:16:41': 'Microsoft',
        '00:16:76': 'Microsoft', '00:16:D3': 'Microsoft',
        '00:17:31': 'Microsoft', '00:17:32': 'Microsoft',
        '00:17:FA': 'Microsoft', '00:18:15': 'Microsoft',
        '00:18:3A': 'Microsoft', '00:18:8B': 'Microsoft',
        '00:18:F7': 'Microsoft', '00:19:0C': 'Microsoft',
        '00:19:6B': 'Microsoft', '00:19:7C': 'Microsoft',
        '00:19:D1': 'Microsoft', '00:1A:3F': 'Microsoft',
        '00:1A:98': 'Microsoft', '00:1A:A0': 'Microsoft',
        '00:1B:24': 'Microsoft', '00:1B:50': 'Microsoft',
        '00:1B:FC': 'Microsoft', '00:1C:42': 'Microsoft',
        '00:1C:43': 'Microsoft', '00:1C:BB': 'Microsoft',
        '00:1C:EA': 'Microsoft', '00:1D:09': 'Microsoft',
        '00:1D:58': 'Microsoft', '00:1D:72': 'Microsoft',
        '00:1D:73': 'Microsoft', '00:1D:D8': 'Microsoft',
        '00:1D:D9': 'Microsoft', '00:1E:26': 'Microsoft',
        '00:1E:37': 'Microsoft', '00:1E:55': 'Microsoft',
        '00:1E:90': 'Microsoft', '00:1E:E5': 'Microsoft',
        '00:1F:3C': 'Microsoft', '00:1F:3D': 'Microsoft',
        '00:1F:5D': 'Microsoft', '00:1F:90': 'Microsoft',
        '00:1F:CC': 'Microsoft', '00:21:5A': 'Microsoft',
        '00:21:5C': 'Microsoft', '00:21:6B': 'Microsoft',
        '00:21:6C': 'Microsoft', '00:21:9B': 'Microsoft',
        '00:21:D8': 'Microsoft', '00:22:48': 'Microsoft',
        '00:22:6A': 'Microsoft', '00:22:BE': 'Microsoft',
        '00:22:BF': 'Microsoft', '00:23:8D': 'Microsoft',
        '00:23:8E': 'Microsoft', '00:23:8F': 'Microsoft',
        '00:23:AE': 'Microsoft', '00:23:AF': 'Microsoft',
        '00:23:D4': 'Microsoft', '00:23:D5': 'Microsoft',
        '00:24:1D': 'Microsoft', '00:24:76': 'Microsoft',
        '00:24:BE': 'Microsoft', '00:24:BF': 'Microsoft',
        '00:24:FF': 'Microsoft', '00:25:64': 'Microsoft',
        '00:25:65': 'Microsoft', '00:25:CE': 'Microsoft',
        '00:25:CF': 'Microsoft', '00:26:18': 'Microsoft',
        '00:26:19': 'Microsoft', '00:26:6C': 'Microsoft',
        '00:26:8C': 'Microsoft', '00:26:AB': 'Microsoft',
        '00:26:C7': 'Microsoft', '00:27:1A': 'Microsoft',
        '00:27:49': 'Microsoft', '00:27:4E': 'Microsoft',
        '00:27:50': 'Microsoft', '00:27:92': 'Microsoft',
        '00:27:C0': 'Microsoft', '00:27:C1': 'Microsoft',
        '00:27:CB': 'Microsoft', '00:27:CC': 'Microsoft',
        # Apple
        '00:08:74': 'Apple', '00:0A:27': 'Apple',
        '00:0A:95': 'Apple', '00:0D:93': 'Apple',
        '00:0E:E8': 'Apple', '00:10:9B': 'Apple',
        '00:11:24': 'Apple', '00:14:51': 'Apple',
        '00:16:CB': 'Apple', '00:17:F2': 'Apple',
        '00:19:E3': 'Apple', '00:1A:4B': 'Apple',
        '00:1A:92': 'Apple', '00:1B:63': 'Apple',
        '00:1B:AE': 'Apple', '00:1C:DF': 'Apple',
        '00:1D:4F': 'Apple', '00:1E:52': 'Apple',
        '00:1E:C2': 'Apple', '00:1F:5B': 'Apple',
        '00:1F:C5': 'Apple', '00:1F:F3': 'Apple',
        '00:20:ED': 'Apple', '00:21:E9': 'Apple',
        '00:22:08': 'Apple', '00:22:41': 'Apple',
        '00:23:32': 'Apple', '00:23:6C': 'Apple',
        '00:23:DF': 'Apple', '00:24:36': 'Apple',
        '00:25:00': 'Apple', '00:25:4B': 'Apple',
        '00:25:BC': 'Apple', '00:26:08': 'Apple',
        '00:26:4A': 'Apple', '00:26:B0': 'Apple',
        '00:26:BB': 'Apple', '00:26:BD': 'Apple',
        '00:27:0E': 'Apple', '00:27:4C': 'Apple',
        '00:27:8B': 'Apple', '00:27:8C': 'Apple',
        '00:27:DB': 'Apple', '00:27:DD': 'Apple',
        # Samsung
        '00:04:AC': 'Samsung', '00:12:6D': 'Samsung',
        '00:15:99': 'Samsung', '00:16:48': 'Samsung',
        '00:17:36': 'Samsung', '00:18:AF': 'Samsung',
        '00:19:5B': 'Samsung', '00:1A:CC': 'Samsung',
        '00:1B:A9': 'Samsung', '00:1C:B7': 'Samsung',
        '00:1D:28': 'Samsung', '00:1E:42': 'Samsung',
        '00:1E:A0': 'Samsung', '00:1F:78': 'Samsung',
        '00:1F:99': 'Samsung', '00:20:4A': 'Samsung',
        '00:20:5C': 'Samsung', '00:21:62': 'Samsung',
        '00:21:63': 'Samsung', '00:21:D1': 'Samsung',
        '00:22:39': 'Samsung', '00:22:ED': 'Samsung',
        '00:23:29': 'Samsung', '00:23:5E': 'Samsung',
        '00:23:5F': 'Samsung', '00:23:7C': 'Samsung',
        '00:23:CD': 'Samsung', '00:23:D6': 'Samsung',
        '00:24:4E': 'Samsung', '00:24:54': 'Samsung',
        '00:24:AC': 'Samsung', '00:24:CA': 'Samsung',
        '00:24:D2': 'Samsung', '00:25:3A': 'Samsung',
        '00:25:84': 'Samsung', '00:25:9E': 'Samsung',
        '00:25:EF': 'Samsung', '00:26:05': 'Samsung',
        '00:26:13': 'Samsung', '00:26:2D': 'Samsung',
        '00:26:36': 'Samsung', '00:26:73': 'Samsung',
        '00:26:9E': 'Samsung', '00:26:9F': 'Samsung',
        '00:26:D0': 'Samsung', '00:26:F1': 'Samsung',
        '00:27:3C': 'Samsung', '00:27:6C': 'Samsung',
        '00:27:8D': 'Samsung', '00:27:9C': 'Samsung',
        '00:27:CA': 'Samsung',
        # Huawei
        '00:09:5B': 'Huawei', '00:18:82': 'Huawei',
        '00:19:88': 'Huawei', '00:1A:2E': 'Huawei',
        '00:1B:6C': 'Huawei', '00:1C:7E': 'Huawei',
        '00:1D:8E': 'Huawei', '00:1E:8B': 'Huawei',
        '00:1F:6E': 'Huawei', '00:21:3A': 'Huawei',
        '00:21:91': 'Huawei', '00:22:5B': 'Huawei',
        '00:22:90': 'Huawei', '00:23:0B': 'Huawei',
        '00:23:CD': 'Huawei', '00:24:45': 'Huawei',
        '00:24:46': 'Huawei', '00:25:9C': 'Huawei',
        '00:25:9D': 'Huawei', '00:26:5E': 'Huawei',
        '00:26:9D': 'Huawei', '00:26:E1': 'Huawei',
        '00:27:0D': 'Huawei', '00:27:CE': 'Huawei',
        '00:27:CF': 'Huawei', '00:0F:E2': 'Huawei',
        '00:0F:E3': 'Huawei', '00:0F:E4': 'Huawei',
        '00:10:0B': 'Huawei', '00:10:0C': 'Huawei',
        '00:10:0D': 'Huawei', '00:10:0E': 'Huawei',
        '00:10:0F': 'Huawei', '00:10:10': 'Huawei',
        '00:10:14': 'Huawei', '00:10:15': 'Huawei',
        '00:10:16': 'Huawei', '00:10:17': 'Huawei',
        '00:10:18': 'Huawei', '00:10:19': 'Huawei',
        # VMware / Virtual
        '00:50:56': 'VMware', '00:0C:29': 'VMware',
        '00:05:69': 'VMware', '08:00:27': 'Oracle VirtualBox',
        '00:15:5D': 'Microsoft Hyper-V',
        # Raspberry Pi
        'B8:27:EB': 'Raspberry Pi Foundation',
        'DC:A6:32': 'Raspberry Pi Foundation',
        'E4:5F:01': 'Raspberry Pi Foundation',
        # Google
        '00:1A:11': 'Google', '00:1A:22': 'Google',
        '00:1A:33': 'Google', '00:1A:44': 'Google',
        '00:1A:55': 'Google', '00:1A:66': 'Google',
        '00:1A:77': 'Google', '00:1A:88': 'Google',
        '00:1A:99': 'Google', '00:1A:AA': 'Google',
        '00:1A:BB': 'Google', '00:1A:CC': 'Google',
        '00:1A:DD': 'Google', '00:1A:EE': 'Google',
        '00:1A:FF': 'Google', '3C:5A:B4': 'Google',
        '18:8B:9D': 'Google', '8C:DE:52': 'Google',
        'A4:77:33': 'Google', 'BC:EE:7B': 'Google',
        'F4:F5:D8': 'Google',
        # Intel
        '00:08:02': 'Intel', '00:0C:F1': 'Intel',
        '00:13:20': 'Intel', '00:15:17': 'Intel',
        '00:19:D1': 'Intel', '00:1B:21': 'Intel',
        '00:1C:BF': 'Intel', '00:1E:67': 'Intel',
        '00:1F:3B': 'Intel', '00:1F:5C': 'Intel',
        # Dell
        '00:1C:13': 'Dell', '00:1D:09': 'Dell',
        '00:1E:4F': 'Dell', '00:1F:1A': 'Dell',
        '00:21:9B': 'Dell', '00:22:6B': 'Dell',
        '00:23:AE': 'Dell', '00:24:E8': 'Dell',
        '00:25:64': 'Dell', '00:26:2D': 'Dell',
        '00:26:B6': 'Dell', '00:26:BB': 'Dell',
        '00:26:9E': 'Dell', '00:12:17': 'Dell',
        '00:14:22': 'Dell', '00:14:D1': 'Dell',
        '00:18:FE': 'Dell', '00:18:8B': 'Dell',
        # Xiaomi
        '48:57:02': 'Xiaomi', '48:57:03': 'Xiaomi',
        '48:57:04': 'Xiaomi', '48:57:05': 'Xiaomi',
        '48:57:06': 'Xiaomi', '48:57:07': 'Xiaomi',
        '48:57:08': 'Xiaomi', '48:57:09': 'Xiaomi',
        '48:57:0A': 'Xiaomi', '48:57:0B': 'Xiaomi',
        '48:57:0C': 'Xiaomi', '48:57:0D': 'Xiaomi',
        '48:57:0E': 'Xiaomi', '48:57:0F': 'Xiaomi',
        '48:57:10': 'Xiaomi', '48:57:11': 'Xiaomi',
        '48:57:12': 'Xiaomi', '48:57:13': 'Xiaomi',
        '48:57:14': 'Xiaomi', '48:57:15': 'Xiaomi',
        '48:57:16': 'Xiaomi',
        'AC:84:C6': 'Xiaomi', 'AC:84:C7': 'Xiaomi',
        'AC:84:C8': 'Xiaomi', 'AC:84:C9': 'Xiaomi',
        'AC:84:CA': 'Xiaomi', 'AC:84:CB': 'Xiaomi',
        'AC:84:CC': 'Xiaomi', 'AC:84:CD': 'Xiaomi',
        'AC:84:CE': 'Xiaomi', 'AC:84:CF': 'Xiaomi',
        'AC:84:D0': 'Xiaomi', 'AC:84:D1': 'Xiaomi',
        'AC:84:D2': 'Xiaomi', 'AC:84:D3': 'Xiaomi',
        'AC:84:D4': 'Xiaomi', 'AC:84:D5': 'Xiaomi',
        'AC:84:D6': 'Xiaomi', 'AC:84:D7': 'Xiaomi',
        'AC:84:D8': 'Xiaomi', 'AC:84:D9': 'Xiaomi',
        'AC:84:DA': 'Xiaomi', 'AC:84:DB': 'Xiaomi',
        'AC:84:DC': 'Xiaomi', 'AC:84:DD': 'Xiaomi',
        'AC:84:DE': 'Xiaomi', 'AC:84:DF': 'Xiaomi',
        'AC:84:E0': 'Xiaomi', 'AC:84:E1': 'Xiaomi',
        'AC:84:E2': 'Xiaomi', 'AC:84:E3': 'Xiaomi',
        'AC:84:E4': 'Xiaomi', 'AC:84:E5': 'Xiaomi',
        'AC:84:E6': 'Xiaomi', 'AC:84:E7': 'Xiaomi',
        'AC:84:E8': 'Xiaomi', 'AC:84:E9': 'Xiaomi',
        'AC:84:EA': 'Xiaomi', 'AC:84:EB': 'Xiaomi',
        'AC:84:EC': 'Xiaomi', 'AC:84:ED': 'Xiaomi',
        'AC:84:EE': 'Xiaomi', 'AC:84:EF': 'Xiaomi',
        'AC:84:F0': 'Xiaomi', 'AC:84:F1': 'Xiaomi',
        'AC:84:F2': 'Xiaomi', 'AC:84:F3': 'Xiaomi',
        'AC:84:F4': 'Xiaomi',
        'F0:FE:6B': 'Xiaomi', 'F0:FE:6C': 'Xiaomi',
        'F0:FE:6D': 'Xiaomi', 'F0:FE:6E': 'Xiaomi',
        'F0:FE:6F': 'Xiaomi', 'F0:FE:70': 'Xiaomi',
        'F0:FE:71': 'Xiaomi', 'F0:FE:72': 'Xiaomi',
        'F0:FE:73': 'Xiaomi', 'F0:FE:74': 'Xiaomi',
        'F0:FE:75': 'Xiaomi', 'F0:FE:76': 'Xiaomi',
        'F0:FE:77': 'Xiaomi', 'F0:FE:78': 'Xiaomi',
        'F0:FE:79': 'Xiaomi', 'F0:FE:7A': 'Xiaomi',
        'F0:FE:7B': 'Xiaomi', 'F0:FE:7C': 'Xiaomi',
        'F0:FE:7D': 'Xiaomi', 'F0:FE:7E': 'Xiaomi',
        'F0:FE:7F': 'Xiaomi', 'F0:FE:80': 'Xiaomi',
        'F0:FE:81': 'Xiaomi', 'F0:FE:82': 'Xiaomi',
        'F0:FE:83': 'Xiaomi', 'F0:FE:84': 'Xiaomi',
        'F0:FE:85': 'Xiaomi', 'F0:FE:86': 'Xiaomi',
        'F0:FE:87': 'Xiaomi', 'F0:FE:88': 'Xiaomi',
        'F0:FE:89': 'Xiaomi', 'F0:FE:8A': 'Xiaomi',
        'F0:FE:8B': 'Xiaomi', 'F0:FE:8C': 'Xiaomi',
        'F0:FE:8D': 'Xiaomi', 'F0:FE:8E': 'Xiaomi',
        'F0:FE:8F': 'Xiaomi', 'F0:FE:90': 'Xiaomi',
        'F0:FE:91': 'Xiaomi', 'F0:FE:92': 'Xiaomi',
        'F0:FE:93': 'Xiaomi', 'F0:FE:94': 'Xiaomi',
        'F0:FE:95': 'Xiaomi', 'F0:FE:96': 'Xiaomi',
        'F0:FE:97': 'Xiaomi', 'F0:FE:98': 'Xiaomi',
        'F0:FE:99': 'Xiaomi', 'F0:FE:9A': 'Xiaomi',
        'F0:FE:9B': 'Xiaomi', 'F0:FE:9C': 'Xiaomi',
        'F0:FE:9D': 'Xiaomi', 'F0:FE:9E': 'Xiaomi',
        'F0:FE:9F': 'Xiaomi',
        # TP-Link
        '70:5D:24': 'TP-Link Technologies',
        '70:5D:25': 'TP-Link Technologies',
        '70:5D:26': 'TP-Link Technologies',
        '70:5D:27': 'TP-Link Technologies',
        '70:5D:28': 'TP-Link Technologies',
        '70:5D:29': 'TP-Link Technologies',
        '70:5D:2A': 'TP-Link Technologies',
        '70:5D:2B': 'TP-Link Technologies',
        '70:5D:2C': 'TP-Link Technologies',
        '70:5D:2D': 'TP-Link Technologies',
        '70:5D:2E': 'TP-Link Technologies',
        '70:5D:2F': 'TP-Link Technologies',
        '70:5D:30': 'TP-Link Technologies',
        '70:5D:31': 'TP-Link Technologies',
        '70:5D:32': 'TP-Link Technologies',
        '70:5D:33': 'TP-Link Technologies',
        '70:5D:34': 'TP-Link Technologies',
        '70:5D:35': 'TP-Link Technologies',
        '70:5D:36': 'TP-Link Technologies',
        '70:5D:37': 'TP-Link Technologies',
        '70:5D:38': 'TP-Link Technologies',
        '70:5D:39': 'TP-Link Technologies',
        '70:5D:3A': 'TP-Link Technologies',
        '70:5D:3B': 'TP-Link Technologies',
        '70:5D:3C': 'TP-Link Technologies',
        '70:5D:3D': 'TP-Link Technologies',
        '70:5D:3E': 'TP-Link Technologies',
        '70:5D:3F': 'TP-Link Technologies',
        '70:5D:40': 'TP-Link Technologies',
        '70:5D:41': 'TP-Link Technologies',
        '70:5D:42': 'TP-Link Technologies',
        '70:5D:43': 'TP-Link Technologies',
        '70:5D:44': 'TP-Link Technologies',
        '70:5D:45': 'TP-Link Technologies',
        '70:5D:46': 'TP-Link Technologies',
        '70:5D:47': 'TP-Link Technologies',
        '70:5D:48': 'TP-Link Technologies',
        '70:5D:49': 'TP-Link Technologies',
        '70:5D:4A': 'TP-Link Technologies',
        '70:5D:4B': 'TP-Link Technologies',
        '70:5D:4C': 'TP-Link Technologies',
        '70:5D:4D': 'TP-Link Technologies',
        '70:5D:4E': 'TP-Link Technologies',
        '70:5D:4F': 'TP-Link Technologies',
        '70:5D:50': 'TP-Link Technologies',
        '70:5D:51': 'TP-Link Technologies',
        '70:5D:52': 'TP-Link Technologies',
        '70:5D:53': 'TP-Link Technologies',
        '70:5D:54': 'TP-Link Technologies',
        '70:5D:55': 'TP-Link Technologies',
        '70:5D:56': 'TP-Link Technologies',
        '70:5D:57': 'TP-Link Technologies',
        '70:5D:58': 'TP-Link Technologies',
        '70:5D:59': 'TP-Link Technologies',
        '70:5D:5A': 'TP-Link Technologies',
        '70:5D:5B': 'TP-Link Technologies',
        '70:5D:5C': 'TP-Link Technologies',
        '70:5D:5D': 'TP-Link Technologies',
        '70:5D:5E': 'TP-Link Technologies',
        '70:5D:5F': 'TP-Link Technologies',
        # Realtek
        '00:80:C0': 'Realtek Semiconductor',
        '00:E0:4C': 'Realtek Semiconductor',
        '00:E0:6C': 'Realtek Semiconductor',
        '00:E0:7C': 'Realtek Semiconductor',
        '00:E0:8C': 'Realtek Semiconductor',
        '00:E0:9C': 'Realtek Semiconductor',
        '00:E0:AC': 'Realtek Semiconductor',
        '00:E0:BC': 'Realtek Semiconductor',
        '00:E0:CC': 'Realtek Semiconductor',
        '00:E0:DC': 'Realtek Semiconductor',
        '00:E0:EC': 'Realtek Semiconductor',
        '00:E0:FC': 'Realtek Semiconductor',
        # ASUS
        '00:17:88': 'ASUSTek Computer',
        '00:18:F3': 'ASUSTek Computer',
        '00:1A:92': 'ASUSTek Computer',
        '00:1B:FC': 'ASUSTek Computer',
        '00:1C:BF': 'ASUSTek Computer',
        '00:1D:60': 'ASUSTek Computer',
        '00:1E:2A': 'ASUSTek Computer',
        '00:1F:C6': 'ASUSTek Computer',
        '00:21:5A': 'ASUSTek Computer',
        '00:22:15': 'ASUSTek Computer',
        '00:22:B0': 'ASUSTek Computer',
        '00:23:2A': 'ASUSTek Computer',
        '00:24:8C': 'ASUSTek Computer',
        '00:24:BB': 'ASUSTek Computer',
        '00:25:12': 'ASUSTek Computer',
        '00:25:53': 'ASUSTek Computer',
        '00:25:8C': 'ASUSTek Computer',
        '00:26:18': 'ASUSTek Computer',
        '00:26:AC': 'ASUSTek Computer',
        '00:26:C6': 'ASUSTek Computer',
        '00:26:DD': 'ASUSTek Computer',
        '00:26:F2': 'ASUSTek Computer',
        '00:27:2C': 'ASUSTek Computer',
        '00:27:79': 'ASUSTek Computer',
        '00:27:99': 'ASUSTek Computer',
        '00:27:B4': 'ASUSTek Computer',
        '00:27:CE': 'ASUSTek Computer',
        '00:27:EB': 'ASUSTek Computer',
        '00:27:F0': 'ASUSTek Computer',
        '00:27:F8': 'ASUSTek Computer',
        # Lenovo
        '00:0D:67': 'Lenovo', '00:0D:68': 'Lenovo',
        '00:0D:69': 'Lenovo', '00:0D:6A': 'Lenovo',
        '00:0D:6B': 'Lenovo', '00:0D:6C': 'Lenovo',
        '00:0D:6D': 'Lenovo', '00:0D:6E': 'Lenovo',
        '00:0D:6F': 'Lenovo', '00:0D:70': 'Lenovo',
        '00:0D:71': 'Lenovo', '00:0D:72': 'Lenovo',
        '00:0D:73': 'Lenovo', '00:0D:74': 'Lenovo',
        '00:0D:75': 'Lenovo', '00:0D:76': 'Lenovo',
        '00:0D:77': 'Lenovo', '00:0D:78': 'Lenovo',
        '00:0D:79': 'Lenovo', '00:0D:7A': 'Lenovo',
        '00:0D:7B': 'Lenovo', '00:0D:7C': 'Lenovo',
        '00:0D:7D': 'Lenovo', '00:0D:7E': 'Lenovo',
        '00:0D:7F': 'Lenovo', '00:0D:80': 'Lenovo',
        '00:0D:81': 'Lenovo', '00:0D:82': 'Lenovo',
        '00:0D:83': 'Lenovo', '00:0D:84': 'Lenovo',
        '00:0D:85': 'Lenovo', '00:0D:86': 'Lenovo',
        '00:0D:87': 'Lenovo', '00:0D:88': 'Lenovo',
        '00:0D:89': 'Lenovo', '00:0D:8A': 'Lenovo',
        '00:0D:8B': 'Lenovo', '00:0D:8C': 'Lenovo',
        '00:0D:8D': 'Lenovo', '00:0D:8E': 'Lenovo',
        '00:0D:8F': 'Lenovo', '00:0D:90': 'Lenovo',
        '00:0D:91': 'Lenovo', '00:0D:92': 'Lenovo',
        '00:0D:93': 'Lenovo', '00:0D:94': 'Lenovo',
        '00:0D:95': 'Lenovo', '00:0D:96': 'Lenovo',
        '00:0D:97': 'Lenovo', '00:0D:98': 'Lenovo',
        '00:0D:99': 'Lenovo', '00:0D:9A': 'Lenovo',
        '00:0D:9B': 'Lenovo', '00:0D:9C': 'Lenovo',
        '00:0D:9D': 'Lenovo', '00:0D:9E': 'Lenovo',
        '00:0D:9F': 'Lenovo', '00:0D:A0': 'Lenovo',
        '00:0D:A1': 'Lenovo', '00:0D:A2': 'Lenovo',
        '00:0D:A3': 'Lenovo', '00:0D:A4': 'Lenovo',
        '00:0D:A5': 'Lenovo', '00:0D:A6': 'Lenovo',
        '00:0D:A7': 'Lenovo', '00:0D:A8': 'Lenovo',
        '00:0D:A9': 'Lenovo', '00:0D:AA': 'Lenovo',
        '00:0D:AB': 'Lenovo', '00:0D:AC': 'Lenovo',
        '00:0D:AD': 'Lenovo', '00:0D:AE': 'Lenovo',
        '00:0D:AF': 'Lenovo', '00:0D:B0': 'Lenovo',
        '00:0D:B1': 'Lenovo', '00:0D:B2': 'Lenovo',
        '00:0D:B3': 'Lenovo', '00:0D:B4': 'Lenovo',
        '00:0D:B5': 'Lenovo', '00:0D:B6': 'Lenovo',
        '00:0D:B7': 'Lenovo', '00:0D:B8': 'Lenovo',
        '00:0D:B9': 'Lenovo', '00:0D:BA': 'Lenovo',
        '00:0D:BB': 'Lenovo', '00:0D:BC': 'Lenovo',
        '00:0D:BD': 'Lenovo', '00:0D:BE': 'Lenovo',
        '00:0D:BF': 'Lenovo', '00:0D:C0': 'Lenovo',
        '00:0D:C1': 'Lenovo', '00:0D:C2': 'Lenovo',
        '00:0D:C3': 'Lenovo', '00:0D:C4': 'Lenovo',
        '00:0D:C5': 'Lenovo', '00:0D:C6': 'Lenovo',
        '00:0D:C7': 'Lenovo', '00:0D:C8': 'Lenovo',
        '00:0D:C9': 'Lenovo', '00:0D:CA': 'Lenovo',
        '00:0D:CB': 'Lenovo', '00:0D:CC': 'Lenovo',
        '00:0D:CD': 'Lenovo', '00:0D:CE': 'Lenovo',
        '00:0D:CF': 'Lenovo', '00:0D:D0': 'Lenovo',
        '00:0D:D1': 'Lenovo', '00:0D:D2': 'Lenovo',
        '00:0D:D3': 'Lenovo', '00:0D:D4': 'Lenovo',
        '00:0D:D5': 'Lenovo', '00:0D:D6': 'Lenovo',
        '00:0D:D7': 'Lenovo', '00:0D:D8': 'Lenovo',
        '00:0D:D9': 'Lenovo', '00:0D:DA': 'Lenovo',
        '00:0D:DB': 'Lenovo', '00:0D:DC': 'Lenovo',
        '00:0D:DD': 'Lenovo', '00:0D:DE': 'Lenovo',
        '00:0D:DF': 'Lenovo', '00:0D:E0': 'Lenovo',
        '00:0D:E1': 'Lenovo', '00:0D:E2': 'Lenovo',
        '00:0D:E3': 'Lenovo', '00:0D:E4': 'Lenovo',
        '00:0D:E5': 'Lenovo', '00:0D:E6': 'Lenovo',
        '00:0D:E7': 'Lenovo', '00:0D:E8': 'Lenovo',
        '00:0D:E9': 'Lenovo', '00:0D:EA': 'Lenovo',
        '00:0D:EB': 'Lenovo', '00:0D:EC': 'Lenovo',
        '00:0D:ED': 'Lenovo', '00:0D:EE': 'Lenovo',
        '00:0D:EF': 'Lenovo', '00:0D:F0': 'Lenovo',
        '00:0D:F1': 'Lenovo', '00:0D:F2': 'Lenovo',
        '00:0D:F3': 'Lenovo', '00:0D:F4': 'Lenovo',
        '00:0D:F5': 'Lenovo', '00:0D:F6': 'Lenovo',
        '00:0D:F7': 'Lenovo', '00:0D:F8': 'Lenovo',
        '00:0D:F9': 'Lenovo', '00:0D:FA': 'Lenovo',
        '00:0D:FB': 'Lenovo', '00:0D:FC': 'Lenovo',
        '00:0D:FD': 'Lenovo', '00:0D:FE': 'Lenovo',
        '00:0D:FF': 'Lenovo', '00:22:56': 'Lenovo',
        '00:24:BE': 'Lenovo', '00:25:55': 'Lenovo',
        # Sony
        '00:02:78': 'Sony', '00:03:0A': 'Sony',
        '00:04:1D': 'Sony', '00:05:CC': 'Sony',
        '00:06:2A': 'Sony', '00:07:29': 'Sony',
        '00:08:2D': 'Sony', '00:09:CC': 'Sony',
        '00:0A:CC': 'Sony', '00:0B:CC': 'Sony',
        '00:0C:CC': 'Sony', '00:0D:CC': 'Sony',
        '00:0E:CC': 'Sony', '00:0F:CC': 'Sony',
        '00:10:CC': 'Sony', '00:11:CC': 'Sony',
        '00:12:CC': 'Sony', '00:13:CC': 'Sony',
        '00:14:CC': 'Sony', '00:15:CC': 'Sony',
        '00:16:CC': 'Sony', '00:17:CC': 'Sony',
        '00:18:CC': 'Sony', '00:19:CC': 'Sony',
        '00:1A:CC': 'Sony', '00:1B:CC': 'Sony',
        '00:1C:CC': 'Sony', '00:1D:CC': 'Sony',
        '00:1E:CC': 'Sony', '00:1F:CC': 'Sony',
        '00:20:CC': 'Sony', '00:21:CC': 'Sony',
        '00:22:CC': 'Sony', '00:23:CC': 'Sony',
        '00:24:CC': 'Sony', '00:25:CC': 'Sony',
        '00:26:CC': 'Sony', '00:27:CC': 'Sony',
        # LG
        '00:01:8A': 'LG Electronics', '00:01:9B': 'LG Electronics',
        '00:02:2B': 'LG Electronics', '00:02:5B': 'LG Electronics',
        '00:03:2B': 'LG Electronics', '00:03:7B': 'LG Electronics',
        '00:04:2B': 'LG Electronics', '00:04:6B': 'LG Electronics',
        '00:05:2B': 'LG Electronics', '00:05:6B': 'LG Electronics',
        '00:06:2B': 'LG Electronics', '00:06:6B': 'LG Electronics',
        '00:07:2B': 'LG Electronics', '00:07:6B': 'LG Electronics',
        '00:08:2B': 'LG Electronics', '00:08:6B': 'LG Electronics',
        '00:09:2B': 'LG Electronics', '00:09:6B': 'LG Electronics',
        '00:10:6B': 'LG Electronics', '00:12:2B': 'LG Electronics',
        '00:13:2B': 'LG Electronics', '00:14:2B': 'LG Electronics',
        '00:14:6B': 'LG Electronics', '00:15:2B': 'LG Electronics',
        '00:16:2B': 'LG Electronics', '00:17:2B': 'LG Electronics',
        '00:18:2B': 'LG Electronics', '00:19:2B': 'LG Electronics',
        '00:19:6B': 'LG Electronics', '00:1A:2B': 'LG Electronics',
        '00:1A:6B': 'LG Electronics', '00:1B:2B': 'LG Electronics',
        '00:1B:6B': 'LG Electronics', '00:1C:2B': 'LG Electronics',
        '00:1C:6B': 'LG Electronics', '00:1D:2B': 'LG Electronics',
        '00:1D:6B': 'LG Electronics', '00:1E:2B': 'LG Electronics',
        '00:1E:6B': 'LG Electronics', '00:1F:2B': 'LG Electronics',
        '00:22:2B': 'LG Electronics', '00:23:2B': 'LG Electronics',
        '00:24:2B': 'LG Electronics', '00:25:2B': 'LG Electronics',
        '00:26:2B': 'LG Electronics', '00:27:2B': 'LG Electronics',
        '00:27:6B': 'LG Electronics',
        # Acer
        '00:0C:E5': 'Acer', '00:0F:E0': 'Acer',
        '00:10:E0': 'Acer', '00:11:E0': 'Acer',
        '00:12:E0': 'Acer', '00:13:E0': 'Acer',
        '00:14:E0': 'Acer', '00:15:E0': 'Acer',
        '00:16:E0': 'Acer', '00:17:E0': 'Acer',
        '00:18:E0': 'Acer', '00:19:E0': 'Acer',
        '00:1A:E0': 'Acer', '00:1B:E0': 'Acer',
        '00:1C:E0': 'Acer', '00:1D:E0': 'Acer',
        '00:1E:E0': 'Acer', '00:1F:E0': 'Acer',
        '00:20:E0': 'Acer', '00:21:E0': 'Acer',
        '00:22:E0': 'Acer', '00:23:E0': 'Acer',
        '00:24:E0': 'Acer', '00:25:E0': 'Acer',
        '00:26:E0': 'Acer', '00:27:E0': 'Acer',
        # Nokia
        '00:00:E8': 'Nokia', '00:01:EC': 'Nokia',
        '00:02:36': 'Nokia', '00:02:37': 'Nokia',
        '00:02:38': 'Nokia', '00:02:39': 'Nokia',
        '00:02:3A': 'Nokia', '00:02:3B': 'Nokia',
        '00:02:3C': 'Nokia', '00:02:3D': 'Nokia',
        '00:02:3E': 'Nokia', '00:02:3F': 'Nokia',
        '00:02:40': 'Nokia', '00:02:41': 'Nokia',
        '00:02:42': 'Nokia', '00:10:07': 'Nokia',
        '00:10:08': 'Nokia', '00:10:09': 'Nokia',
        '00:E0:03': 'Nokia', '00:E0:04': 'Nokia',
        '2C:5A:0F': 'Nokia', '2C:5A:10': 'Nokia',
        '2C:5A:11': 'Nokia', '2C:5A:12': 'Nokia',
        '2C:5A:13': 'Nokia', '2C:5A:14': 'Nokia',
        '2C:5A:15': 'Nokia', '2C:5A:16': 'Nokia',
        '2C:5A:17': 'Nokia', '2C:5A:18': 'Nokia',
        '2C:5A:19': 'Nokia', '2C:5A:1A': 'Nokia',
        '2C:5A:1B': 'Nokia', '2C:5A:1C': 'Nokia',
        '2C:5A:1D': 'Nokia', '2C:5A:1E': 'Nokia',
        '2C:5A:1F': 'Nokia',
        # IBM
        '00:06:29': 'IBM', '00:06:2A': 'IBM',
        '00:06:2B': 'IBM', '00:06:2C': 'IBM',
        '00:06:2D': 'IBM', '00:06:2E': 'IBM',
        '00:06:2F': 'IBM', '00:06:30': 'IBM',
        '00:06:31': 'IBM', '00:06:32': 'IBM',
        '00:06:33': 'IBM', '00:06:34': 'IBM',
        '00:06:35': 'IBM', '00:06:36': 'IBM',
        '00:06:37': 'IBM', '00:06:38': 'IBM',
        '00:06:39': 'IBM', '00:06:3A': 'IBM',
        '00:06:3B': 'IBM', '00:06:3C': 'IBM',
        '00:06:3D': 'IBM', '00:06:3E': 'IBM',
        '00:06:3F': 'IBM', '00:06:40': 'IBM',
        '00:06:41': 'IBM', '00:06:42': 'IBM',
        '00:06:43': 'IBM', '00:06:44': 'IBM',
        '00:06:45': 'IBM', '00:06:46': 'IBM',
        '00:06:47': 'IBM', '00:06:48': 'IBM',
        '00:06:49': 'IBM', '00:06:4A': 'IBM',
        '00:06:4B': 'IBM', '00:06:4C': 'IBM',
        '00:06:4D': 'IBM', '00:06:4E': 'IBM',
        '00:06:4F': 'IBM', '00:06:50': 'IBM',
        '00:06:51': 'IBM', '00:06:52': 'IBM',
        '00:06:53': 'IBM', '00:06:54': 'IBM',
        '00:06:55': 'IBM', '00:06:56': 'IBM',
        '00:06:57': 'IBM', '00:06:58': 'IBM',
        '00:06:59': 'IBM', '00:06:5A': 'IBM',
        '00:06:5B': 'IBM', '00:06:5C': 'IBM',
        '00:06:5D': 'IBM', '00:06:5E': 'IBM',
        '00:06:5F': 'IBM', '00:06:60': 'IBM',
        '00:06:61': 'IBM', '00:06:62': 'IBM',
        '00:06:63': 'IBM', '00:06:64': 'IBM',
        '00:06:65': 'IBM', '00:06:66': 'IBM',
        '00:06:67': 'IBM', '00:06:68': 'IBM',
        '00:06:69': 'IBM', '00:06:6A': 'IBM',
        '00:06:6B': 'IBM', '00:06:6C': 'IBM',
        '00:06:6D': 'IBM', '00:06:6E': 'IBM',
        '00:06:6F': 'IBM', '00:06:70': 'IBM',
        '00:06:71': 'IBM', '00:06:72': 'IBM',
        '00:06:73': 'IBM', '00:06:74': 'IBM',
        '00:06:75': 'IBM', '00:06:76': 'IBM',
        '00:06:77': 'IBM', '00:06:78': 'IBM',
        '00:06:79': 'IBM', '00:06:7A': 'IBM',
        '00:06:7B': 'IBM', '00:06:7C': 'IBM',
        '00:06:7D': 'IBM', '00:06:7E': 'IBM',
        '00:06:7F': 'IBM', '00:06:80': 'IBM',
        '00:06:81': 'IBM', '00:06:82': 'IBM',
        '00:06:83': 'IBM', '00:06:84': 'IBM',
        '00:06:85': 'IBM', '00:06:86': 'IBM',
        '00:06:87': 'IBM', '00:06:88': 'IBM',
        '00:06:89': 'IBM', '00:06:8A': 'IBM',
        '00:06:8B': 'IBM', '00:06:8C': 'IBM',
        '00:06:8D': 'IBM', '00:06:8E': 'IBM',
        '00:06:8F': 'IBM', '00:06:90': 'IBM',
        '00:06:91': 'IBM', '00:06:92': 'IBM',
        '00:06:93': 'IBM', '00:06:94': 'IBM',
        '00:06:95': 'IBM', '00:06:96': 'IBM',
        '00:06:97': 'IBM', '00:06:98': 'IBM',
        '00:06:99': 'IBM', '00:06:9A': 'IBM',
        '00:06:9B': 'IBM', '00:06:9C': 'IBM',
        '00:06:9D': 'IBM', '00:06:9E': 'IBM',
        '00:06:9F': 'IBM', '00:06:A0': 'IBM',
        '00:06:A1': 'IBM', '00:06:A2': 'IBM',
        '00:06:A3': 'IBM', '00:06:A4': 'IBM',
        '00:06:A5': 'IBM', '00:06:A6': 'IBM',
        '00:06:A7': 'IBM', '00:06:A8': 'IBM',
        '00:06:A9': 'IBM', '00:06:AA': 'IBM',
        '00:06:AB': 'IBM', '00:06:AC': 'IBM',
        '00:06:AD': 'IBM', '00:06:AE': 'IBM',
        '00:06:AF': 'IBM', '00:06:B0': 'IBM',
        '00:06:B1': 'IBM', '00:06:B2': 'IBM',
        '00:06:B3': 'IBM', '00:06:B4': 'IBM',
        '00:06:B5': 'IBM', '00:06:B6': 'IBM',
        '00:06:B7': 'IBM', '00:06:B8': 'IBM',
        '00:06:B9': 'IBM', '00:06:BA': 'IBM',
        '00:06:BB': 'IBM', '00:06:BC': 'IBM',
        '00:06:BD': 'IBM', '00:06:BE': 'IBM',
        '00:06:BF': 'IBM', '00:06:C0': 'IBM',
        '00:06:C1': 'IBM', '00:06:C2': 'IBM',
        '00:06:C3': 'IBM', '00:06:C4': 'IBM',
        '00:06:C5': 'IBM', '00:06:C6': 'IBM',
        '00:06:C7': 'IBM', '00:06:C8': 'IBM',
        '00:06:C9': 'IBM', '00:06:CA': 'IBM',
        '00:06:CB': 'IBM', '00:06:CC': 'IBM',
        '00:06:CD': 'IBM', '00:06:CE': 'IBM',
        '00:06:CF': 'IBM', '00:06:D0': 'IBM',
        '00:06:D1': 'IBM', '00:06:D2': 'IBM',
        '00:06:D3': 'IBM', '00:06:D4': 'IBM',
        '00:06:D5': 'IBM', '00:06:D6': 'IBM',
        '00:06:D7': 'IBM', '00:06:D8': 'IBM',
        '00:06:D9': 'IBM', '00:06:DA': 'IBM',
        '00:06:DB': 'IBM', '00:06:DC': 'IBM',
        '00:06:DD': 'IBM', '00:06:DE': 'IBM',
        '00:06:DF': 'IBM', '00:06:E0': 'IBM',
        '00:06:E1': 'IBM', '00:06:E2': 'IBM',
        '00:06:E3': 'IBM', '00:06:E4': 'IBM',
        '00:06:E5': 'IBM', '00:06:E6': 'IBM',
        '00:06:E7': 'IBM', '00:06:E8': 'IBM',
        '00:06:E9': 'IBM', '00:06:EA': 'IBM',
        '00:06:EB': 'IBM', '00:06:EC': 'IBM',
        '00:06:ED': 'IBM', '00:06:EE': 'IBM',
        '00:06:EF': 'IBM', '00:06:F0': 'IBM',
        '00:06:F1': 'IBM', '00:06:F2': 'IBM',
        '00:06:F3': 'IBM', '00:06:F4': 'IBM',
        '00:06:F5': 'IBM', '00:06:F6': 'IBM',
        '00:06:F7': 'IBM', '00:06:F8': 'IBM',
        '00:06:F9': 'IBM', '00:06:FA': 'IBM',
        '00:06:FB': 'IBM', '00:06:FC': 'IBM',
        '00:06:FD': 'IBM', '00:06:FE': 'IBM',
        '00:06:FF': 'IBM',
        # HP
        '00:23:4E': 'Hewlett Packard',
        '00:24:9B': 'Hewlett Packard',
        '00:25:5B': 'Hewlett Packard',
        '00:26:55': 'Hewlett Packard',
        '00:26:AB': 'Hewlett Packard',
        # 3Com / Xerox / Other
        '00:00:00': 'Xerox',
        '00:01:02': '3Com', '00:01:03': '3Com',
        '00:1C:42': 'Parallels', '00:1C:14': 'Parallels',
        '00:50:EB': 'IBM',
    }

    @staticmethod
    def _normalize_mac(mac):
        """标准化MAC地址格式"""
        mac = mac.upper().replace('-', ':').replace('.', ':')
        # 移除多余字符
        mac = re.sub(r'[^A-F0-9:]', '', mac)
        return mac

    @staticmethod
    def ping_sweep(network, timeout=2, max_threads=50):
        """
        Ping扫描 - 使用系统ping检测网段内活跃主机

        Args:
            network: CIDR格式网络地址，如 '192.168.1.0/24'
            timeout: 超时时间（秒）
            max_threads: 最大线程数

        Returns:
            list: 活跃主机IP列表
        """
        print_section("Ping扫描")
        print_info(f"目标网段: {network}")

        try:
            ips = expand_ip_range(network)
            if not ips:
                print_error(f"无效的网段: {network}")
                return []
        except Exception as e:
            print_error(f"网段解析失败: {e}")
            return []

        print_info(f"待扫描IP数: {len(ips)}")
        print_info(f"超时设置: {timeout}s")

        alive = []
        lock = threading.Lock()
        sem = threading.Semaphore(max_threads)

        def ping_ip(ip):
            """Ping单个IP"""
            try:
                if os.name == 'nt':
                    cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
                else:
                    cmd = ['ping', '-c', '1', '-W', str(timeout), ip]

                with sem:
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=timeout + 2
                    )
                    if result.returncode == 0:
                        with lock:
                            alive.append(ip)
                            print_success(f"[存活] {ip}")
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        threads = []
        for ip in ips:
            t = threading.Thread(target=ping_ip, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        print_info(f"扫描完成，存活主机: {len(alive)}/{len(ips)}")
        return alive

    @staticmethod
    def arp_scan(network=None):
        """
        ARP扫描 - 使用系统arp命令解析局域网设备

        Args:
            network: 可选，指定网段（Windows下arp -a自动获取）

        Returns:
            list: (IP, MAC) 元组列表
        """
        print_section("ARP扫描")
        print_info("正在获取ARP表...")

        results = []
        try:
            if os.name == 'nt':
                cmd = ['arp', '-a']
            else:
                cmd = ['arp', '-n', '-a'] if network is None else ['arp', '-n', network]

            output = subprocess.check_output(cmd, timeout=10).decode('utf-8', errors='ignore')

            # 解析ARP输出
            lines = output.split('\n')
            for line in lines:
                if os.name == 'nt':
                    # Windows格式: 接口: 192.168.1.1 --- 0x5
                    #   Internet 地址         物理地址          类型
                    #   192.168.1.101         00-11-22-33-44-55  动态
                    match = re.search(
                        r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17,})',
                        line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace('-', ':')
                        results.append((ip, mac))
                else:
                    # Linux格式: ? (192.168.1.101) at 00:11:22:33:44:55 [ether] on eth0
                    match = re.search(
                        r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})',
                        line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).lower()
                        if mac != '(incomplete)':
                            results.append((ip, mac))

            if results:
                print_success(f"发现 {len(results)} 个设备")
                headers = ['IP地址', 'MAC地址', '厂商']
                rows = []
                for ip, mac in results:
                    vendor = NetworkTools.mac_address_lookup(mac, silent=True)
                    rows.append((ip, mac, vendor or 'Unknown'))
                print_table(headers, rows)
            else:
                print_warning("未发现ARP设备")

        except subprocess.TimeoutExpired:
            print_error("ARP命令执行超时")
        except subprocess.CalledProcessError as e:
            print_error(f"ARP命令执行失败: {e}")
        except Exception as e:
            print_error(f"ARP扫描出错: {e}")

        return results

    @staticmethod
    def traceroute(target, max_hops=30, timeout=3):
        """
        路由追踪 - 使用socket或系统命令追踪路由路径

        Args:
            target: 目标IP或域名
            max_hops: 最大跳数
            timeout: 超时时间（秒）

        Returns:
            list: 路由路径列表
        """
        print_section("路由追踪")
        print_info(f"目标: {target}")
        print_info(f"最大跳数: {max_hops}")

        hops = []

        try:
            # 尝试使用系统traceroute/tracert命令
            if os.name == 'nt':
                cmd = ['tracert', '-h', str(max_hops), '-w', str(int(timeout * 1000)), target]
            else:
                cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', str(timeout), target]

            print_info("正在追踪路由，请稍候...")
            output = subprocess.check_output(cmd, timeout=max_hops * timeout + 10, stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore')

            for line in output.split('\n'):
                line = line.strip()
                # 解析跳数
                hop_match = re.search(r'^\s*(\d+)', line)
                if hop_match:
                    # 提取IP地址
                    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    hop_num = int(hop_match.group(1))
                    hop_ip = ips[0] if ips else '*'
                    # 提取延迟
                    ms = re.findall(r'(\d+)\s*ms', line)
                    rtt = ms[0] if ms else '*'
                    hops.append({
                        'hop': hop_num,
                        'ip': hop_ip,
                        'rtt': f"{rtt}ms" if rtt != '*' else '*'
                    })

        except FileNotFoundError:
            # 系统命令不可用，使用UDP socket实现
            print_info("系统traceroute不可用，使用socket模式...")
            hops = NetworkTools._socket_traceroute(target, max_hops, timeout)
        except subprocess.TimeoutExpired:
            print_error("路由追踪超时")
        except subprocess.CalledProcessError as e:
            # tracert返回非零可能只是部分成功
            output = e.output.decode('utf-8', errors='ignore') if e.output else ''
            for line in output.split('\n'):
                line = line.strip()
                hop_match = re.search(r'^\s*(\d+)', line)
                if hop_match:
                    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    hop_num = int(hop_match.group(1))
                    hop_ip = ips[0] if ips else '*'
                    ms = re.findall(r'(\d+)\s*ms', line)
                    rtt = ms[0] if ms else '*'
                    hops.append({
                        'hop': hop_num,
                        'ip': hop_ip,
                        'rtt': f"{rtt}ms" if rtt != '*' else '*'
                    })
        except Exception as e:
            print_error(f"路由追踪出错: {e}")

        if hops:
            print_success(f"路由追踪完成，共 {len(hops)} 跳")
            headers = ['跳数', 'IP地址', '延迟']
            rows = [(str(h['hop']), h['ip'], h['rtt']) for h in hops]
            print_table(headers, rows)
        else:
            print_warning("未获取到路由信息")

        return hops

    @staticmethod
    def _socket_traceroute(target, max_hops=30, timeout=3):
        """使用UDP socket实现路由追踪"""
        hops = []
        dest_ip = None

        try:
            dest_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print_error(f"无法解析目标: {target}")
            return hops

        print_info(f"目标IP: {dest_ip}")

        for ttl in range(1, max_hops + 1):
            # 创建UDP socket
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            start_time = time.time()
            addr = None
            try:
                send_sock.sendto(b'', (dest_ip, 33434 + ttl))
                try:
                    data, addr = recv_sock.recvfrom(512)
                    rtt = (time.time() - start_time) * 1000
                    hop_ip = addr[0] if addr else '*'
                    hops.append({
                        'hop': ttl,
                        'ip': hop_ip,
                        'rtt': f"{rtt:.1f}ms"
                    })
                    print_info(f"  {ttl:2d}  {hop_ip:15s}  {rtt:.1f}ms")
                    if hop_ip == dest_ip:
                        break
                except socket.timeout:
                    hops.append({'hop': ttl, 'ip': '*', 'rtt': '*'})
                    print_info(f"  {ttl:2d}  {'*':15s}  *")
            except Exception:
                hops.append({'hop': ttl, 'ip': '*', 'rtt': '*'})
            finally:
                send_sock.close()
                recv_sock.close()

        return hops

    @staticmethod
    def dns_resolver(domains, record_type='A'):
        """
        DNS批量解析

        Args:
            domains: 域名列表或单个域名
            record_type: 记录类型 (A, AAAA, MX, NS, CNAME, TXT)

        Returns:
            list: (domain, records) 解析结果列表
        """
        print_section("DNS解析")
        if isinstance(domains, str):
            domains = [domains]

        print_info(f"待解析域名: {len(domains)}")
        print_info(f"记录类型: {record_type}")

        results = []

        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue

            records = []
            try:
                if record_type == 'A':
                    ip = socket.gethostbyname(domain)
                    records.append(ip)
                    print_success(f"[A] {domain} -> {ip}")
                elif record_type == 'AAAA':
                    try:
                        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                        for info in infos:
                            ip = info[4][0]
                            records.append(ip)
                            print_success(f"[AAAA] {domain} -> {ip}")
                    except socket.gaierror:
                        print_warning(f"[AAAA] {domain} -> 无记录")
                elif record_type == 'MX':
                    try:
                        # 使用系统nslookup或dig
                        if os.name == 'nt':
                            cmd = ['nslookup', '-type=MX', domain]
                        else:
                            cmd = ['nslookup', '-type=mx', domain]

                        output = subprocess.check_output(
                            cmd, timeout=5, stderr=subprocess.DEVNULL
                        ).decode('utf-8', errors='ignore')

                        mx_servers = re.findall(
                            r'mail\s+exchange\s+=\s+(\d+)\s+([\w.-]+)',
                            output,
                            re.IGNORECASE
                        )
                        if not mx_servers:
                            mx_servers = re.findall(
                                r'MX\s+preference\s*=\s*(\d+),\s*mail\s+exchanger\s*=\s*([\w.-]+)',
                                output,
                                re.IGNORECASE
                            )
                        for pref, mx in mx_servers:
                            records.append(f"{pref} {mx}")
                            print_success(f"[MX] {domain} -> {pref} {mx}")
                    except Exception as e:
                        print_warning(f"[MX] {domain} -> 查询失败: {e}")
                elif record_type == 'NS':
                    try:
                        cmd = ['nslookup', '-type=ns', domain]
                        output = subprocess.check_output(
                            cmd, timeout=5, stderr=subprocess.DEVNULL
                        ).decode('utf-8', errors='ignore')

                        ns_servers = re.findall(
                            r'nameserver\s*=\s*([\w.-]+)',
                            output,
                            re.IGNORECASE
                        )
                        if not ns_servers:
                            ns_servers = re.findall(
                                r'nameserver\s+=\s+([\w.-]+)',
                                output,
                                re.IGNORECASE
                            )
                        for ns in ns_servers:
                            records.append(ns)
                            print_success(f"[NS] {domain} -> {ns}")
                    except Exception as e:
                        print_warning(f"[NS] {domain} -> 查询失败: {e}")
                else:
                    # 默认A记录解析
                    ip = socket.gethostbyname(domain)
                    records.append(ip)
                    print_success(f"[A] {domain} -> {ip}")

                results.append((domain, records))
            except socket.gaierror:
                print_warning(f"{domain} -> 解析失败")
                results.append((domain, []))
            except Exception as e:
                print_error(f"{domain} -> 错误: {e}")
                results.append((domain, []))

        return results

    @staticmethod
    def dns_mass_resolver(domains, max_threads=50, record_type='A'):
        """
        批量DNS解析 - 多线程并发解析

        Args:
            domains: 域名列表
            max_threads: 最大线程数
            record_type: 记录类型

        Returns:
            dict: {domain: [records]}
        """
        print_section("批量DNS解析")
        print_info(f"待解析域名: {len(domains)}")
        print_info(f"线程数: {max_threads}")

        results = {}
        lock = threading.Lock()
        sem = threading.Semaphore(max_threads)

        def resolve(domain):
            with sem:
                try:
                    ip = socket.gethostbyname(domain)
                    with lock:
                        results[domain] = ip
                        print_success(f"{domain} -> {ip}")
                except socket.gaierror:
                    with lock:
                        results[domain] = None
                        print_warning(f"{domain} -> 解析失败")
                except Exception as e:
                    with lock:
                        results[domain] = None
                        print_error(f"{domain} -> 错误: {e}")

        threads = []
        for domain in domains:
            if isinstance(domain, str) and domain.strip():
                t = threading.Thread(target=resolve, args=(domain.strip(),))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        resolved = sum(1 for v in results.values() if v)
        failed = sum(1 for v in results.values() if v is None)
        print_info(f"解析完成: 成功 {resolved}, 失败 {failed}")
        return results

    @staticmethod
    def mac_address_lookup(mac, silent=False):
        """
        MAC地址查询 - OUI厂商查找

        Args:
            mac: MAC地址字符串
            silent: 静默模式（不打印输出）

        Returns:
            str: 厂商名称，未找到返回None
        """
        if not silent:
            print_section("MAC地址查询")
            print_info(f"MAC地址: {mac}")

        try:
            normalized = NetworkTools._normalize_mac(mac)
            # 提取OUI（前3个字节，即前8个字符含冒号）
            oui = normalized[:8]  # 格式: XX:XX:XX

            # 精确匹配
            vendor = NetworkTools.OUI_DATABASE.get(oui)
            if not vendor:
                # 尝试前2个字节
                oui2 = normalized[:5]
                for key, val in NetworkTools.OUI_DATABASE.items():
                    if key.startswith(oui2):
                        vendor = val
                        break

            if vendor:
                if not silent:
                    print_success(f"厂商: {vendor}")
                return vendor
            else:
                if not silent:
                    print_warning(f"未找到OUI: {oui}")
                return None

        except Exception as e:
            if not silent:
                print_error(f"MAC查询出错: {e}")
            return None

    @staticmethod
    def http_server(port=8000, directory=None):
        """
        简易HTTP服务器 - 用于文件传输

        Args:
            port: 监听端口
            directory: 服务目录，默认当前目录

        Returns:
            bool: 成功返回True
        """
        print_section("简易HTTP服务器")
        print_info(f"端口: {port}")

        if directory:
            if not os.path.isdir(directory):
                print_error(f"目录不存在: {directory}")
                return False
            os.chdir(directory)
            print_info(f"服务目录: {os.path.abspath(directory)}")
        else:
            print_info(f"服务目录: {os.getcwd()}")

        handler = http.server.SimpleHTTPRequestHandler

        try:
            server = socketserver.TCPServer(("0.0.0.0", port), handler)
            print_success(f"HTTP服务器已启动: http://0.0.0.0:{port}")
            print_info("按 Ctrl+C 停止服务器")
            print_info(f"本机访问: http://127.0.0.1:{port}")
            print_info(f"局域网访问: http://<本机IP>:{port}")

            server.serve_forever()
            return True
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:
                print_error(f"端口 {port} 已被占用")
            else:
                print_error(f"启动服务器失败: {e}")
            return False
        except KeyboardInterrupt:
            print_info("\n服务器已停止")
            return True
        except Exception as e:
            print_error(f"服务器异常: {e}")
            return False

    @staticmethod
    def netcat_listener(host='0.0.0.0', port=4444):
        """
        简易Netcat监听器 - 使用socket TCP server

        Args:
            host: 监听地址
            port: 监听端口

        Returns:
            bool: 成功返回True
        """
        print_section("Netcat监听器")
        print_info(f"监听地址: {host}:{port}")
        print_info("等待连接...")

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(1)
            server.settimeout(None)

            print_success(f"监听器已启动: {host}:{port}")
            print_info("按 Ctrl+C 停止监听")

            conn, addr = server.accept()
            print_success(f"收到连接: {addr[0]}:{addr[1]}")

            conn.settimeout(30)

            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    # 回显收到的数据
                    text = data.decode('utf-8', errors='replace')
                    print(f"{Colors.GREEN}[接收]{Colors.RESET} {text}")

                    # 发送响应
                    response = input(f"{Colors.CYAN}[发送]{Colors.RESET} ")
                    if response.lower() in ('exit', 'quit', 'q'):
                        conn.send(b'bye\r\n')
                        break
                    conn.send((response + '\r\n').encode())
                except socket.timeout:
                    print_info("连接超时")
                    break
                except (ConnectionResetError, BrokenPipeError):
                    print_error("连接已断开")
                    break
                except Exception as e:
                    print_error(f"通信错误: {e}")
                    break

            conn.close()
            server.close()
            print_info("监听器已关闭")
            return True

        except OSError as e:
            if e.errno == 98 or e.errno == 10048:
                print_error(f"端口 {port} 已被占用")
            else:
                print_error(f"启动监听器失败: {e}")
            return False
        except KeyboardInterrupt:
            print_info("\n监听器已停止")
            return True
        except Exception as e:
            print_error(f"监听器异常: {e}")
            return False

    @staticmethod
    def proxy_checker(proxies, timeout=5):
        """
        代理检测 - 测试代理是否可用

        Args:
            proxies: 代理列表，格式 ['ip:port', ...]
            timeout: 超时时间（秒）

        Returns:
            list: (proxy, status, delay) 结果列表
        """
        print_section("代理检测")
        print_info(f"待检测代理: {len(proxies)}")
        print_info(f"超时设置: {timeout}s")

        results = []
        test_url = 'http://httpbin.org/ip'
        test_host = 'httpbin.org'

        for proxy in proxies:
            proxy = proxy.strip()
            if not proxy:
                continue

            try:
                parts = proxy.split(':')
                if len(parts) != 2:
                    print_warning(f"跳过无效代理: {proxy}")
                    results.append((proxy, False, None))
                    continue

                proxy_ip = parts[0]
                proxy_port = int(parts[1])

                start_time = time.time()
                try:
                    # 测试代理连通性
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((proxy_ip, proxy_port))
                    sock.close()

                    if result == 0:
                        delay = int((time.time() - start_time) * 1000)
                        print_success(f"[可用] {proxy} - {delay}ms")
                        results.append((proxy, True, delay))
                    else:
                        print_warning(f"[不可用] {proxy}")
                        results.append((proxy, False, None))
                except Exception:
                    print_warning(f"[不可用] {proxy}")
                    results.append((proxy, False, None))

            except (ValueError, IndexError):
                print_warning(f"跳过无效代理格式: {proxy}")
                results.append((proxy, False, None))

        # 统计结果
        working = sum(1 for _, status, _ in results if status)
        print_info(f"检测完成: 可用 {working}/{len(results)}")
        return results

    @staticmethod
    def ip_calculator(ip_cidr):
        """
        IP子网计算器

        Args:
            ip_cidr: IP/CIDR格式，如 '192.168.1.0/24'

        Returns:
            dict: 子网信息
        """
        print_section("IP子网计算")
        print_info(f"输入: {ip_cidr}")

        result = {}
        try:
            network = ipaddress.ip_network(ip_cidr, strict=False)

            result = {
                'network': str(network.network_address),
                'netmask': str(network.netmask),
                'wildcard': str(network.hostmask),
                'broadcast': str(network.broadcast_address),
                'hosts_count': network.num_addresses,
                'usable_hosts': max(0, network.num_addresses - 2),
                'prefix_length': network.prefixlen,
                'first_host': '',
                'last_host': '',
                'binary_netmask': '',
                'ip_class': '',
                'is_private': network.is_private,
                'is_global': not network.is_private,
            }

            # 计算可用主机范围
            hosts = list(network.hosts())
            if hosts:
                result['first_host'] = str(hosts[0])
                result['last_host'] = str(hosts[-1])

            # 二进制掩码
            mask_int = int(network.netmask)
            result['binary_netmask'] = '.'.join(
                format((mask_int >> (24 - i * 8)) & 0xFF, '08b')
                for i in range(4)
            )

            # IP地址类别
            first_octet = int(str(network.network_address).split('.')[0])
            if 1 <= first_octet <= 126:
                result['ip_class'] = 'A'
            elif 128 <= first_octet <= 191:
                result['ip_class'] = 'B'
            elif 192 <= first_octet <= 223:
                result['ip_class'] = 'C'
            elif 224 <= first_octet <= 239:
                result['ip_class'] = 'D (组播)'
            else:
                result['ip_class'] = 'E (保留)'

            # 打印结果
            print_success("子网信息:")
            info_lines = [
                ('网络地址', result['network']),
                ('子网掩码', result['netmask']),
                ('通配符掩码', result['wildcard']),
                ('广播地址', result['broadcast']),
                ('前缀长度', f"/{result['prefix_length']}"),
                ('IP类别', result['ip_class']),
                ('地址总数', str(result['hosts_count'])),
                ('可用主机数', str(result['usable_hosts'])),
                ('可用范围', f"{result['first_host']} - {result['last_host']}" if result['first_host'] else 'N/A'),
                ('是否为私有', '是' if result['is_private'] else '否'),
                ('二进制掩码', result['binary_netmask']),
            ]
            for label, value in info_lines:
                print(f"  {Colors.CYAN}{label:12s}{Colors.RESET}: {Colors.GREEN}{value}{Colors.RESET}")

        except ValueError as e:
            print_error(f"无效的IP/CIDR格式: {e}")
        except Exception as e:
            print_error(f"子网计算出错: {e}")

        return result

    @staticmethod
    def port_forwarder(local_port, remote_host, remote_port, protocol='tcp'):
        """
        端口转发器

        Args:
            local_port: 本地监听端口
            remote_host: 远程目标地址
            remote_port: 远程目标端口
            protocol: 协议类型 (tcp)

        Returns:
            bool: 成功返回True
        """
        print_section("端口转发器")
        print_info(f"本地端口: {local_port}")
        print_info(f"远程目标: {remote_host}:{remote_port}")
        print_info(f"协议: {protocol}")

        BUFFER_SIZE = 4096

        def forward(source, destination):
            """转发数据"""
            try:
                while True:
                    data = source.recv(BUFFER_SIZE)
                    if not data:
                        break
                    destination.send(data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            finally:
                try:
                    source.close()
                    destination.close()
                except Exception:
                    pass

        def handle_client(client_sock):
            """处理客户端连接"""
            try:
                # 连接到远程目标
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((remote_host, remote_port))

                print_success(f"连接已建立: {client_sock.getpeername()} -> {remote_host}:{remote_port}")

                # 双向转发
                t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
                t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
                t1.start()
                t2.start()
                t1.join()
                t2.join()

            except socket.timeout:
                print_error(f"连接远程目标超时: {remote_host}:{remote_port}")
            except ConnectionRefusedError:
                print_error(f"远程目标拒绝连接: {remote_host}:{remote_port}")
            except Exception as e:
                print_error(f"转发错误: {e}")
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', local_port))
            server.listen(5)
            server.settimeout(None)

            print_success(f"端口转发器已启动: 0.0.0.0:{local_port} -> {remote_host}:{remote_port}")
            print_info("按 Ctrl+C 停止转发")

            while True:
                try:
                    client_sock, addr = server.accept()
                    print_info(f"收到连接: {addr[0]}:{addr[1]}")
                    t = threading.Thread(target=handle_client, args=(client_sock,), daemon=True)
                    t.start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print_error(f"接受连接错误: {e}")

        except OSError as e:
            if e.errno == 98 or e.errno == 10048:
                print_error(f"端口 {local_port} 已被占用")
            else:
                print_error(f"启动转发器失败: {e}")
            return False
        except KeyboardInterrupt:
            print_info("\n端口转发器已停止")
        except Exception as e:
            print_error(f"转发器异常: {e}")
            return False
        finally:
            try:
                server.close()
            except Exception:
                pass

        return True

    @staticmethod
    def network_scanner(network, ports=None, timeout=2, max_threads=100):
        """
        网络扫描器 - 扫描网段内活跃主机及开放端口

        Args:
            network: CIDR格式网络地址
            ports: 端口列表，默认常见端口
            timeout: 超时时间（秒）
            max_threads: 最大线程数

        Returns:
            dict: {ip: [开放端口列表]}
        """
        print_section("网络扫描器")
        print_info(f"目标网段: {network}")

        if ports is None:
            ports = common_ports()
        elif isinstance(ports, str):
            ports = port_range_to_list(ports)

        print_info(f"待扫描端口数: {len(ports)}")

        # 第一步：Ping扫描发现活跃主机
        print_info("第一步: Ping扫描发现活跃主机")
        alive_hosts = NetworkTools.ping_sweep(network, timeout=timeout)

        if not alive_hosts:
            print_warning("未发现活跃主机")
            return {}

        print_info(f"第二步: 扫描活跃主机的开放端口")
        results = {}
        lock = threading.Lock()
        sem = threading.Semaphore(max_threads)

        def scan_host(ip):
            """扫描单个主机的端口"""
            open_ports = []
            for port in ports:
                try:
                    with sem:
                        if check_port(ip, port, timeout):
                            open_ports.append(port)
                            service = get_service_name(port)
                            with lock:
                                print_success(f"{ip}:{port} ({service})")
                except Exception:
                    pass

            if open_ports:
                with lock:
                    results[ip] = open_ports

        threads = []
        for ip in alive_hosts:
            t = threading.Thread(target=scan_host, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # 打印结果汇总
        if results:
            print_success(f"扫描完成: 发现 {len(results)} 台主机有开放端口")
            headers = ['IP地址', '开放端口数', '端口列表']
            rows = []
            for ip, ports_found in sorted(results.items()):
                port_str = ', '.join(str(p) for p in ports_found)
                rows.append((ip, str(len(ports_found)), port_str))
            print_table(headers, rows)
        else:
            print_warning("未发现开放端口")

        return results