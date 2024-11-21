window.onload = function() {
    // 加载网络设备列表
    fetch('/api/devices')
        .then(response => response.json())
        .then(devices => {
            const tableBody = document.getElementById('devices-table').querySelector('tbody');
            devices.forEach(device => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${device.ip}</td>
                    <td>${device.mac}</td>
                    <td>${device.hostname}</td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading devices:', error));

    // 启动 ARP 欺骗
    document.getElementById('startBtn').addEventListener('click', () => {
        const targetIp = document.getElementById('target_ip').value;
        // const targetMac = document.getElementById('target_mac').value;
        sendControlRequest('start', targetIp);
    });

    // 停止 ARP 欺骗
    document.getElementById('stopBtn').addEventListener('click', () => {
        sendControlRequest('stop');
    });

    // 开始端口扫描
    document.getElementById('scanPortsBtn').addEventListener('click', () => {
        const ip = document.getElementById('scan_ip').value;

        // 显示进度条
        document.getElementById('progress-container').style.display = 'block';
        document.getElementById('scan-progress').value = 0;
        document.getElementById('progress-text').textContent = '0%';

        // 发起端口扫描请求
        fetch('/api/scan_ports', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            const resultsDiv = document.getElementById('port-scan-results');
            if (data.error) {
                resultsDiv.textContent = `Error: ${data.error}`;
            } else if (data.open_ports.length === 0) {
                resultsDiv.textContent = 'No open ports found.';
            } else {
                resultsDiv.innerHTML = `<strong>开放端口:</strong> ${data.open_ports.join(', ')}`;
            }
            // 隐藏进度条
            document.getElementById('progress-container').style.display = 'none';
        })
        .catch(error => console.error('Error scanning ports:', error));

        // 定时获取扫描进度
        const progressInterval = setInterval(() => {
            fetch('/api/scan_progress')
                .then(response => response.json())
                .then(data => {
                    const progress = data.progress;
                    document.getElementById('scan-progress').value = progress;
                    document.getElementById('progress-text').textContent = `${progress}%`;

                    // 扫描完成，清除定时器
                    if (progress >= 100) {
                        clearInterval(progressInterval);
                    }
                })
                .catch(error => console.error('Error fetching scan progress:', error));
        }, 500);
    });
};

// 发送 ARP 欺骗控制请求
function sendControlRequest(action, targetIp) {
    fetch('/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            action: action,
            target_ip: targetIp,
            // target_mac: targetMac,
        })
    })
    .then(response => response.text())
    .then(result => {
        document.getElementById('status').innerText = result;
    })
    .catch(error => {
        document.getElementById('status').innerText = '操作失败，请检查输入并重试。';
        console.error('Error during ARP Spoofing request:', error);
    });
}
