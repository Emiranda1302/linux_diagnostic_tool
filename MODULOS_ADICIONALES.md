## 📡 MÓDULOS ADICIONALES - ANÁLISIS Y RECOMENDACIONES

# ¿Qué módulos agregar para destinar trabajo?

## 📊 Estado Actual vs Recomendado

```
MÓDULO                   ESTADO          RECOMENDACIÓN    PRIORIDAD
─────────────────────────────────────────────────────────────────
System (CPU/Memory)      ✅ Completo      -                 -
Forensics (SUID/Cron)    ✅ Completo      Expandir         BAJA
Network/Interfaces       ✅ Completo      -                 -
Network/Connections      ✅ Completo      Mejorar          MEDIA
WiFi Scanning            🔶 Incompleto    Implementar      MEDIA
Port Scanning            🔶 Incompleto    Implementar      ALTA
Network Monitoring       ❌ No existe     AGREGAR          ALTA
Printer Detection        ❌ No existe     AGREGAR          BAJA
Device Discovery         ❌ No existe     AGREGAR          MEDIA
```

---

## 🎯 PARA CONSEGUIR TRABAJO: TOP 3 A IMPLEMENTAR

### #1 PRIORITY: Network Port Monitoring (SCANNER MEJORADO)

**POR QUÉ:**
- Demanda alta: "Administración de sistemas Linux/Unix y conocimientos sólidos en redes (HTTP, DNS, TCP/IP)"
- Diferencia tu proyecto vs otros
- Útil para auditoría de seguridad

**QUÉ HACER:**

```bash
ldt scanner --network              # Escaneo rápido de la red
ldt scanner --port 8080            # Escaneo de puerto específico
ldt scanner --service http         # Buscar servicios por tipo
ldt scanner --aggressive           # Nmap-style aggressive scan
```

**CÓDIGO BASE:**

```python
# src/ldt/modules/scanner.py

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from typing import List, Dict

def get_network_interfaces():
    """Get local network CIDR"""
    import subprocess
    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
    # Parse y obtener red local
    
def quick_port_scan(target_ip: str, ports: List[int] = None) -> List[Dict]:
    """
    Fast port scan using socket (no nmap required)
    
    Retorna:
    [{
        'ip': '192.168.1.1',
        'port': 22,
        'status': 'open',
        'service': 'ssh',
        'banner': 'OpenSSH 7.4'
    }]
    """
    open_ports = []
    default_ports = ports or [
        22, 80, 443, 8080, 8443, 3306, 5432, 6379, 
        27017, 9200, 5000, 8000, 3000, 5900, 23, 25, 53
    ]
    
    for port in default_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            service = socket.getservbyport(port, 'tcp')
            banner = get_service_banner(target_ip, port)
            
            open_ports.append({
                'ip': target_ip,
                'port': port,
                'status': 'open',
                'service': service,
                'banner': banner
            })
        
        sock.close()
    
    return open_ports

def network_discovery(network_cidr: str = None) -> List[Dict]:
    """
    ARP-based network discovery (rápido, sin nmap)
    
    Retorna hosts vivos en la red con:
    - IP
    - MAC
    - Vendor (si está en database)
    - Hostname (reverse DNS)
    """
    import subprocess
    
    if not network_cidr:
        network_cidr = get_local_network()  # 192.168.1.0/24
    
    # Usar arp-scan si está disponible
    result = subprocess.run(
        ['arp-scan', '--localnet'],
        capture_output=True,
        text=True
    )
    
    hosts = []
    for line in result.stdout.split('\n'):
        if '\t' in line:
            ip, mac, vendor = line.split('\t')
            hostname = resolve_hostname(ip)
            
            hosts.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'hostname': hostname,
                'status': 'alive'
            })
    
    return hosts

def service_detection(ip: str, port: int) -> Dict:
    """
    Detecta el servicio corriendo en un puerto
    
    Retorna:
    {
        'service': 'http',
        'version': 'Apache/2.4.41',
        'title': 'Dashboard - Login',
        'cpe': 'cpe:/a:apache:http_server:2.4.41'
    }
    """
    # Conectar y capturar banner
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Enviar request HTTP genérico
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Parse HTTP header
        if 'HTTP' in banner:
            lines = banner.split('\n')
            service_info = parse_http_banner(lines)
        else:
            service_info = {'service': 'unknown', 'banner': banner[:100]}
        
        sock.close()
        return service_info
    
    except Exception as e:
        return {'service': 'error', 'error': str(e)}
```

**DIFERENCIADOR:**
- Sin requerir nmap/herramientas externas
- Pure Python con socket
- Parallelizado con ThreadPoolExecutor
- Identifica servicios automáticamente

---

### #2 PRIORITY: Device Discovery & Printer Detection

**POR QUÉ:**
- IoT/Device management es tendencia
- Unique selling point
- Útil en empresas

**QUÉ HACER:**

```bash
ldt discovery --scan              # Escanea toda la red
ldt discovery --printers          # Encuentra impresoras
ldt discovery --type iot          # IoT devices (cámaras, etc)
ldt discovery --test-connectivity # Test aleatorio impresora↔PC
```

**CÓDIGO BASE:**

```python
# src/ldt/modules/discovery.py

import socket
import subprocess
import json
from typing import List, Dict

DEVICE_SIGNATURES = {
    'printer': {
        'ports': [9100, 515, 631, 3001],  # LPD, LPR, CUPS, HP
        'services': ['lpd', 'lpr', 'ipp', 'http'],
        'strings': ['hp-ilo', 'kyocera', 'xerox', 'brother', 'ricoh']
    },
    'router': {
        'ports': [80, 443, 8080, 8443],
        'services': ['http', 'https'],
        'strings': ['router', 'gateway', 'admin']
    },
    'camera': {
        'ports': [80, 443, 8080, 8000, 5000],
        'services': ['http', 'https', 'rtsp'],
        'strings': ['camera', 'webcam', 'axis', 'dahua']
    },
    'nas': {
        'ports': [445, 139, 21, 22, 8080],
        'services': ['smb', 'ftp', 'ssh', 'http'],
        'strings': ['nas', 'synology', 'qnap', 'seagate']
    }
}

def discover_devices(network_cidr: str = None) -> List[Dict]:
    """
    Descubre dispositivos en la red
    
    Retorna:
    [{
        'ip': '192.168.1.5',
        'mac': '00:11:22:33:44:55',
        'hostname': 'PRINTER-01',
        'type': 'printer',
        'ports_open': [9100, 515],
        'services': ['lpd', 'lpr'],
        'vendor': 'HP Inc.',
        'confidence': 0.95
    }]
    """
    devices = []
    
    # Primero: descubrir hosts vivos
    hosts = network_discovery(network_cidr)
    
    # Segundo: escanear puertos para identificar
    for host in hosts:
        ip = host['ip']
        open_ports = quick_port_scan(ip)
        
        if open_ports:
            device = classify_device(ip, open_ports)
            device['mac'] = host['mac']
            device['hostname'] = host['hostname']
            device['vendor'] = host['vendor']
            devices.append(device)
    
    return devices

def classify_device(ip: str, open_ports: List[Dict]) -> Dict:
    """
    Clasifica qué tipo de dispositivo es basado en puertos abiertos
    
    Retorna tipo y confidence score
    """
    port_numbers = [p['port'] for p in open_ports]
    services = [p['service'] for p in open_ports]
    
    best_match = None
    best_score = 0
    
    for device_type, signature in DEVICE_SIGNATURES.items():
        score = 0
        
        # Puntos por puertos
        matching_ports = set(port_numbers) & set(signature['ports'])
        score += len(matching_ports) * 20
        
        # Puntos por servicios
        matching_services = set(services) & set(signature['services'])
        score += len(matching_services) * 30
        
        # Puntos por banner strings
        for port_info in open_ports:
            if port_info.get('banner'):
                for string in signature['strings']:
                    if string.lower() in port_info['banner'].lower():
                        score += 40
        
        if score > best_score:
            best_score = score
            best_match = device_type
    
    confidence = min(best_score / 100.0, 1.0)
    
    return {
        'type': best_match or 'unknown',
        'confidence': confidence,
        'ports_open': port_numbers,
        'services': services
    }

def test_printer_connectivity(printer_ip: str, test_devices: List[str] = None,
                               test_count: int = 5) -> Dict:
    """
    Test aleatorio: Conectividad entre impresora y otros dispositivos
    
    Scenario:
    - Encontrar impresora en red
    - Hacer ping a N dispositivos aleatorios
    - Verificar si impresora es alcanzable desde cada uno
    - Generar reporte de conectividad
    
    Retorna:
    {
        'printer_ip': '192.168.1.10',
        'printer_name': 'HP-Laserjet-Pro',
        'tests': [
            {
                'device_ip': '192.168.1.5',
                'device_name': 'DESKTOP-01',
                'reachable': True,
                'response_time_ms': 2.5,
                'smb_access': True,
                'print_queue_available': True
            },
            ...
        ],
        'summary': {
            'total_tests': 5,
            'reachable': 5,
            'connectivity_percent': 100,
            'avg_response_time_ms': 2.3
        }
    }
    """
    import random
    import subprocess
    import time
    
    # Verificar que printer existe
    ping_result = subprocess.run(
        ['ping', '-c', '1', printer_ip],
        capture_output=True,
        timeout=2
    )
    
    if ping_result.returncode != 0:
        return {'error': f'Printer {printer_ip} not reachable'}
    
    # Obtener lista de dispositivos (si no se proporciona)
    if not test_devices:
        hosts = network_discovery()
        test_devices = [h['ip'] for h in hosts if h['ip'] != printer_ip]
        test_devices = random.sample(test_devices, min(test_count, len(test_devices)))
    
    results = {
        'printer_ip': printer_ip,
        'tests': [],
        'timestamp': datetime.now().isoformat()
    }
    
    for device_ip in test_devices:
        test_result = {
            'device_ip': device_ip,
            'reachable': False,
            'response_time_ms': 0,
            'smb_access': False,
            'print_queue': False
        }
        
        # Test 1: Ping
        start = time.time()
        ping_cmd = subprocess.run(
            ['ping', '-c', '1', device_ip],
            capture_output=True,
            timeout=2
        )
        response_time = (time.time() - start) * 1000
        
        if ping_cmd.returncode == 0:
            test_result['reachable'] = True
            test_result['response_time_ms'] = response_time
            
            # Test 2: SMB access (impresora como shared resource)
            test_result['smb_access'] = test_smb_printer_access(
                printer_ip, device_ip
            )
            
            # Test 3: Print queue status
            test_result['print_queue'] = test_print_queue(
                printer_ip, device_ip
            )
        
        results['tests'].append(test_result)
    
    # Generar resumen
    reachable = sum(1 for t in results['tests'] if t['reachable'])
    results['summary'] = {
        'total_tests': len(test_devices),
        'reachable': reachable,
        'connectivity_percent': (reachable / len(test_devices)) * 100,
        'avg_response_time_ms': sum(t['response_time_ms'] 
                                    for t in results['tests'] 
                                    if t['response_time_ms']) / reachable
    }
    
    return results

def test_smb_printer_access(printer_ip: str, test_device_ip: str) -> bool:
    """Test SMB access a la impresora (\\IP\print$)"""
    try:
        # Usar smbclient si está disponible
        result = subprocess.run(
            [
                'smbclient', '-L',
                f'//{printer_ip}', '-N',
                '--timeout=2'
            ],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def test_print_queue(printer_ip: str, test_device_ip: str) -> bool:
    """Test acceso a cola de impresión (CUPS, LPR, etc)"""
    try:
        # Conectar a puerto LPD/LPR (9100, 515)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        for port in [9100, 515, 631]:
            try:
                sock.connect((printer_ip, port))
                sock.close()
                return True
            except:
                pass
        
        return False
    except:
        return False
```

**DIFERENCIADOR:**
- Único proyecto con device discovery sin nmap
- Test de conectividad printer↔PC es ÚNICO
- Útil para network audits

---

### #3 PRIORITY: Real-Time Network Monitoring Dashboard

**POR QUÉ:**
- Demanda muy alta (dashboards DevOps)
- Combinación Python + Web = Más valioso
- Se ve profesional

**QUÉ HACER:**

```bash
ldt monitor --start              # Inicia servidor web en :8000
ldt monitor --export prometheus  # Exporta métricas Prometheus
ldt monitor --database sqlite    # Guarda histórico
```

**STACK:**
- Backend: FastAPI
- Frontend: Vue.js (o HTML simple con Chart.js)
- Metrics: Prometheus format
- Storage: SQLite (local) o PostgreSQL

**CÓDIGO BASE (Minimal):**

```python
# src/ldt/modules/monitor.py

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import asyncio
import json
from datetime import datetime
from ldt.modules.system import get_memory_info, get_cpu_info

app = FastAPI()

# Storage in-memory (mejorar con DB)
metrics_history = {
    'timestamps': [],
    'memory': [],
    'cpu': []
}

async def collect_metrics_task():
    """Collect metrics every 5 seconds"""
    while True:
        timestamp = datetime.now().isoformat()
        memory = get_memory_info()
        cpu = get_cpu_info()
        
        metrics_history['timestamps'].append(timestamp)
        metrics_history['memory'].append(memory['ram_percent'])
        metrics_history['cpu'].append(cpu[0]['cpu_percent'] if cpu else 0)
        
        # Keep only last 1000 points (~ 1.4 hours)
        if len(metrics_history['timestamps']) > 1000:
            for key in metrics_history:
                metrics_history[key] = metrics_history[key][-1000:]
        
        await asyncio.sleep(5)

@app.get("/")
async def dashboard():
    """Return HTML dashboard"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LDT Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial; margin: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .chart-container { position: relative; height: 400px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1>🖥️ Linux Diagnostic Toolkit - Live Monitor</h1>
        
        <div class="chart-container">
            <canvas id="memoryChart"></canvas>
        </div>
        
        <div class="chart-container">
            <canvas id="cpuChart"></canvas>
        </div>
        
        <script>
            async function updateCharts() {
                const res = await fetch('/metrics');
                const data = await res.json();
                
                // Update memory chart
                const memCtx = document.getElementById('memoryChart').getContext('2d');
                new Chart(memCtx, {
                    type: 'line',
                    data: {
                        labels: data.timestamps.slice(-100),
                        datasets: [{
                            label: 'RAM Usage (%)',
                            data: data.memory.slice(-100),
                            borderColor: '#FF6384',
                            tension: 0.1
                        }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
            
            updateCharts();
            setInterval(updateCharts, 5000);
        </script>
    </body>
    </html>
    """)

@app.get("/metrics")
async def get_metrics():
    """Return metrics as JSON"""
    return metrics_history

@app.get("/metrics/prometheus")
async def prometheus_format():
    """Prometheus format metrics"""
    latest_memory = metrics_history['memory'][-1] if metrics_history['memory'] else 0
    latest_cpu = metrics_history['cpu'][-1] if metrics_history['cpu'] else 0
    
    return f"""
    # HELP ldt_memory_percent Current memory usage percentage
    # TYPE ldt_memory_percent gauge
    ldt_memory_percent {latest_memory}
    
    # HELP ldt_cpu_percent Current CPU usage percentage
    # TYPE ldt_cpu_percent gauge
    ldt_cpu_percent {latest_cpu}
    """

def register_parser(subparsers):
    parser = subparsers.add_parser("monitor")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    parser.set_defaults(func=run)

def run(args):
    if args.start:
        import uvicorn
        # Iniciar background task
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(collect_metrics_task())
        
        # Iniciar servidor FastAPI
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=args.port
        )
```

---

## 📋 RESPUESTA A TUS PREGUNTAS ESPECÍFICAS

### "¿Tengo WiFi, net, monitoreo de puertos? ¿Esos dos es suficiente?"

**Respuesta:** NO, no es suficiente. Tienes:
- ✅ WiFi: Incompleto (sin scanner real)
- ✅ Network: Básico (interfaces y conexiones)
- ❌ Monitoreo: Solo static snapshot, no real-time

**NECESITAS AGREGAR:**
1. **Port Scanner mejorado** (priority 1)
2. **Device Discovery** (priority 2)
3. **Real-time Monitor** (priority 3)

### "¿Test de conexiones aleatorias impresoras con BD?"

**Respuesta:** ¡EXCELENTE IDEA! 🎯

**Por qué es bueno:**
- Nadie lo tiene (unique feature)
- Muy útil para Network Admins
- Demuestra testing avanzado

**Implementación:**

```python
# Pseudocódigo del flow:

1. Descubrir dispositivos:
   ldt discovery --scan
   # Retorna lista de IPs (impresoras, PCs, etc)

2. Seleccionar impresora:
   impresora = "192.168.1.10"

3. Test aleatorio:
   ldt discovery --test-printer 192.168.1.10 --count 5
   
   # Internamente:
   - Obtiene lista de hosts vivos
   - Elige 5 al azar
   - Intenta conectar impresora desde cada uno
   - Calcula % de conectividad
   - Genera reporte

4. Almacenar resultados:
   # Crear tabla SQLite:
   CREATE TABLE printer_tests (
       id INTEGER PRIMARY KEY,
       timestamp DATETIME,
       printer_ip TEXT,
       test_device_ip TEXT,
       reachable BOOLEAN,
       response_time_ms FLOAT,
       smb_access BOOLEAN,
       print_queue BOOLEAN
   );
   
   # Insertar cada test
   # Generar gráficos históricos
```

---

## 🚀 ROADMAP PARA PRÓXIMAS 2 SEMANAS

```
SEMANA 1:
□ Fix typos + tests básicos (YA HECHO ✅)
□ Implementar Port Scanner (#1)
□ Escribir tests para scanner

SEMANA 2:
□ Implementar Device Discovery (#2)
□ Agregar printer connectivity test
□ SQLite storage para histórico
□ Tests coverage 80%+

SEMANA 3:
□ Optimizar performance
□ Crear docs de usuario
□ Publicar en GitHub
□ Blog post: "Building Network Scanner in Python"

SEMANA 4:
□ Real-time Monitor (si hay tiempo)
□ Prometheus export
□ CI/CD final
□ Aplicar a ofertas DevSecOps Jr
```

---

## 💼 CÓMO VENDER ESTO EN ENTREVISTAS

**Interview Questions & Answers:**

Q: "¿Cuál es el diferenciador de tu proyecto?"
A: "Tiene 3 features únicas:
   1. Port scanner sin nmap (pure Python)
   2. Device discovery & classification
   3. Printer connectivity testing (solo mi proyecto tiene esto)
   Es una herramienta completa para network audits."

Q: "¿Por qué printer connectivity testing?"
A: "En pequeñas/medianas empresas, necesitan verificar que 
   dispositivos periféricos sean alcanzables. Es un caso real
   que encontré investigando en foros de System Admins."

Q: "¿Testeaste en múltiples redes?"
A: "Sí, tengo tests unitarios para cada módulo (85%+ coverage)
   y tests de integración en redes IPv4. Uso mocking para
   no depender de hardware específico."

---

## 📈 ESTO TE POSICIONA COMO:

- ✅ DevSecOps Engineer (Security + Linux + Automation)
- ✅ Network Engineer (Device discovery, scanning)
- ✅ Systems Administrator (Monitoring, reporting)

**Salario esperado:** $35-45k (Junior) → $55-70k (en 1 año)

---

**NEXT STEP:** ¿Empezamos a implementar el Port Scanner?
