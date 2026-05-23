## 🏗️ ARCHITECTURE.md - Documentación Técnica

# Linux Diagnostic Toolkit - Documentación de Arquitectura

## 📐 Estructura General

```
linux_diagnostic_tool/
├── src/ldt/
│   ├── __init__.py                    # Package initialization
│   ├── main.py                        # CLI entry point with module discovery
│   ├── config.py                      # Logging and configuration
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── system.py                  # CPU, Memory, Ports, Logins
│   │   ├── forensics.py               # SUID, Cron, Bashrc, SSH Keys
│   │   ├── threat_intel.py            # IP Reputation, TOR Detection, ISP Info
│   │   ├── scanner.py                 # Port scanning
│   │   └── network/
│   │       ├── __init__.py
│   │       ├── interfaces.py          # Network interface enumeration
│   │       ├── connections.py         # Active connection monitoring
│   │       └── wifi/
│   │           ├── __init__.py
│   │           └── scanner.py         # WiFi network scanning
│   └── utils/
│       ├── __init__.py
│       └── whitelist.py               # SUID whitelist and suspicious paths
├── tests/
│   ├── __init__.py
│   ├── test_system.py                 # System module tests (35+ tests)
│   ├── test_forensics.py              # Forensics module tests (20+ tests)
│   ├── test_network.py                # Network module tests
│   └── conftest.py                    # Pytest configuration
├── .github/workflows/
│   └── tests.yml                      # GitHub Actions CI/CD
├── docs/
│   ├── API.md                         # API reference
│   ├── MODULES.md                     # Module documentation
│   └── EXAMPLES.md                    # Usage examples
├── requirements.txt                   # Production dependencies
├── requirements-dev.txt               # Development dependencies
├── pyproject.toml                     # Package configuration
├── setup.sh                           # Installation script
├── DEVELOPMENT.md                     # Development guide
└── README.md                          # User guide
```

## 🔄 Flujo de Ejecución

```
┌─────────────────┐
│  ldt CLI Call   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  main.py (Entry Point)      │
│  - Parse arguments          │
│  - Discover modules         │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Module Auto-Discovery      │
│  - scan ldt.modules/        │
│  - load register_parser()   │
│  - build subcommands        │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  Execute Module run()       │
│  - Gather system data       │
│  - Format output            │
│  - Display results          │
└─────────────────────────────┘
```

## 📦 Módulos Principales

### 1. System Module (system.py)

**Responsabilidad:** Monitoreo de recursos del sistema

**Funciones:**
- `get_running_processes()` → list[dict]
  - Obtiene todos los procesos en ejecución
  - Incluye: PID, nombre, usuario, línea de comando, tiempo de inicio
  - Calcula uptime automáticamente

- `get_cpu_info()` → list[dict]
  - CPU usage por proceso (top 10)
  - Retorna: PID, nombre, usuario, estado, CPU%, MEM%

- `get_memory_info()` → dict
  - Información de RAM y SWAP
  - Retorna: total, usado, libre, porcentaje de cada uno

- `get_listening_ports()` → list[dict]
  - Puertos en LISTEN
  - Retorna: proceso, IP, puerto, estado

- `get_failed_logins()` → list[dict]
  - Intentos fallidos de SSH
  - Retorna: timestamp, usuario, IP remota, puerto

**Dependencias:**
- `psutil`: Información de procesos y sistema
- `subprocess`: Ejecutar journalctl para logs SSH
- `re`: Parsing de logs

**Performance:**
- `get_memory_info()`: < 100ms
- `get_running_processes()`: < 2s
- `get_cpu_info()`: < 2s (incluye sleep de 0.5s)

### 2. Forensics Module (forensics.py)

**Responsabilidad:** Auditoría de seguridad y detección de compromisos

**Funciones:**
- `sha256_file(path)` → str
  - Calcula hash SHA256 de archivo
  - Procesa en chunks de 4KB (eficiente para archivos grandes)

- `classify_suid(binary_path)` → tuple(bool, str, float, str)
  - Clasifica binarios SUID como legítimos o sospechosos
  - Retorna: (es_sospechoso, severidad, puntuación, razón)
  - Severidad: INFO, LOW, MEDIUM, HIGH, CRITICAL

- Más funciones disponibles (cron, bashrc, SSH keys)

**Mappeos MITRE ATT&CK:**
- SUID: T1548.001 - Setuid and Setgid
- Cron: T1053.003 - Cron
- Bashrc: T1546.004 - Unix Shell Config Modification
- SSH Keys: T1098.004 - SSH Authorized Keys

**Dependencias:**
- `subprocess`: Escaneo de archivos
- `hashlib`: Cálculo de hashes
- `pwd`: Información de usuarios
- `logging`: Registro de eventos

### 3. Threat Intelligence Module (threat_intel.py)

**Responsabilidad:** Consultas de reputación de IP

**Funciones:**
- `check_ip_reputation(ip)` → dict
  - Consulta AbuseIPDB
  - Retorna: score, reportes, país, TOR status, ISP

- `detect_tor_exit_node(ip)` → bool
  - Verifica si IP es nodo de salida TOR

- `get_isp_info(ip)` → dict
  - Información de ISP y geolocalización

**Dependencias:**
- `requests`: HTTP requests a APIs
- `python-dotenv`: Carga de ABUSEIPDB_API_KEY

**Notas:**
- Requiere API key de AbuseIPDB (gratuita)
- Limitado a ~15,000 consultas/mes en plan free

### 4. Network Module (network/)

**Responsabilidad:** Análisis de red

#### interfaces.py
- Lista interfaces de red
- Obtiene IP, MAC, estado

#### connections.py
- Monitorea conexiones activas
- TCP/UDP, estados, procesos asociados
- Detecta conexiones a IPs públicas

#### wifi/scanner.py
- Escaneo de redes WiFi (próximo)
- Análisis de seguridad de redes inalámbricas

## 🧪 Estrategia de Testing

### Coverage Target: 85%+

```
┌─────────────────────────────────┐
│  Unit Tests (70% del código)    │
│  - test_system.py: 35+ tests    │
│  - test_forensics.py: 20+ tests │
│  - test_network.py: 15+ tests   │
└─────────────────────────────────┘
        ▼
┌─────────────────────────────────┐
│  Integration Tests (10%)        │
│  - Flujo completo de módulos    │
│  - Interacción entre componentes│
└─────────────────────────────────┘
        ▼
┌─────────────────────────────────┐
│  E2E Tests (5%)                 │
│  - CLI commands                 │
│  - Output formatting            │
└─────────────────────────────────┘
```

### Ejecutar Tests

```bash
# Todos los tests
pytest

# Con cobertura
pytest --cov=ldt tests/

# Tests específicos
pytest tests/test_system.py::TestMemoryInfo

# Verbose
pytest -v

# Con timeout
pytest --timeout=10
```

## 🔌 Patrón de Módulos

Cada módulo debe implementar:

```python
def register_parser(subparsers):
    """Registrar argumentos CLI"""
    parser = subparsers.add_parser("mymodule")
    parser.add_argument("--option", help="...")
    parser.set_defaults(func=run)

def run(args):
    """Ejecutar lógica del módulo"""
    data = get_data(args)
    display_data(data)
```

**Ventaja:** Auto-discovery automático, fácil extensión.

## 📊 Diagrama de Dependencias

```
system.py
├── psutil
├── subprocess
├── re
└── time

forensics.py
├── subprocess
├── hashlib
├── pwd
├── logging
└── utils.whitelist

threat_intel.py
├── requests
├── python-dotenv
└── subprocess

network/
├── psutil
├── socket
└── subprocess

wifi/
├── scapy (future)
├── python-wifi (future)
└── subprocess
```

## 🚀 Próximos Módulos

### Priority 1: Network Monitoring Dashboard
```
features/
├── Real-time monitoring
├── Prometheus metrics export
├── FastAPI web dashboard
└── Database (SQLite) for history
```

### Priority 2: Advanced Forensics
```
features/
├── Malware detection (hash lookups)
├── Log analysis (YARA rules)
├── Registry analysis (Windows)
└── Memory analysis
```

### Priority 3: Automated Reporting
```
features/
├── JSON export
├── HTML reports
├── PDF generation
└── SIEM integration
```

## 🔐 Consideraciones de Seguridad

1. **Privilegios Requeridos:**
   - Root/sudo para: SUID scan, SSH logs, network connections
   - Regular user: CPU, Memory, Network interfaces

2. **Manejo de Credenciales:**
   - API keys en `.env` (nunca en git)
   - No loguear información sensible

3. **Validación de Entrada:**
   - Sanitizar comandos subprocess
   - Validar rutas de archivo

4. **Rate Limiting:**
   - AbuseIPDB: 15,000 req/mes (plan free)
   - Implementar caché para IPs

## 📈 Performance Targets

| Función | Target | Actual |
|---------|--------|--------|
| get_memory_info | < 100ms | ~50ms |
| get_running_processes | < 5s | ~2-3s |
| get_cpu_info | < 5s | ~2s |
| get_listening_ports | < 2s | ~1s |
| get_failed_logins | < 3s | ~1-2s |
| forensics scan | < 10s | ~5-8s |

## 🔄 Logging Architecture

```python
# config.py proporciona:
- Logs a archivo: ~/.ldt/logs/ldt.log
- Logs a consola: stdout
- Formato: timestamp, nivel, mensaje
- Niveles: DEBUG, INFO, WARNING, ERROR
```

## 📚 Referencias

- **MITRE ATT&CK:** https://attack.mitre.org/
- **psutil docs:** https://psutil.readthedocs.io/
- **AbuseIPDB API:** https://www.abuseipdb.com/api
- **Linux Forensics:** https://linux-audit.com/

---

**Última actualización:** Mayo 2026
**Versión:** 0.2.0
**Maintainer:** @Emiranda1302
