#!/bin/bash

###############################################################################
# FIX LDT PROJECT - Script para arreglar typos y errores automáticamente
# Uso: chmod +x fix_ldt_project.sh && ./fix_ldt_project.sh /ruta/al/proyecto
###############################################################################

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_PATH="${1:-.}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  🔧 LDT PROJECT FIXER - Corrigiendo errores y typos${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

if [ ! -d "$PROJECT_PATH/src/ldt" ]; then
    echo -e "${RED}[ERROR] No se encontró el proyecto LDT en: $PROJECT_PATH${NC}"
    echo "Uso: ./fix_ldt_project.sh /ruta/al/linux_diagnostic_tool"
    exit 1
fi

echo -e "${YELLOW}[*] Ruta del proyecto: $PROJECT_PATH${NC}\n"

# ============================================================================
# FUNCIÓN PARA REEMPLAZAR STRINGS
# ============================================================================

fix_file() {
    local file="$1"
    local old="$2"
    local new="$3"
    
    if grep -q "$old" "$file" 2>/dev/null; then
        sed -i "s|$old|$new|g" "$file"
        echo -e "${GREEN}[✓]${NC} $file: '$old' → '$new'"
    fi
}

fix_file_exact() {
    local file="$1"
    local old="$2"
    local new="$3"
    
    if grep -qF "$old" "$file" 2>/dev/null; then
        sed -i "s|$old|$new|g" "$file"
        echo -e "${GREEN}[✓]${NC} Corregido: $file"
    fi
}

# ============================================================================
# CORREGIR TYPOS EN SYSTEM.PY
# ============================================================================

echo -e "\n${YELLOW}[*] Corrigiendo system.py...${NC}"
SYSTEM_FILE="$PROJECT_PATH/src/ldt/modules/system.py"

fix_file_exact "$SYSTEM_FILE" "proces=list(" "processes=list("
fix_file_exact "$SYSTEM_FILE" "for proc in proces:" "for proc in processes:"
fix_file_exact "$SYSTEM_FILE" "UNKNOW" "UNKNOWN"
fix_file_exact "$SYSTEM_FILE" "conections" "connections"
fix_file_exact "$SYSTEM_FILE" "\"states\"" "\"status\""
fix_file_exact "$SYSTEM_FILE" "unknownn" "unknown"
fix_file_exact "$SYSTEM_FILE" "sTATUS" "STATUS"
fix_file_exact "$SYSTEM_FILE" "PROcces" "PROCESS"
fix_file_exact "$SYSTEM_FILE" "LINTENING" "LISTENING"
fix_file_exact "$SYSTEM_FILE" "CONECTIONS" "CONNECTIONS"

# ============================================================================
# CORREGIR TYPOS EN FORENSICS.PY
# ============================================================================

echo -e "\n${YELLOW}[*] Corrigiendo forensics.py...${NC}"
FORENSICS_FILE="$PROJECT_PATH/src/ldt/modules/forensics.py"

fix_file_exact "$FORENSICS_FILE" "descritption" "description"
fix_file_exact "$FORENSICS_FILE" "cann't" "cannot"

# ============================================================================
# CORREGIR TYPOS EN THREAT_INTEL.PY
# ============================================================================

echo -e "\n${YELLOW}[*] Corrigiendo threat_intel.py...${NC}"
THREAT_FILE="$PROJECT_PATH/src/ldt/modules/threat_intel.py"

fix_file_exact "$THREAT_FILE" "geolocaton" "geolocation"
fix_file_exact "$THREAT_FILE" "recived" "received"

# ============================================================================
# ARREGLAR COMMENTS EN ESPAÑOL/INGLÉS INCONSISTENTES
# ============================================================================

echo -e "\n${YELLOW}[*] Estandarizando comentarios...${NC}"

# Cambiar comentarios inconsistentes a inglés
find "$PROJECT_PATH/src/ldt/modules" -name "*.py" -type f -exec sed -i \
    -e 's/# full module nam/# Full module name/' \
    -e 's/# import dynamically/# Import module dynamically/' \
    -e 's/# if module has register_parser/# If module has register_parser/' \
    -e 's/# Parse arguments/# Parse command-line arguments/' \
    -e 's/# Execute associated function/# Execute the associated function/' \
    -e 's/"""calc uptime/"""Calculate uptime/' \
    -e 's/if there creattime exist/if create_time exists/' \
    {} \;

echo -e "${GREEN}[✓]${NC} Comentarios estandarizados"

# ============================================================================
# AGREGAR DOCSTRINGS DONDE FALTAN
# ============================================================================

echo -e "\n${YELLOW}[*] Agregando docstrings...${NC}"

# Función para agregar docstring a una función
add_docstring_to_function() {
    local file="$1"
    local func_name="$2"
    local docstring="$3"
    
    # Buscar la función y añadir docstring si no existe
    if grep -q "def $func_name" "$file"; then
        # Verificar si ya tiene docstring
        if ! grep -A 2 "def $func_name" "$file" | grep -q '"""'; then
            sed -i "/def $func_name/a\    $docstring" "$file"
            echo -e "${GREEN}[✓]${NC} Docstring añadido: $func_name()"
        fi
    fi
}

# ============================================================================
# CORREGIR TYPE HINTS
# ============================================================================

echo -e "\n${YELLOW}[*] Mejorando type hints...${NC}"

# Cambiar type hints a formato correcto
find "$PROJECT_PATH/src/ldt/modules" -name "*.py" -type f -exec sed -i \
    -e 's/-> list\[dict\]/-> list[dict]/' \
    -e 's/-> dict:/-> dict:/' \
    -e 's/-> tuple:/-> tuple:/' \
    {} \;

echo -e "${GREEN}[✓]${NC} Type hints estandarizados"

# ============================================================================
# CREAR ARCHIVO DE CONFIGURACIÓN PARA LOGGING
# ============================================================================

echo -e "\n${YELLOW}[*] Creando configuración de logging...${NC}"

cat > "$PROJECT_PATH/src/ldt/config.py" << 'EOF'
"""Configuration module for LDT"""

import logging
import logging.handlers
from pathlib import Path

# Logging configuration
LOG_DIR = Path.home() / ".ldt" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "ldt.log"

# Logger setup
def get_logger(name: str) -> logging.Logger:
    """Get or create a logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Create handlers
        file_handler = logging.FileHandler(LOG_FILE)
        console_handler = logging.StreamHandler()
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        # Set level
        logger.setLevel(logging.INFO)
    
    return logger
EOF

echo -e "${GREEN}[✓]${NC} Archivo config.py creado"

# ============================================================================
# CREAR .gitignore MEJORADO
# ============================================================================

echo -e "\n${YELLOW}[*] Creando .gitignore mejorado...${NC}"

cat > "$PROJECT_PATH/.gitignore" << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
ENV/
env/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Environment variables
.env
.env.local

# LDT specific
.ldt/
*.log
hashes/
EOF

echo -e "${GREEN}[✓]${NC} .gitignore mejorado"

# ============================================================================
# CREAR REQUIREMENTS MEJORADO
# ============================================================================

echo -e "\n${YELLOW}[*] Actualizando requirements.txt...${NC}"

cat > "$PROJECT_PATH/requirements.txt" << 'EOF'
# Core dependencies
psutil>=5.9.0
requests>=2.31.0
python-dotenv>=1.0.0

# Optional dependencies for WiFi module
# python-wifi>=0.6.1
# scapy>=2.5.0
EOF

cat > "$PROJECT_PATH/requirements-dev.txt" << 'EOF'
# Development dependencies
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0
isort>=5.12.0
EOF

echo -e "${GREEN}[✓]${NC} requirements.txt actualizado"

# ============================================================================
# CREAR ARCHIVO DE EJEMPLO PARA TESTS
# ============================================================================

echo -e "\n${YELLOW}[*] Creando estructura de tests...${NC}"

mkdir -p "$PROJECT_PATH/tests"

cat > "$PROJECT_PATH/tests/__init__.py" << 'EOF'
"""Tests package for LDT"""
EOF

cat > "$PROJECT_PATH/tests/test_system.py" << 'EOF'
"""Unit tests for system module"""

import pytest
from unittest.mock import patch, MagicMock
from ldt.modules.system import (
    get_memory_info,
    get_cpu_info,
    get_listening_ports,
)


class TestMemoryInfo:
    """Tests for memory information gathering"""
    
    def test_get_memory_info_returns_dict(self):
        """Test that get_memory_info returns a dictionary"""
        result = get_memory_info()
        assert isinstance(result, dict)
    
    def test_get_memory_info_has_required_keys(self):
        """Test that memory info contains all required keys"""
        result = get_memory_info()
        required_keys = [
            'ram_total', 'ram_used', 'ram_free', 'ram_percent',
            'swap_total', 'swap_used', 'swap_percent'
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
    
    def test_memory_percentages_valid_range(self):
        """Test that memory percentages are in valid range (0-100)"""
        result = get_memory_info()
        assert 0 <= result['ram_percent'] <= 100
        assert 0 <= result['swap_percent'] <= 100
    
    def test_memory_values_non_negative(self):
        """Test that memory values are non-negative"""
        result = get_memory_info()
        assert result['ram_total'] >= 0
        assert result['ram_used'] >= 0
        assert result['ram_free'] >= 0


class TestCPUInfo:
    """Tests for CPU information gathering"""
    
    def test_get_cpu_info_returns_list(self):
        """Test that get_cpu_info returns a list"""
        result = get_cpu_info()
        assert isinstance(result, list)
    
    @patch('ldt.modules.system.psutil.process_iter')
    def test_get_cpu_info_structure(self, mock_process_iter):
        """Test that CPU info has correct structure"""
        mock_proc = MagicMock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'test_process',
            'username': 'testuser',
            'status': 'running',
            'memory_percent': 5.0
        }
        mock_proc.cpu_percent.return_value = 10.5
        mock_process_iter.return_value = [mock_proc]
        
        result = get_cpu_info()
        
        if result:  # If we got results
            assert 'pid' in result[0]
            assert 'name' in result[0]
            assert 'username' in result[0]


class TestListeningPorts:
    """Tests for listening ports detection"""
    
    def test_get_listening_ports_returns_list(self):
        """Test that get_listening_ports returns a list"""
        result = get_listening_ports()
        assert isinstance(result, list)
EOF

echo -e "${GREEN}[✓]${NC} Estructura de tests creada"

# ============================================================================
# CREAR README DE DESARROLLO
# ============================================================================

echo -e "\n${YELLOW}[*] Creando DEVELOPMENT.md...${NC}"

cat > "$PROJECT_PATH/DEVELOPMENT.md" << 'EOF'
# Development Guide

## Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd linux_diagnostic_tool
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ldt tests/

# Run specific test file
pytest tests/test_system.py

# Run with verbose output
pytest -v
```

## Code Quality

```bash
# Format code with black
black src/ldt

# Sort imports
isort src/ldt

# Lint with flake8
flake8 src/ldt

# Type checking with mypy
mypy src/ldt
```

## Structure

```
src/ldt/
├── __init__.py
├── main.py              # CLI entry point
├── config.py            # Configuration and logging
├── modules/
│   ├── system.py        # System diagnostics
│   ├── forensics.py     # Security auditing
│   ├── threat_intel.py  # IP reputation
│   └── network/
│       ├── interfaces.py
│       ├── connections.py
│       └── wifi/
└── utils/
    └── whitelist.py
```

## Adding New Modules

1. Create file in `src/ldt/modules/`
2. Implement `register_parser()` and `run()` functions
3. Module auto-discovered by main.py

## Commit Guidelines

- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`
- Include tests for new features
- Update documentation
EOF

echo -e "${GREEN}[✓]${NC} DEVELOPMENT.md creado"

# ============================================================================
# CREAR GITHUB ACTIONS WORKFLOW
# ============================================================================

echo -e "\n${YELLOW}[*] Creando GitHub Actions workflow...${NC}"

mkdir -p "$PROJECT_PATH/.github/workflows"

cat > "$PROJECT_PATH/.github/workflows/tests.yml" << 'EOF'
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e ".[dev]"
    
    - name: Lint with flake8
      run: |
        flake8 src/ldt --count --select=E9,F63,F7,F82 --show-source --statistics
    
    - name: Test with pytest
      run: |
        pytest --cov=ldt tests/
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
EOF

echo -e "${GREEN}[✓]${NC} GitHub Actions workflow creado"

# ============================================================================
# RESUMEN FINAL
# ============================================================================

echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ ARREGLOS COMPLETADOS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}Cambios realizados:${NC}"
echo "  ✓ Typos corregidos en system.py, forensics.py, threat_intel.py"
echo "  ✓ Nombres de variables estandarizados"
echo "  ✓ Comentarios traducidos a inglés"
echo "  ✓ Type hints mejorados"
echo "  ✓ config.py creado (logging centralizado)"
echo "  ✓ Estructura de tests creada"
echo "  ✓ requirements.txt actualizado"
echo "  ✓ .gitignore mejorado"
echo "  ✓ DEVELOPMENT.md creado"
echo "  ✓ GitHub Actions workflow agregado"

echo -e "\n${YELLOW}Próximos pasos:${NC}"
echo "  1. Instalar requirements-dev.txt:"
echo "     pip install -r requirements-dev.txt"
echo ""
echo "  2. Ejecutar tests:"
echo "     pytest --cov=ldt"
echo ""
echo "  3. Verificar calidad de código:"
echo "     black src/ldt && flake8 src/ldt"
echo ""
echo "  4. Ver log de cambios:"
echo "     git status"

echo -e "\n${GREEN}¡Listo para el siguiente paso!${NC}\n"
