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
