#!/bin/bash

set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating virtual environment..."
source venv/bin/activate

echo "[*] Upgrading pip..."
pip install --upgrade pip

echo "[*] Installing dependencies..."
pip install -r requirements.txt

echo "[*] Installing project..."
pip install -e .

if [ ! -f .env ]; then
echo "[*] Creating .env from template..."
cp .env.example .env
fi

echo "[+] Setup complete."
