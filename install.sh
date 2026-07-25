#!/bin/bash

echo "[+] Updating system..."

sudo apt update

echo "[+] Installing required tools..."

sudo apt install -y \
    python3 \
    python3-pip \
    poppler-utils \
    qpdf \
    exiftool \
    xpdf \
    binwalk

echo "[+] Installing pdf-parser..."

if ! command -v pdf-parser &> /dev/null
then
    sudo wget -O /usr/local/bin/pdf-parser \
    https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py

    sudo chmod +x /usr/local/bin/pdf-parser
fi

echo "[+] Installing Python requirements..."

pip3 install -r requirements.txt --break-system-packages

echo "[+] Making launcher executable..."

chmod +x pdfuncover

echo "[+] Installation completed."

sudo ln -sf $(pwd)/pdfuncover /usr/local/bin/pdfuncover