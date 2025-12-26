#!/bin/bash
set -e
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}=== Gateway Zero Enterprise Installer (Final) ===${NC}"

# Cleanup
if [ -f "/opt/gateway-zero/data/config.json" ]; then rm -f /opt/gateway-zero/data/config.json; fi
if [ -f "/opt/gateway-zero/data/hosts.json" ]; then rm -f /opt/gateway-zero/data/hosts.json; fi
if systemctl is-active --quiet gateway-zero; then systemctl stop gateway-zero; fi

# 1. System
apt update && apt upgrade -y
apt install -y curl git tar nano

# 2. Go
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" ~/.bashrc; then echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc; fi
    rm go1.22.1.linux-amd64.tar.gz
fi

# 3. Struktur
mkdir -p /opt/gateway-zero/static
mkdir -p /opt/gateway-zero/data/sites
mkdir -p /opt/gateway-zero/data/certs

# 4. Copy Code
if [ -f "server.go" ]; then cp server.go /opt/gateway-zero/; fi
if [ -f "index.html" ]; then cp index.html /opt/gateway-zero/static/; fi

# 5. Build
echo -e "${GREEN}Lade Abhängigkeiten (ACME, OAuth, GeoIP)...${NC}"
cd /opt/gateway-zero
if [ ! -f "go.mod" ]; then /usr/local/go/bin/go mod init gateway-zero; fi

/usr/local/go/bin/go get golang.org/x/crypto/acme/autocert
/usr/local/go/bin/go get golang.org/x/crypto/bcrypt
/usr/local/go/bin/go get golang.org/x/oauth2
/usr/local/go/bin/go get golang.org/x/oauth2/google
/usr/local/go/bin/go get github.com/oschwald/geoip2-golang

/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -o gateway-zero server.go

# 6. GeoIP DB (Optional: Hier könnte man einen Download einbauen, wenn Lizenz vorhanden)
# Für den Start erstellen wir eine leere Datei, damit der Code nicht crasht
touch /opt/gateway-zero/data/geoip.mmdb

# 7. Service
cat <<EOF > /etc/systemd/system/gateway-zero.service
[Unit]
Description=Gateway Zero Enterprise
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gateway-zero
ExecStart=/opt/gateway-zero/gateway-zero -port 80
Restart=on-failure
ReadWritePaths=/opt/gateway-zero/data

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gateway-zero
systemctl restart gateway-zero

echo -e "${GREEN}Fertig! Alles installiert.${NC}"