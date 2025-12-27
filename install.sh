#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
APP_NAME="gateway-zero"
APP_USER="gatewayzero"
APP_DIR="/opt/gateway-zero"
SERVICE_NAME="gateway-zero"
VERSION="2.0.0"

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}    Gateway Zero Enterprise Installer v${VERSION}${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}✗ Dieser Installer muss als root ausgeführt werden${NC}"
   echo "  Bitte verwenden Sie: sudo bash install.sh"
   exit 1
fi

# Backup existing installation
if [ -d "$APP_DIR" ]; then
    echo -e "${YELLOW}⚠  Existierende Installation gefunden${NC}"
    echo -e "${BLUE}Möchten Sie:${NC}"
    echo "  1) Update (Daten behalten)"
    echo "  2) Neuinstallation (Daten löschen, frisches Setup)"
    read -p "Auswahl [1]: " INSTALL_TYPE
    INSTALL_TYPE=${INSTALL_TYPE:-1}

    BACKUP_DIR="${APP_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    echo -e "${BLUE}→ Erstelle Backup: $BACKUP_DIR${NC}"
    cp -r "$APP_DIR" "$BACKUP_DIR"

    # Stop service if running
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${BLUE}→ Stoppe laufenden Service${NC}"
        systemctl stop $SERVICE_NAME
    fi

    if [ "$INSTALL_TYPE" = "2" ]; then
        echo -e "${YELLOW}→ Lösche alte Daten für frisches Setup${NC}"
        rm -rf $APP_DIR/data/*.json
        echo -e "${GREEN}✓ Daten gelöscht. Setup-Wizard wird beim nächsten Start erscheinen.${NC}"
    fi
fi

# 1. System Update
echo -e "\n${GREEN}[1/7] System Update${NC}"
apt update && apt upgrade -y
apt install -y curl git tar nano wget ufw fail2ban

# 2. Go Installation
echo -e "\n${GREEN}[2/7] Go Installation${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${BLUE}→ Installiere Go 1.22.1${NC}"
    wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz

    # Add to PATH for all users
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi

    export PATH=$PATH:/usr/local/go/bin
    rm go1.22.1.linux-amd64.tar.gz
    echo -e "${GREEN}✓ Go installiert${NC}"
else
    echo -e "${GREEN}✓ Go bereits installiert: $(go version)${NC}"
fi

# 3. Create dedicated user
echo -e "\n${GREEN}[3/7] Benutzer & Verzeichnisse${NC}"
if ! id -u $APP_USER > /dev/null 2>&1; then
    echo -e "${BLUE}→ Erstelle Systembenutzer: $APP_USER${NC}"
    useradd --system --no-create-home --shell /bin/false $APP_USER
    echo -e "${GREEN}✓ Benutzer erstellt${NC}"
else
    echo -e "${GREEN}✓ Benutzer existiert bereits${NC}"
fi

# Create directory structure
echo -e "${BLUE}→ Erstelle Verzeichnisstruktur${NC}"
mkdir -p $APP_DIR/{static,data/{sites,certs,backups}}
chmod 750 $APP_DIR
chmod 700 $APP_DIR/data

# 4. Copy and Build Application
echo -e "\n${GREEN}[4/7] Application Build${NC}"
if [ -f "server.go" ]; then
    echo -e "${BLUE}→ Kopiere Dateien${NC}"
    cp server.go $APP_DIR/

    if [ -f "static/index.html" ]; then
        cp static/index.html $APP_DIR/static/
    elif [ -f "index.html" ]; then
        cp index.html $APP_DIR/static/
    fi
else
    echo -e "${RED}✗ server.go nicht gefunden!${NC}"
    exit 1
fi

cd $APP_DIR

# Initialize Go module
if [ ! -f "go.mod" ]; then
    echo -e "${BLUE}→ Initialisiere Go Modul${NC}"
    /usr/local/go/bin/go mod init gateway-zero
fi

# Download dependencies
echo -e "${BLUE}→ Lade Abhängigkeiten${NC}"
/usr/local/go/bin/go get golang.org/x/crypto/acme/autocert
/usr/local/go/bin/go get golang.org/x/crypto/bcrypt
/usr/local/go/bin/go get golang.org/x/oauth2
/usr/local/go/bin/go get golang.org/x/oauth2/google
/usr/local/go/bin/go get github.com/oschwald/geoip2-golang

/usr/local/go/bin/go mod tidy

# Build application
echo -e "${BLUE}→ Kompiliere Gateway Zero${NC}"
/usr/local/go/bin/go build -ldflags="-s -w" -o $APP_NAME server.go
echo -e "${GREEN}✓ Build erfolgreich${NC}"

# 5. Set Permissions
echo -e "\n${GREEN}[5/7] Berechtigungen${NC}"
chown -R $APP_USER:$APP_USER $APP_DIR
chmod 750 $APP_DIR/$APP_NAME
chmod 600 $APP_DIR/data/*.json 2>/dev/null || true

# Allow binding to privileged ports (80, 443)
echo -e "${BLUE}→ Setze Capability für Port-Binding${NC}"
setcap 'cap_net_bind_service=+ep' $APP_DIR/$APP_NAME

# Verify capability was set
if getcap $APP_DIR/$APP_NAME | grep -q cap_net_bind_service; then
    echo -e "${GREEN}✓ Capability erfolgreich gesetzt${NC}"
else
    echo -e "${YELLOW}⚠  Capability konnte nicht gesetzt werden. Verwende alternative Systemd-Methode.${NC}"
fi

# 6. Create Systemd Service with Hardening
echo -e "\n${GREEN}[6/7] Systemd Service${NC}"
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Gateway Zero Enterprise Security Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/$APP_NAME -port 80 -https-port 443
Restart=on-failure
RestartSec=5s

# Capabilities for binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
PrivateMounts=true

# Resource Limits
LimitNOFILE=65536
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Service erstellt mit Security Hardening${NC}"

# 7. Firewall Configuration
echo -e "\n${GREEN}[7/7] Firewall Konfiguration${NC}"
if command -v ufw &> /dev/null; then
    echo -e "${BLUE}→ Konfiguriere UFW${NC}"
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw reload
    echo -e "${GREEN}✓ Firewall konfiguriert${NC}"
fi

# Configure Fail2Ban
if [ -f "/etc/fail2ban/jail.local" ]; then
    echo -e "${BLUE}→ Fail2Ban bereits konfiguriert${NC}"
else
    echo -e "${BLUE}→ Konfiguriere Fail2Ban${NC}"
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
EOF
    systemctl restart fail2ban
    echo -e "${GREEN}✓ Fail2Ban konfiguriert${NC}"
fi

# Start Service
echo -e "\n${GREEN}Service wird gestartet...${NC}"
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# Wait for service to start
sleep 2

# Check status
if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Installation erfolgreich abgeschlossen!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo
    echo -e "${BLUE}Service Status:${NC}    $(systemctl is-active $SERVICE_NAME)"
    echo -e "${BLUE}Port HTTP:${NC}         80"
    echo -e "${BLUE}Port HTTPS:${NC}        443"
    echo
    echo -e "${YELLOW}⚠  Wichtige Informationen:${NC}"
    echo -e "   • Gateway läuft als dedizierter User: $APP_USER"
    echo -e "   • Konfiguration: $APP_DIR/data/"
    echo -e "   • Logs: journalctl -u $SERVICE_NAME -f"
    echo -e "   • Service: systemctl status $SERVICE_NAME"
    echo
    echo -e "${BLUE}Nächste Schritte:${NC}"
    echo -e "   1. Öffne http://$(hostname -I | awk '{print $1}') im Browser"
    echo -e "   2. Führe das Setup durch"
    echo -e "   3. Konfiguriere DNS-Records für deine Domain"
    echo
    echo -e "${GREEN}Gateway Zero ist bereit!${NC}"
    echo
else
    echo -e "\n${RED}✗ Service konnte nicht gestartet werden${NC}"
    echo -e "${YELLOW}Prüfe Logs mit: journalctl -u $SERVICE_NAME -n 50${NC}"
    exit 1
fi

# Create helpful aliases
echo -e "\n${BLUE}Erstelle nützliche Aliases...${NC}"
cat > /usr/local/bin/gateway-zero-logs <<EOF
#!/bin/bash
journalctl -u $SERVICE_NAME -f
EOF
chmod +x /usr/local/bin/gateway-zero-logs

cat > /usr/local/bin/gateway-zero-status <<EOF
#!/bin/bash
systemctl status $SERVICE_NAME
EOF
chmod +x /usr/local/bin/gateway-zero-status

echo -e "${GREEN}✓ Aliases erstellt: gateway-zero-logs, gateway-zero-status${NC}"
