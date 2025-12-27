# Gateway Zero 2.0

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)

**Enterprise-Grade Reverse Proxy & Security Gateway** - Self-Hosted, Open Source, Production-Ready

Gateway Zero ist ein modernes, selbstgehostetes Security Gateway mit automatischem SSL, OAuth2-Integration, GeoIP-Blocking, Fail2Ban und vielen weiteren Enterprise-Features.

---

## ✨ Features

### 🔐 Sicherheit
- ✅ **Automatisches SSL/TLS** via Let's Encrypt (ACME)
- ✅ **CSRF-Protection** für alle Mutations-Operationen
- ✅ **Secure Cookies** (HttpOnly, Secure, SameSite)
- ✅ **OAuth2 Google-Integration** für Services
- ✅ **GeoIP-Blocking** (LAN, DE, EU, Weltweit)
- ✅ **Fail2Ban-Integration** mit konfigurierbaren Schwellwerten
- ✅ **Rate-Limiting** auf allen Endpoints
- ✅ **Input-Validation** (MAC, IP, Subdomain, Email)
- ✅ **Non-Root Execution** mit Systemd-Hardening
- ✅ **Session-Management** mit Persistenz

### 🚀 Performance & Zuverlässigkeit
- ✅ **Reverse Proxy** mit WebSocket-Support
- ✅ **Static File Hosting** für einfache Websites
- ✅ **Graceful Shutdown** mit Auto-Save
- ✅ **Persistent Sessions** (überleben Server-Neustarts)
- ✅ **Auto-Recovery** bei Fehlern
- ✅ **Resource Limits** via Systemd

### 🎯 Management
- ✅ **Modernes Web-Dashboard** (Tailwind CSS)
- ✅ **Live-Monitoring** (Requests, Bans, Uptime)
- ✅ **Network-Scanner** für Auto-Discovery
- ✅ **Wake-on-LAN** Support (Green Mode)
- ✅ **Maintenance-Modus** pro Service
- ✅ **Backup/Restore** Funktionalität
- ✅ **Guest-Tokens** (24h temporärer Zugang)
- ✅ **Multi-Subdomain Routing**

### 📊 Monitoring & Logs
- ✅ **Real-Time Logs** mit Filter
- ✅ **GeoIP-Visualisierung** auf Weltkarte
- ✅ **Traffic-Flow Darstellung**
- ✅ **Banned IPs Management**
- ✅ **Session-Übersicht**
- ✅ **System-Metriken** (Ping, Uptime, Requests)

---

## 🏗️ Architektur

```
Internet → Port 80/443 → Gateway Zero
                            ↓
            ┌───────────────┼───────────────┐
            ↓               ↓               ↓
    Security Layer  Routing Layer   Proxy Layer
    ├─ Blacklist    ├─ Subdomain    ├─ Reverse Proxy
    ├─ Fail2Ban     ├─ SSL/TLS      ├─ WebSockets
    ├─ GeoIP        ├─ OAuth        ├─ Static Files
    ├─ Rate Limit   └─ Guest Token  └─ Health Checks
    └─ CSRF
                            ↓
            ┌───────────────┼───────────────┐
            ↓               ↓               ↓
    homeassistant.   plex.domain.    website.
    domain.com:8123  com:32400       domain.com
```

---

## 📦 Installation

### Anforderungen
- **Ubuntu/Debian** Linux Server
- **Root-Zugriff** (für Installation)
- **Domain** mit konfigurierbaren DNS-Records
- **2 GB RAM** minimum
- **10 GB Disk Space** minimum

### Quick Install

```bash
# 1. Repository klonen
git clone https://github.com/your-username/Gateway-Zero.git
cd Gateway-Zero

# 2. Installation ausführen
sudo bash install.sh
```

Das Installationsskript führt automatisch aus:
1. System-Update und Paket-Installation
2. Go 1.22.1 Installation
3. Dedizierten Systembenutzer erstellen
4. Application Build
5. Systemd-Service mit Security Hardening
6. Firewall-Konfiguration (UFW)
7. Fail2Ban-Setup

### Nach der Installation

1. **Öffne Browser**: `http://YOUR-SERVER-IP`
2. **Setup durchführen**:
   - Domain eingeben (z.B. `gateway.example.com`)
   - Admin Email für SSL-Zertifikate
   - Admin-Benutzername und Passwort

3. **DNS konfigurieren**:
   ```
   A     gateway.example.com      → YOUR-SERVER-IP
   A     *.gateway.example.com    → YOUR-SERVER-IP
   ```

4. **Let's Encrypt** wird automatisch Zertifikate für alle Subdomains holen

---

## 🎮 Verwendung

### Service hinzufügen

1. **Dashboard öffnen** → "Dienst hinzufügen"
2. **Auto-Scan** nutzen oder manuell konfigurieren
3. **Verbindung konfigurieren**:
   - Name: `Home Assistant`
   - IP: `192.168.178.50`
   - Port: `8123`
   - Subdomain: `home`

4. **Security konfigurieren**:
   - Google Auth erzwingen (optional)
   - GeoIP: Nur DE/EU/LAN
   - Fail2Ban aktivieren

5. **Speichern** → Service ist sofort unter `https://home.gateway.example.com` erreichbar!

### Service-Optionen

#### Security-Features
- **Google OAuth**: Erzwingt Google-Login vor Zugriff
- **GeoIP-Blocking**:
  - `none`: Weltweit erreichbar
  - `lan`: Nur lokales Netzwerk
  - `de`: Nur Deutschland + LAN
  - `eu`: Nur EU-Länder + LAN
- **Fail2Ban**: Auto-Block bei zu vielen Fehlern
- **WebSockets**: Für Echtzeit-Anwendungen

#### Advanced Features
- **Wake-on-LAN**: Server bei Zugriff automatisch wecken
- **Maintenance-Modus**: Service temporär deaktivieren
- **Sleeping-Modus**: Green Computing
- **Guest-Token**: 24h temporäre Links generieren

### Statisches Hosting

1. **Dienst erstellen** → "Statische Seite" wählen
2. **.html oder .zip hochladen**
3. **Sofort online** unter `https://subdomain.domain.com`

Perfekt für:
- Landing Pages
- Dokumentationen
- Status-Seiten
- Static Site Generators (Hugo, Jekyll)

---

## ⚙️ Konfiguration

### System-Einstellungen

#### OAuth/Google
```
Client ID: Deine Google OAuth Client ID
Client Secret: Dein Google OAuth Secret
Redirect URI: https://auth.domain.com/callback
```

[Google Cloud Console](https://console.cloud.google.com/apis/credentials) → OAuth 2.0 Client erstellen

#### Firewall-Listen

**Whitelist** (CIDR-Format):
```
192.168.178.0/24    # Lokales Netzwerk
10.0.0.50/32        # Spezifische IP
```
→ Diese IPs umgehen Fail2Ban & GeoIP

**Blacklist** (CIDR-Format):
```
1.2.3.4/32          # Einzelne IP
5.6.7.0/24          # IP-Range
```
→ Diese IPs werden sofort geblockt

### Environment-Variablen

```bash
# Ports ändern (optional)
gateway-zero -port 8080 -https-port 8443
```

### Systemd-Service

```bash
# Status prüfen
systemctl status gateway-zero
gateway-zero-status

# Logs anzeigen
journalctl -u gateway-zero -f
gateway-zero-logs

# Service neustarten
systemctl restart gateway-zero

# Service stoppen
systemctl stop gateway-zero
```

---

## 🔧 Management

### Backup erstellen

1. **Dashboard** → "Backup"
2. **"Backup erstellen"** klicken
3. **Timestamp** wird angezeigt

Backup enthält:
- Alle Host-Konfigurationen
- System-Config
- Sessions
- Guest-Tokens
- Banned IPs

### Backup wiederherstellen

1. **Backup-Liste** öffnen
2. **Backup wählen** → "Restore"
3. **Bestätigen** → System lädt neu

### Banned IPs verwalten

1. **Dashboard** → "Banned IPs"
2. **Liste** aller gebannten IPs mit Fail-Count
3. **Einzeln entbannen** oder alle löschen

### Sessions verwalten

1. **Dashboard** → "Sessions"
2. **Aktive Sessions** anzeigen (IP, User, Created)
3. **Session beenden** (z.B. bei Kompromittierung)

---

## 📊 Monitoring

### System-Metriken

| Metrik | Beschreibung |
|--------|--------------|
| **Latenz** | Ping zu 1.1.1.1 (Cloudflare) |
| **Gebannt** | Anzahl gebannter IPs |
| **Services** | Aktive Dienste |
| **Requests** | Gesamt-Requests seit Start |
| **Uptime** | Server-Laufzeit |

### Live-Logs

- **Real-Time Updates** alle 2 Sekunden
- **Farbcodierung**:
  - 🟢 Grün: ALLOW, LOGIN
  - 🔴 Rot: BLOCKED, BANNED, 404
  - 🟡 Gelb: ERROR, LOGIN_FAIL

### GeoIP-Karte

- **Visualisierung** von Zugriffen weltweit
- **Grün**: Erlaubte Zugriffe
- **Rot**: Blockierte Zugriffe
- **Animation**: Pulsing-Effekt für Events

---

## 🔒 Sicherheit

### Implementierte Maßnahmen

#### Backend (server.go)
- ✅ Bcrypt-Hashing (Cost: 14) für Passwörter
- ✅ CSRF-Tokens mit constant-time Vergleich
- ✅ Input-Validation mit Regex
- ✅ Sanitization aller User-Inputs
- ✅ Rate-Limiting (100 req/min pro IP)
- ✅ Session-IP-Tracking
- ✅ Secure Cookies (HttpOnly, Secure, SameSite=Strict)
- ✅ ZipSlip-Protection beim Upload
- ✅ Graceful Shutdown mit Datensicherung

#### Systemd-Hardening
```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=false
```

#### Non-Root Execution
- Service läuft als dedizierter User `gatewayzero`
- Port-Binding via `CAP_NET_BIND_SERVICE` capability
- Minimale Dateisystem-Berechtigungen

#### Firewall
- UFW aktiviert (Default Deny)
- Nur Ports 22, 80, 443 offen
- Fail2Ban für SSH

---

## 🛠️ Entwicklung

### Projekt-Struktur

```
Gateway-Zero/
├── server.go              # Backend (Go)
├── static/
│   └── index.html         # Frontend (HTML/JS/Tailwind)
├── install.sh             # Installations-Script
├── README.md              # Diese Datei
├── CHANGELOG.md           # Versions-History
└── data/                  # Runtime-Daten (nach Installation)
    ├── hosts.json         # Service-Konfigurationen
    ├── config.json        # System-Config
    ├── sessions.json      # Aktive Sessions
    ├── tokens.json        # Guest-Tokens
    ├── banned.json        # Banned IPs
    ├── certs/             # SSL-Zertifikate
    ├── sites/             # Statische Websites
    └── backups/           # Backups
```

### Lokales Development

```bash
# Dependencies installieren
go mod download

# Development-Server starten (ohne TLS)
go run server.go -port 8080

# Build erstellen
go build -o gateway-zero server.go

# Mit Binary testen
./gateway-zero -port 8080
```

### API-Endpoints

| Endpoint | Method | Auth | Beschreibung |
|----------|--------|------|--------------|
| `/api/auth/status` | GET | - | System-Status |
| `/api/auth/setup` | POST | - | Erstes Setup |
| `/api/auth/login` | POST | - | Login |
| `/api/auth/logout` | POST | ✓ | Logout |
| `/api/config` | GET/POST | ✓ | Konfiguration |
| `/api/hosts` | GET/POST/DELETE | ✓ | Services |
| `/api/logs` | GET | ✓ | Access-Logs |
| `/api/stats` | GET | - | System-Stats |
| `/api/scan` | GET | ✓ | Netzwerk-Scan |
| `/api/banned` | GET/DELETE | ✓ | Banned IPs |
| `/api/sessions` | GET/DELETE | ✓ | Sessions |
| `/api/backup` | POST | ✓ | Backup erstellen |
| `/api/restore` | POST | ✓ | Backup wiederherstellen |

**Alle POST/PUT/DELETE Requests benötigen:**
- Session-Cookie `gz_session`
- CSRF-Token im Header `X-CSRF-Token`

---

## 📝 Changelog

Siehe [CHANGELOG.md](CHANGELOG.md) für detaillierte Versions-Historie.

**Latest: v2.0.0**
- Komplette Security-Überarbeitung
- CSRF-Protection
- Session-Persistenz
- GeoIP-Auto-Download
- Non-Root Execution
- Systemd-Hardening
- Backup/Restore
- Banned IPs Management

---

## 🤝 Contributing

Contributions sind willkommen! Bitte:

1. **Fork** das Repository
2. **Feature-Branch** erstellen (`git checkout -b feature/amazing`)
3. **Commit** deine Changes (`git commit -m 'Add amazing feature'`)
4. **Push** zum Branch (`git push origin feature/amazing`)
5. **Pull Request** öffnen

### Coding-Standards
- Go: `gofmt`, `golint`
- Frontend: ESLint-kompatibel
- Commits: Conventional Commits

---

## 📄 Lizenz

MIT License - siehe [LICENSE](LICENSE)

---

## 🙏 Credits

- **Let's Encrypt** für kostenloses SSL
- **Leaflet.js** für die Karte
- **Tailwind CSS** für das UI
- **Lucide Icons** für Icons
- **MaxMind/db-ip** für GeoIP-Daten

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/Gateway-Zero/issues)
- **Dokumentation**: Diese README
- **Security**: Bitte verantwortungsvoll melden

---

## ⚠️ Disclaimer

Gateway Zero ist ein Hobbyprojekt und wird "as-is" bereitgestellt. Für Production-Umgebungen empfehlen wir:
- Regelmäßige Backups
- Security-Audits
- Monitoring
- Redundante Setups

**Nicht empfohlen für:**
- High-Security Szenarien (Banken, Krankenhäuser)
- Mission-Critical Infrastruktur ohne Backup
- Ungetestete Deployments in Production

---

**Made with ❤️ for the Self-Hosting Community**

Gateway Zero - Your Gateway to Zero Compromises™
