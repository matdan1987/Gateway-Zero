# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt hält sich an [Semantic Versioning](https://semver.org/lang/de/).

## [2.0.0] - 2024-12-26

### 🚀 Major Release - Komplette Überarbeitung

Diese Version ist ein komplettes Rewrite mit Fokus auf Security, Stabilität und Production-Readiness.

### Added
- **CSRF-Protection**: Alle Mutations-Operationen sind gegen CSRF-Attacken geschützt
- **Session-Persistenz**: Sessions überleben Server-Neustarts
- **GeoIP Auto-Download**: Automatischer Download der GeoIP-Datenbank beim ersten Start
- **Input Validation**: Regex-basierte Validierung für MAC, IP, Subdomain, Email
- **Rate-Limiting**: 100 Requests/Minute pro IP, 5 Login-Attempts/5min
- **Backup/Restore System**: Vollständige Datensicherung über Web-UI
- **Banned IPs Management**: Liste aller gebannten IPs mit Unban-Funktion
- **Session Management**: Übersicht aktiver Sessions mit Revoke-Funktion
- **Non-Root Execution**: Service läuft als dedizierter User `gatewayzero`
- **Systemd Hardening**: Umfangreiche Security-Policies im Systemd-Service
- **Graceful Shutdown**: Automatisches Speichern aller Daten beim Shutdown
- **Auto-Save Routine**: Periodisches Speichern alle 5 Minuten
- **Session Cleanup**: Automatisches Löschen abgelaufener Sessions
- **HTTPS Redirect**: HTTP Port 80 leitet automatisch auf HTTPS um
- **Improved Logging**: Strukturiertes Logging mit Systemd-Journal
- **Health Checks**: Erweiterte System-Metriken (Uptime, Total Requests)
- **ZipSlip Protection**: Sichere Behandlung von Zip-Uploads
- **Firewall Setup**: Automatische UFW-Konfiguration im Installer
- **Fail2Ban Integration**: SSH-Protection out-of-the-box

### Changed
- **Cookies**: `Secure: true` (nur HTTPS), `SameSite: Strict` statt Lax
- **Password Hashing**: Bcrypt-Cost auf 14 erhöht
- **Log Limit**: Von 100 auf 500 Einträge erweitert
- **EU Country List**: Auf alle 27 EU-Länder erweitert
- **Token Length**: Guest-Tokens von 8 auf 16 Zeichen
- **Config Permissions**: `config.json` auf 0600 (nur Owner lesbar)
- **Session Duration**: Konfigurierbar (Default: 7 Tage)
- **Network Scanner**: Concurrency von 100 auf 50 reduziert (weniger Last)
- **Error Messages**: Keine Stack-Traces mehr an Frontend (Security)
- **HTTP Port Handling**: Saubere ACME-Challenge-Behandlung

### Security
- **CRITICAL FIX**: Session-Cookies jetzt nur über HTTPS (`Secure: true`)
- **CRITICAL FIX**: CSRF-Validation für alle POST/PUT/DELETE Requests
- **HIGH FIX**: Input-Sanitization gegen XSS
- **HIGH FIX**: MAC-Validation vor WOL-Broadcast
- **HIGH FIX**: IP-Validation vor Speicherung
- **MEDIUM FIX**: Login Rate-Limiting (Brute-Force Protection)
- **MEDIUM FIX**: Session IP-Tracking (Session-Hijacking Detection)
- **MEDIUM FIX**: Constant-Time CSRF-Vergleich (Timing-Attack Prevention)
- **LOW FIX**: Error-Message Sanitization

### Fixed
- **Race Condition**: Hosts-Lock wird jetzt konsistent verwendet
- **Memory Leak**: Sessions wurden nicht aus dem Speicher entfernt
- **Memory Leak**: Rate-Limiter räumt alte Einträge auf
- **GeoIP Fallback**: System funktioniert auch ohne GeoIP-Datenbank
- **Port Binding**: Capabilities statt Root für Ports 80/443
- **File Permissions**: Korrekte Owner-Permissions nach Installation
- **Service Restart**: Backup vor Update-Installation
- **SSL HostPolicy**: Neue Hosts werden sofort für SSL akzeptiert

### Removed
- **Root Execution**: Service läuft nicht mehr als Root
- **Setup Reset**: Setup kann nicht mehr überschrieben werden (Security)
- **Dummy GeoIP**: Leere Datei wird durch echten Download ersetzt

### Infrastructure
- **Systemd Service**:
  - `NoNewPrivileges=true`
  - `PrivateTmp=true`
  - `ProtectSystem=strict`
  - `ProtectHome=true`
  - `ReadWritePaths` nur für `/opt/gateway-zero/data`
  - `RestrictAddressFamilies` auf AF_UNIX, AF_INET, AF_INET6
  - `LimitNOFILE=65536` (mehr File-Handles)

- **Installer Improvements**:
  - Backup vor Update
  - Farbiges Output
  - Progress-Anzeige
  - UFW-Setup
  - Fail2Ban-Setup
  - Helper-Scripts (`gateway-zero-logs`, `gateway-zero-status`)

### Breaking Changes
⚠️ **ACHTUNG**: Diese Version ist NICHT kompatibel mit v1.x!

- Session-Format geändert (alte Sessions werden ungültig)
- Config-Format erweitert (Migration automatisch)
- API-Endpoints benötigen jetzt CSRF-Token
- Cookies funktionieren nur noch über HTTPS
- Service läuft unter anderem User (Permissions!)

**Migrations-Pfad**:
1. Backup erstellen: `cp -r /opt/gateway-zero/data ~/gateway-zero-backup`
2. Service stoppen: `systemctl stop gateway-zero`
3. Installation ausführen: `sudo bash install.sh`
4. Alte Daten werden automatisch übernommen
5. Im Browser neu einloggen (alte Sessions ungültig)

---

## [1.0.0] - 2024-12-25

### Initial Release

- Basis Reverse-Proxy Funktionalität
- Let's Encrypt SSL via ACME
- OAuth2 Google-Integration
- GeoIP-Blocking (Basic)
- Fail2Ban-Integration
- Web-Dashboard
- Network-Scanner
- Wake-on-LAN Support
- Static File Hosting
- Live-Logging
- Basic Rate-Limiting

### Known Issues (v1.0)
- ⚠️ Service läuft als Root (Security-Risk)
- ⚠️ Cookies ohne Secure-Flag (kann über HTTP gesendet werden)
- ⚠️ Keine CSRF-Protection
- ⚠️ Sessions nicht persistent
- ⚠️ GeoIP-Datenbank muss manuell geladen werden
- ⚠️ Keine Input-Validation

**Diese Issues sind in v2.0.0 behoben!**

---

## Versionierungs-Schema

### Major (X.0.0)
- Breaking Changes
- Architektur-Änderungen
- Neue Haupt-Features

### Minor (0.X.0)
- Neue Features (rückwärts-kompatibel)
- Größere Verbesserungen
- API-Erweiterungen

### Patch (0.0.X)
- Bugfixes
- Security-Patches
- Kleinere Verbesserungen

---

## Geplante Features (Roadmap)

### v2.1.0 (Q1 2025)
- [ ] Multi-User Support (verschiedene Admin-Level)
- [ ] 2FA / TOTP-Support
- [ ] Telegram/Discord Notifications
- [ ] Prometheus-Exporter
- [ ] Grafana-Dashboard
- [ ] HTTP/3 Support
- [ ] Custom Error Pages
- [ ] IP Whitelisting per Service

### v2.2.0 (Q2 2025)
- [ ] Container-Support (Docker/Podman)
- [ ] Kubernetes-Deployment
- [ ] HA-Setup (High-Availability)
- [ ] Load-Balancing zwischen mehreren Backends
- [ ] Health-Checks mit Auto-Failover
- [ ] Request-Caching
- [ ] CDN-Integration

### v3.0.0 (Q3 2025)
- [ ] Web-UI Redesign (React/Vue)
- [ ] API v2 (GraphQL)
- [ ] Plugin-System
- [ ] Marketplace für Community-Plugins
- [ ] Mobile App (iOS/Android)
- [ ] Advanced Analytics
- [ ] ML-basierte Anomalie-Erkennung

---

## Mitwirken

Haben Sie Ideen für neue Features? Öffnen Sie ein Issue oder Pull Request!

**Feature-Requests**: [GitHub Issues](https://github.com/your-username/Gateway-Zero/issues)

---

## Links

- [Homepage](https://github.com/your-username/Gateway-Zero)
- [Dokumentation](README.md)
- [Installation](README.md#installation)
- [Security](README.md#security)
