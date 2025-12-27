package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// --- Version ---
const VERSION = "2.0.0"

// --- Konfiguration & Typen ---

type Config struct {
	Domain             string   `json:"domain"`
	Email              string   `json:"email"`
	AdminUser          string   `json:"admin_user"`
	AdminPassHash      string   `json:"admin_pass_hash"`
	GoogleClientID     string   `json:"google_client_id"`
	GoogleClientSecret string   `json:"google_client_secret"`
	GlobalWhitelist    []string `json:"whitelist"`
	GlobalBlacklist    []string `json:"blacklist"`
	SetupDone          bool     `json:"setup_done"`
	MaxLoginAttempts   int      `json:"max_login_attempts"`
	BanThreshold       int      `json:"ban_threshold"`
	SessionDuration    int      `json:"session_duration_hours"`
}

type Host struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Subdomain  string   `json:"subdomain"`
	InternalIP string   `json:"internalIp"`
	Port       int      `json:"port"`
	Icon       string   `json:"icon"`
	Status     string   `json:"status"`
	MAC        string   `json:"mac"`
	Features   Features `json:"features"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

type Features struct {
	GoogleAuth bool   `json:"googleAuth"`
	GeoIP      string `json:"geo"`
	Websockets bool   `json:"websockets"`
	WOL        bool   `json:"wol"`
	Fail2Ban   bool   `json:"fail2ban"`
}

type LogEntry struct {
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"country"`
	Host    string `json:"host"`
}

type GuestToken struct {
	HostID    string    `json:"host_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
}

type SystemStats struct {
	PingMs        int64  `json:"ping"`
	BannedCount   int    `json:"bannedCount"`
	ActiveHosts   int    `json:"activeHosts"`
	TotalRequests int64  `json:"totalRequests"`
	Uptime        int64  `json:"uptime"`
	Version       string `json:"version"`
	SSLStatus     string `json:"sslStatus"`
}

type Session struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
}

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
}

// Globaler Speicher
var (
	hosts        = []Host{}
	hostsLock    sync.RWMutex
	accessLogs   = []LogEntry{}
	logsLock     sync.RWMutex
	bannedIPs    = make(map[string]int)
	banLock      sync.RWMutex
	guestTokens  = make(map[string]GuestToken)
	tokenLock    sync.RWMutex
	currentPing  int64 = 0
	startTime    = time.Now()
	totalReqs    int64 = 0

	dataFile    = "data/hosts.json"
	configFile  = "data/config.json"
	sessionFile = "data/sessions.json"
	sitesDir    = "data/sites"
	geoIPFile   = "data/GeoLite2-Country.mmdb"
	tokensFile  = "data/tokens.json"
	banFile     = "data/banned.json"

	globalConfig Config
	configLock   sync.RWMutex

	oauthConfig *oauth2.Config
	geoDB       *geoip2.Reader

	sessions    = make(map[string]Session)
	sessionLock sync.RWMutex

	csrfTokens    = make(map[string]string)
	csrfLock      sync.RWMutex
	rateLimiter   = &RateLimiter{requests: make(map[string][]time.Time)}
	loginAttempts = make(map[string]int)
	loginLock     sync.RWMutex
)

// --- Input Validation ---

var (
	subdomainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	macRegex       = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	ipRegex        = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	emailRegex     = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

func validateSubdomain(s string) bool {
	return subdomainRegex.MatchString(strings.ToLower(s)) && len(s) <= 63
}

func validateMAC(m string) bool {
	return macRegex.MatchString(m)
}

func validateIP(ip string) bool {
	if !ipRegex.MatchString(ip) {
		return false
	}
	parts := strings.Split(ip, ".")
	for _, p := range parts {
		var num int
		fmt.Sscanf(p, "%d", &num)
		if num > 255 {
			return false
		}
	}
	return true
}

func validateEmail(e string) bool {
	return emailRegex.MatchString(e)
}

func sanitizeString(s string) string {
	return strings.TrimSpace(regexp.MustCompile(`[^\w\s\-.]`).ReplaceAllString(s, ""))
}

// --- Rate Limiting ---

func (rl *RateLimiter) Allow(ip string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if _, exists := rl.requests[ip]; !exists {
		rl.requests[ip] = []time.Time{}
	}

	// Cleanup old requests
	validReqs := []time.Time{}
	for _, t := range rl.requests[ip] {
		if now.Sub(t) < window {
			validReqs = append(validReqs, t)
		}
	}

	if len(validReqs) >= limit {
		rl.requests[ip] = validReqs
		return false
	}

	validReqs = append(validReqs, now)
	rl.requests[ip] = validReqs
	return true
}

// --- Initialisierung ---

func loadData() {
	os.MkdirAll("data", 0755)
	os.MkdirAll(sitesDir, 0755)
	os.MkdirAll("data/certs", 0755)
	os.MkdirAll("data/backups", 0755)

	// Hosts
	if file, err := os.ReadFile(dataFile); err == nil {
		json.Unmarshal(file, &hosts)
	}

	// Config
	if cFile, err := os.ReadFile(configFile); err == nil {
		json.Unmarshal(cFile, &globalConfig)
	} else {
		globalConfig = Config{
			SetupDone:        false,
			MaxLoginAttempts: 5,
			BanThreshold:     10,
			SessionDuration:  168, // 7 days
		}
		saveConfigLocked()
	}

	// Sessions
	if sFile, err := os.ReadFile(sessionFile); err == nil {
		json.Unmarshal(sFile, &sessions)
		cleanupExpiredSessions()
	}

	// Tokens
	if tFile, err := os.ReadFile(tokensFile); err == nil {
		json.Unmarshal(tFile, &guestTokens)
	}

	// Banned IPs
	if bFile, err := os.ReadFile(banFile); err == nil {
		json.Unmarshal(bFile, &bannedIPs)
	}

	// OAuth Init
	updateOAuthConfig()

	// GeoIP Laden
	initGeoIP()
}

func initGeoIP() {
	var err error

	// Download GeoIP if not exists
	if _, err := os.Stat(geoIPFile); os.IsNotExist(err) {
		log.Println("GeoIP-Datenbank wird heruntergeladen...")
		if err := downloadGeoIPDatabase(); err != nil {
			log.Printf("GeoIP-Download fehlgeschlagen: %v. GeoIP-Features deaktiviert.", err)
			return
		}
	}

	geoDB, err = geoip2.Open(geoIPFile)
	if err != nil {
		log.Printf("GeoIP-Fehler: %v. Geo-Blocking auf LAN beschränkt.", err)
	} else {
		log.Println("✓ GeoIP-Datenbank erfolgreich geladen.")
	}
}

func downloadGeoIPDatabase() error {
	// Using free GeoLite2 database from db-ip.com
	// Note: This downloads the latest monthly release
	url := "https://download.db-ip.com/free/dbip-country-lite-2025-01.mmdb.gz"

	log.Println("Downloading GeoIP database from", url)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Try alternative URL (monthly archives)
		log.Printf("First URL failed with HTTP %d, trying fallback...", resp.StatusCode)

		// Fallback: Try current month
		url = "https://download.db-ip.com/free/dbip-country-lite-2024-12.mmdb.gz"
		resp, err = client.Get(url)
		if err != nil || resp.StatusCode != 200 {
			// If both fail, create empty file and continue without GeoIP
			log.Println("GeoIP download not available. Continuing without GeoIP features.")
			return fmt.Errorf("GeoIP download failed")
		}
		defer resp.Body.Close()
	}

	// Save to file
	out, err := os.Create(geoIPFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	log.Println("✓ GeoIP database downloaded successfully")
	return nil
}

func updateOAuthConfig() {
	if globalConfig.GoogleClientID != "" && globalConfig.Domain != "" {
		oauthConfig = &oauth2.Config{
			ClientID:     globalConfig.GoogleClientID,
			ClientSecret: globalConfig.GoogleClientSecret,
			RedirectURL:  "https://auth." + globalConfig.Domain + "/callback",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		}
	} else {
		oauthConfig = nil
	}
}

func saveData() {
	hostsLock.Lock()
	defer hostsLock.Unlock()
	data, _ := json.MarshalIndent(hosts, "", "  ")
	os.WriteFile(dataFile, data, 0644)
}

func saveConfigLocked() {
	data, _ := json.MarshalIndent(globalConfig, "", "  ")
	os.WriteFile(configFile, data, 0600) // Only owner can read
}

func saveConfig() {
	configLock.Lock()
	defer configLock.Unlock()
	saveConfigLocked()
}

func saveSessions() {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	data, _ := json.MarshalIndent(sessions, "", "  ")
	os.WriteFile(sessionFile, data, 0600)
}

func saveTokens() {
	tokenLock.Lock()
	defer tokenLock.Unlock()
	data, _ := json.MarshalIndent(guestTokens, "", "  ")
	os.WriteFile(tokensFile, data, 0644)
}

func saveBannedIPs() {
	banLock.Lock()
	defer banLock.Unlock()
	data, _ := json.MarshalIndent(bannedIPs, "", "  ")
	os.WriteFile(banFile, data, 0644)
}

func cleanupExpiredSessions() {
	sessionLock.Lock()
	defer sessionLock.Unlock()

	now := time.Now()
	for id, sess := range sessions {
		if now.After(sess.ExpiresAt) {
			delete(sessions, id)
		}
	}
}

// --- Netzwerk Tools ---

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func getCountryISO(ipStr string) string {
	if isPrivateIP(ipStr) {
		return "LAN"
	}
	if geoDB == nil {
		return "??"
	}

	ip := net.ParseIP(ipStr)
	record, err := geoDB.Country(ip)
	if err != nil || record.Country.IsoCode == "" {
		return "??"
	}
	return record.Country.IsoCode
}

func isIPInList(ipStr string, cidrList []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrList {
		if !strings.Contains(cidr, "/") {
			if cidr == ipStr {
				return true
			}
		} else {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func isEU(iso string) bool {
	eu := map[string]bool{
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
		"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
		"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
		"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
		"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
		"ES": true, "SE": true,
	}
	return eu[iso]
}

func addLog(ip, status, msg, host string) {
	logsLock.Lock()
	defer logsLock.Unlock()
	country := getCountryISO(ip)
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		IP:      ip,
		Status:  status,
		Message: sanitizeString(msg),
		Country: country,
		Host:    sanitizeString(host),
	}
	accessLogs = append([]LogEntry{entry}, accessLogs...)
	if len(accessLogs) > 500 {
		accessLogs = accessLogs[:500]
	}
}

func sendMagicPacket(macAddr string) error {
	if !validateMAC(macAddr) {
		return fmt.Errorf("invalid MAC address")
	}

	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return err
	}

	packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	for i := 0; i < 16; i++ {
		packet = append(packet, mac...)
	}

	// Broadcast to local network only
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(255, 255, 255, 255),
		Port: 9,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	return err
}

// --- Auth & Crypto ---

func hashPassword(p string) (string, error) {
	b, e := bcrypt.GenerateFromPassword([]byte(p), 14)
	return string(b), e
}

func checkPasswordHash(p, h string) bool {
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(p)) == nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func setSession(w http.ResponseWriter, r *http.Request, user string) string {
	id := generateToken()

	configLock.RLock()
	duration := globalConfig.SessionDuration
	if duration == 0 {
		duration = 168
	}
	configLock.RUnlock()

	sess := Session{
		ID:        id,
		User:      user,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(duration) * time.Hour),
		IP:        getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	sessionLock.Lock()
	sessions[id] = sess
	sessionLock.Unlock()

	saveSessions()

	cd := ""
	configLock.RLock()
	d := globalConfig.Domain
	configLock.RUnlock()

	host := strings.Split(r.Host, ":")[0]
	if d != "" && strings.HasSuffix(host, d) {
		cd = "." + d
	}

	// Secure flag: only for HTTPS connections
	isHTTPS := r.TLS != nil

	http.SetCookie(w, &http.Cookie{
		Name:     "gz_session",
		Value:    id,
		Path:     "/",
		Domain:   cd,
		HttpOnly: true,
		Secure:   isHTTPS, // Only secure for HTTPS
		MaxAge:   duration * 3600,
		SameSite: http.SameSiteStrictMode,
	})

	return id
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func isAdminAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("gz_session")
	if err != nil {
		return false
	}

	sessionLock.RLock()
	sess, ok := sessions[c.Value]
	sessionLock.RUnlock()

	if !ok {
		return false
	}

	// Check expiration
	if time.Now().After(sess.ExpiresAt) {
		sessionLock.Lock()
		delete(sessions, c.Value)
		sessionLock.Unlock()
		saveSessions()
		return false
	}

	// Check IP consistency (optional security feature)
	clientIP := getClientIP(r)
	if sess.IP != clientIP {
		log.Printf("Security: Session IP mismatch for %s (expected %s, got %s)", sess.User, sess.IP, clientIP)
		// Optional: invalidate session on IP change
		// For now we allow it but log it
	}

	return sess.User == "admin_user"
}

func isUserAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("gz_session")
	if err != nil {
		return false
	}

	sessionLock.RLock()
	sess, ok := sessions[c.Value]
	sessionLock.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(sess.ExpiresAt) {
		return false
	}

	return strings.Contains(sess.User, "@")
}

func validateCSRF(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		return false
	}

	c, err := r.Cookie("gz_session")
	if err != nil {
		return false
	}

	csrfLock.RLock()
	expected, ok := csrfTokens[c.Value]
	csrfLock.RUnlock()

	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func getOrCreateCSRF(sessionID string) string {
	csrfLock.Lock()
	defer csrfLock.Unlock()

	if token, ok := csrfTokens[sessionID]; ok {
		return token
	}

	token := generateCSRFToken()
	csrfTokens[sessionID] = token
	return token
}

// --- OAuth ---

func handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()
	if oauthConfig == nil {
		http.Error(w, "Google OAuth nicht konfiguriert", 500)
		return
	}
	http.Redirect(w, r, oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline), 307)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()
	if oauthConfig == nil {
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Auth Error", 401)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, _ := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	defer resp.Body.Close()

	var info struct {
		Email string `json:"email"`
	}
	json.NewDecoder(resp.Body).Decode(&info)

	setSession(w, r, info.Email)
	http.Redirect(w, r, "https://"+globalConfig.Domain, 302)
}

// --- CORE PROXY ---

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	totalReqs++
	clientIP := getClientIP(r)

	// Rate limiting for all requests
	if !rateLimiter.Allow(clientIP, 100, 1*time.Minute) {
		http.Error(w, "Rate limit exceeded", 429)
		return
	}

	configLock.RLock()
	setupDone := globalConfig.SetupDone
	baseDom := globalConfig.Domain
	bl := globalConfig.GlobalBlacklist
	wl := globalConfig.GlobalWhitelist
	configLock.RUnlock()

	hostHeader := strings.Split(r.Host, ":")[0]

	// 1. Setup Check
	if !setupDone {
		http.ServeFile(w, r, "static/index.html")
		return
	}

	// 2. Auth Domain
	if hostHeader == "auth."+baseDom {
		if strings.HasPrefix(r.URL.Path, "/login") {
			handleOAuthLogin(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/callback") {
			handleOAuthCallback(w, r)
			return
		}
	}

	// 3. Global Blacklist Check
	if isIPInList(clientIP, bl) {
		addLog(clientIP, "DROP", "Global Blacklist", "")
		http.Error(w, "Access Denied", 403)
		return
	}

	// 4. Dashboard Check
	parts := strings.Split(hostHeader, ".")
	isDash := net.ParseIP(hostHeader) != nil || hostHeader == "localhost" || hostHeader == baseDom || len(parts) < 3

	if isDash {
		if !strings.HasPrefix(r.URL.Path, "/api/auth") && !strings.HasPrefix(r.URL.Path, "/static") {
			if !isAdminAuthenticated(r) {
				if strings.HasPrefix(r.URL.Path, "/api") {
					http.Error(w, "Unauthorized", 401)
					return
				}
			}
		}
		http.ServeFile(w, r, "static/index.html")
		return
	}

	// 5. Fail2Ban Check
	if !isIPInList(clientIP, wl) {
		banLock.RLock()
		cnt := bannedIPs[clientIP]
		banLock.RUnlock()

		configLock.RLock()
		threshold := globalConfig.BanThreshold
		configLock.RUnlock()

		if cnt > threshold {
			addLog(clientIP, "BANNED", "Fail2Ban", "")
			http.Error(w, "Access Denied (Fail2Ban)", 403)
			return
		}
	}

	// 6. Host Lookup
	if len(parts) < 1 {
		http.NotFound(w, r)
		return
	}

	subdomain := parts[0]
	var target *Host

	hostsLock.RLock()
	for i := range hosts {
		if hosts[i].Subdomain == subdomain {
			target = &hosts[i]
			break
		}
	}
	hostsLock.RUnlock()

	if target == nil {
		if !isIPInList(clientIP, wl) {
			banLock.Lock()
			bannedIPs[clientIP]++
			banLock.Unlock()
			saveBannedIPs()
		}
		addLog(clientIP, "404", "Unknown: "+subdomain, "")
		http.NotFound(w, r)
		return
	}

	// 7. Security Features

	// Guest Token
	token := r.URL.Query().Get("token")
	isGuest := false
	if token != "" {
		tokenLock.RLock()
		info, ok := guestTokens[token]
		tokenLock.RUnlock()
		if ok && info.HostID == target.ID && time.Now().Before(info.ExpiresAt) {
			isGuest = true
		}
	}

	if !isGuest {
		// GeoIP Check
		iso := getCountryISO(clientIP)
		if target.Features.GeoIP != "none" && target.Features.GeoIP != "" {
			allowed := false
			if target.Features.GeoIP == "lan" && iso == "LAN" {
				allowed = true
			}
			if target.Features.GeoIP == "de" && (iso == "DE" || iso == "LAN") {
				allowed = true
			}
			if target.Features.GeoIP == "eu" && (isEU(iso) || iso == "LAN") {
				allowed = true
			}

			if !allowed {
				addLog(clientIP, "BLOCK", "GeoIP ("+iso+")", target.Name)
				http.Error(w, "Access Denied (GeoIP)", 403)
				return
			}
		}

		// OAuth Check
		if target.Features.GoogleAuth {
			if oauthConfig == nil {
				http.Error(w, "Google Auth aktiv aber nicht konfiguriert", 500)
				return
			}
			if !isUserAuthenticated(r) {
				http.Redirect(w, r, "https://auth."+baseDom+"/login", 302)
				return
			}
		}
	}

	// 8. Maintenance / Sleep
	if target.Status == "maintenance" {
		w.WriteHeader(503)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Wartung</title><style>body{font-family:sans-serif;text-align:center;padding:50px;background:#0f172a;color:#fff}</style></head><body><h1>🔧 Wartungsarbeiten</h1><p>%s ist gleich zurück.</p></body></html>`, target.Name)
		return
	}

	if target.Status == "sleeping" {
		if target.Features.WOL && target.MAC != "" {
			sendMagicPacket(target.MAC)
			w.WriteHeader(504)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Server wird geweckt</title><style>body{font-family:sans-serif;text-align:center;padding:50px;background:#0f172a;color:#fff}</style></head><body><h1>🌙 Server wird geweckt...</h1><p>Magic Packet an %s gesendet.</p><p>Seite lädt automatisch neu in 30 Sekunden.</p><script>setTimeout(()=>location.reload(), 30000)</script></body></html>`, target.MAC)
		} else {
			w.WriteHeader(503)
			fmt.Fprint(w, "Server schläft (Green Mode)")
		}
		return
	}

	addLog(clientIP, "ALLOW", target.Name, target.Subdomain)

	// Static hosting
	if target.InternalIP == "Local" {
		path := filepath.Join(sitesDir, target.Subdomain)
		os.MkdirAll(path, 0755)

		if _, err := os.Stat(filepath.Join(path, "index.html")); os.IsNotExist(err) {
			os.WriteFile(filepath.Join(path, "index.html"), []byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>%s</title></head><body><h1>Willkommen zu %s</h1><p>Diese Seite wird von Gateway Zero gehostet.</p></body></html>`, target.Name, target.Name)), 0644)
		}

		http.FileServer(http.Dir(path)).ServeHTTP(w, r)
		return
	}

	// Reverse proxy
	targetUrl := fmt.Sprintf("http://%s:%d", target.InternalIP, target.Port)
	u, err := url.Parse(targetUrl)
	if err != nil {
		http.Error(w, "Invalid target URL", 500)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https")

		if target.Features.Websockets {
			req.Header.Set("Connection", req.Header.Get("Connection"))
			req.Header.Set("Upgrade", req.Header.Get("Upgrade"))
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if target.Features.Fail2Ban && !isIPInList(clientIP, wl) {
			banLock.Lock()
			bannedIPs[clientIP]++
			banLock.Unlock()
			saveBannedIPs()
		}
		addLog(clientIP, "ERROR", "Target down", target.Name)
		w.WriteHeader(502)
		fmt.Fprint(w, "Bad Gateway")
	}

	proxy.ServeHTTP(w, r)
}

// --- API ---

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Auth routes (no CSRF needed)
	if strings.HasPrefix(r.URL.Path, "/api/auth/") {
		handleAuthAPI(w, r)
		return
	}

	// Stats endpoint (public)
	if r.URL.Path == "/api/stats" {
		handleStatsAPI(w, r)
		return
	}

	// Config endpoint
	if r.URL.Path == "/api/config" {
		if !isAdminAuthenticated(r) {
			http.Error(w, "Unauthorized", 401)
			return
		}

		if r.Method == "GET" {
			handleGetConfig(w, r)
			return
		}

		if r.Method == "POST" {
			if !validateCSRF(r) {
				http.Error(w, "CSRF validation failed", 403)
				return
			}
			handleUpdateConfig(w, r)
			return
		}
	}

	// Protected routes - require auth and CSRF for mutations
	if !isAdminAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}

	// CSRF token endpoint
	if r.URL.Path == "/api/csrf" && r.Method == "GET" {
		c, _ := r.Cookie("gz_session")
		token := getOrCreateCSRF(c.Value)
		json.NewEncoder(w).Encode(map[string]string{"token": token})
		return
	}

	// Validate CSRF for all mutation operations
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
		if !validateCSRF(r) {
			http.Error(w, "CSRF validation failed", 403)
			return
		}
	}

	// Route to specific handlers
	switch r.URL.Path {
	case "/api/hosts":
		handleHostsAPI(w, r)
	case "/api/upload":
		handleUploadAPI(w, r)
	case "/api/logs":
		handleLogsAPI(w, r)
	case "/api/scan":
		handleScanAPI(w, r)
	case "/api/guest-token":
		handleGuestTokenAPI(w, r)
	case "/api/fetch-icon":
		handleFetchIconAPI(w, r)
	case "/api/backup":
		handleBackupAPI(w, r)
	case "/api/restore":
		handleRestoreAPI(w, r)
	case "/api/banned":
		handleBannedAPI(w, r)
	case "/api/sessions":
		handleSessionsAPI(w, r)
	default:
		http.NotFound(w, r)
	}
}

// --- API Handlers ---

func handleAuthAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/auth/status" {
		configLock.RLock()
		setupDone := globalConfig.SetupDone
		domain := globalConfig.Domain
		configLock.RUnlock()

		authenticated := isAdminAuthenticated(r)

		// Get CSRF token if authenticated
		csrf := ""
		if authenticated {
			if c, err := r.Cookie("gz_session"); err == nil {
				csrf = getOrCreateCSRF(c.Value)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"setup_done":    setupDone,
			"logged_in":     authenticated,
			"domain":        domain,
			"csrf_token":    csrf,
			"version":       VERSION,
			"uptime":        int64(time.Since(startTime).Seconds()),
			"total_requests": totalReqs,
		})
		return
	}

	if r.URL.Path == "/api/auth/setup" && r.Method == "POST" {
		configLock.Lock()
		if globalConfig.SetupDone {
			configLock.Unlock()
			http.Error(w, "Setup already done", 403)
			return
		}

		var req struct {
			Domain   string `json:"domain"`
			Email    string `json:"email"`
			User     string `json:"user"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// Validation
		if req.Domain == "" || req.Email == "" || req.User == "" || req.Password == "" {
			configLock.Unlock()
			http.Error(w, "All fields required", 400)
			return
		}

		if !validateEmail(req.Email) {
			configLock.Unlock()
			http.Error(w, "Invalid email format", 400)
			return
		}

		if len(req.Password) < 8 {
			configLock.Unlock()
			http.Error(w, "Password must be at least 8 characters", 400)
			return
		}

		hash, _ := hashPassword(req.Password)
		globalConfig = Config{
			Domain:           sanitizeString(req.Domain),
			Email:            req.Email,
			AdminUser:        sanitizeString(req.User),
			AdminPassHash:    hash,
			SetupDone:        true,
			MaxLoginAttempts: 5,
			BanThreshold:     10,
			SessionDuration:  168,
		}
		saveConfigLocked()
		updateOAuthConfig()
		configLock.Unlock()

		setSession(w, r, "admin_user")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	if r.URL.Path == "/api/auth/login" && r.Method == "POST" {
		var req struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		clientIP := getClientIP(r)

		// Rate limiting for login attempts
		if !rateLimiter.Allow(clientIP, 5, 5*time.Minute) {
			http.Error(w, "Too many login attempts", 429)
			return
		}

		configLock.RLock()
		validUser := sanitizeString(req.User) == globalConfig.AdminUser
		validPass := checkPasswordHash(req.Password, globalConfig.AdminPassHash)
		maxAttempts := globalConfig.MaxLoginAttempts
		configLock.RUnlock()

		if validUser && validPass {
			// Reset login attempts on success
			loginLock.Lock()
			delete(loginAttempts, clientIP)
			loginLock.Unlock()

			setSession(w, r, "admin_user")
			addLog(clientIP, "LOGIN", "Admin login successful", "")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		} else {
			loginLock.Lock()
			loginAttempts[clientIP]++
			attempts := loginAttempts[clientIP]
			loginLock.Unlock()

			addLog(clientIP, "LOGIN_FAIL", fmt.Sprintf("Failed attempt %d/%d", attempts, maxAttempts), "")

			if attempts >= maxAttempts {
				banLock.Lock()
				bannedIPs[clientIP] += 10 // Immediate ban
				banLock.Unlock()
				saveBannedIPs()
			}

			http.Error(w, "Invalid credentials", 401)
		}
		return
	}

	if r.URL.Path == "/api/auth/logout" && r.Method == "POST" {
		if c, err := r.Cookie("gz_session"); err == nil {
			sessionLock.Lock()
			delete(sessions, c.Value)
			sessionLock.Unlock()
			saveSessions()

			csrfLock.Lock()
			delete(csrfTokens, c.Value)
			csrfLock.Unlock()
		}

		http.SetCookie(w, &http.Cookie{
			Name:   "gz_session",
			Value:  "",
			MaxAge: -1,
		})

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
		return
	}
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()

	// Don't send secrets to frontend
	safeConfig := map[string]interface{}{
		"domain":              globalConfig.Domain,
		"email":               globalConfig.Email,
		"google_client_id":    globalConfig.GoogleClientID,
		"google_client_secret": "***", // Masked
		"whitelist":           globalConfig.GlobalWhitelist,
		"blacklist":           globalConfig.GlobalBlacklist,
		"max_login_attempts":  globalConfig.MaxLoginAttempts,
		"ban_threshold":       globalConfig.BanThreshold,
		"session_duration":    globalConfig.SessionDuration,
	}

	json.NewEncoder(w).Encode(safeConfig)
}

func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var update map[string]interface{}
	json.NewDecoder(r.Body).Decode(&update)

	configLock.Lock()
	defer configLock.Unlock()

	// Update only allowed fields
	if val, ok := update["google_client_id"].(string); ok {
		globalConfig.GoogleClientID = sanitizeString(val)
	}
	if val, ok := update["google_client_secret"].(string); ok && val != "***" {
		globalConfig.GoogleClientSecret = val
	}
	if val, ok := update["whitelist"].([]interface{}); ok {
		list := []string{}
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				list = append(list, sanitizeString(s))
			}
		}
		globalConfig.GlobalWhitelist = list
	}
	if val, ok := update["blacklist"].([]interface{}); ok {
		list := []string{}
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				list = append(list, sanitizeString(s))
			}
		}
		globalConfig.GlobalBlacklist = list
	}

	saveConfigLocked()
	updateOAuthConfig()

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	hostsLock.RLock()
	activeCount := 0
	for _, h := range hosts {
		if h.Status != "sleeping" && h.Status != "maintenance" {
			activeCount++
		}
	}
	hostsLock.RUnlock()

	banLock.RLock()
	bannedCount := len(bannedIPs)
	banLock.RUnlock()

	sslStatus := "OK"
	if _, err := os.Stat("data/certs"); os.IsNotExist(err) {
		sslStatus = "Not configured"
	}

	stats := SystemStats{
		PingMs:        currentPing,
		BannedCount:   bannedCount,
		ActiveHosts:   activeCount,
		TotalRequests: totalReqs,
		Uptime:        int64(time.Since(startTime).Seconds()),
		Version:       VERSION,
		SSLStatus:     sslStatus,
	}

	json.NewEncoder(w).Encode(stats)
}

func handleHostsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		hostsLock.RLock()
		json.NewEncoder(w).Encode(hosts)
		hostsLock.RUnlock()
		return
	}

	if r.Method == "POST" {
		var h Host
		if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}

		// Validation
		if !validateSubdomain(h.Subdomain) {
			http.Error(w, "Invalid subdomain format", 400)
			return
		}

		if h.InternalIP != "Local" && !validateIP(h.InternalIP) {
			http.Error(w, "Invalid IP address", 400)
			return
		}

		if h.Port < 1 || h.Port > 65535 {
			http.Error(w, "Invalid port", 400)
			return
		}

		if h.MAC != "" && !validateMAC(h.MAC) {
			http.Error(w, "Invalid MAC address", 400)
			return
		}

		h.Name = sanitizeString(h.Name)
		h.UpdatedAt = time.Now().Unix()

		hostsLock.Lock()
		found := false
		for i, ex := range hosts {
			if ex.ID == h.ID {
				h.CreatedAt = ex.CreatedAt
				hosts[i] = h
				found = true
				break
			}
		}
		if !found {
			h.CreatedAt = time.Now().Unix()
			hosts = append(hosts, h)
		}
		hostsLock.Unlock()

		saveData()
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
		return
	}

	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "ID required", 400)
			return
		}

		hostsLock.Lock()
		newHosts := []Host{}
		for _, h := range hosts {
			if h.ID != id {
				newHosts = append(newHosts, h)
			}
		}
		hosts = newHosts
		hostsLock.Unlock()

		saveData()
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}
}

func handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	logsLock.RLock()
	defer logsLock.RUnlock()

	// Support filtering
	filter := r.URL.Query().Get("filter")
	limit := 100

	if filter == "" {
		if len(accessLogs) > limit {
			json.NewEncoder(w).Encode(accessLogs[:limit])
		} else {
			json.NewEncoder(w).Encode(accessLogs)
		}
		return
	}

	// Filter logs
	filtered := []LogEntry{}
	for _, log := range accessLogs {
		if strings.Contains(strings.ToLower(log.Status), strings.ToLower(filter)) ||
			strings.Contains(strings.ToLower(log.Message), strings.ToLower(filter)) ||
			strings.Contains(log.IP, filter) {
			filtered = append(filtered, log)
			if len(filtered) >= limit {
				break
			}
		}
	}

	json.NewEncoder(w).Encode(filtered)
}

func handleScanAPI(w http.ResponseWriter, r *http.Request) {
	results := scanNetwork()
	json.NewEncoder(w).Encode(results)
}

func handleGuestTokenAPI(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("id")
	if hostID == "" {
		http.Error(w, "Host ID required", 400)
		return
	}

	token := generateToken()[:16]

	guestToken := GuestToken{
		HostID:    hostID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedBy: "admin",
	}

	tokenLock.Lock()
	guestTokens[token] = guestToken
	tokenLock.Unlock()

	saveTokens()

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func handleFetchIconAPI(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "URL required", 400)
		return
	}

	// Basic validation
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	icon := "server" // default
	// Icon fetching logic would go here

	json.NewEncoder(w).Encode(map[string]string{"icon": icon})
}

func handleUploadAPI(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "File too large", 400)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", 400)
		return
	}
	defer file.Close()

	sub := r.FormValue("subdomain")
	if !validateSubdomain(sub) {
		http.Error(w, "Invalid subdomain", 400)
		return
	}

	targetDir := filepath.Join(sitesDir, sub)
	os.MkdirAll(targetDir, 0755)

	// Check file type
	filename := handler.Filename
	ext := strings.ToLower(filepath.Ext(filename))

	if ext == ".zip" {
		// Extract zip
		dst := filepath.Join(targetDir, "upload.zip")
		out, _ := os.Create(dst)
		io.Copy(out, file)
		out.Close()

		// Unzip
		if err := unzip(dst, targetDir); err != nil {
			http.Error(w, "Unzip failed", 500)
			return
		}
		os.Remove(dst)
	} else if ext == ".html" || ext == ".htm" {
		dst := filepath.Join(targetDir, "index.html")
		out, _ := os.Create(dst)
		io.Copy(out, file)
		out.Close()
	} else {
		http.Error(w, "Only .html and .zip files allowed", 400)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "uploaded"})
}

func handleBackupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupDir := filepath.Join("data/backups", timestamp)
	os.MkdirAll(backupDir, 0755)

	// Copy all data files
	files := []string{dataFile, configFile, sessionFile, tokensFile, banFile}
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			data, _ := os.ReadFile(f)
			os.WriteFile(filepath.Join(backupDir, filepath.Base(f)), data, 0644)
		}
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"backup": timestamp})
}

func handleRestoreAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	backup := r.URL.Query().Get("backup")
	if backup == "" {
		http.Error(w, "Backup name required", 400)
		return
	}

	backupDir := filepath.Join("data/backups", backup)
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		http.Error(w, "Backup not found", 404)
		return
	}

	// Restore files
	files := []string{"hosts.json", "config.json", "sessions.json", "tokens.json", "banned.json"}
	for _, f := range files {
		src := filepath.Join(backupDir, f)
		if _, err := os.Stat(src); err == nil {
			data, _ := os.ReadFile(src)
			os.WriteFile(filepath.Join("data", f), data, 0644)
		}
	}

	// Reload data
	loadData()

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "restored"})
}

func handleBannedAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		banLock.RLock()
		defer banLock.RUnlock()

		// Convert to slice for sorting
		type BannedIP struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}

		banned := []BannedIP{}
		for ip, count := range bannedIPs {
			banned = append(banned, BannedIP{IP: ip, Count: count})
		}

		// Sort by count
		sort.Slice(banned, func(i, j int) bool {
			return banned[i].Count > banned[j].Count
		})

		json.NewEncoder(w).Encode(banned)
		return
	}

	if r.Method == "DELETE" {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "IP required", 400)
			return
		}

		banLock.Lock()
		delete(bannedIPs, ip)
		banLock.Unlock()

		saveBannedIPs()

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "unbanned"})
		return
	}
}

func handleSessionsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sessionLock.RLock()
		defer sessionLock.RUnlock()

		// Convert to slice
		sessSlice := []Session{}
		for _, sess := range sessions {
			sessSlice = append(sessSlice, sess)
		}

		// Sort by creation time
		sort.Slice(sessSlice, func(i, j int) bool {
			return sessSlice[i].CreatedAt.After(sessSlice[j].CreatedAt)
		})

		json.NewEncoder(w).Encode(sessSlice)
		return
	}

	if r.Method == "DELETE" {
		sessionID := r.URL.Query().Get("id")
		if sessionID == "" {
			http.Error(w, "Session ID required", 400)
			return
		}

		sessionLock.Lock()
		delete(sessions, sessionID)
		sessionLock.Unlock()

		saveSessions()

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}
}

// --- Network Scanner ---

func scanNetwork() []map[string]interface{} {
	found := []map[string]interface{}{}
	var mutex sync.Mutex
	var wg sync.WaitGroup

	prefix := "192.168.1"

	// Auto-detect network
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				parts := strings.Split(ipnet.IP.String(), ".")
				if len(parts) == 4 {
					prefix = strings.Join(parts[:3], ".")
					break
				}
			}
		}
	}

	ports := []int{80, 8080, 8123, 9000, 32400, 443, 3000, 5000}
	sem := make(chan struct{}, 50) // Reduced concurrency

	for i := 1; i < 255; i++ {
		targetIP := fmt.Sprintf("%s.%d", prefix, i)

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			for _, port := range ports {
				sem <- struct{}{}

				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 200*time.Millisecond)
				if err == nil {
					conn.Close()

					mutex.Lock()
					found = append(found, map[string]interface{}{
						"name": fmt.Sprintf("Service on :%d", port),
						"ip":   ip,
						"port": port,
						"icon": "server",
					})
					mutex.Unlock()
				}

				<-sem
			}
		}(targetIP)
	}

	wg.Wait()
	return found
}

// --- Utility Functions ---

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip vulnerability
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

// --- Main ---

func main() {
	port := flag.String("port", "80", "HTTP Port")
	httpsPort := flag.String("https-port", "443", "HTTPS Port")
	flag.Parse()

	log.Printf("🚀 Gateway Zero %s starting...", VERSION)

	loadData()

	// Ping routine
	go func() {
		for {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
			if err == nil {
				conn.Close()
				currentPing = time.Since(start).Milliseconds()
			} else {
				currentPing = -1
			}
			time.Sleep(30 * time.Second)
		}
	}()

	// Session cleanup routine
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			cleanupExpiredSessions()
			saveSessions()
		}
	}()

	// Auto-save routine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			saveData()
			saveSessions()
			saveTokens()
			saveBannedIPs()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", apiHandler)
	mux.HandleFunc("/", proxyHandler)

	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("data/certs"),
		Email:  globalConfig.Email,
		HostPolicy: func(_ context.Context, host string) error {
			configLock.RLock()
			d := globalConfig.Domain
			configLock.RUnlock()

			if host == d || host == "auth."+d {
				return nil
			}

			hostsLock.RLock()
			defer hostsLock.RUnlock()
			for _, h := range hosts {
				if h.Subdomain+"."+d == host {
					return nil
				}
			}

			return fmt.Errorf("host not allowed")
		},
	}

	// HTTP server (handles setup, then redirects to HTTPS)
	go func() {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Allow ACME challenges
			if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				certManager.HTTPHandler(nil).ServeHTTP(w, r)
				return
			}

			// Check if setup is done and we have a domain
			configLock.RLock()
			setupDone := globalConfig.SetupDone
			domain := globalConfig.Domain
			configLock.RUnlock()

			// If setup not done, or accessing via IP, serve HTTP
			host := strings.Split(r.Host, ":")[0]
			isIP := net.ParseIP(host) != nil

			if !setupDone || isIP || domain == "" {
				// Serve via HTTP (setup phase or IP access)
				mux.ServeHTTP(w, r)
				return
			}

			// Setup is done and accessing via domain - redirect to HTTPS
			target := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})

		log.Printf("✓ HTTP server listening on :%s", *port)
		if err := http.ListenAndServe(":"+*port, httpMux); err != nil {
			log.Fatal(err)
		}
	}()

	// HTTPS server
	server := &http.Server{
		Addr:      ":" + *httpsPort,
		Handler:   mux,
		TLSConfig: certManager.TLSConfig(),
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\n🛑 Shutting down gracefully...")

		// Save all data
		saveData()
		saveSessions()
		saveTokens()
		saveBannedIPs()
		saveConfig()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}

		os.Exit(0)
	}()

	log.Printf("✓ HTTPS server listening on :%s", *httpsPort)
	log.Println("✓ Gateway Zero ready!")

	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Printf("HTTPS server error: %v", err)
	}
}
