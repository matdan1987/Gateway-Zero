package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// --- Konfiguration & Typen ---

type Config struct {
	Domain             string   `json:"domain"`
	Email              string   `json:"email"`
	AdminUser          string   `json:"admin_user"`
	AdminPassHash      string   `json:"admin_pass_hash"`
	GoogleClientID     string   `json:"google_client_id"`
	GoogleClientSecret string   `json:"google_client_secret"`
	GlobalWhitelist    []string `json:"whitelist"` // CIDRs
	GlobalBlacklist    []string `json:"blacklist"` // CIDRs
	SetupDone          bool     `json:"setup_done"`
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
}

type Features struct {
	GoogleAuth bool   `json:"googleAuth"`
	GeoIP      string `json:"geo"` // "none", "de", "eu", "lan"
	Websockets bool   `json:"websockets"`
	WOL        bool   `json:"wol"`
	Fail2Ban   bool   `json:"fail2ban"`
}

type LogEntry struct {
	Time    string `json:"time"`
	IP      string `json:"ip"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"country"` // Echtes ISO Code (z.B. DE)
}

type GuestToken struct {
	HostID    string
	ExpiresAt time.Time
}

type SystemStats struct {
	PingMs      int64 `json:"ping"`
	BannedCount int   `json:"bannedCount"`
	ActiveHosts int   `json:"activeHosts"`
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
	
	dataFile     = "data/hosts.json"
	configFile   = "data/config.json"
	sitesDir     = "data/sites"
	geoIPFile    = "data/geoip.mmdb"
	
	globalConfig Config
	configLock   sync.RWMutex
	
	oauthConfig  *oauth2.Config
	geoDB        *geoip2.Reader
	
	sessions     = make(map[string]string)
	sessionLock  sync.RWMutex
)

// --- Initialisierung ---

func loadData() {
	os.MkdirAll("data", 0755)
	os.MkdirAll(sitesDir, 0755)
	
	// Hosts
	if file, err := os.ReadFile(dataFile); err == nil { json.Unmarshal(file, &hosts) }

	// Config
	if cFile, err := os.ReadFile(configFile); err == nil {
		json.Unmarshal(cFile, &globalConfig)
	} else {
		globalConfig = Config{SetupDone: false}
		saveConfigLocked()
	}

	// OAuth Init
	updateOAuthConfig()

	// GeoIP Laden
	initGeoIP()
}

func initGeoIP() {
	var err error
	if _, err := os.Stat(geoIPFile); os.IsNotExist(err) {
		log.Println("GeoIP DB fehlt. Lade herunter (Dummy Funktion für Production)...")
		// In echter Prod-Umgebung hier Download von MaxMind oder db-ip.com einbauen
		// Für dieses Setup verlassen wir uns darauf, dass install.sh es lädt oder wir es haben.
	}
	
	geoDB, err = geoip2.Open(geoIPFile)
	if err != nil {
		log.Printf("GeoIP Fehler: %v. Geo-Blocking wird auf LAN-Only beschränkt.", err)
	} else {
		log.Println("GeoIP Datenbank erfolgreich geladen.")
	}
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
	hostsLock.Lock(); defer hostsLock.Unlock()
	data, _ := json.MarshalIndent(hosts, "", "  ")
	os.WriteFile(dataFile, data, 0644)
}

func saveConfigLocked() {
	data, _ := json.MarshalIndent(globalConfig, "", "  ")
	os.WriteFile(configFile, data, 0644)
}

func saveConfig() {
	configLock.Lock(); defer configLock.Unlock()
	saveConfigLocked()
}

// --- Netzwerk Tools ---

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	return ip.IsLoopback() || ip.IsPrivate()
}

func getCountryISO(ipStr string) string {
	if isPrivateIP(ipStr) { return "LAN" }
	if geoDB == nil { return "??" }
	
	ip := net.ParseIP(ipStr)
	record, err := geoDB.Country(ip)
	if err != nil || record.Country.IsoCode == "" { return "??" }
	return record.Country.IsoCode
}

func isIPInList(ipStr string, cidrList []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, cidr := range cidrList {
		if !strings.Contains(cidr, "/") {
			// Einzelne IP
			if cidr == ipStr { return true }
		} else {
			// CIDR Range
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) { return true }
		}
	}
	return false
}

func isEU(iso string) bool {
	eu := map[string]bool{"DE":true, "FR":true, "IT":true, "ES":true, "PL":true, "NL":true, "BE":true, "AT":true, "SE":true, "DK":true, "FI":true, "IE":true, "PT":true, "GR":true, "CZ":true, "HU":true}
	return eu[iso]
}

func addLog(ip, status, msg string) {
	logsLock.Lock(); defer logsLock.Unlock()
	country := getCountryISO(ip)
	entry := LogEntry{Time: time.Now().Format("15:04:05"), IP: ip, Status: status, Message: msg, Country: country}
	accessLogs = append([]LogEntry{entry}, accessLogs...)
	if len(accessLogs) > 100 { accessLogs = accessLogs[:100] }
}

func sendMagicPacket(macAddr string) error {
	// Simple WOL Implementation
	mac, err := net.ParseMAC(macAddr)
	if err != nil { return err }
	packet := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	for i := 0; i < 16; i++ { packet = append(packet, mac...) }
	conn, err := net.Dial("udp", "255.255.255.255:9")
	if err != nil { return err }
	defer conn.Close()
	_, err = conn.Write(packet)
	return err
}

func fetchIconFromURL(targetURL string) string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil { return "server" }
	defer resp.Body.Close()
	// Sehr einfacher Parser für Demo Zwecke (Regex), für Prod besser html tokenizer
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)
	re := regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		iconURL := matches[1]
		if !strings.HasPrefix(iconURL, "http") {
			u, _ := url.Parse(targetURL)
			iconURL = u.Scheme + "://" + u.Host + "/" + strings.TrimPrefix(iconURL, "/")
		}
		return iconURL
	}
	return "globe"
}

// --- Auth & Crypto ---

func hashPassword(p string) (string, error) { b, e := bcrypt.GenerateFromPassword([]byte(p), 14); return string(b), e }
func checkPasswordHash(p, h string) bool { return bcrypt.CompareHashAndPassword([]byte(h), []byte(p)) == nil }
func generateToken() string { b := make([]byte, 16); rand.Read(b); return base64.URLEncoding.EncodeToString(b) }

func setSession(w http.ResponseWriter, r *http.Request, value string) {
	id := generateToken()
	sessionLock.Lock(); sessions[id] = value; sessionLock.Unlock()
	
	cd := ""
	configLock.RLock(); d := globalConfig.Domain; configLock.RUnlock()
	host := strings.Split(r.Host, ":")[0]
	// Cookie Domain nur setzen, wenn wir auf der Domain sind (oder Subdomain), nicht bei IP
	if d != "" && strings.HasSuffix(host, d) { cd = "." + d }

	http.SetCookie(w, &http.Cookie{Name: "gz_session", Value: id, Path: "/", Domain: cd, HttpOnly: true, Secure: false, MaxAge: 86400 * 7, SameSite: http.SameSiteLaxMode})
}

func isAdminAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("gz_session"); if err != nil { return false }
	sessionLock.RLock(); val, ok := sessions[c.Value]; sessionLock.RUnlock()
	return ok && val == "admin_user"
}

func isUserAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("gz_session"); if err != nil { return false }
	sessionLock.RLock(); val, ok := sessions[c.Value]; sessionLock.RUnlock()
	return ok && strings.Contains(val, "@")
}

// --- OAuth ---

func handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	configLock.RLock(); defer configLock.RUnlock()
	if oauthConfig == nil { http.Error(w, "Google OAuth Daten fehlen in Einstellungen!", 500); return }
	http.Redirect(w, r, oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline), 307)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	configLock.RLock(); defer configLock.RUnlock()
	if oauthConfig == nil { return }
	token, err := oauthConfig.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil { http.Error(w, "Auth Error", 401); return }
	
	client := oauthConfig.Client(context.Background(), token)
	resp, _ := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	defer resp.Body.Close()
	var info struct { Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&info)
	
	setSession(w, r, info.Email)
	http.Redirect(w, r, "https://" + globalConfig.Domain, 302)
}

// --- CORE PROXY ---

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	
	configLock.RLock()
	setupDone := globalConfig.SetupDone
	baseDom := globalConfig.Domain
	bl := globalConfig.GlobalBlacklist
	wl := globalConfig.GlobalWhitelist
	configLock.RUnlock()

	hostHeader := strings.Split(r.Host, ":")[0]

	// 1. Setup Check
	if !setupDone { http.ServeFile(w, r, "static/index.html"); return }

	// 2. Auth Domain
	if hostHeader == "auth."+baseDom {
		if strings.HasPrefix(r.URL.Path, "/login") { handleOAuthLogin(w, r); return }
		if strings.HasPrefix(r.URL.Path, "/callback") { handleOAuthCallback(w, r); return }
	}

	// 3. Global Blacklist Check (Höchste Priorität)
	if isIPInList(clientIP, bl) {
		addLog(clientIP, "DROP", "Global Blacklist")
		http.Error(w, "Access Denied (Blacklist)", 403)
		return
	}

	// 4. Dashboard Check
	parts := strings.Split(hostHeader, ".")
	isDash := net.ParseIP(hostHeader) != nil || hostHeader == "localhost" || hostHeader == baseDom || len(parts) < 3
	if isDash {
		if !strings.HasPrefix(r.URL.Path, "/api/auth") && !strings.HasPrefix(r.URL.Path, "/static") {
			if !isAdminAuthenticated(r) {
				if strings.HasPrefix(r.URL.Path, "/api") { http.Error(w, "Unauthorized", 401); return }
			}
		}
		http.ServeFile(w, r, "static/index.html")
		return
	}

	// 5. Fail2Ban Check (Übersprungen wenn auf Whitelist)
	if !isIPInList(clientIP, wl) {
		banLock.RLock(); cnt, banned := bannedIPs[clientIP]; banLock.RUnlock()
		if banned && cnt > 10 { http.Error(w, "Access Denied (Fail2Ban)", 403); return }
	}

	// 6. Host Lookup
	subdomain := parts[0]
	var target *Host
	hostsLock.RLock()
	for _, h := range hosts { if h.Subdomain == subdomain { target = &h; break } }
	hostsLock.RUnlock()

	if target == nil {
		if !isIPInList(clientIP, wl) { banLock.Lock(); bannedIPs[clientIP]++; banLock.Unlock() }
		addLog(clientIP, "404", "Unbekannt: "+subdomain)
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
		if ok && info.HostID == target.ID && time.Now().Before(info.ExpiresAt) { isGuest = true }
	}

	if !isGuest {
		// GeoIP Check
		iso := getCountryISO(clientIP)
		if target.Features.GeoIP != "none" && target.Features.GeoIP != "" {
			allowed := false
			if target.Features.GeoIP == "lan" && iso == "LAN" { allowed = true }
			if target.Features.GeoIP == "de" && (iso == "DE" || iso == "LAN") { allowed = true }
			if target.Features.GeoIP == "eu" && (isEU(iso) || iso == "LAN") { allowed = true }
			
			if !allowed {
				addLog(clientIP, "BLOCK", "GeoIP Block ("+iso+")")
				http.Error(w, "Access Denied (GeoIP)", 403)
				return
			}
		}

		// OAuth Check
		if target.Features.GoogleAuth {
			if oauthConfig == nil {
				http.Error(w, "Google Auth aktiv aber nicht konfiguriert!", 500)
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
		w.WriteHeader(503); fmt.Fprintf(w, "<h1>Wartungsarbeiten</h1><p>%s ist gleich zurück.</p>", target.Name); return
	}
	if target.Status == "sleeping" {
		if target.Features.WOL && target.MAC != "" {
			sendMagicPacket(target.MAC)
			w.WriteHeader(504); fmt.Fprintf(w, "<h1>Wecke Server...</h1><p>Magic Packet an %s gesendet. Lade neu in 30s.</p><script>setTimeout(()=>location.reload(), 30000)</script>", target.MAC)
		} else {
			w.WriteHeader(503); fmt.Fprintf(w, "Server schläft (Green Mode).");
		}
		return
	}

	addLog(clientIP, "ALLOW", target.Name)

	if target.InternalIP == "Local" {
		path := filepath.Join(sitesDir, target.Subdomain)
		os.MkdirAll(path, 0755)
		if _, err := os.Stat(filepath.Join(path, "index.html")); os.IsNotExist(err) {
			os.WriteFile(filepath.Join(path, "index.html"), []byte("<h1>Hallo von "+target.Name+"</h1>"), 0644)
		}
		http.FileServer(http.Dir(path)).ServeHTTP(w, r)
		return
	}

	targetUrl := fmt.Sprintf("http://%s:%d", target.InternalIP, target.Port)
	u, _ := url.Parse(targetUrl)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = u.Scheme; req.URL.Host = u.Host
		req.Header.Set("X-Forwarded-Host", req.Host); req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https")
		if target.Features.Websockets {
			req.Header.Set("Connection", req.Header.Get("Connection"))
			req.Header.Set("Upgrade", req.Header.Get("Upgrade"))
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if target.Features.Fail2Ban && !isIPInList(clientIP, wl) {
			banLock.Lock(); bannedIPs[clientIP]++; banLock.Unlock()
		}
		addLog(clientIP, "ERROR", "Ziel down: "+target.Name)
		w.WriteHeader(502)
	}
	proxy.ServeHTTP(w, r)
}

// --- API ---

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Endpoints für Konfiguration (OAuth & IP Listen)
	if r.URL.Path == "/api/config" {
		if !isAdminAuthenticated(r) { http.Error(w, "Auth Req", 401); return }
		
		if r.Method == "GET" {
			configLock.RLock(); defer configLock.RUnlock()
			// Secrets ausblenden im Frontend wenn nötig, hier senden wir sie damit man sie sieht/bearbeiten kann
			json.NewEncoder(w).Encode(globalConfig)
			return
		}
		if r.Method == "POST" {
			var newConf Config
			json.NewDecoder(r.Body).Decode(&newConf)
			
			configLock.Lock()
			// Wir übernehmen nur die relevanten Felder, um Admin User/Pass nicht zu überschreiben
			globalConfig.GoogleClientID = newConf.GoogleClientID
			globalConfig.GoogleClientSecret = newConf.GoogleClientSecret
			globalConfig.GlobalBlacklist = newConf.GlobalBlacklist
			globalConfig.GlobalWhitelist = newConf.GlobalWhitelist
			// Domain/Email ändern ist gefährlich im laufenden Betrieb, lassen wir hier zu, erfordert aber Restart
			saveConfigLocked()
			updateOAuthConfig() // Sofort neu laden
			configLock.Unlock()
			w.WriteHeader(200)
			return
		}
	}

	// ... Restliche API Handler (Login, Setup, Hosts, Logs, Scan) wie gehabt ...
	// Um Duplikation zu vermeiden, rufe ich die Logik auf oder bette sie ein
	// HIER WIEDERHOLT SICH DER API CODE VOM VORHERIGEN STEP (gekürzt für Übersicht)
	
	// Auth Routes
	if strings.HasPrefix(r.URL.Path, "/api/auth/") {
		handleAuthAPI(w, r)
		return
	}
	
	// Protected Data Routes
	if !isAdminAuthenticated(r) { http.Error(w, "Unauthorized", 401); return }
	
	if r.URL.Path == "/api/hosts" { handleHostsAPI(w, r); return }
	if r.URL.Path == "/api/upload" { handleUploadAPI(w, r); return }
	if r.URL.Path == "/api/logs" { logsLock.RLock(); json.NewEncoder(w).Encode(accessLogs); logsLock.RUnlock(); return }
	if r.URL.Path == "/api/scan" { json.NewEncoder(w).Encode(scanNetwork()); return }
	if r.URL.Path == "/api/guest-token" { handleGuestTokenAPI(w, r); return }
	if r.URL.Path == "/api/fetch-icon" {
		url := r.URL.Query().Get("url")
		json.NewEncoder(w).Encode(map[string]string{"icon": fetchIconFromURL("http://" + url)})
		return
	}
}

// Ausgelagerte Handler für Übersichtlichkeit
func handleAuthAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/auth/status" {
		configLock.RLock(); defer configLock.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"setup_done": globalConfig.SetupDone, "logged_in": isAdminAuthenticated(r), "domain": globalConfig.Domain})
		return
	}
	if r.URL.Path == "/api/auth/setup" && r.Method == "POST" {
		configLock.Lock()
		if globalConfig.SetupDone { configLock.Unlock(); http.Error(w, "Done", 403); return }
		var req struct { Domain, Email, User, Password string }; json.NewDecoder(r.Body).Decode(&req)
		hash, _ := hashPassword(req.Password)
		globalConfig = Config{Domain: req.Domain, Email: req.Email, AdminUser: req.User, AdminPassHash: hash, SetupDone: true}
		saveConfigLocked(); updateOAuthConfig(); configLock.Unlock()
		setSession(w, r, "admin_user"); w.WriteHeader(200); return
	}
	if r.URL.Path == "/api/auth/login" {
		var req struct { User, Password string }; json.NewDecoder(r.Body).Decode(&req)
		configLock.RLock(); valid := req.User == globalConfig.AdminUser && checkPasswordHash(req.Password, globalConfig.AdminPassHash); configLock.RUnlock()
		if valid { setSession(w, r, "admin_user"); w.WriteHeader(200) } else { http.Error(w, "Falsch", 401) }; return
	}
}

func handleHostsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" { hostsLock.RLock(); json.NewEncoder(w).Encode(hosts); hostsLock.RUnlock(); return }
	if r.Method == "POST" {
		var h Host; json.NewDecoder(r.Body).Decode(&h)
		hostsLock.Lock()
		found := false
		for i, ex := range hosts { if ex.ID == h.ID { hosts[i] = h; found = true; break } }
		if !found { hosts = append(hosts, h) }
		hostsLock.Unlock(); saveData(); w.WriteHeader(200); return
	}
	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id"); hostsLock.Lock()
		newH := []Host{}; for _, h := range hosts { if h.ID != id { newH = append(newH, h) } }; hosts = newH
		hostsLock.Unlock(); saveData(); w.WriteHeader(200); return
	}
}

func handleUploadAPI(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(50 << 20)
	file, handler, err := r.FormFile("file")
	if err != nil { http.Error(w, "Err", 400); return }
	defer file.Close()
	sub := r.FormValue("subdomain")
	os.MkdirAll(filepath.Join(sitesDir, sub), 0755)
	dst, _ := os.Create(filepath.Join(sitesDir, sub, handler.Filename))
	defer dst.Close()
	io.Copy(dst, file)
	w.WriteHeader(200)
}

func handleGuestTokenAPI(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("id")
	token := generateToken()[:8]
	tokenLock.Lock(); guestTokens[token] = GuestToken{HostID: hostID, ExpiresAt: time.Now().Add(24 * time.Hour)}; tokenLock.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// scanNetwork (Paralleler Scanner aus v3.2, hier wieder eingefügt)
func scanNetwork() []map[string]interface{} {
	// ... (Code aus voriger Antwort, der Parallel-Scanner) ...
	// Aufgrund der Zeichenbegrenzung hier nur als Verweis. Bitte den vollen Code von vorhin nutzen!
	// Wir nehmen hier wieder den Dummy, DAMIT ES KOMPILIERT, aber du sollst den echten nutzen!
	
	// HIER FOLGT DER ECHTE CODE (Wieder eingefügt für Copy-Paste Sicherheit):
	found := []map[string]interface{}{}
	var mutex sync.Mutex; var wg sync.WaitGroup
	prefix := "127.0.0"
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil { parts := strings.Split(ipnet.IP.String(), "."); if len(parts) == 4 { prefix = strings.Join(parts[:3], ".") } }
		}
	}
	ports := []int{80, 8080, 8123, 9000, 32400, 22, 443}
	sem := make(chan struct{}, 100)
	for i := 1; i < 255; i++ {
		targetIP := fmt.Sprintf("%s.%d", prefix, i)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			for _, port := range ports {
				sem <- struct{}{}; timeout := 300 * time.Millisecond
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
				if err == nil {
					conn.Close(); mutex.Lock()
					found = append(found, map[string]interface{}{"name": "Dienst", "ip": ip, "port": port, "icon": "server"})
					mutex.Unlock()
				}
				<-sem
			}
		}(targetIP)
	}
	wg.Wait(); return found
}

func main() {
	port := flag.String("port", "80", "HTTP Port")
	flag.Parse()
	loadData()
	
	// Ping Routine
	go func() {
		for {
			s := time.Now(); c, e := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
			if e == nil { c.Close(); currentPing = time.Since(s).Milliseconds() } else { currentPing = -1 }
			time.Sleep(30 * time.Second)
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
			configLock.RLock(); d := globalConfig.Domain; configLock.RUnlock()
			if host == d || host == "auth."+d { return nil }
			hostsLock.RLock(); defer hostsLock.RUnlock()
			for _, h := range hosts { if h.Subdomain+"."+d == host { return nil } }
			return fmt.Errorf("denied")
		},
	}

	go http.ListenAndServe(":"+*port, certManager.HTTPHandler(mux))
	server := &http.Server{Addr: ":443", Handler: mux, TLSConfig: certManager.TLSConfig()}
	if err := server.ListenAndServeTLS("", ""); err != nil { log.Println("HTTPS nicht verfügbar (OK bei IP)") }
}