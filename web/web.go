package web

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/Nerdberg/fahrmarke/arplib"
	db "github.com/Nerdberg/fahrmarke/dblib"
	"github.com/go-chi/chi"
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 15

type errorResponse struct {
	Httpstatus   string `json:"httpstatus"`
	Errormessage string `json:"errormessage"`
	RequestURL   string `json:"requesturl"`
}

func apierror(w http.ResponseWriter, r *http.Request, err string, httpcode int) {
	log.Println(err)
	er := errorResponse{strconv.Itoa(httpcode), err, r.URL.Path}
	j, erro := json.Marshal(&er)
	if erro != nil {
		return
	}
	http.Error(w, string(j), httpcode)
}

func webError(w http.ResponseWriter, err string, publicerr string, httpcode int) {
	if publicerr == "" {
		publicerr = err
	}
	log.Println(err)
	http.Error(w, publicerr, httpcode)
}

type User struct {
	ID         int               `json:"-"`
	Username   string            `json:"-"`
	Showname   string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
	Devices    []db.Device       `json:"-"`
	Online     bool              `json:"online"`
}

func (u *User) LoadDetails(devices, attributes bool) error {
	if devices {
		devs, err := db.GetUserDevices(u.ID)
		if err != nil {
			return errors.New("Failed to get user devices: " + err.Error())
		}
		u.Devices = devs
	}
	if attributes {
		attrs, err := db.GetUserAttributes(u.ID)
		if err != nil {
			return errors.New("Failed to get user attributes: " + err.Error())
		}
		u.Attributes = attrs
	}
	return nil
}

func dbUserToUser(dbUser db.User) User {
	return User{
		ID:       dbUser.ID,
		Username: dbUser.Username,
		Showname: dbUser.GetShowname(),
	}
}

func getUsers(devices, attributes bool) ([]User, error) {
	usersdb, err := db.GetUsers()
	if err != nil {
		return nil, errors.New("Failed to get users from DB: " + err.Error())
	}
	var users []User
	for _, u := range usersdb {
		user := dbUserToUser(u)
		if err := user.LoadDetails(devices, attributes); err != nil {
			return nil, errors.New("Failed to load user details: " + err.Error())
		}
		user.Online = arplib.CheckUserIsPresent(u.ID)
		users = append(users, user)
	}
	return users, nil
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	getDevices := false
	getAttributes := true
	users, err := getUsers(getDevices, getAttributes)
	if err != nil {
		apierror(w, r, "Failed to get users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func getAPIRouter(r *chi.Mux) {
	r.Route("/api", func(r chi.Router) {
		r.Get("/users", getUsersHandler)
	})
}

type Theme struct {
	Name      string
	Tpl       *template.Template
	StaticDir string
}

var currentTheme atomic.Value // stores *Theme

func getActiveTheme() *Theme {
	return currentTheme.Load().(*Theme)
}

// load from disk or embed based on name
func loadTheme(base, name string) (*Theme, error) {
	dir := filepath.Join(base, "themes", name)

	// ensure dir exists
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, errors.New("theme directory not found: " + dir)
	}

	// parse templates: themes/<name>/templates/*.html
	tmplDir := filepath.Join(dir, "templates")
	pattern := filepath.Join(tmplDir, "*.html")
	tpl, err := template.ParseGlob(pattern)
	if err != nil {
		return nil, errors.New("failed to parse templates for theme " + name + ": " + err.Error())
	}

	staticPath := filepath.Join(dir, "static")
	if fi, err := os.Stat(staticPath); err != nil || !fi.IsDir() {
		return nil, errors.New("static directory not found for theme " + name + ": " + staticPath)
	}

	return &Theme{Name: name, Tpl: tpl, StaticDir: staticPath}, nil
}

// read 'Theme' from SETTINGS, load and swap
func reloadThemeFromDB(datadir string) (*Theme, error) {
	name, err := db.GetSetting("Theme")
	if err != nil {
		return nil, errors.New("Failed to get Theme setting: " + err.Error())
	}
	th, err := loadTheme(datadir, name)
	if err != nil {
		return nil, err
	}
	currentTheme.Store(th)
	return th, nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	switch r.Method {
	case http.MethodGet:
		err := th.Tpl.ExecuteTemplate(w, "register.html", nil)
		if err != nil {
			webError(w, "Failed to render template: "+err.Error(), "", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		username := strings.TrimSpace(r.FormValue("username"))
		p1 := r.FormValue("password")
		p2 := r.FormValue("password2")

		if username == "" || p1 == "" || p1 != p2 {
			webError(w, "Invalid input", "", http.StatusBadRequest)
			return
		}

		// already exists?
		if _, err := db.GetUserByUsername(username); err == nil {
			webError(w, "User already exists", "", http.StatusConflict)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(p1), bcryptCost)
		if err != nil {
			webError(w, "Error generating hash: "+err.Error(), "User creation failed", http.StatusInternalServerError)
			return
		}

		id, err := db.CreateUser(username, string(hash), 0)
		if err != nil {
			webError(w, "Error creating user: "+err.Error(), "User creation failed", http.StatusInternalServerError)
			return
		}

		// Session
		sid, s, err := newSession(id)
		if err != nil {
			webError(w, "Creating new Session failed:"+err.Error(), "User creation failed", http.StatusInternalServerError)
			return
		}
		session.Set(sid, s)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(24 * time.Hour / time.Second),
			HttpOnly: true,
		})

		http.Redirect(w, r, "/me", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	switch r.Method {
	case http.MethodGet:
		err := th.Tpl.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			webError(w, "Failed to render template: "+err.Error(), "", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		u, err := db.GetUserByUsername(username)
		if err != nil {
			webError(w, "Error finding user:"+err.Error(), "Wrong username or password", http.StatusUnauthorized)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
			webError(w, "Error comparing password:"+err.Error(), "Wrong username or password", http.StatusUnauthorized)
			return
		}

		sid, s, err := newSession(u.ID)
		if err != nil {
			webError(w, "Error creating session:"+err.Error(), "Wrong username or password", http.StatusInternalServerError)
			return
		}
		session.Set(sid, s)

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			MaxAge:   int(24 * time.Hour / time.Second),
			HttpOnly: true,
		})

		http.Redirect(w, r, "/me", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		destroySession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	uidVal := r.Context().Value(ctxUserID)
	if uidVal == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := uidVal.(int)

	u, err := db.GetUserByID(userID)
	if err != nil {
		webError(w, "Failed to get user: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	user := dbUserToUser(u)
	getDevices := true
	getAttributes := true
	err = user.LoadDetails(getDevices, getAttributes)
	if err != nil {
		webError(w, "Failed to load user details: "+err.Error(), "", http.StatusInternalServerError)
		return
	}

	err = th.Tpl.ExecuteTemplate(w, "profile.html", user)
	if err != nil {
		webError(w, "Failed to render template: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
}

func setShownameHandler(w http.ResponseWriter, r *http.Request) {
	uidVal := r.Context().Value(ctxUserID)
	if uidVal == nil {
		webError(w, "Not logged in", "", http.StatusUnauthorized)
		return
	}
	userID := uidVal.(int)
	name := strings.TrimSpace(r.FormValue("showname"))
	if name == "" {
		webError(w, "Showname empty", "", http.StatusBadRequest)
		return
	}
	if err := db.SetUserShowname(userID, name); err != nil {
		webError(w, "Error setting Showname: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}

const saltSize = 16

func generateRandomSalt(saltSize int) string {

	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	return string(salt)
}

func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	uidVal := r.Context().Value(ctxUserID)
	if uidVal == nil {
		webError(w, "Not logged in", "", http.StatusUnauthorized)
		return
	}
	userID := uidVal.(int)
	macStr := r.FormValue("mac")
	mac, err := net.ParseMAC(strings.TrimSpace(macStr))
	if err != nil {
		webError(w, "Invalid MAC address", "", http.StatusBadRequest)
		return
	}
	salt := generateRandomSalt(saltSize)
	hashedMac := arplib.HashMAC(mac, salt)
	name := strings.TrimSpace(r.FormValue("name"))
	if err := db.AddOrUpdateDevice(userID, hashedMac, name, salt); err != nil { // in dblib hinzufügen
		webError(w, "Error adding or updating device: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}

func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	uidVal := r.Context().Value(ctxUserID)
	if uidVal == nil {
		webError(w, "Not logged in", "", http.StatusUnauthorized)
		return
	}
	userID := uidVal.(int)
	macStr := r.FormValue("mac")
	mac, err := net.ParseMAC(strings.TrimSpace(macStr))
	if err != nil {
		webError(w, "Invalid MAC address", "", http.StatusBadRequest)
		return
	}
	if err := db.DeleteDevice(userID, mac.String()); err != nil { // in dblib hinzufügen
		webError(w, "Error deleting device: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}

func setAttributeHandler(w http.ResponseWriter, r *http.Request) {
	uidVal := r.Context().Value(ctxUserID)
	if uidVal == nil {
		webError(w, "Not logged in", "", http.StatusUnauthorized)
		return
	}
	userID := uidVal.(int)
	key := strings.TrimSpace(r.FormValue("key"))
	val := strings.TrimSpace(r.FormValue("value"))
	if key == "" {
		webError(w, "Key empty", "", http.StatusBadRequest)
		return
	}
	if err := db.SetUserAttribute(userID, key, val); err != nil {
		webError(w, "Error setting attribute: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}

func webInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	getDevices := false
	getAttributes := true
	users, err := getUsers(getDevices, getAttributes)
	if err != nil {
		webError(w, "Failed to load users: "+err.Error(), "", http.StatusInternalServerError)
		return
	}
	if err := th.Tpl.ExecuteTemplate(w, "index.html", users); err != nil {
		webError(w, "Failed to render template: "+err.Error(), "", http.StatusInternalServerError)
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	fs := http.FileServer(http.Dir(th.StaticDir))
	http.StripPrefix("/static/", fs).ServeHTTP(w, r)
}

var datadir string

func getWebRouter(r *chi.Mux) {
	_, err := reloadThemeFromDB(datadir) // initial load
	if err != nil {
		log.Fatal("Failed to load initial theme: ", err)
	}
	hmac, err := db.GetSetting("SessionHMACKey")
	if err != nil {
		log.Fatal("Failed to get SessionHMACKey: ", err)
	}
	if hmac != "" {
		sessionHMACKey = []byte(hmac)
	} else {
		log.Fatal("No SessionHMACKey found. Please set in Database")
	}
	r.Get("/favicon.ico", staticHandler)
	r.Get("/static/*", staticHandler)

	// Auth Routen
	r.Get("/register", registerHandler)
	r.Post("/register", registerHandler)
	r.Get("/login", loginHandler)
	r.Post("/login", loginHandler)
	r.Post("/logout", logoutHandler)

	// Private Routen
	r.Group(func(pr chi.Router) {
		pr.Use(RequireAuth)
		pr.Get("/me", profileHandler)
		pr.Post("/me/showname", setShownameHandler)
		pr.Post("/me/devices/add", addDeviceHandler)
		pr.Post("/me/devices/delete", deleteDeviceHandler)
		pr.Post("/me/attributes/set", setAttributeHandler)
	})

	r.Get("/", webInterfaceHandler)
}

func GetRouter(r *chi.Mux, dir string) {
	r.Use(SessionMiddleware)
	datadir = dir
	csrfKeySetting, err := db.GetSetting("CSRFKey")
	if err != nil {
		log.Fatal("Failed to get CSRFKey: ", err)
	}
	if csrfKeySetting == "" {
		log.Fatal("No CSRFKey found. Please set in Database")
	}
	csrfKey := []byte(csrfKeySetting)

	r.Use(csrf.Protect(
		csrfKey,
	))

	getAPIRouter(r)
	getWebRouter(r)
}
