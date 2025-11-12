package web

import (
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/Nerdberg/fahrmarke/arplib"
	db "github.com/Nerdberg/fahrmarke/dblib"
	"github.com/go-chi/chi"
)

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

type User struct {
	ID         int               `json:"-"`
	Username   string            `json:"-"`
	Showname   string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
	Devices    []db.Device       `json:"-"`
	Online     bool              `json:"online"`
}

func (u *User) LoadDetails() error {
	if u.Showname == "" {
		u.Showname = u.Username
	}
	devs, err := db.GetUserDevices(u.ID)
	if err != nil {
		return errors.New("Failed to get user devices: " + err.Error())
	}
	u.Devices = devs
	attrs, err := db.GetUserAttributes(u.ID)
	if err != nil {
		return errors.New("Failed to get user attributes: " + err.Error())
	}
	u.Attributes = attrs
	return nil
}

func getUsers() ([]User, error) {
	usersdb, err := db.GetUsers()
	if err != nil {
		return nil, errors.New("Failed to get users from DB: " + err.Error())
	}
	var users []User
	for _, u := range usersdb {
		user := User{
			ID:       u.ID,
			Username: u.Username,
		}
		if u.Showname.Valid {
			user.Showname = u.Showname.String
		}
		if err := user.LoadDetails(); err != nil {
			return nil, errors.New("Failed to load user details: " + err.Error())
		}
		user.Online = false
		for _, dev := range user.Devices {
			mac, err := net.ParseMAC(dev.MACAddress)
			if err != nil {
				log.Println("Failed to parse MAC address:", err, "for device:", dev.MACAddress)
				continue
			}
			if arplib.CheckMACisOnline(mac) {
				user.Online = true
				break
			}
		}
		users = append(users, user)
	}
	return users, nil
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := getUsers()
	if err != nil {
		apierror(w, r, "Failed to get users: "+err.Error(), 500)
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

func webInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	users, err := getUsers()
	if err != nil {
		http.Error(w, "Failed to load users: "+err.Error(), 500)
		return
	}
	if err := th.Tpl.ExecuteTemplate(w, "index.html", users); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	th := getActiveTheme()
	fs := http.FileServer(http.Dir(th.StaticDir))
	http.StripPrefix("/static/", fs).ServeHTTP(w, r)
}

func getWebRouter(r *chi.Mux, datadir string) {
	_, err := reloadThemeFromDB(datadir) // initial load
	if err != nil {
		log.Fatal("Failed to load initial theme: ", err)
	}
	r.Get("/favicon.ico", staticHandler)
	r.Get("/static/*", staticHandler)
	r.Get("/", webInterfaceHandler)
}

func GetRouter(r *chi.Mux, datadir string) {
	getAPIRouter(r)
	getWebRouter(r, datadir)
}
