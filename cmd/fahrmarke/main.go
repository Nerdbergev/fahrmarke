package main

import (
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Nerdberg/fahrmarke/arplib"
	db "github.com/Nerdberg/fahrmarke/dblib"
	version "github.com/Nerdberg/fahrmarke/versionlib"
	"github.com/Nerdberg/fahrmarke/web"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/httprate"
	"github.com/spf13/pflag"
)

func main() {
	datapath := pflag.String("datapath", "./", "Path for database and themes")
	pflag.Parse()
	absPath, err := filepath.Abs(*datapath)
	log.Println("Using datapath: ", absPath)
	if err != nil {
		log.Fatal("Error determining absolute path:", err)
	}
	dbpath := filepath.Join(absPath, "fahrmarke.db")
	err = db.InitDB(dbpath)
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}

	version.UpdateVersion()

	scantime, err := db.GetSetting("Scantime")
	if err != nil {
		log.Fatal("Error retrieving Scantime setting:", err)
	}
	log.Println("Scantime setting value:", scantime)

	interfacename, err := db.GetSetting("Interface")
	if err != nil {
		log.Fatal("Error retrieving Interface setting:", err)
	}
	interfacefromdb := false
	rangepref := ""
	if interfacename != "" {
		interfacefromdb = true
	}
	if !interfacefromdb {
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatal("Error retrieving network interfaces:", err)
		}
		for _, iface := range interfaces {
			if (iface.Flags&net.FlagUp != 0) && (iface.Flags&net.FlagLoopback == 0) {
				interfacename = iface.Name
				log.Println("No interface set in settings, using first active non-loopback interface:", interfacename)
				adresses, err := iface.Addrs()
				if err != nil {
					log.Fatal("Error retrieving interface addresses:", err)
				}
				rangepref = adresses[0].String()
				_, ipNet, err := net.ParseCIDR(rangepref)
				if err != nil {
					log.Fatal("Error parsing CIDR:", err)
				}
				rangepref = ipNet.String()
				log.Println("Using interface", interfacename, "with address", rangepref)
				break
			}
		}
	}
	log.Println("Interface setting value:", interfacename)

	if interfacefromdb {
		rangepref, err = db.GetSetting("Range")
		if err != nil {
			log.Fatal("Error retrieving Range setting:", err)
		}
	}
	log.Println("Range setting value:", rangepref)

	scantimeInt, err := strconv.Atoi(scantime)
	if err != nil {
		log.Fatal("Error converting Scantime setting to int:", err)
	}
	arplib.StartScanTicker(interfacename, rangepref, time.Duration(scantimeInt)*time.Minute)

	listenPort, err := db.GetSetting("Port")
	if err != nil {
		log.Fatal("Error retrieving Port setting:", err)
	}
	log.Println("Port setting value:", listenPort)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(httprate.Limit(
		10,             // requests
		10*time.Second, // per duration
		httprate.WithKeyFuncs(httprate.KeyByIP, httprate.KeyByEndpoint),
	))

	web.GetRouter(r, absPath)

	useHTTPS, err := db.GetSetting("UseHTTPS")
	if err != nil {
		log.Fatal("Error retrieving UseHTTPS setting:", err)
	}

	if useHTTPS == "true" {
		certPath := filepath.Join(absPath, "cert.pem")
		keyPath := filepath.Join(absPath, "key.pem")
		log.Println("Starting HTTPS server on port " + listenPort)
		err = http.ListenAndServeTLS(":"+listenPort, certPath, keyPath, r)
		if err != nil {
			log.Fatal("Error starting HTTPS server:", err)
		}
	} else {
		log.Println("Starting server on port " + listenPort)
		err = http.ListenAndServe(":"+listenPort, r)
		if err != nil {
			log.Fatal("Error starting server:", err)
		}
	}

}
