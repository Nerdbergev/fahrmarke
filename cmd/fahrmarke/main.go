package main

import (
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Nerdberg/fahrmarke/arplib"
	db "github.com/Nerdberg/fahrmarke/dblib"
	"github.com/Nerdberg/fahrmarke/web"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/spf13/pflag"
)

func main() {
	datapath := pflag.String("datapath", "./", "database path")
	pflag.Parse()

	dbpath := filepath.Join(*datapath, "fahrmarke.db")
	err := db.InitDB(dbpath)
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}

	scantime, err := db.GetSetting("Scantime")
	if err != nil {
		log.Fatal("Error retrieving Scantime setting:", err)
	}
	log.Println("Scantime setting value:", scantime)

	interfacename, err := db.GetSetting("Interface")
	if err != nil {
		log.Fatal("Error retrieving Interface setting:", err)
	}
	log.Println("Interface setting value:", interfacename)

	rangepref, err := db.GetSetting("Range")
	if err != nil {
		log.Fatal("Error retrieving Range setting:", err)
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

	web.GetRouter(r, *datapath)

	log.Println("Starting server on port " + listenPort)
	err = http.ListenAndServe(":"+listenPort, r)
	if err != nil {
		log.Fatal("Error starting server:", err)
	}

}
