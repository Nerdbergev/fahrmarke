package version

import (
	"log"
	"strconv"
	"strings"

	db "github.com/Nerdberg/fahrmarke/dblib"
)

const CurrentVersion = "1.3.0"

func compareVersions(v1, v2 string) int {
	v1 = strings.Replace(v1, ".", "", -1)
	v2 = strings.Replace(v2, ".", "", -1)
	versions1, err := strconv.Atoi(v1)
	if err != nil {
		return 0
	}
	versions2, err := strconv.Atoi(v2)
	if err != nil {
		return 0
	}
	if versions1 < versions2 {
		return -1
	} else if versions1 > versions2 {
		return 1
	}
	return 0
}

func UpdateVersion() {
	localversion, err := db.GetSetting("Version")
	if err != nil {
		log.Fatal("Error retrieving Version setting:", err)
	}
	for compareVersions(localversion, CurrentVersion) == -1 {
		log.Println("Updating software from version", localversion, "to", CurrentVersion)
		if compareVersions(localversion, "1.3.0") == -1 {
			db.SetSetting("UseHTTPS", "true")
			db.SetSetting("Version", "1.3.0")
			localversion = "1.3.0"
		}
	}
	log.Println("Software version is up to date:", CurrentVersion)
}
