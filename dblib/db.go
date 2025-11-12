package db

import (
	"database/sql"
	"errors"
	"log"

	"github.com/jmoiron/sqlx"

	_ "github.com/mattn/go-sqlite3"
)

var db *sqlx.DB

func InitDB(dbpath string) error {
	var err error

	db, err = sqlx.Open("sqlite3", dbpath)
	if err != nil {
		return errors.New("Failed to open database: " + err.Error())
	}

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='SETTINGS';", nil)
	if err != nil {
		return errors.New("Failed to query database: " + err.Error())
	}
	defer rows.Close()

	if !rows.Next() {
		log.Println("Settings table not found, creating database")
		err = createSchema()
		if err != nil {
			return errors.New("Error creating DB: " + err.Error())
		}
	}

	return nil
}

func createSchema() error {
	// Create your database tables here
	createTableSQL := `
				BEGIN TRANSACTION;

				-- Table: SETTINGS
				CREATE TABLE SETTINGS (
					KEY   TEXT PRIMARY KEY
							UNIQUE
							NOT NULL,
					VALUE TEXT NOT NULL
				);

				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Range',
										'192.168.2.0/24'
									);

				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Version',
										'1.0.0'
									);

				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Scantime',
										'5'
									);

				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Theme',
										'fahrmarke'
									);


				-- Table: USER
				CREATE TABLE USER (
					ID       INTEGER     PRIMARY KEY AUTOINCREMENT
										NOT NULL,
					USERNAME TEXT        NOT NULL
										UNIQUE,
					SHOWNAME  TEXT        NOT NULL,
					PASSWORD TEXT        NOT NULL,
					ADMIN    INTEGER (1) NOT NULL
				);

				INSERT INTO USER (
									ID,
									USERNAME,
									PASSWORD,
									ADMIN
								)
								VALUES (
									1,
									'admin',
									'$2a$15$Gv79204y0ZLGPkaNbHKFxOvXk7BihD9nOVFTksSDo9hJsQcLB1Ziq',
									1
								);


				-- Table: USER_ATTRIBUTES
				CREATE TABLE USER_ATTRIBUTES (
					ID   INTEGER PRIMARY KEY AUTOINCREMENT
								NOT NULL,
					Name TEXT    NOT NULL
								UNIQUE
				);


				-- Table: USER_HAS_ATTRIBUTES
				CREATE TABLE USER_HAS_ATTRIBUTES (
					ATTRIBUTE_ID INTEGER REFERENCES USER_ATTRIBUTES (ID) ON DELETE CASCADE
																		ON UPDATE CASCADE
										NOT NULL,
					USER_ID      INTEGER REFERENCES USER (ID) ON DELETE CASCADE
															ON UPDATE CASCADE
										NOT NULL,
					VALUE        TEXT    NOT NULL,
					PRIMARY KEY (
						ATTRIBUTE_ID,
						USER_ID
					)
				);


				COMMIT TRANSACTION;
				PRAGMA foreign_keys = on;
	`

	_, err := db.Exec(createTableSQL)
	return err
}

func CloseDB() error {
	if db != nil {
		err := db.Close()
		if err != nil {
			return errors.New("Failed to close database: " + err.Error())
		}
	}
	return nil
}

func GetSetting(key string) (string, error) {
	var value string
	err := db.Get(&value, "SELECT VALUE FROM SETTINGS WHERE KEY = ?", key)
	if err != nil {
		return "", errors.New("Failed to get setting: " + err.Error())
	}
	return value, nil
}

type User struct {
	ID       int            `db:"ID" json:"id"`
	Username string         `db:"USERNAME" json:"username"`
	Showname sql.NullString `db:"SHOWNAME" json:"showname"`
}

func GetUsers() ([]User, error) {
	var users []User
	err := db.Select(&users, "SELECT ID, USERNAME, SHOWNAME FROM USERS")
	if err != nil {
		return nil, errors.New("Failed to get users: " + err.Error())
	}
	return users, nil
}

func GetUserAttributes(userid int) (map[string]string, error) {
	attributes := make(map[string]string)
	rows, err := db.Query("SELECT UA.Name, UHA.VALUE FROM USER_HAS_ATTRIBUTES UHA JOIN USER_ATTRIBUTES UA ON UHA.ATTRIBUTE_ID = UA.ID WHERE UHA.USER_ID = ?", userid)
	if err != nil {
		return nil, errors.New("Failed to get user attributes: " + err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, errors.New("Failed to scan user attributes: " + err.Error())
		}
		attributes[name] = value
	}

	return attributes, nil
}

type Device struct {
	MACAddress string `db:"MACADDRESS" json:"macaddress"`
	DeviceName string `db:"DEVICENAME" json:"devicename"`
}

func GetUserDevices(userid int) ([]Device, error) {
	var devices []Device
	err := db.Select(&devices, "SELECT MACAddress, DeviceName FROM DEVICES WHERE USER_ID = ?", userid)
	if err != nil {
		return nil, errors.New("Failed to get user devices: " + err.Error())
	}
	return devices, nil
}
