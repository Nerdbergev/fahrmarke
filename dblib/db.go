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
				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Interface',
										'eth0'
									);
				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'Port',
										'7070'
									);
				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'SessionHMAC',
										''
									);
				INSERT INTO SETTINGS (
										KEY,
										VALUE
									)
									VALUES (
										'CSRFKey',
										''
									);

				-- Table: USER
				CREATE TABLE USER (
					ID       INTEGER     PRIMARY KEY AUTOINCREMENT
										NOT NULL,
					USERNAME TEXT        NOT NULL
										UNIQUE,
					SHOWNAME  TEXT,
					PASSWORD TEXT        NOT NULL,
					ADMIN    INTEGER (1) NOT NULL DEFAULT (0) 
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

				-- Table: DEVICES
				CREATE TABLE DEVICES (
					MACADDRESS TEXT (64) PRIMARY KEY
										NOT NULL,
					SALT       TEXT (16) NOT NULL,
					DEVICENAME,
					USER_ID              REFERENCES USERS (ID) ON DELETE CASCADE
															ON UPDATE CASCADE
										NOT NULL
				);


				-- Index: sqlite_autoindex_DEVICES_1
				CREATE UNIQUE INDEX sqlite_autoindex_DEVICES_1 ON DEVICES (
					MACADDRESS COLLATE BINARY
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
	Password string         `db:"PASSWORD" json:"-"`
	Admin    int            `db:"ADMIN" json:"-"`
}

func (u *User) GetShowname() string {
	result := u.Username
	if u.Showname.Valid {
		if u.Showname.String != "" {
			result = u.Showname.String
		}
	}
	return result
}

func CreateUser(username string, password string, admin int) (int, error) {
	result, err := db.Exec("INSERT INTO USERS (USERNAME, PASSWORD, ADMIN) VALUES (?, ?, ?)", username, password, admin)
	if err != nil {
		return 0, errors.New("Failed to create user: " + err.Error())
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, errors.New("Failed to retrieve new user ID: " + err.Error())
	}
	return int(id), nil
}

func GetUsers() ([]User, error) {
	var users []User
	err := db.Select(&users, "SELECT ID, USERNAME, SHOWNAME FROM USERS")
	if err != nil {
		return nil, errors.New("Failed to get users: " + err.Error())
	}
	return users, nil
}

func GetUserByID(userid int) (User, error) {
	var user User
	err := db.Get(&user, "SELECT ID, USERNAME, SHOWNAME FROM USERS WHERE ID = ?", userid)
	if err != nil {
		return User{}, errors.New("Failed to get user by ID: " + err.Error())
	}
	return user, nil
}

func GetUserByUsername(username string) (User, error) {
	var user User
	err := db.Get(&user, "SELECT * FROM USERS WHERE USERNAME = ?", username)
	if err != nil {
		return User{}, errors.New("Failed to get user by username: " + err.Error())
	}
	return user, nil
}

func GetUserAttributes(userid int) (map[string]string, error) {
	var attributeNames []string
	attributes := make(map[string]string)
	err := db.Select(&attributeNames, "Select Name FROM USER_ATTRIBUTES")
	if err != nil {
		return nil, errors.New("Failed to get attribute names: " + err.Error())
	}
	for _, name := range attributeNames {
		attributes[name] = ""
	}
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

func SetUserShowname(userid int, showname string) error {
	_, err := db.Exec("UPDATE USERS SET SHOWNAME = ? WHERE ID = ?", showname, userid)
	if err != nil {
		return errors.New("Failed to set user showname: " + err.Error())
	}
	return nil
}

func SetUserAttribute(userid int, name string, value string) error {
	var attributeID int
	err := db.Get(&attributeID, "SELECT ID FROM USER_ATTRIBUTES WHERE Name = ?", name)
	if err != nil {
		return errors.New("Attribute not found: " + err.Error())
	}
	_, err = db.Exec("INSERT OR REPLACE INTO USER_HAS_ATTRIBUTES (ATTRIBUTE_ID, USER_ID, VALUE) VALUES (?, ?, ?)", attributeID, userid, value)
	if err != nil {
		return errors.New("Failed to set user attribute: " + err.Error())
	}
	return nil
}

type Device struct {
	UserID       int            `db:"USER_ID" json:"-"`
	MACAddress   string         `db:"MACADDRESS" json:"macaddress"`
	DeviceNameDB sql.NullString `db:"DEVICENAME" json:"-"`
	DeviceName   string         `json:"devicename"`
	Salt         string         `db:"SALT" json:"-"`
}

func GetUserDevices(userid int) ([]Device, error) {
	var devices []Device
	err := db.Select(&devices, "SELECT MACAddress, DeviceName FROM DEVICES WHERE USER_ID = ?", userid)
	if err != nil {
		return nil, errors.New("Failed to get user devices: " + err.Error())
	}
	for i := range devices {
		if devices[i].DeviceNameDB.Valid {
			devices[i].DeviceName = devices[i].DeviceNameDB.String
		}
	}
	return devices, nil
}

func GetDevicesSparse() ([]Device, error) {
	var devices []Device
	err := db.Select(&devices, "SELECT USER_ID, MACAddress, SALT FROM DEVICES")
	if err != nil {
		return nil, errors.New("Failed to get devices: " + err.Error())
	}
	return devices, nil
}

func AddOrUpdateDevice(userid int, macaddress string, devicename string, salt string) error {
	var deviceID int
	err := db.Get(&deviceID, "SELECT ID FROM DEVICES WHERE MACADDRESS = ? AND USER_ID = ?", macaddress, userid)
	if err != nil {
		// Device does not exist, insert new
		_, err = db.Exec("INSERT INTO DEVICES (USER_ID, MACADDRESS, DEVICENAME, SALT) VALUES (?, ?, ?, ?)", userid, macaddress, devicename, salt)
		if err != nil {
			return errors.New("Failed to add device: " + err.Error())
		}
	} else {
		// Device exists, update
		_, err = db.Exec("UPDATE DEVICES SET DEVICENAME = ? WHERE ID = ?", devicename, deviceID)
		if err != nil {
			return errors.New("Failed to update device: " + err.Error())
		}
	}
	return nil
}

func DeleteDevice(userid int, macaddress string) error {
	_, err := db.Exec("DELETE FROM DEVICES WHERE MACADDRESS = ? AND USER_ID = ?", macaddress, userid)
	if err != nil {
		return errors.New("Failed to delete device: " + err.Error())
	}
	return nil
}
