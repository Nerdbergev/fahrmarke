# Fahrmarke

Fahrmarke is a small self‑hosted presence board. It periodically scans the local network (ARP) to detect users' devices and shows who is "Untertage" (online/present) or "Übertage" (offline) on a web interface. Users can register themselves, manage a display name, attach custom attributes, and associate (hashed) device MAC addresses. Administrators can manage users, attributes, themes and system settings through a built‑in admin panel.

> Name inspiration: Traditional mining shift boards with tokens marking whether a miner is underground or above ground.

---

## Table of Contents

1. Overview
2. Features
3. Quick Start
4. Installation (Binary & Debian Package)
5. Configuration & Settings
6. Network Scanning & Device Hashing
7. Web Interface & Endpoints
8. Theming
9. Admin Panel
10. Security Notes
11. Building From Source
12. Troubleshooting
13. Roadmap / Ideas
14. License

---

## 1. Overview

Fahrmarke consists of:

* A Go web server (Chi router) serving HTML templates from the `themes/` directory.
* A periodic ARP scanner (`arplib`) that hashes device MAC addresses with per‑device salt before storing them in SQLite.
* A lightweight SQLite database auto‑initialized on first start.
* An admin control panel for system maintenance (`/admin`).

It is designed to be simple to deploy (single binary + themes + SQLite file) and easy to customize.
Attention: Currently ARP scanning only works in linux, for windows it only adds dummy MAC addresses.

## 2. Features

* User self‑registration and login
* Display name ("Showname") customization
* Per‑user custom attributes (key/value)
* Device association (MAC stored as salted hash, never in plaintext)
* Periodic presence detection via ARP (hashed MAC matching)
* Admin panel for users, attributes, settings, themes
* Password change (self & admin reset)
* Optional HTTPS (served directly if cert/key placed in datapath and `UseHTTPS=true`)
* Rate limiting & basic middleware (request ID, logging, recovery, timeout)

## 3. Quick Start

Download a release asset (`fahrmarke-<os>-<arch>.zip`) from GitHub Releases and unzip.

Launch (Linux / macOS):

```bash
./fahrmarke --datapath ./data
```

On first run Fahrmarke will create:

* `fahrmarke.db` (SQLite) with default settings and a seeded `admin` user.

Then browse to: `http://localhost:7070/` (or HTTPS if enabled) and register a user or log in as admin (see Security Notes about resetting the admin password).

## 4. Installation

### Option A: Binary (Zip)

1. Download zip for your platform.
2. Unzip into desired directory (e.g. `/opt/fahrmarke`).
3. Create a persistent data folder: `mkdir /opt/fahrmarke/data`.
4. Run with `--datapath /opt/fahrmarke/data`.
5. (Optional) Create a systemd service (see Debian package for example).

### Option B: Debian Package (.deb)

1. Download the `.deb` matching your architecture.
2. Install: `sudo dpkg -i fahrmarke_<version>_<arch>.deb`.
3. Data lives in `/var/lib/fahrmarke`. Binary placed in `/usr/bin/fahrmarke`.
4. A systemd service file is installed (e.g. `lib/systemd/system/fahrmarke.service`). Enable & start:

```bash
sudo systemctl enable --now fahrmarke
```

### Option C: From Source

See Building From Source section.

## 5. Configuration & Settings

Settings are stored in the `SETTINGS` table. Most can be edited in the admin panel.

| Key           | Purpose                                                  | Example / Default       |
|---------------|----------------------------------------------------------|-------------------------|
| `Range`       | CIDR range to scan if interface manually specified       | `192.168.2.0/24`        |
| `Scantime`    | Minutes between ARP scan ticks                           | `5`                     |
| `Theme`       | Active theme folder name                                 | `fahrmarke`             |
| `Interface`   | Network interface name (blank = auto‑select)             | `eth0`                  |
| `Port`        | Listen port (HTTP/HTTPS)                                 | `7070`                  |
| `SessionHMAC` | HMAC key for signing session IDs (must be set!)          | (empty at init)         |
| `CSRFKey`     | Key for CSRF protection (future/planned)                 | (empty at init)         |
| `UseHTTPS`    | `true` to serve HTTPS (needs `cert.pem` & `key.pem`)     | `true`                  |

You can set a setting through Admin Panel or manually:

```sql
UPDATE SETTINGS SET VALUE='7070' WHERE KEY='Port';
```

### Session & Security Keys

After first start fahrmarke sets:

1. A random `SessionHMAC` (e.g. 32 bytes base64)
2. A random `CSRFKey`

These are saved in the databased and can be changed at anytime

## 6. Network Scanning & Device Hashing

Presence is determined by ARP scanning the configured interface range every `Scantime` minutes.

Process:

1. Determine interface (from `Interface` setting or first active non‑loopback).
2. Determine CIDR range (from `Range` or derived from interface address).
3. Send ARP probes / read responses.
4. Hash discovered MAC addresses using a per‑device random salt + iterative SHA256 (see `arplib`).
5. Match hashed MACs against stored device hashes to mark users online.

Because MACs are salted+hashed, the original MAC cannot be recovered even if the DB leaks.

### Privileges

Raw ARP may require elevated privileges. Options:

* Run as root (simple but broader risk).
* Grant capability: `sudo setcap 'cap_net_raw+ep' ./fahrmarke` (preferred on Linux).

## 7. Web Interface & Endpoints

### Interface Endpoints

Public:

* `GET /` – Presence board.
* `GET /register`, `POST /register` – Self registration.
* `GET /login`, `POST /login` – Authentication.
* `POST /logout` – Session end.

Authenticated (`/me` namespace):

* `GET /me` – Profile page.
* `POST /me/showname` – Update display name.
* `POST /me/devices/add` / `delete` – Manage devices.
* `POST /me/attributes/set` – Set attribute value.
* `POST /me/password` – Change own password.

Admin (`/admin` namespace):

* `GET /admin` – Admin dashboard.
* `POST /admin/theme` / `theme/reload` – Set & reload theme.
* `POST /admin/user/create` / `delete` / `admin` / `password` – User management.
* `POST /admin/attribute/create` / `delete` / `rename` – Attribute management.
* `POST /admin/setting/set` – Update arbitrary setting.

### API Endpoints

* `GET /api/users` – Raw user JSON list (for integrations).

## 8. Theming

Themes live under `themes/<name>/` and typically include:

* `templates/*.html` – Go `html/template` files
* `static/` – CSS, images, etc.

Switch theme by setting `Theme` and (optionally) POST `/admin/theme/reload`.

To create a theme:

1. Copy existing `themes/fahrmarke` to `themes/mytheme`.
2. Edit templates & CSS. Keep IDs/classes used by handlers.
3. Set `Theme` to `mytheme`.

## 9. Admin Panel

URL: `/admin` (requires admin session). Functions:

* View all users & toggle admin flag.
* Reset user passwords.
* Create / delete / rename attributes.
* Adjust scanning settings (`Range`, `Scantime`, interface selection).
* Manage theme & reload templates without restarting.
* Update arbitrary settings including security keys.

## 10. Security Notes

* Passwords stored using bcrypt (cost 15). Adjust cost if needed for performance.
* MAC addresses are never stored in plaintext – salted iterative SHA256 hash.
* Set `SessionHMAC` immediately after first run; empty key weakens session integrity.
* Consider placing the binary behind a reverse proxy (Caddy / Nginx) for TLS management & additional rate limiting.
* Keep the SQLite file permissions restricted: `chmod 600 fahrmarke.db`.
* Change the seeded `admin` user's password ASAP (use admin panel or run SQL update after generating a new bcrypt hash).
* If enabling HTTPS set `UseHTTPS=true` and place `cert.pem` & `key.pem` in your datapath.

## 11. Building From Source

Prerequisites: Go 1.21+, Git.

```bash
git clone https://github.com/Nerdberg/fahrmarke.git
cd fahrmarke
go build -o fahrmarke ./cmd/fahrmarke
./fahrmarke --datapath ./data
```

## 12. License

This project is licensed under the terms of the license found in `LICENSE` (likely MIT unless changed). See the file for full text.

---

## Contributing

PRs and issues welcome. Open an issue describing improvements or bugs. Keep changes small, focused, and include rationale.

## Disclaimer

Network scanning may have security & privacy implications. Ensure compliance with local policies before deployment.

