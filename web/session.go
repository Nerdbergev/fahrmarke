package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

var sessionHMACKey = []byte("")

func signSID(sid string) string {
	mac := hmac.New(sha256.New, sessionHMACKey)
	mac.Write([]byte(sid))
	sig := mac.Sum(nil)
	return sid + "." + base64.RawURLEncoding.EncodeToString(sig[:16])
}

func verifySignedSID(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	sid, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, sessionHMACKey)
	mac.Write([]byte(sid))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])

	if !hmac.Equal([]byte(sig), []byte(want)) {
		return false
	}
	return true
}

type sessionData struct {
	UserID int
	Exp    time.Time
}

type sessionStore struct {
	sync.RWMutex
	sessions map[string]sessionData
}

func (s *sessionStore) Get(sid string) (sessionData, bool) {
	s.RLock()
	defer s.RUnlock()
	sess, ok := s.sessions[sid]
	return sess, ok
}

func (s *sessionStore) Set(sid string, data sessionData) {
	s.Lock()
	defer s.Unlock()
	s.sessions[sid] = data
}

func (s *sessionStore) Delete(sid string) {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, sid)
}

var session = sessionStore{
	sessions: make(map[string]sessionData),
}

const sessionCookieName = "sid"

func newSession(userID int) (string, sessionData, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", sessionData{}, err
	}
	sid := base64.RawURLEncoding.EncodeToString(b)
	sid = signSID(sid)
	s := sessionData{
		UserID: userID,
		Exp:    time.Now().Add(24 * time.Hour),
	}
	session.Set(sid, s)
	return sid, s, nil
}

func getSession(sid string) (sessionData, bool) {
	valid := verifySignedSID(sid)
	if !valid {

		return sessionData{}, false
	}
	s, ok := session.Get(sid)
	if !ok || time.Now().After(s.Exp) {
		return sessionData{}, false
	}
	return s, true
}

func destroySession(sid string) {
	valid := verifySignedSID(sid)
	if !valid {
		return
	}
	session.Delete(sid)
}

// Middleware: Session einlesen
type ctxKey string

const ctxUserID ctxKey = "uid"

func SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err == nil {
			if s, ok := getSession(c.Value); ok {
				ctx := context.WithValue(r.Context(), ctxUserID, s.UserID)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware: Login Pflicht
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ctxUserID) == nil {
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
