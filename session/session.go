package session

import (
	"net/http"
	"time"
	"errors"
)

type SessionState int

const (
	NEW     SessionState = 0
	VALID   SessionState = 1
	EXPIRED SessionState = 2
)

func (ss SessionState) String() string {
	if ss == NEW {
		return "NEW"
	} else if ss == VALID {
		return "VALID"
	} else {
		return "EXPIRED"

	}
}

type Provider interface {
	// save a session; must return a token/id that will be saved in cookie header.
	Put(sess *Session) (string, error)
	// retrieve a session
	Get(token string) (*Session, error)

	// delete a session
	Delete(token string) error
}

type CookieOptions struct {
	Store  Provider
	Name   string
	Path   string
	Domain string
	Secure bool
	MaxAge time.Duration
}

type Session struct {
	// State of the session
	State SessionState

	// Expiry of the session in seconds
	Expiry uint32

	// A uniqie string that identifies the session in session store/provider;
	// not applicable when using cookies as session storage
	Token string

	// storage for user identity
	LoginName string

	// an unsigned integer storage
	Flags uint64

	// extra generic storage
	Data interface{}
}

var cookie CookieOptions

// initialized cookie parameters
func Init(provider Provider, cookieName, domain, path string, maxAge int, secure bool) {
	cookie.Store = provider
	cookie.Name = cookieName
	cookie.Path = path
	cookie.Domain = domain
	cookie.MaxAge = time.Duration(int64(time.Second) * int64(maxAge))
	cookie.Secure = secure // transmit on https only
}

// start a session; returns error when session.State is NEW
func Start(r *http.Request) (*Session, error) {
	var s *Session
	c, er := r.Cookie(cookie.Name)
	if er != nil {
		return new(Session), er
	}
	if c.Value == "" {
		return new(Session), errors.New("cookie is empty")
	}
	s, er = cookie.Store.Get(c.Value)

	if er != nil {
		return new(Session), er
	}
	if s.Expiry < uint32(time.Now().Unix()) {
		s.State = EXPIRED
		cookie.Store.Delete(s.Token)
		return s, nil
	}
	s.State = VALID
	return s, nil
}

func Save(w http.ResponseWriter, s *Session) error {
	s.State = VALID
	t := time.Now().Add(cookie.MaxAge)
	s.Expiry = uint32(t.Unix())

	c := new(http.Cookie)
	// token value
	tv, err := cookie.Store.Put(s)
	if err != nil {
		return err
	}
	c.Value = tv
	c.Name = cookie.Name
	c.Domain = cookie.Domain
	c.Path = cookie.Path
	c.Secure = cookie.Secure
	c.HttpOnly = true
	//c.Expires = t
	c.MaxAge = 0

	http.SetCookie(w, c)
	return nil
}

func Destroy(w http.ResponseWriter, s *Session) error {
	c := new(http.Cookie)
	err := cookie.Store.Delete(s.Token)
	if err != nil {
		return err
	}
	c.Value = ""
	c.Name = cookie.Name
	c.Domain = cookie.Domain
	c.Path = cookie.Path
	c.Secure = cookie.Secure
	c.HttpOnly = true
	//c.Expires = t
	c.MaxAge = -1

	http.SetCookie(w, c)
	return nil
}

