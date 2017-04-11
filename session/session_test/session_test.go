package session_test

import (
	"fmt"
	"kayo/session"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type User struct {
	FirstName    string
	LastName     string
	EmailAddress string
}

func TestCookieSession(t *testing.T) {
	// create the cookie store
	cookieStore, er := session.NewCookieStore([]byte("1234"), []byte("1234567890abcdef"), session.NewJSONCoder(), func() interface{} { return new(User) })
	if er != nil {
		fmt.Println(er)
	}
	//initialize the cookie session
	session.Init(cookieStore, "mysession", "localhost", "/", 2, false)

	// create an empty request
	request := &http.Request{}

	// start checking the request if there is a session
	sess, err := session.Start(request)
	if err != nil {
		t.Error()
	}

	if sess.State != session.NEW {
		t.Errorf("Test failed, expected: %s got:%s\n", session.NEW, sess.State)
	}
	// put some data
	sess.LoginName = "johndoe"
	sess.Flags = 0xFFFF
	sess.Data = &User{FirstName: "John", LastName: "Doe", EmailAddress: "johndoe@gmail.com"}

	// save the session
	recorder := httptest.NewRecorder()
	session.Save(recorder, sess)

	// Copy the cookie from recorder to a new request
	request2 := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	//start checking the 2nd request if there is a session
	sess, err = session.Start(request2)

	// validate expected data
	if sess.State != session.VALID {
		t.Errorf("Test failed, expected: %s got:%s\n", session.VALID, sess.State)
	}
	if sess.LoginName != "johndoe" {
		t.Errorf("Test failed, expected: %s got:%s\n", "johndoe", sess.LoginName)
	}
	usr := sess.Data.(*User)
	if usr.FirstName != "John" {
		t.Errorf("Test failed, expected: %s got:%s\n", "John", usr.FirstName)
	}
	if usr.LastName != "Doe" {
		t.Errorf("Test failed, expected: %s got:%s\n", "Doe", usr.LastName)
	}
	if usr.EmailAddress != "johndoe@gmail.com" {
		t.Errorf("Test failed, expected: %s got:%s\n", "johndoe@gmail.com", usr.EmailAddress)
	}

	// save the session again
	recorder2 := httptest.NewRecorder()
	session.Save(recorder2, sess)

	// sleep for 3 seconds
	time.Sleep(3 * time.Second)
	// Copy the cookie again from recorder to a new request
	request3 := &http.Request{Header: http.Header{"Cookie": recorder2.HeaderMap["Set-Cookie"]}}
	//start checking the 3nd request if there is a session
	sess, err = session.Start(request3)

	if sess.State != session.EXPIRED {
		t.Errorf("Test failed, expected: %s got:%s\n", session.EXPIRED, sess.State)

	}
	// destroy the session again
	recorder3 := httptest.NewRecorder()
	session.Destroy(recorder3, sess)

	// Copy the cookie again from recorder to a new request
	request4 := &http.Request{Header: http.Header{"Cookie": recorder3.HeaderMap["Set-Cookie"]}}

	//start checking the 4th request if there is a session
	sess, err = session.Start(request4)

	if sess.State != session.NEW {
		t.Errorf("Test failed, expected: %s got:%s\n", session.NEW, sess.State)
	}

}
