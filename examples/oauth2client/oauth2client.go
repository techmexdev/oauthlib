package main

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/knq/oauthlib"
	"github.com/knq/oauthlib/oauthlibtest"
)

func main() {
	config := oauthlib.NewConfig()
	config.HttpStatusCode = http.StatusNotFound
	server := oauthlib.NewServer(config, oauthlib.NewTestStorage(nil))

	client := &oauth2.Config{
		ClientID:     "1234",
		ClientSecret: "aabbccdd",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:14000/authorize",
			TokenURL: "http://localhost:14000/token",
		},
		RedirectURL: "http://localhost:14000/appauth/code",
	}

	// authorization code endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if ar := server.HandleAuthReq(resp, r); ar != nil {
			if !oauthlibtest.HandleLoginPage(ar, w, r) {
				return
			}
			ar.Authorized = true
			server.FinishAuthReq(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		oauthlib.WriteJSON(w, resp)
	})

	// access token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if tr := server.HandleTokenReq(resp, r); tr != nil {
			tr.Authorized = true
			server.FinishTokenReq(resp, r, tr)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		oauthlib.WriteJSON(w, resp)
	})

	// information endpoint
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if ir := server.HandleInfoReq(resp, r); ir != nil {
			server.FinishInfoReq(resp, r, ir)
		}
		oauthlib.WriteJSON(w, resp)
	})

	// application home endpoint
	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Login</a><br/>", client.AuthCodeURL(""))))
		w.Write([]byte("</body></html>"))
	})

	// Application destination - CODE
	http.HandleFunc("/appauth/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		code := r.Form.Get("code")
		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - CODE<br/>"))
		defer w.Write([]byte("</body></html>"))

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		var jr *oauth2.Token
		var err error

		// if parse, download and parse json
		if r.Form.Get("doparse") == "1" {
			jr, err = client.Exchange(oauth2.NoContext, code)
			if err != nil {
				jr = nil
				w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", err)))
			}
		}

		// show json access token
		if jr != nil {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", jr.AccessToken)))
			if jr.RefreshToken != "" {
				w.Write([]byte(fmt.Sprintf("REFRESH TOKEN: %s<br/>\n", jr.RefreshToken)))
			}
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		cururl := *r.URL
		curq := cururl.Query()
		curq.Add("doparse", "1")
		cururl.RawQuery = curq.Encode()
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
	})

	http.ListenAndServe(":14000", nil)
}
