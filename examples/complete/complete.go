package main

// Open url in browser:
// http://localhost:14000/app

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/kenshaw/oauthlib"
	"github.com/kenshaw/oauthlib/oauthlibtest"
)

func main() {
	sconfig := oauthlib.NewConfig()
	sconfig.AllowedAuthRequestTypes = []string{"code", "token"}
	sconfig.AllowedGrantTypes = []oauthlib.GrantType{
		oauthlib.AuthorizationCodeGrant,
		oauthlib.RefreshTokenGrant,
		oauthlib.PasswordGrant,
		oauthlib.ClientCredentialsGrant,
		oauthlib.AssertionGrant,
	}
	server := oauthlib.NewServer(sconfig, oauthlib.NewTestStorage(nil))

	// Authorization code endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if ar := server.HandleAuthRequest(resp, r); ar != nil {
			if !oauthlibtest.HandleLoginPage(ar, w, r) {
				return
			}
			ar.UserData = struct{ Login string }{Login: "test"}
			ar.Authorized = true
			server.FinishAuthRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		if !resp.IsError {
			resp.Output["custom_parameter"] = 187723
		}
		oauthlib.WriteJSON(w, resp)
	})

	// Access token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if tr := server.HandleTokenRequest(resp, r); tr != nil {
			switch tr.GrantType {
			case oauthlib.AuthorizationCodeGrant:
				tr.Authorized = true
			case oauthlib.RefreshTokenGrant:
				tr.Authorized = true
			case oauthlib.PasswordGrant:
				if tr.Username == "test" && tr.Password == "test" {
					tr.Authorized = true
				}
			case oauthlib.ClientCredentialsGrant:
				tr.Authorized = true
			case oauthlib.AssertionGrant:
				if tr.AssertionType == "urn:oauthlib.example.complete" && tr.Assertion == "oauthlib.data" {
					tr.Authorized = true
				}
			}
			server.FinishTokenRequest(resp, r, tr)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		if !resp.IsError {
			resp.Output["custom_parameter"] = 19923
		}
		oauthlib.WriteJSON(w, resp)
	})

	// Information endpoint
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}

		oauthlib.WriteJSON(w, resp)
	})

	// Application home endpoint
	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))

		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Code</a><br/>", url.QueryEscape("http://localhost:14000/appauth/code"))))
		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=token&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Implict</a><br/>", url.QueryEscape("http://localhost:14000/appauth/token"))))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/password\">Password</a><br/>")))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/client_credentials\">Client Credentials</a><br/>")))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/assertion\">Assertion</a><br/>")))

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

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
			url.QueryEscape("http://localhost:14000/appauth/code"), url.QueryEscape(code))

		// if parse, download and parse json
		if r.Form.Get("doparse") == "1" {
			err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
				&oauthlib.BasicAuth{"1234", "aabbccdd"}, jr)
			if err != nil {
				w.Write([]byte(err.Error()))
				w.Write([]byte("<br/>"))
			}
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		// output links
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

		cururl := *r.URL
		curq := cururl.Query()
		curq.Add("doparse", "1")
		cururl.RawQuery = curq.Encode()
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}
	})

	// Application destination - TOKEN
	http.HandleFunc("/appauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - TOKEN<br/>"))

		w.Write([]byte("Response data in fragment - not acessible via server - Nothing to do"))

		w.Write([]byte("</body></html>"))
	})

	// Application destination - PASSWORD
	http.HandleFunc("/appauth/password", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - PASSWORD<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=password&scope=everything&username=%s&password=%s",
			"test", "test")

		// download token
		err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
			&oauthlib.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - CLIENT_CREDENTIALS
	http.HandleFunc("/appauth/client_credentials", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - CLIENT CREDENTIALS<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=client_credentials")

		// download token
		err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
			&oauthlib.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - ASSERTION
	http.HandleFunc("/appauth/assertion", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - ASSERTION<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=assertion&assertion_type=urn:oauthlib.example.complete&assertion=oauthlib.data")

		// download token
		err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
			&oauthlib.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - REFRESH
	http.HandleFunc("/appauth/refresh", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - REFRESH<br/>"))
		defer w.Write([]byte("</body></html>"))

		code := r.Form.Get("code")

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=refresh_token&refresh_token=%s", url.QueryEscape(code))

		// download token
		err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
			&oauthlib.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}
	})

	// Application destination - INFO
	http.HandleFunc("/appauth/info", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - INFO<br/>"))
		defer w.Write([]byte("</body></html>"))

		code := r.Form.Get("code")

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/info?code=%s", url.QueryEscape(code))

		// download token
		err := oauthlibtest.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl),
			&oauthlib.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}
	})

	http.ListenAndServe(":14000", nil)
}
