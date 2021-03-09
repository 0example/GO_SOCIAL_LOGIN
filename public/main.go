package main

import (
	"fmt" //Package fmt implements formatted I/O with functions
	"golang.org/x/oauth2" //Package oauth2 provides support for making OAuth2 authorized and authenticated HTTP requests
	"golang.org/x/oauth2/facebook" //Package facebook provides constants for using OAuth2 to access Facebook.
	"golang.org/x/oauth2/github" //Package github provides constants for using OAuth2 to access Github.
	"golang.org/x/oauth2/google" //Package google provides support for making OAuth2 authorized and authenticated HTTP requests to Google APIs.
	"html/template" //Package template (html/template) implements data-driven templates for generating HTML output safe against code injection.
	"io/ioutil" //Package ioutil implements some I/O utility functions.
	"log" //Package log implements a simple logging package.
	"net/http" //Package http provides HTTP client and server implementations.
	"net/url" //Package url parses URLs and implements query escaping.
	"strings" //Package strings implements simple functions to manipulate UTF-8 encoded strings.
)

var (
	oauthConGi = &oauth2.Config{ //This setups the 0auth client.
// Set ClientId and ClientSecret to
		ClientID:     "2465faa5c05ee74980a2",
		ClientSecret: "b5211e6350df7dc8bd5256c81d80b952ad351fa3",
		RedirectURL:  "http://localhost:9090/auth/github/callback",
// select level of access you want
		Scopes:       []string{" http://www.wixis360.com/"},
		Endpoint:     github.Endpoint,
	}
// random string for oauth2 API calls to protect against CSRF(Cross-site request forgery)
	oauthStateString = "thisshouldberandom"

	oauthConFa = &oauth2.Config{
		ClientID:     "225077211913752",
		ClientSecret: "b3e33defed81f511e81f4a9b3e64981c",
		RedirectURL:  "http://www.wixis360.com/",
		Endpoint:     facebook.Endpoint,
		Scopes:       []string{"public_profile"},
	}
// random string for oauth2 API calls to protect against CSRF
	oauthStateString1 = "thisshouldberandom"

	oauthConGo = &oauth2.Config{
		ClientID:     "391803363826-v06sb3njb224k6dq3ale44v08nckgab8.apps.googleusercontent.com",
		ClientSecret: "PRHm3LznPFCthledv923yOOh",
		RedirectURL:  "https://www.wixis360.com",
		Scopes:       []string{"email https://mail.google.com"},
		Endpoint:     google.Endpoint,
	}
// random string for oauth2 API calls to protect against CSRF
	oauthStateString2 = "thisshouldberandom"

)
var html = template.Must(template.ParseGlob("web/*")) //Must is a helper that wraps a call to a function returning and panics if the error is non-nil. 

func handleMain(w http.ResponseWriter, r *http.Request) { //This runs the html page.

	html.ExecuteTemplate(w,"index.html",nil) //ExecuteTemplate applies the template associated with w that has the given name to the specified data object and writes the output to wr

}

//Login to Github
func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	Url, err := url.Parse(oauthConGi.Endpoint.AuthURL)
	if err != nil {
		log.Fatal("Parse: ", err)
	}
	parameters := url.Values{}
	parameters.Add("client_id", oauthConGi.ClientID)
	parameters.Add("scope", strings.Join(oauthConGi.Scopes, " "))
	parameters.Add("redirect_uri", oauthConGi.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	Url.RawQuery = parameters.Encode()
	url := Url.String()
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

//Login to Facebook
func handleFacebookLogin(ww http.ResponseWriter, rr *http.Request) {
	Url,err := url.Parse(oauthConFa.Endpoint.AuthURL)
	if err !=nil{
		log.Fatal("Parse: ",err)
	}
	parameters := url.Values{}
	parameters.Add("client_id",oauthConFa.ClientID)
	parameters.Add("scope",strings.Join(oauthConFa.Scopes,""))
	parameters.Add("redirect_uri",oauthConFa.RedirectURL)
	parameters.Add("response_type","code")
	parameters.Add("state",oauthStateString1)
	Url.RawQuery = parameters.Encode()
	url := Url.String()
	http.Redirect(ww,rr,url,http.StatusTemporaryRedirect)
}

//Login to Google APIs
func handleGoogleLogin(www http.ResponseWriter, rrr *http.Request) {
	Url,err := url.Parse(oauthConGo.Endpoint.AuthURL)
	if err !=nil{
		log.Fatal("Parse: ",err)
	}
	parameters := url.Values{}
	parameters.Add("client_id",oauthConGo.ClientID)
	parameters.Add("scope",strings.Join(oauthConGo.Scopes,""))
	parameters.Add("redirect_uri",oauthConGo.RedirectURL)
	parameters.Add("response_type","code")
	parameters.Add("state",oauthStateString2)
	Url.RawQuery = parameters.Encode()
	url := Url.String()
	http.Redirect(www,rrr,url,http.StatusTemporaryRedirect)
}

//Called by Github after authorization is granted
func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")

// Handle the exchange code to initiate a transport.
	token, err := oauthConGi.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConGi.Exchange() failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	resp, err := http.Get("https://graph.github.com/me?access_token=" +
		url.QueryEscape(token.AccessToken))
	if err != nil {
		fmt.Printf("Get: %s\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body) //This reads the response of the body
	if err != nil {
		fmt.Printf("ReadAll: %s\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("parseResponseBody: %s\n", string(response))

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
//
func handleFacebookCallback(ww http.ResponseWriter, rr *http.Request)  {
	state := rr.FormValue("state")
	if state != oauthStateString1{
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(ww, rr, "/", http.StatusTemporaryRedirect)
		return
	}
	code := rr.FormValue("code")

	token, err := oauthConFa.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConFa.Exchange() failed with '%s'\n", err)
		http.Redirect(ww, rr, "/", http.StatusTemporaryRedirect)
		return
	}
	resp, err := http.Get("https://graph.facebook.com/me?access_token=" +
		url.QueryEscape(token.AccessToken))
	if err != nil {
		fmt.Printf("Get: %s\n", err)
		http.Redirect(ww, rr, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ReadAll: %s\n", err)
		http.Redirect(ww, rr, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("parseResponseBody: %s\n", string(response))

	http.Redirect(ww, rr, "/", http.StatusTemporaryRedirect)

}
//
func handleGoogleCallback(www http.ResponseWriter, rrr *http.Request)  {
	state := rrr.FormValue("state")
	if state != oauthStateString2 {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(www, rrr, "/", http.StatusTemporaryRedirect)
		return
	}
	code := rrr.FormValue("code")

	token, err := oauthConGo.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConGo.Exchange() failed with '%s'\n", err)
		http.Redirect(www, rrr, "/", http.StatusTemporaryRedirect)
		return
	}
	resp, err := http.Get("https://graph.google.com/me?access_token=" +
		url.QueryEscape(token.AccessToken))
	if err != nil {
		fmt.Printf("Get: %s\n", err)
		http.Redirect(www, rrr, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ReadAll: %s\n", err)
		http.Redirect(www, rrr, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("parseResponseBody: %s\n", string(response))

	http.Redirect(www, rrr, "/", http.StatusTemporaryRedirect)

}
//And finally this is how you tie everything together
func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login1", handleGithubLogin)
	http.HandleFunc("/login2",handleFacebookLogin)
	http.HandleFunc("/login3",handleGoogleLogin)
	http.HandleFunc("/oauth2callback1", handleGithubCallback)
	http.HandleFunc("/oauth2callback2",handleFacebookCallback)
	http.HandleFunc("/oauth2callback3",handleGoogleCallback)
	fmt.Print("Started running on http://localhost:9090\n")
	log.Fatal(http.ListenAndServe(":9090", nil))
}
