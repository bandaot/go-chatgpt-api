package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	arkose "github.com/xqdoo00o/funcaptcha"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
}

func NewError(location string, statusCode int, details string) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
	}
}

type AccountCookies map[string][]*http.Cookie

var allCookies AccountCookies

type Result struct {
	AccessToken string `json:"access_token"`
	PUID        string `json:"puid"`
}

const (
	defaultPrefix 	                   = "https://ai-%s.fakeopen.com"
	defaultErrorMessageKey             = "errorMessage"
	AuthorizationHeader                = "Authorization"
	XAuthorizationHeader               = "X-Authorization"
	ContentType                        = "application/x-www-form-urlencoded"
	UserAgent                          = "ChatGPTApp/1490 CFNetwork/1410.0.3 Darwin/22.6.0"
	Auth0Url                           = "https://auth0.openai.com"
	LoginUsernameUrl                   = Auth0Url + "/u/login/identifier?state="
	LoginPasswordUrl                   = Auth0Url + "/u/login/password?state="
	AuthTokenUrl                       = Auth0Url + "/oauth/token"
	ParseUserInfoErrorMessage          = "Failed to parse user login info."
	GetAuthorizedUrlErrorMessage       = "Failed to get authorized url."
	GetStateErrorMessage               = "Failed to get state."
	EmailInvalidErrorMessage           = "Email is not valid."
	EmailOrPasswordInvalidErrorMessage = "Email or password is not correct."
	GetAccessTokenErrorMessage         = "Failed to get access token."
	GetArkoseTokenErrorMessage         = "Failed to get arkose token."
	defaultTimeoutSeconds              = 600 // 10 minutes

	csrfUrl                  = "https://chat.openai.com/api/auth/csrf"
	promptLoginUrl           = "https://chat.openai.com/api/auth/signin/auth0?prompt=login"
	getCsrfTokenErrorMessage = "Failed to get CSRF token."
	authSessionUrl           = "https://chat.openai.com/api/auth/session"
	code_challenge           = "ne-n5bA7hslzCq0ZUfJW0LjLEusAsn-Hc4u1n8m32eQ"
    code_verifier            = "ndYNRSJaqtW60RC_ldZHYhbT5JN1xZxNiKBNvw6I-Ns"
)

type UserLogin struct {
	Username string
	Password string
	client   tls_client.HttpClient
	Result   Result
}

func defaultApiPrefix() string {
	yesterday := time.Now().AddDate(0, 0, -1)
	return fmt.Sprintf(defaultPrefix, yesterday.Format("20060102"))
}

//goland:noinspection GoUnhandledErrorResult,SpellCheckingInspection
func NewHttpClient(proxyUrl string) tls_client.HttpClient {
	client := getHttpClient()

	if proxyUrl != "" {
		client.SetProxy(proxyUrl)
	}

	return client
}

func getHttpClient() tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}...)
	return client
}

func NewAuthenticator(emailAddress, password, proxy string) *UserLogin {
	userLogin := &UserLogin{
		Username: emailAddress,
		Password: password,
		client:   NewHttpClient(proxy),
	}
	return userLogin
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetAuthorizedUrl(preauth string) (string) {
	baseURL := "https://auth0.openai.com/authorize"
	
	params := url.Values{}
	params.Add("ios_app_version", "1490")
	params.Add("client_id", "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh")
	params.Add("auth0Client", "eyJlbnYiOnsiaU9TIjoiMTYuNiIsInN3aWZ0IjoiNS54In0sIm5hbWUiOiJBdXRoMC5zd2lmdCIsInZlcnNpb24iOiIyLjMuMiJ9")
	params.Add("audience", "https://api.openai.com/v1")
	params.Add("redirect_uri", "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback")
	params.Add("scope", "openid email profile offline_access model.request model.read organization.read offline")
	params.Add("response_type", "code")
	params.Add("code_challenge", code_challenge)
	params.Add("code_challenge_method", "S256")
	params.Add("prompt", "login")
	params.Add("preauth_cookie", preauth)
	params.Add("ios_device_id", "9806ED3F-D165-451F-A669-3ED531CFF18E")
	params.Add("state", "76mpoSWxHWGaZJvSkFSLvrMf2owL_3WFDUhBJgQRiYU")


	authUrl := baseURL + "?" + params.Encode()
	return authUrl
	// req, err := http.NewRequest(http.MethodGet, authUrl, nil)
	// req.Header.Set("Content-Type", ContentType)
	// req.Header.Set("User-Agent", UserAgent)
	
	// resp, err := userLogin.client.Do(req)
	// if err != nil {
	// 	return "", http.StatusInternalServerError, err
	// }

	// defer resp.Body.Close()
	// if resp.StatusCode != http.StatusOK {
	// 	return "", resp.StatusCode, errors.New(GetAuthorizedUrlErrorMessage)
	// }

	// urlParams, _ := url.ParseQuery(resp.Request.URL.RawQuery)

	// states, _ := urlParams["state"]
	// state := states[0]

	// responseMap := make(map[string]string)
	// json.NewDecoder(resp.Body).Decode(&responseMap)
	// return responseMap["url"], http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetState(authorizedUrl string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, authorizedUrl, nil)
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Referer", "https://ios.chat.openai.com/")
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(GetStateErrorMessage)
	}

	urlParams, _ := url.ParseQuery(resp.Request.URL.RawQuery)
	states, _ := urlParams["state"]
	state := states[0]
	return state, http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckUsername(state string, username string) (int, error) {
	formParams := url.Values{
		"state":                       {state},
		"username":                    {username},
		"js-available":                {"true"},
		"webauthn-available":          {"true"},
		"is-brave":                    {"false"},
		"webauthn-platform-available": {"false"},
		"action":                      {"default"},
	}
	req, _ := http.NewRequest(http.MethodPost, LoginUsernameUrl+state, strings.NewReader(formParams.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Referer", LoginUsernameUrl+state)
	req.Header.Set("Origin", "https://auth0.openai.com")
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errors.New(EmailInvalidErrorMessage)
	}

	return http.StatusOK, nil
}

func (userLogin *UserLogin) setArkose() (int, error) {
	token, err := arkose.GetOpenAIAuthToken("", userLogin.client.GetProxy())
	if err == nil {
		u, _ := url.Parse("https://openai.com")
		cookies := []*http.Cookie{}
		userLogin.client.GetCookieJar().SetCookies(u, append(cookies, &http.Cookie{Name: "arkoseToken", Value: token}))
		return http.StatusOK, nil
	} else {
		println("Error getting auth Arkose token")
		return http.StatusInternalServerError, err
	}
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckPassword(state string, username string, password string) (string, int, error) {
	formParams := url.Values{
		"state":    {state},
		"username": {username},
		"password": {password},
		"action":   {"default"},
	}
	req, err := http.NewRequest(http.MethodPost, LoginPasswordUrl+state, strings.NewReader(formParams.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Referer", LoginPasswordUrl+state)
	req.Header.Set("Origin", "https://auth0.openai.com")
	userLogin.client.SetFollowRedirect(false)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		alert := doc.Find("#prompt-alert").Text()
		if alert != "" {
			return "", resp.StatusCode, errors.New(strings.TrimSpace(alert))
		}

		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		println("Location1: " + location)
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+location, nil)
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Referer", Auth0Url+location)
		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		defer resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			println("Location2: " + location)
			if strings.HasPrefix(location, "/u/mfa-otp-challenge") {
				return "", http.StatusBadRequest, errors.New("Login with two-factor authentication enabled is not supported currently.")
			}

			parsedURL, err := url.Parse(location)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
				return "", http.StatusInternalServerError, err
			}

			queryParams := parsedURL.Query()
			code := queryParams.Get("code")

			fmt.Println("Code:", code)

			jsonParams := map[string]string{
				"code_verifier": code_verifier,
				"redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
				"code": code,
				"client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
				"grant_type": "authorization_code",
			}

			jsonBody, err := json.Marshal(jsonParams)
			if err != nil {
				println("Error: " + err.Error())
				return "", http.StatusInternalServerError, err
			}
			content := string(jsonBody)
			// println(content)
			req, _ := http.NewRequest(http.MethodPost, AuthTokenUrl, strings.NewReader(content))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", UserAgent)
			resp, err := userLogin.client.Do(req)
			if err != nil {
				println("Error: " + err.Error())
				return "", http.StatusInternalServerError, err
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				fmt.Println("Status code:", resp.StatusCode)
				return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response body:", err)
				return "", resp.StatusCode, err
			}

			// fmt.Println("Status code:", resp.StatusCode)
			
			return string(bodyBytes), resp.StatusCode, nil;
		}

		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	return "", resp.StatusCode, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat,GoUnusedParameter
func (userLogin *UserLogin) GetAccessTokenInternal(code string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, authSessionUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			responseMap := make(map[string]string)
			json.NewDecoder(resp.Body).Decode(&responseMap)
			return "", resp.StatusCode, errors.New(responseMap["detail"])
		}

		return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	// Check if access token in data
	if _, ok := result["accessToken"]; !ok {
		result_string := fmt.Sprintf("%v", result)
		return result_string, 0, errors.New("missing access token")
	}
	return result["accessToken"].(string), http.StatusOK, nil
}

func (userLogin *UserLogin) Begin() (string, *Error) {
	_, err, result := userLogin.GetToken()
	if err != "" {
		return "", NewError("begin", 0, err)
	}
	userLogin.Result.AccessToken = result
	return result, nil
}

func (userLogin *UserLogin) GetToken() (int, string, string) {
	// get preauth_cookie
	url := fmt.Sprintf(defaultApiPrefix()+"/auth/preauth")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err.Error(), ""
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			doc, _ := goquery.NewDocumentFromReader(resp.Body)
			alert := doc.Find(".message").Text()
			if alert != "" {
				return resp.StatusCode, strings.TrimSpace(alert), ""
			}
		}

		return resp.StatusCode, getCsrfTokenErrorMessage, ""
	}

	// get authorized url
	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	authorizedUrl := userLogin.GetAuthorizedUrl(responseMap["preauth_cookie"])
	println(authorizedUrl)

	// get state
	state, statusCode, err := userLogin.GetState(authorizedUrl)
	println(state)
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// check username
	statusCode, err = userLogin.CheckUsername(state, userLogin.Username)
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// set arkose captcha
	statusCode, err = userLogin.setArkose()
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// check password
	result, statusCode, err := userLogin.CheckPassword(state, userLogin.Username, userLogin.Password)
	if err != nil {
		return statusCode, err.Error(), ""
	}

	// println(result)

	return http.StatusOK, "", result
}

func (userLogin *UserLogin) GetAccessToken() string {
	return userLogin.Result.AccessToken
}

func (userLogin *UserLogin) GetPUID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_puid", 0, "Missing access token")
	}
	// Make request to https://chat.openai.com/backend-api/models
	req, _ := http.NewRequest("GET", "https://chat.openai.com/backend-api/models?history_and_training_disabled=false", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_puid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_puid", resp.StatusCode, "Failed to make request")
	}
	// Find `_puid` cookie in response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_puid" {
			userLogin.Result.PUID = cookie.Value
			return cookie.Value, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_puid", 0, "PUID cookie not found")
}

func init() {
	allCookies = AccountCookies{}
	file, err := os.Open("cookies.json")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&allCookies)
	if err != nil {
		return
	}
}

func (userLogin *UserLogin) ResetCookies() {
	userLogin.client.SetCookieJar(tls_client.NewCookieJar())
}

func (userLogin *UserLogin) SaveCookies() *Error {
	u, _ := url.Parse("https://chat.openai.com")
	cookies := userLogin.client.GetCookieJar().Cookies(u)
	file, err := os.OpenFile("cookies.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	defer file.Close()
	filtered := []*http.Cookie{}
	expireTime := time.Now().AddDate(0, 0, 7)
	for _, cookie := range cookies {
		if cookie.Expires.After(expireTime) {
			filtered = append(filtered, cookie)
		}
	}
	allCookies[userLogin.Username] = filtered
	encoder := json.NewEncoder(file)
	err = encoder.Encode(allCookies)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	return nil
}

func (userLogin *UserLogin) RenewWithCookies() *Error {
	cookies := allCookies[userLogin.Username]
	if len(cookies) == 0 {
		return NewError("readCookie", 0, "no cookies")
	}
	u, _ := url.Parse("https://chat.openai.com")
	userLogin.client.GetCookieJar().SetCookies(u, cookies)
	accessToken, statusCode, err := userLogin.GetAccessTokenInternal("")
	if err != nil {
		return NewError("renewToken", statusCode, err.Error())
	}
	userLogin.Result.AccessToken = accessToken
	return nil
}

func (userLogin *UserLogin) GetAuthResult() Result {
	return userLogin.Result
}
