package cookie

import (
	"api-forward-auth/internal/config"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type CookieFactory struct {
	config *config.Config
}

func NewCookieFactory(config *config.Config) *CookieFactory {
	return &CookieFactory{config}
}

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, email, expires)|expires|email
func (cf *CookieFactory) ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Unable to decode cookie mac")
	}

	expectedSignature := cf.cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("Unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("Invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("Unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("Cookie has expired")
	}

	// Looks valid
	return parts[2], nil
}

// Utility methods

// Get redirect uri
func (cf *CookieFactory) RedirectUri(r *http.Request) string {
	u := url.URL{}
	u.Host = r.Header.Get("X-Forwarded-Host")
	u.Scheme = r.Header.Get("X-Forwarded-Proto")
	u.Path = r.Header.Get("X-Forwarded-Uri")
	return u.String()
}

// Cookie methods

// MakeCookie creates an auth cookie
func (cf *CookieFactory) MakeCookie(r *http.Request, userID string) *http.Cookie {
	expires := cf.cookieExpiry()
	mac := cf.cookieSignature(r, userID, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), userID)

	return &http.Cookie{
		Name:     cf.config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cf.cookieDomain(r),
		HttpOnly: true,
		Secure:   !cf.config.InsecureCookie,
		Expires:  expires,
		SameSite: http.SameSiteStrictMode,
	}
}

// ClearCookie clears the auth cookie
func (cf *CookieFactory) ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     cf.config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cf.cookieDomain(r),
		HttpOnly: true,
		Secure:   !cf.config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
		SameSite: http.SameSiteStrictMode,
	}
}

// Cookie domain
func (cf *CookieFactory) cookieDomain(r *http.Request) string {
	// Check if any of the given cookie domains matches
	domain, _ := cf.matchCookieDomains(r.Header.Get("X-Forwarded-Host"))
	return domain
}

// Return matching cookie domain if exists
func (cf *CookieFactory) matchCookieDomains(domain string) (string, bool) {
	// Remove port
	domain = strings.Split(domain, ":")[0]

	for _, d := range cf.config.CookieDomains {
		if domain == d || strings.HasSuffix(domain, d) {
			return d, true
		}
	}

	return domain, false
}

// Create cookie hmac
func (cf *CookieFactory) cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, cf.config.Secret)
	hash.Write([]byte(cf.cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func (cf *CookieFactory) cookieExpiry() time.Time {
	return time.Now().Local().Add(cf.config.Lifetime)
}
