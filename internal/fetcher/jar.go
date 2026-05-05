package fetcher

import (
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// newCookieJar, public suffix listeli güvenli bir cookie jar üretir.
// Cloaker'ların session cookie üzerinden ikinci ziyareti farklı handle etmesini
// görebilmek için her profilin kendi jar'ı olur.
func newCookieJar() (*cookiejar.Jar, error) {
	return cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}
