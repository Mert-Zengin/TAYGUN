// Package fetcher, hedef URL'yi farklı ziyaretçi profilleriyle paralel olarak
// çeker; her istekte tüm yönlendirme zincirini, gövdeyi, header'ları ve süreyi
// kaydeder. Çıktı analyzer paketi tarafından kıyaslanmak üzere üretilir.
package fetcher

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Mert-Zengin/taygun/internal/profiles"
)

// Hop, yönlendirme zincirindeki tek bir adımı temsil eder.
type Hop struct {
	URL        string
	Status     int
	Location   string
	SetCookies []string
}

// Result, tek bir profilin çekim sonucudur.
type Result struct {
	Profile     profiles.Profile
	StartedAt   time.Time
	Duration    time.Duration
	Err         error
	FinalURL    string
	StatusCode  int
	Hops        []Hop
	Headers     http.Header
	Body        []byte
	BodySHA256  string
	BodyLen     int
	ContentType string
}

// Options, fetcher davranışını ayarlar.
type Options struct {
	Timeout         time.Duration // Tek istek için toplam zaman aşımı
	MaxRedirects    int           // İzlenecek maksimum yönlendirme sayısı
	MaxBodyBytes    int64         // Bellek koruması için gövde okuma sınırı
	InsecureTLS     bool          // Self-signed sertifikalı black page'ler için
	FollowJSMeta    bool          // <meta http-equiv="refresh"> takip et (faz 2)
	ConcurrencyLimit int          // Eş zamanlı istek sınırı
}

// DefaultOptions, makul varsayılanlar üretir.
func DefaultOptions() Options {
	return Options{
		Timeout:          15 * time.Second,
		MaxRedirects:     10,
		MaxBodyBytes:     5 * 1024 * 1024, // 5 MB
		InsecureTLS:      true,
		FollowJSMeta:     false,
		ConcurrencyLimit: 8,
	}
}

// FetchAll, verilen profillerle hedef URL'yi paralel olarak çeker.
func FetchAll(ctx context.Context, target string, profs []profiles.Profile, opts Options) []Result {
	if opts.ConcurrencyLimit <= 0 {
		opts.ConcurrencyLimit = 1
	}
	results := make([]Result, len(profs))
	sem := make(chan struct{}, opts.ConcurrencyLimit)
	var wg sync.WaitGroup

	for i, p := range profs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, prof profiles.Profile) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = fetchOne(ctx, target, prof, opts)
		}(i, p)
	}
	wg.Wait()
	return results
}

func fetchOne(ctx context.Context, target string, prof profiles.Profile, opts Options) Result {
	res := Result{Profile: prof, StartedAt: time.Now()}
	defer func() { res.Duration = time.Since(res.StartedAt) }()

	// Profil URLParams taşıyorsa, hedef URL'sine merge et (override mantığı).
	// Cloaker'ların reklam-tıklaması zorunluluğunu test etmek için kritik.
	target = augmentURL(target, prof.URLParams)

	// Her istek için sıfırdan client kuruyoruz; çünkü redirect callback'ini
	// içine kapatarak hop'ları yakalıyoruz.
	jar, _ := newCookieJar()
	client := &http.Client{
		Timeout: opts.Timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureTLS},
			// Cloaker'lar bazen ProxyFromEnvironment'a göre davranır;
			// kullanıcı çevresini kirletmemek için boş bırakıyoruz.
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return errors.New("max redirects exceeded")
			}
			// Her hop'u kayıt altına al
			last := via[len(via)-1]
			res.Hops = append(res.Hops, Hop{
				URL:        last.URL.String(),
				Status:     0, // Status yalnızca response'tan gelir; redirect öncesi cevapta da var
				Location:   req.URL.String(),
				SetCookies: nil,
			})
			// İmza tutarlılığı için header'ları her hop'ta tekrar ekle
			applyProfileHeaders(req, prof)
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		res.Err = fmt.Errorf("istek oluşturulamadı: %w", err)
		return res
	}
	applyProfileHeaders(req, prof)

	resp, err := client.Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Headers = resp.Header
	res.ContentType = resp.Header.Get("Content-Type")
	res.FinalURL = resp.Request.URL.String()

	// Son hop'un status/cookies bilgisini ekle
	res.Hops = append(res.Hops, Hop{
		URL:        res.FinalURL,
		Status:     resp.StatusCode,
		SetCookies: resp.Header.Values("Set-Cookie"),
	})

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	if err != nil {
		res.Err = fmt.Errorf("gövde okunamadı: %w", err)
		return res
	}
	res.Body = body
	res.BodyLen = len(body)
	sum := sha256.Sum256(body)
	res.BodySHA256 = hex.EncodeToString(sum[:])

	return res
}

// applyProfileHeaders, profil bilgilerini istek header'larına yazar.
func applyProfileHeaders(req *http.Request, prof profiles.Profile) {
	req.Header.Set("User-Agent", prof.UserAgent)
	if prof.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", prof.AcceptLanguage)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity") // gzip açma derdine girmiyoruz; analyzer ham içeriği görsün
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	if prof.Referer != "" {
		req.Header.Set("Referer", prof.Referer)
	}
	for k, v := range prof.ExtraHeaders {
		req.Header.Set(k, v)
	}
}

// augmentURL, hedef URL'nin query string'ine profile özel parametreleri
// ekler/üzerine yazar. Profile URLParams nil ise URL aynen döner.
func augmentURL(target string, params map[string]string) string {
	if len(params) == 0 {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// NormalizeURL, kullanıcıdan gelen hedefi http(s) şemasına tamamlar ve doğrular.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("hedef URL boş")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("geçersiz host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("desteklenmeyen şema: %s", u.Scheme)
	}
	return u.String(), nil
}
