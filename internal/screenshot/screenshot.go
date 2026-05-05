// Package screenshot, chromedp (headless Chrome/Chromium) kullanarak verilen
// hedefi her ziyaretçi profili imzasıyla render edip PNG ekran görüntüsü alır.
//
// HTTP fetcher'ın göremediği iki sınıf cloaker'ı yakalamak için gereklidir:
//
//  1. JS challenge (Cloudflare-benzeri, fingerprintjs, anti-bot) ardından
//     enjekte edilen black page.
//  2. Saf HTTP yanıtında bulunmayan, runtime'da DOM'a yazılan formlar.
//
// Chrome/Chromium/Edge sistemde yüklü olmalıdır. Bulunamazsa nazikçe hata döner.
package screenshot

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mert-Zengin/taygun/internal/profiles"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Options, headless tarayıcı davranışını ayarlar.
type Options struct {
	Timeout    time.Duration // Tek profil için toplam süre
	WaitAfter  time.Duration // Sayfa yüklendikten sonra JS render için bekleme
	Quality    int           // JPEG kalitesi değil; FullScreenshot için 0-100
	WindowW    int
	WindowH    int
	ChromePath string // Boşsa PATH'ten otomatik bulunur
}

// DefaultOptions, makul varsayılanlar.
func DefaultOptions() Options {
	return Options{
		Timeout:   30 * time.Second,
		WaitAfter: 2500 * time.Millisecond,
		Quality:   90,
		WindowW:   1366,
		WindowH:   900,
	}
}

// Capture, tek profille tek hedefin ekran görüntüsünü PNG byte olarak döner.
func Capture(ctx context.Context, target string, prof profiles.Profile, opts Options) ([]byte, error) {
	headers := map[string]any{}
	if prof.AcceptLanguage != "" {
		headers["Accept-Language"] = prof.AcceptLanguage
	}
	if prof.Referer != "" {
		headers["Referer"] = prof.Referer
	}
	for k, v := range prof.ExtraHeaders {
		headers[k] = v
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(opts.WindowW, opts.WindowH),
		chromedp.UserAgent(prof.UserAgent),
	)
	if opts.ChromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(opts.ChromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()

	bctx, bcancel := chromedp.NewContext(allocCtx)
	defer bcancel()

	tctx, tcancel := context.WithTimeout(bctx, opts.Timeout)
	defer tcancel()

	var buf []byte
	tasks := chromedp.Tasks{
		network.Enable(),
		emulation.SetUserAgentOverride(prof.UserAgent).
			WithAcceptLanguage(prof.AcceptLanguage),
	}
	if len(headers) > 0 {
		tasks = append(tasks, network.SetExtraHTTPHeaders(network.Headers(headers)))
	}
	tasks = append(tasks,
		chromedp.Navigate(target),
		chromedp.Sleep(opts.WaitAfter),
		chromedp.FullScreenshot(&buf, opts.Quality),
	)

	if err := chromedp.Run(tctx, tasks); err != nil {
		return nil, classifyError(err)
	}
	return buf, nil
}

// classifyError, kullanıcıya anlamlı hata döndürür.
func classifyError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case contains(msg, "executable file not found"),
		contains(msg, "no chrome path"),
		contains(msg, "exec: \"chrome\""):
		return errors.New("Chrome/Chromium yüklü değil veya PATH'te bulunamıyor; -screenshot için kurun veya -chrome-path verin")
	case contains(msg, "context deadline exceeded"):
		return fmt.Errorf("screenshot zaman aşımına uğradı (-screenshot-timeout artırın): %w", err)
	default:
		return fmt.Errorf("screenshot başarısız: %w", err)
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
