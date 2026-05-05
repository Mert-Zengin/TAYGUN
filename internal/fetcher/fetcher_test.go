package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Mert-Zengin/taygun/internal/profiles"
)

func TestAugmentURL_AddsParams(t *testing.T) {
	got := augmentURL("https://x.com/p?a=1", map[string]string{
		"utm_source": "ig",
		"fbclid":     "abc",
	})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("a") != "1" {
		t.Fatalf("orijinal param kaybedildi: %s", got)
	}
	if q.Get("utm_source") != "ig" {
		t.Fatalf("utm_source eklenmedi: %s", got)
	}
	if q.Get("fbclid") != "abc" {
		t.Fatalf("fbclid eklenmedi: %s", got)
	}
}

func TestAugmentURL_OverridesExisting(t *testing.T) {
	// Kullanıcı utm_source=google ile geldi, profil utm_source=fb istiyor.
	// Profil senaryosu bozulmasın diye override etmeli.
	got := augmentURL("https://x.com/?utm_source=google", map[string]string{
		"utm_source": "fb",
	})
	u, _ := url.Parse(got)
	if u.Query().Get("utm_source") != "fb" {
		t.Fatalf("override başarısız: %s", got)
	}
}

func TestAugmentURL_NilParamsIsNoOp(t *testing.T) {
	in := "https://x.com/p?a=1&b=2"
	if got := augmentURL(in, nil); got != in {
		t.Fatalf("boş paramda URL değişmemeli: %s", got)
	}
}

// TestFetchAll_AppliesProfileURLParams, gerçek bir HTTP mock sunucusuyla
// profile URLParams'ının istek URL'sine doğru enjekte edildiğini garanti eder.
func TestFetchAll_AppliesProfileURLParams(t *testing.T) {
	type recorded struct {
		path  string
		query url.Values
		ua    string
	}
	gotByUA := map[string]recorded{}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotByUA[r.UserAgent()] = recorded{
			path:  r.URL.Path,
			query: r.URL.Query(),
			ua:    r.UserAgent(),
		}
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><title>ok</title></html>"))
	}))
	defer srv.Close()

	profs := []profiles.Profile{
		{
			Name:      "Plain",
			Kind:      "human",
			UserAgent: "ua-plain",
		},
		{
			Name:      "AdClick",
			Kind:      "human",
			UserAgent: "ua-adclick",
			URLParams: map[string]string{
				"utm_source": "ig",
				"fbclid":     "PAcid_xyz",
			},
		},
	}

	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second
	results := FetchAll(context.Background(), srv.URL+"/lndirim/urun.php?s=cay", profs, opts)
	if len(results) != 2 {
		t.Fatalf("2 sonuç bekleniyordu, gelen %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("fetch hatası: %v", r.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	plain := gotByUA["ua-plain"]
	if plain.path != "/lndirim/urun.php" {
		t.Fatalf("plain path beklenmedik: %s", plain.path)
	}
	if plain.query.Get("s") != "cay" {
		t.Fatalf("plain orijinal s param yok: %v", plain.query)
	}
	if plain.query.Get("utm_source") != "" {
		t.Fatalf("plain profilde utm enjeksiyonu olmamalı: %v", plain.query)
	}

	ad := gotByUA["ua-adclick"]
	if ad.query.Get("s") != "cay" {
		t.Fatalf("ad orijinal s param yok: %v", ad.query)
	}
	if ad.query.Get("utm_source") != "ig" {
		t.Fatalf("ad profilinde utm_source enjekte edilmedi: %v", ad.query)
	}
	if ad.query.Get("fbclid") != "PAcid_xyz" {
		t.Fatalf("ad profilinde fbclid enjekte edilmedi: %v", ad.query)
	}
}
