package analyzer

import (
	"strings"
	"testing"

	"github.com/Mert-Zengin/taygun/internal/fetcher"
	"github.com/Mert-Zengin/taygun/internal/profiles"
)

const whitePage = `<html><head><title>Peyser Market</title>
<meta name="description" content="Premium gıdanın yeni adresi - en taze ürünler bir tıkla kapınızda">
</head><body>
<h1>Premium Gıdanın Yeni Adresi</h1>
<p>Yerel üreticilerden özenle seçilmiş organik sebze ve meyveler. 2012'den beri şehrin merkezinde en kaliteli ve taze ürünleri sunmaktan gurur duyuyoruz. Yerel üreticileri desteklemek ve sizlere en iyi lezzetleri sunmak önceliğimizdir.</p>
<p>Artisan ekmekleri, gourmet peynirler, organik şaraplar, deniz ürünleri ve dünya mutfağından seçkin tatlar.</p>
<p>Her gün taze fırından çıkan ekmekler ve yerel üreticilerin ürünleri.</p>
</body></html>`

const blackPage = `<html><head><title>A101 Hediye Çeki - Üye Girişi</title></head><body>
<h1>Üye Girişi</h1>
<form action="/login" method="post">
  <input type="text" name="username" />
  <input type="password" name="password" />
</form>
<script>var card_number = "";</script>
</body></html>`

func TestFingerprintExtraction(t *testing.T) {
	fp := buildFingerprint([]byte(blackPage), DefaultBrands)
	if !strings.Contains(fp.Title, "A101") {
		t.Fatalf("title yakalanamadı: %q", fp.Title)
	}
	if !fp.HasPassword {
		t.Fatal("password input tespit edilemedi")
	}
	if fp.BrandHits["a101"] == 0 {
		t.Fatal("a101 marka sızıntısı tespit edilemedi")
	}
	if len(fp.SuspiciousJS) == 0 {
		t.Fatal("şüpheli JS deseni (card_number) tespit edilemedi")
	}
	if len(fp.FormsAction) == 0 {
		t.Fatal("form action toplanamadı")
	}
}

func TestAnalyzeDetectsCloaking(t *testing.T) {
	results := []fetcher.Result{
		{
			Profile:    profiles.Profile{Name: "Human Chrome", Kind: "human"},
			StatusCode: 200,
			Body:       []byte(whitePage),
			BodyLen:    len(whitePage),
			BodySHA256: "white",
			FinalURL:   "https://test/",
		},
		{
			Profile:    profiles.Profile{Name: "TR Ads click", Kind: "human"},
			StatusCode: 200,
			Body:       []byte(blackPage),
			BodyLen:    len(blackPage),
			BodySHA256: "black",
			FinalURL:   "https://test/",
		},
	}
	rep := Analyze("https://test/", results, DefaultBrands)
	if rep.OverallScore < 70 {
		t.Fatalf("cloaking tespit edilemedi, skor=%d, verdict=%s", rep.OverallScore, rep.OverallVerdict)
	}
	if rep.OverallVerdict != "CLOAKING TESPİT EDİLDİ" {
		t.Fatalf("beklenen verdict gelmedi: %s", rep.OverallVerdict)
	}
	if rep.UniqueHashes != 2 {
		t.Fatalf("beklenen 2 tekil hash, gelen %d", rep.UniqueHashes)
	}
	if rep.CloakingProfile == nil || rep.CloakingProfile.Result.Profile.Name != "TR Ads click" {
		t.Fatal("cloaking profili doğru raporlanmadı")
	}
}

func TestAnalyzeAllSameContent(t *testing.T) {
	results := []fetcher.Result{
		{
			Profile:    profiles.Profile{Name: "Human Chrome", Kind: "human"},
			StatusCode: 200,
			Body:       []byte(whitePage),
			BodyLen:    len(whitePage),
			BodySHA256: "same",
			FinalURL:   "https://test/",
		},
		{
			Profile:    profiles.Profile{Name: "Googlebot", Kind: "bot"},
			StatusCode: 200,
			Body:       []byte(whitePage),
			BodyLen:    len(whitePage),
			BodySHA256: "same",
			FinalURL:   "https://test/",
		},
	}
	rep := Analyze("https://test/", results, DefaultBrands)
	if rep.OverallScore != 0 {
		t.Fatalf("hash aynıysa skor 0 olmalı, gelen=%d", rep.OverallScore)
	}
	if rep.UniqueHashes != 1 {
		t.Fatalf("tek hash beklendi, gelen %d", rep.UniqueHashes)
	}
	if len(rep.Diagnostics) == 0 {
		t.Fatal("diagnostic mesajı üretilmedi")
	}
}
