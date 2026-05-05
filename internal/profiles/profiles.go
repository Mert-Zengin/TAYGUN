// Package profiles, cloaking tespiti için kullanılan ziyaretçi
// profillerini (User-Agent + Referer + Accept-Language + bilinen bot IP'leri)
// merkezi olarak tutar. Cloaker'lar genellikle UA + IP + Referer üçlüsüne
// göre karar verdiği için profilleri bu üç eksene göre çeşitlendiriyoruz.
package profiles

// Profile, tek bir sanal ziyaretçinin imzasını tanımlar.
type Profile struct {
	Name           string            // Rapor için okunabilir ad (ör. "Googlebot Desktop")
	Kind           string            // "bot" | "human"
	UserAgent      string            // HTTP User-Agent
	AcceptLanguage string            // Accept-Language başlığı
	Referer        string            // Boş bırakılırsa gönderilmez
	ExtraHeaders   map[string]string // İhtiyaç hâlinde ek başlıklar (X-Forwarded-For vb.)

	// URLParams, hedef URL'ye eklenecek/üzerine yazılacak query parametreleri.
	// Cloaker'ların büyük çoğunluğu sadece reklam tıklaması (utm_source / fbclid /
	// gclid) varsa black page açar. Bu alan, base URL verildiğinde bile reklam
	// tıklamasını simüle etmemizi sağlar. Kullanıcı zaten utm verdiyse bu alan
	// onları override eder (her profil kendi imzasını ister).
	URLParams map[string]string
}

// All, varsayılan tarama setini döndürür.
// Sıralama önemlidir: ilk profil "baseline" (insan) kabul edilir, diğerleri ona kıyaslanır.
func All() []Profile {
	return []Profile{
		// --- BASELINE: gerçek kullanıcı ---
		{
			Name:           "Human Chrome (Windows)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			AcceptLanguage: "tr-TR,tr;q=0.9,en;q=0.8",
			Referer:        "https://www.google.com/",
		},
		{
			Name:           "Human Safari (iPhone)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			Referer:        "https://www.google.com/",
		},
		{
			Name:           "Human Firefox (Linux)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			AcceptLanguage: "en-US,en;q=0.5",
			Referer:        "",
		},

		// --- ARAMA MOTORU BOTLARI ---
		{
			Name:           "Googlebot Desktop",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/W.X.Y.Z Safari/537.36",
			AcceptLanguage: "en-US,en;q=0.9",
			ExtraHeaders: map[string]string{
				// Cloaker'ların IP whitelist mantığını da test edelim
				"From":            "googlebot(at)googlebot.com",
				"X-Forwarded-For": "66.249.66.1", // Google crawler aralığı
			},
		},
		{
			Name:           "Googlebot Smartphone",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			AcceptLanguage: "en-US,en;q=0.9",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "66.249.69.1",
			},
		},
		{
			Name:           "Bingbot",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			AcceptLanguage: "en-US,en;q=0.9",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "207.46.13.1",
			},
		},
		{
			Name:           "YandexBot",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			AcceptLanguage: "ru-RU,ru;q=0.9,en;q=0.8",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "100.43.85.1",
			},
		},
		{
			Name:           "DuckDuckBot",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "Baiduspider",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
			AcceptLanguage: "zh-CN,zh;q=0.9",
		},

		// --- SOSYAL MEDYA / MESAJLAŞMA ÖNİZLEME BOTLARI ---
		{
			Name:           "FacebookExternalHit",
			Kind:           "bot",
			UserAgent:      "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "Meta-ExternalAgent",
			Kind:           "bot",
			UserAgent:      "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "Twitterbot",
			Kind:           "bot",
			UserAgent:      "Twitterbot/1.0",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "LinkedInBot",
			Kind:           "bot",
			UserAgent:      "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "Slackbot-LinkExpanding",
			Kind:           "bot",
			UserAgent:      "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "TelegramBot",
			Kind:           "bot",
			UserAgent:      "TelegramBot (like TwitterBot)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "WhatsApp Preview",
			Kind:           "bot",
			UserAgent:      "WhatsApp/2.23.20.0 A",
			AcceptLanguage: "en-US,en;q=0.9",
		},

		// --- GÜVENLİK / İTİBAR TARAYICILARI ---
		{
			Name:           "PhishTank Crawler",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; PhishTank/1.0; +http://www.phishtank.com/)",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		{
			Name:           "Mozilla URLClassifier",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (Safe Browsing) Gecko/20100101",
			AcceptLanguage: "en-US,en;q=0.9",
		},

		// --- TÜRKİYE CERT / DEVLET TARAYICI İMZALARI ---
		// NOT: USOM (Ulusal Siber Olaylara Müdahale Merkezi / TR-CERT) ve
		// BTK'nın resmî olarak yayımladığı bir crawler User-Agent imzası
		// kamuya açık değildir. Aşağıdaki UA'lar sentetik olup, "USOM",
		// "TR-CERT" veya ".gov.tr" anahtar kelimelerini gördüğünde davranış
		// değiştiren paranoid cloaker'ları tetiklemek için tasarlanmıştır.
		// Bunlar resmî USOM araçları değildir.
		{
			Name:           "USOM Inspector (sentetik)",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; USOM-URL-Inspector/1.0; +https://www.usom.gov.tr/bildirim)",
			AcceptLanguage: "tr-TR,tr;q=0.9,en;q=0.8",
			Referer:        "https://www.usom.gov.tr/",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "212.156.0.1", // TR Telekom bloğu
				"From":            "iletisim@usom.gov.tr",
			},
		},
		{
			Name:           "TR-CERT Crawler (sentetik)",
			Kind:           "bot",
			UserAgent:      "TR-CERT/2.0 (+https://www.usom.gov.tr; phishing-takedown-bot)",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "193.140.0.1",
			},
		},
		{
			Name:           "BTK URL Filter (sentetik)",
			Kind:           "bot",
			UserAgent:      "Mozilla/5.0 (compatible; BTK-URLFilter/1.0; +https://www.btk.gov.tr)",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			ExtraHeaders: map[string]string{
				"X-Forwarded-For": "193.140.16.1",
			},
		},

		// --- REKLAM TIKLAMASI SİMÜLASYONLARI ---
		// Cloaker'ların büyük kısmı sadece "reklam üzerinden gelen" trafiği
		// black page'e yönlendirir. Bu profiller; doğru UA + Referer + TR coğrafi
		// header + KENDİ UTM/fbclid/gclid query parametrelerini hedef URL'ye
		// enjekte ederek tam reklam tıklaması davranışını simüle eder.
		// Token'lar dummy'dir; çoğu cloaker token'ı doğrulamaz, varlığına bakar.
		{
			Name:           "TR Kullanıcı (Google Ads click)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			Referer:        "https://www.google.com/aclk?sa=L&ai=DChcSEwiTaygunCloakerCheck&num=1",
			ExtraHeaders: map[string]string{
				"CF-IPCountry":       "TR",
				"X-Country-Code":     "TR",
				"X-AppEngine-Country": "TR",
				"X-Forwarded-For":    "31.223.5.10",
				"Sec-CH-UA":          `"Chromium";v="126", "Google Chrome";v="126"`,
				"Sec-CH-UA-Mobile":   "?1",
				"Sec-CH-UA-Platform": `"Android"`,
			},
			URLParams: map[string]string{
				"utm_source":   "google",
				"utm_medium":   "cpc",
				"utm_campaign": "search_brand",
				"utm_content":  "cloaker_check",
				"utm_term":     "discount",
				"gclid":        "EAIaIQobChMI_TaygunDummyToken_BwE",
				"gad_source":   "1",
			},
		},
		{
			Name:           "TR Kullanıcı (Facebook Ads click)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FBAN/FBIOS;FBAV/470.0.0",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			Referer:        "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com&fbclid=PAcid_TaygunDummy",
			ExtraHeaders: map[string]string{
				"CF-IPCountry":    "TR",
				"X-Country-Code":  "TR",
				"X-Forwarded-For": "78.180.10.20",
			},
			URLParams: map[string]string{
				"utm_source":   "fb",
				"utm_medium":   "paid",
				"utm_campaign": "fb_brand_click",
				"utm_content":  "carousel_01",
				"fbclid":       "PAcid_TaygunDummyTokenForCloakerProbe",
			},
		},
		{
			Name:           "TR Kullanıcı (Instagram in-app)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 320.0.0.0",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			Referer:        "https://www.instagram.com/",
			ExtraHeaders: map[string]string{
				"CF-IPCountry":    "TR",
				"X-Forwarded-For": "85.96.20.30",
			},
			URLParams: map[string]string{
				"utm_source":   "ig",
				"utm_medium":   "paid",
				"utm_campaign": "ig_story_ad",
				"utm_content":  "story_01",
				"utm_term":     "promo",
				"fbclid":       "PAcid_TaygunDummyInstagramProbe_aem_xyz",
			},
		},
		{
			Name:           "TR Kullanıcı (TikTok in-app)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (Linux; Android 13; SM-S908E) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36 trill_320603 JsSdk/1.0 NetType/WIFI Channel/googleplay AppName/musical_ly app_version/32.6.3",
			AcceptLanguage: "tr-TR,tr;q=0.9",
			Referer:        "https://www.tiktok.com/",
			ExtraHeaders: map[string]string{
				"CF-IPCountry":    "TR",
				"X-Forwarded-For": "176.232.10.5",
			},
			URLParams: map[string]string{
				"utm_source":   "tiktok",
				"utm_medium":   "paid",
				"utm_campaign": "tt_in_feed_ad",
				"ttclid":       "EAIaIQobChMI_TaygunTikTokDummyToken",
			},
		},
		{
			Name:           "US Kullanıcı (organik)",
			Kind:           "human",
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			AcceptLanguage: "en-US,en;q=0.9",
			Referer:        "https://duckduckgo.com/",
			ExtraHeaders: map[string]string{
				"CF-IPCountry":    "US",
				"X-Country-Code":  "US",
				"X-Forwarded-For": "8.8.8.8",
			},
			// URLParams yok bilerek: organik trafik utm taşımaz, cloaker bunu görmeli.
		},
	}
}
